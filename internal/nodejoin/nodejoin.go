// Package nodejoin is the node side of one-line joins
// (plans/kubectl-style-cluster-ops.md §3.1, §4, §4.1, §4.3, §4.4): the
// `sandboxd preflight`, `init`, `join`, `adopt` and `reset` commands. The
// cluster side (tokens, the join port, signing, adopt) is internal/cluster;
// this package only calls it, over the join port (:7003) for a new machine
// and over the node's own API for the rest.
//
//	init   ─► checks ─► CA, gossip key, credential key, seed cert ─► cluster.env
//	       ─► restart sandboxd ─► wait to lead ─► adopt self ─► register tokens
//	       ─► admin-context.json ─► print a join command and a login line
//	join   ─► cluster-info (check the CA by HMAC or pin) ─► checks + dial-back
//	       ─► node key ─► POST /v1/join ─► write files ─► restart ─► wait to be a member
//	adopt  ─► POST /v1/cluster/adopt on this server (imports or fetches the CA key)
//	reset  ─► ask the cluster to delete this node ─► stop sandboxd ─► remove cluster state
//
// Every effect outside the files it owns (systemctl, listening, the clock,
// the network) goes through Host or an HTTP client, and every path is in
// Paths, so the tests run offline and unprivileged.
package nodejoin

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Paths are the files one node command works on. The defaults are the
// ones install.sh and cluster-init.sh use, so old and new nodes look alike.
type Paths struct {
	EnvFile      string // install.sh's /etc/sandboxd/sandboxd.env
	ClusterEnv   string // /etc/sandboxd/cluster.env
	DropIn       string // the systemd drop-in that loads ClusterEnv
	Unit         string // install.sh's sandboxd.service
	TLSDir       string // ca.crt, node.crt, node.key (SB_CLUSTER_TLS_DIR)
	CADir        string // the CA store on servers (SB_CLUSTER_CA_DIR)
	RaftDir      string // SB_RAFT_DATA_DIR
	StateDir     string // where the database lives, for the disk check
	AdminContext string // the login `aerolvm config import` reads
	CgroupRoot   string
	KVMDevice    string
	// KVMSysfs is the kvm device's entry in sysfs (the pod preflight). An
	// unprivileged container has no /dev/kvm, whatever the machine has,
	// but sees the machine's sysfs read-only, where the device shows as
	// soon as the kvm module made it.
	KVMSysfs string
	// OSRelease is the kernel's release string (the pod preflight).
	OSRelease string
	// BridgeNF is br_netfilter's sysctl: present only with the module
	// loaded (the pod preflight).
	BridgeNF string
}

// DefaultPaths are a node's real paths.
func DefaultPaths() Paths {
	return Paths{
		EnvFile:      "/etc/sandboxd/sandboxd.env",
		ClusterEnv:   "/etc/sandboxd/cluster.env",
		DropIn:       "/etc/systemd/system/sandboxd.service.d/cluster.conf",
		Unit:         "/etc/systemd/system/sandboxd.service",
		TLSDir:       "/etc/sandboxd/tls",
		CADir:        "/etc/sandboxd/cluster-ca",
		RaftDir:      "/var/lib/sandboxd/raft",
		StateDir:     "/var/lib/sandboxd",
		AdminContext: "/etc/sandboxd/admin-context.json",
		CgroupRoot:   "/sys/fs/cgroup",
		KVMDevice:    "/dev/kvm",
		KVMSysfs:     "/sys/class/misc/kvm",
		OSRelease:    "/proc/sys/kernel/osrelease",
		BridgeNF:     "/proc/sys/net/bridge/bridge-nf-call-iptables",
	}
}

// Default listen ports, the same as the scripts'.
const (
	defaultAPIPort = "21212"
	raftBind       = "0.0.0.0:7000"
	gossipBind     = "0.0.0.0:7001"
	internalBind   = "0.0.0.0:7002"
	// defaultMaxAutoVoters is cluster-init.sh's default.
	defaultMaxAutoVoters = "5"
	// DefaultInstallerURL serves install.sh (docs: getting-started).
	DefaultInstallerURL = "https://aerolvm.aerol.ai"
	// clusterServerName is the name every node cert carries
	// (DNS:aerolvm-cluster-node), the one the join port's cert is checked
	// against.
	clusterServerName = "aerolvm-cluster-node"
)

// dropInBody is the drop-in cluster-init.sh writes, byte for byte.
const dropInBody = "[Service]\nEnvironmentFile=/etc/sandboxd/cluster.env\n"

// Host is every effect a node command has on the machine outside the files
// it writes. SystemHost is the real one.
type Host interface {
	IsRoot() bool
	DaemonReload(ctx context.Context) error
	RestartSandboxd(ctx context.Context) error
	StopSandboxd(ctx context.Context) error
	// Listen opens a TCP listener (the dial-back and the free-port check).
	Listen(addr string) (net.Listener, error)
	// FreeBytes is the space free on the file system holding path.
	FreeBytes(path string) (uint64, error)
	// PrimaryIP is the source address of the default route.
	PrimaryIP() (string, error)
	Hostname() (string, error)
	Now() time.Time
}

// SystemHost is Host on a real systemd machine.
type SystemHost struct{}

var _ Host = SystemHost{}

func (SystemHost) IsRoot() bool { return os.Geteuid() == 0 }

func systemctl(ctx context.Context, args ...string) error {
	out, err := exec.CommandContext(ctx, "systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (SystemHost) DaemonReload(ctx context.Context) error { return systemctl(ctx, "daemon-reload") }
func (SystemHost) RestartSandboxd(ctx context.Context) error {
	return systemctl(ctx, "restart", "sandboxd")
}
func (SystemHost) StopSandboxd(ctx context.Context) error { return systemctl(ctx, "stop", "sandboxd") }

func (SystemHost) Listen(addr string) (net.Listener, error) { return net.Listen("tcp", addr) }

func (SystemHost) FreeBytes(path string) (uint64, error) {
	p := nearestExisting(path)
	var st syscall.Statfs_t
	if err := syscall.Statfs(p, &st); err != nil {
		return 0, fmt.Errorf("statfs %s: %w", p, err)
	}
	return st.Bavail * uint64(st.Bsize), nil //nolint:gosec // block size is positive
}

// PrimaryIP asks which source address the default route would use. A UDP
// "dial" sends nothing; it only picks the route, like `ip route get`.
func (SystemHost) PrimaryIP() (string, error) {
	conn, err := net.Dial("udp", "1.1.1.1:80")
	if err == nil {
		defer conn.Close()
		if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok && !addr.IP.IsUnspecified() {
			return addr.IP.String(), nil
		}
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}
	for _, a := range addrs {
		if ip, ok := a.(*net.IPNet); ok && ip.IP.To4() != nil && !ip.IP.IsLoopback() {
			return ip.IP.String(), nil
		}
	}
	return "", errors.New("no IPv4 address on this machine; pass --advertise")
}

func (SystemHost) Hostname() (string, error) {
	name, err := os.Hostname()
	if err != nil {
		return "", err
	}
	// hostname -s: the scripts' default node ID.
	short, _, _ := strings.Cut(name, ".")
	return short, nil
}

func (SystemHost) Now() time.Time { return time.Now() }

// nearestExisting walks up to a directory that exists, so a disk check on
// a state directory not made yet reads the file system it will land on.
func nearestExisting(path string) string {
	p := path
	for {
		if _, err := os.Stat(p); err == nil {
			return p
		}
		parent := filepath.Dir(p)
		if parent == p {
			return p
		}
		p = parent
	}
}

// Printer is the command's output: progress and results go to Out.
type Printer struct {
	Out io.Writer
}

func (p Printer) printf(format string, args ...any) {
	if p.Out != nil {
		fmt.Fprintf(p.Out, format, args...)
	}
}
