package rootd

import (
	"errors"
	"fmt"
	"math"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/rootpolicy"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/egresspolicy"
	"github.com/aerol-ai/microvm/pkg/gvisorpids"
	"github.com/aerol-ai/microvm/pkg/isolate"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Defaults for the socket and its peer (plans/security-gaps-m1-m4.md §3.3).
// The agent's own folders default to sandboxd's own defaults
// (internal/config), so a helper beside an agent with default settings
// needs none either. Every file root opens because a container names it
// (host files, ready socket names, FIFOs, runsc configs, moves) defaults
// to the helper's own folders, which the agent cannot write (review H2,
// files.go).
const (
	// DefaultSocket sits in a folder of the helper's own: the socket's
	// folder must be root's alone (listen), and /run/aerolvm, where it was
	// first meant to go, is an emptyDir every worker container can write.
	// The folder holds the socket alone: no sandbox may bind anything in
	// it (ForbiddenRoots), while the ready socket names beside it in
	// /run/aerolvm-rootd/ready are binds.
	DefaultSocket      = "/run/aerolvm-rootd/sock/root.sock"
	DefaultSocketGroup = "aerolvm"
	// DefaultAgentUID is a uid nothing else in AerolVM runs as. The peer
	// check goes by uid, so the agent's must be its own: 65532 is the
	// egress gateway's, edge's and the operator's, and 65534 is nobody's.
	DefaultAgentUID = 65531
	// DefaultStateDir holds what root reads on the agent's word: the runsc
	// configs and the gVisor moves folder.
	DefaultStateDir = "/var/lib/aerolvm-rootd"
	// DefaultNetnsDir holds the sandboxes' network namespaces in split
	// mode: the helper's own folder, root's alone (mode 0700), never the
	// node's shared /run/netns. Anything a name in it points at is then
	// what the helper made, never an operator's `ip netns add`, and no
	// other user can open the folder, to read it or to hold its lock.
	DefaultNetnsDir = "/run/aerolvm-rootd/netns"

	defaultContainerdSocket = "/run/containerd/containerd.sock"
	defaultNamespace        = "aerolvm"
	defaultSnapshotterRoot  = "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs"
	defaultRunDir           = "/var/lib/sandboxd/containerd"
	defaultMountsRoot       = "/var/lib/sandboxd/mounts"
	defaultCredDir          = "/run/sandboxd"
	defaultDBPath           = "/var/lib/sandboxd/state.db"
	defaultToolbox          = "/usr/local/bin/toolboxd"
	defaultFIFODir          = "/run/aerolvm-rootd/fifo"
	// sandboxd's own CNI defaults (internal/config).
	defaultCNIPluginDir = "/opt/cni/bin"
	defaultCNIConfPath  = "/etc/cni/net.d/aerolvm.conflist"
	defaultReadyDir     = "/run/aerolvm-rootd/ready"
	defaultPidsLimit    = 4096
	// sandboxd's defaults for the users its jails run as.
	defaultJailUID = 1000
	// sandboxd's WASM worker user (config.DefaultWasmWorkerID) and modules
	// folder.
	defaultWasmWorkerID   = 61000
	defaultWasmModulesDir = "/var/lib/sandboxd/wasm/modules"
	// DefaultWasmSocketDir holds the WASM hosts' sockets: a folder of the
	// helper's, beside its own socket's, for the agent's group alone.
	DefaultWasmSocketDir = "/run/aerolvm-rootd/wasm"
	// nobodyUID is shared by every daemon that runs as nobody.
	nobodyUID = 65534
	// imageUID is what the chart and the images run the egress gateway
	// (setpriv), edge, the operator and preflight as. The helper's
	// environment names none of them on Kubernetes, so it is refused by
	// number.
	imageUID = 65532
)

// Config is the helper's own configuration. It comes from the helper's own
// environment, which the operator sets (the systemd unit, the worker pod's
// runtime container), never from the agent: nothing the agent sends over
// the socket can change it, the policy least of all.
type Config struct {
	// Socket is where the helper listens.
	Socket string
	// SocketGID owns the socket, mode 0660, so the filesystem lets only
	// root and that group connect before the peer check runs.
	SocketGID int
	// AgentUID is the only uid the peer check lets in.
	AgentUID uint32
	// AgentCgroup, when set, is a fragment the caller's /proc/<pid>/cgroup
	// must contain (on VMs, "sandboxd.service"): a second process running
	// as the agent's user is not the agent.
	AgentCgroup string
	// ContainerdSocket is the real containerd, which only root can open.
	ContainerdSocket string
	// Policy is what the containerd gate checks every write against.
	Policy rootpolicy.Policy
	// Files is where the helper makes the files runc, runsc and the shim
	// open as root (files.go). The FIFOs go in Policy.FIFODir.
	Files FileDirs
	// Network is the helper's CNI (network.go); sandboxes' namespaces go
	// in Policy.NetnsDir.
	Network NetworkConfig
	// Firewall is the host firewall's settings (firewall.go).
	Firewall FirewallConfig
	// Mounts is external storage (mounts.go); nil when this node has no
	// mount user, and the helper serves no mount call.
	Mounts *MountsConfig
	// Reclaim is platform volume reclaim on NFS (reclaim.go); nil unless
	// the node's platform volumes are on NFS.
	Reclaim *ReclaimConfig
	// HostPorts bound raw-TCP host-port forwarding (hostports.go), under
	// sandboxd's names: the host-port range (SB_L4_PORT_RANGE_START,
	// SB_L4_PORT_RANGE_END; 22000 to 23000) and sandboxd's redirect
	// listener (SB_HOSTPORT_REDIRECT_PORT, 21215). The helper's own copy:
	// the agent cannot widen what a forward may take.
	HostPorts rootpolicy.HostPortBounds
	// Hosts are the host-process runtimes' settings (hosts.go).
	Hosts HostsConfig
}

// HostsConfig is what the helper starts host processes with (M1 PR 9),
// from its own environment, under sandboxd's names.
type HostsConfig struct {
	// CgroupParent is the cgroup every host's group goes under, relative to
	// the cgroup mount, as sandboxd's SB_HOST_PROCESS_CGROUP_PARENT
	// (defaulting to SB_CONTAINERD_CGROUP_PARENT): "" is the mount itself.
	CgroupParent string
	// LogPath is the file host processes write to, in the helper's state
	// folder.
	LogPath string
	// Workerd runs V8-isolate group hosts; nil when this node runs none
	// (SB_ENABLE_ISOLATE).
	Workerd *WorkerdHostsConfig
	// Wasm runs WASM workers and resident hosts; nil when this node runs
	// none (SB_ENABLE_WASM).
	Wasm *WasmHostsConfig
	// Firecracker runs Firecracker VMs and their TAPs (M1 PR 9b); nil when
	// this node runs none (SB_ENABLE_FIRECRACKER).
	Firecracker *FirecrackerHostsConfig
}

// FirecrackerHostsConfig is how the helper runs Firecracker VMs, under
// sandboxd's names (internal/config): the jailer and firecracker binaries,
// the jailer's chroot base and user, the kernel every VM boots, mkfs.ext4,
// and the TAP pool's layout. None of it comes from a request.
type FirecrackerHostsConfig struct {
	JailerBinary      string // SB_JAILER_BINARY
	FirecrackerBinary string // SB_FIRECRACKER_BINARY
	ChrootBase        string // SB_JAILER_CHROOT_BASE
	UID, GID          int    // SB_JAILER_UID, SB_JAILER_GID
	// Kernel is SB_FIRECRACKER_KERNEL: it must be root's, in folders only
	// root writes (checked at the first VM).
	Kernel   string
	Mkfs4Bin string // SB_FIRECRACKER_MKFS_BIN
	// Shim is the helper's own binary, which sets firecracker's umask and
	// becomes the jailer.
	Shim     string
	AgentUID uint32
	// SocketWait bounds how long a started VM has to bind its API socket.
	SocketWait time.Duration
	IPBinary   string // SB_FIRECRACKER_IP_BINARY; "" is ip from PATH
	// TapBase and TapPoolSize are the TAP pool's layout
	// (SB_FIRECRACKER_TAP_BASE_CIDR, SB_FIRECRACKER_TAP_POOL_SIZE).
	TapBase     string
	TapPoolSize int
}

// WorkerdHostsConfig is the V8 group hosts' jail.
type WorkerdHostsConfig struct {
	Jail isolate.RootJail
	// PidsMax is SB_ISOLATE_JAIL_PIDS_MAX: every group's pids limit, at
	// most.
	PidsMax uint32
}

// any reports whether the helper serves a host kind.
func (h HostsConfig) any() bool { return h.Workerd != nil || h.Wasm != nil || h.Firecracker != nil }

func (h HostsConfig) validate() error {
	if !h.any() {
		return nil
	}
	if p := h.CgroupParent; p != "" && (!filepath.IsAbs(p) || filepath.Clean(p) != p || p == "/") {
		return fmt.Errorf("root helper: host-process cgroup parent %q: want a clean absolute cgroup path below the root", p)
	}
	if !filepath.IsAbs(h.LogPath) || filepath.Clean(h.LogPath) != h.LogPath {
		return fmt.Errorf("root helper: hosts' log %q: want a clean absolute path", h.LogPath)
	}
	if w := h.Workerd; w != nil {
		if err := w.Jail.Validate(); err != nil {
			return fmt.Errorf("root helper: %w", err)
		}
		if w.PidsMax == 0 {
			return errors.New("root helper: SB_ISOLATE_JAIL_PIDS_MAX must be above 0: the V8 jail lets workerd make threads")
		}
	}
	if w := h.Wasm; w != nil {
		for name, p := range map[string]string{"binary": w.Binary, "socket folder": w.SocketDir} {
			if !filepath.IsAbs(p) || filepath.Clean(p) != p || p == "/" {
				return fmt.Errorf("root helper: WASM host %s %q: want a clean absolute path other than /", name, p)
			}
		}
		if w.CacheRoot != "" && (!filepath.IsAbs(w.CacheRoot) || filepath.Clean(w.CacheRoot) != w.CacheRoot) {
			return fmt.Errorf("root helper: WASM compile cache root %q: want a clean absolute path", w.CacheRoot)
		}
		// Compared as int64, so no setting wraps onto root or the agent;
		// (uid_t)-1 and past is no user at all.
		if int64(w.UID) >= math.MaxUint32 || int64(w.GID) >= math.MaxUint32 {
			return fmt.Errorf("root helper: WASM worker user %d:%d: want ids below %d", w.UID, w.GID, uint32(math.MaxUint32))
		}
		if w.UID <= 0 || w.GID <= 0 || int64(w.UID) == int64(w.AgentUID) {
			return fmt.Errorf("root helper: WASM worker user %d:%d must be neither root nor the agent", w.UID, w.GID)
		}
		if w.ReadyWait <= 0 {
			return errors.New("root helper: WASM hosts need a ready wait")
		}
	}
	if fc := h.Firecracker; fc != nil {
		if err := fc.validate(); err != nil {
			return err
		}
		if w := h.Workerd; w != nil && w.Jail.UID == fc.UID {
			return fmt.Errorf("root helper: SB_JAILER_UID=%d is the V8 jail's user too: a VM's escape could signal and read a jailed workerd", fc.UID)
		}
		if w := h.Wasm; w != nil && w.UID == fc.UID {
			return fmt.Errorf("root helper: SB_JAILER_UID=%d is the WASM worker's user too", fc.UID)
		}
	}
	return nil
}

func (c *FirecrackerHostsConfig) validate() error {
	for name, p := range map[string]string{"jailer": c.JailerBinary, "firecracker": c.FirecrackerBinary, "kernel": c.Kernel,
		"mkfs.ext4": c.Mkfs4Bin, "shim": c.Shim} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return fmt.Errorf("root helper: Firecracker %s %q: want a clean absolute path", name, p)
		}
	}
	if c.IPBinary != "" && (!filepath.IsAbs(c.IPBinary) || filepath.Clean(c.IPBinary) != c.IPBinary) {
		return fmt.Errorf("root helper: SB_FIRECRACKER_IP_BINARY %q: want a clean absolute path", c.IPBinary)
	}
	if _, _, _, err := rootpolicy.FirecrackerJail(c.ChrootBase, "sb-0"); err != nil {
		return fmt.Errorf("root helper: SB_JAILER_CHROOT_BASE: %w", err)
	}
	if c.UID <= 0 || c.GID <= 0 || uint32(c.UID) == c.AgentUID {
		return fmt.Errorf("root helper: jailer user %d:%d must be neither root nor the agent", c.UID, c.GID)
	}
	if c.SocketWait <= 0 {
		return errors.New("root helper: Firecracker VMs need a socket wait")
	}
	if err := rootpolicy.CheckTapBase(c.TapBase, c.TapPoolSize); err != nil {
		return fmt.Errorf("root helper: %w", err)
	}
	return nil
}

// MountsConfig is where and as whom the helper mounts external storage
// (mounts.go, pkg/mounts tools.go). Each folder is the helper's own.
type MountsConfig struct {
	// Root is the mounts folder (SB_ROOTD_MOUNTS_DIR): every mount point
	// is <Root>/<sandbox>/<index>, and it is the policy's MountsRoot.
	Root string
	// CredDir holds sshfs's key files (SB_ROOTD_MOUNT_CRED_DIR): on /run,
	// so no key is ever written to disk.
	CredDir string
	// CacheDir holds rclone's write caches.
	CacheDir string
	// UID and GID are the mount tools' own user (SB_ROOTD_MOUNT_USER).
	UID, GID uint32
	// CgroupRoot is where the tools' cgroup is made, as sandboxd makes it
	// (SB_HOST_PROCESS_CGROUP_PARENT, by default SB_CONTAINERD_CGROUP_PARENT,
	// under the cgroup v2 root); empty: the cgroup v2 root.
	CgroupRoot string
	// WaitTimeout bounds one mount's start (SB_MOUNT_WAIT_TIMEOUT).
	WaitTimeout time.Duration
	// NodeCredentials lets a mount use the node's own cloud identity
	// (SB_MOUNTS_ALLOW_NODE_CREDENTIALS, models.MountToolPolicy), read from
	// the helper's own environment: the agent cannot turn it on for root.
	NodeCredentials bool
}

// DefaultMountUser is the mount tools' user: the installer and the runtime
// image make it. sshfs's ssh needs a passwd entry for the uid it runs as.
const DefaultMountUser = "aerolvm-mounts"

// FirewallConfig is the helper's own copy of the host firewall's settings,
// under sandboxd's names.
type FirewallConfig struct {
	// Backend is SB_NETRULES_BACKEND ("netlink", the default, or
	// "iptables").
	Backend string
	// Interconnect is SB_SANDBOX_INTERCONNECT: sandboxes on the node may
	// reach each other.
	Interconnect bool
	// NodePorts are the node ports sandboxes may ever reach (PR 5 review,
	// plan §3.3): the helper owns the node guard's inputs, and the agent
	// may only narrow them. From the helper's own environment, the names
	// sandboxd reads too: DNS (53, on any node address), the egress
	// gateway's DNS and proxy ports (SB_EGRESS_DNS_PORT, 53054;
	// SB_EGRESS_PROXY_PORT, 15080), the public web ports, and the
	// operator's SB_SANDBOX_NODE_PORTS_ALLOW (refused in enterprise mode,
	// as sandboxd refuses it).
	NodePorts []rootpolicy.NodePort
}

// sharedNetnsDirs are the folders iproute2, systemd units and CNI tools
// share on a node; SB_ROOTD_NETNS_DIR may name none of them.
var sharedNetnsDirs = map[string]bool{"/run/netns": true, "/var/run/netns": true}

// FileDirs are the helper's own folders for the files it makes for
// containers. Each must be root's alone: the agent can rename anything in a
// folder it can write, so a file root opens there could be swapped for a
// link between the gate's check and root's open.
type FileDirs struct {
	// Hosts holds each container's host files, in <Hosts>/<id>. A helper
	// file root of the policy.
	Hosts string
	// Ready holds a name for each container's ready socket, in
	// <Ready>/<id>. A helper file root of the policy.
	Ready string
	// Runsc holds the runsc shim configs, the policy's RunscConfigPaths.
	Runsc string
	// AgentReady is where the agent binds its ready sockets (sandboxd's
	// DockerReadySocketDir). The helper hard-links each socket from here
	// into Ready, so both must be on one filesystem.
	AgentReady string
	// Toolbox is the toolbox binary specs bind (toolbox.go), one of the
	// policy's bind files: the operator's, or the helper's own copy of
	// ToolboxSource, in a folder of the helper's.
	Toolbox string
	// ToolboxSource, when set, is the agent's copy of toolboxd, in a
	// folder the agent writes (SB_ROOTD_TOOLBOX_SOURCE); the helper copies
	// it to Toolbox.
	ToolboxSource string
	// ImageRoot is an empty folder of the helper's: the bottom layer of
	// every read of an image's users (imageuser_linux.go), whose overlay
	// wants two lower folders on older kernels. Nothing is mounted on it.
	ImageRoot string
}

// validate checks the folders and that the policy lets the gate accept
// what the helper makes in them. socketDir is the helper's socket folder.
func (d FileDirs) validate(p rootpolicy.Policy, socketDir string) error {
	folders := []struct{ name, dir string }{{"hosts", d.Hosts}, {"ready", d.Ready}, {"runsc", d.Runsc}, {"agent ready", d.AgentReady}}
	for _, f := range folders {
		if !filepath.IsAbs(f.dir) || filepath.Clean(f.dir) != f.dir || f.dir == "/" {
			return fmt.Errorf("root helper: %s folder %q: want a clean absolute folder other than /", f.name, f.dir)
		}
	}
	// Each folder has one job and one rule: what a sandbox may bind (hosts,
	// ready), what root reads (runsc, moves), FIFOs, the socket, and the
	// agent's own. One inside another would put the first's files under
	// the second's rule: a ready folder holding the runsc folder would let
	// a spec bind a runsc config.
	folders = append(folders, []struct{ name, dir string }{{"moves", p.MovesDir}, {"FIFO", p.FIFODir}, {"socket", socketDir}}...)
	for i, a := range folders {
		for _, b := range folders[i+1:] {
			if a.dir == b.dir || strings.HasPrefix(a.dir, b.dir+"/") || strings.HasPrefix(b.dir, a.dir+"/") {
				return fmt.Errorf("root helper: the %s folder %s and the %s folder %s overlap", a.name, a.dir, b.name, b.dir)
			}
		}
	}
	for _, root := range []string{d.Hosts, d.Ready} {
		if !slices.Contains(p.HelperFileRoots, root) {
			return fmt.Errorf("root helper: the policy's helper file roots %v lack %s, where the helper makes binds", p.HelperFileRoots, root)
		}
	}
	for _, path := range []string{d.runscPath(runscDefaultFile), d.runscPath(runscRestoreFile)} {
		if !slices.Contains(p.RunscConfigPaths, path) {
			return fmt.Errorf("root helper: the policy's runsc configs %v lack %s, which the helper writes", p.RunscConfigPaths, path)
		}
	}
	if d.ImageRoot != "" {
		if !filepath.IsAbs(d.ImageRoot) || filepath.Clean(d.ImageRoot) != d.ImageRoot || d.ImageRoot == "/" {
			return fmt.Errorf("root helper: image root %q: want a clean absolute folder other than /", d.ImageRoot)
		}
		for _, f := range folders {
			if d.ImageRoot == f.dir || strings.HasPrefix(d.ImageRoot, f.dir+"/") || strings.HasPrefix(f.dir, d.ImageRoot+"/") {
				return fmt.Errorf("root helper: the image root %s and the %s folder %s overlap", d.ImageRoot, f.name, f.dir)
			}
		}
	}
	if d.Toolbox != "" && !slices.Contains(p.BindFiles, d.Toolbox) {
		return fmt.Errorf("root helper: the policy's bind files %v lack the toolbox binary %s", p.BindFiles, d.Toolbox)
	}
	if d.ToolboxSource != "" {
		if d.Toolbox == "" || filepath.Base(d.Toolbox) != toolboxFile {
			return fmt.Errorf("root helper: the toolbox copy %q must be a %s in a folder of the helper's", d.Toolbox, toolboxFile)
		}
		if !filepath.IsAbs(d.ToolboxSource) || filepath.Clean(d.ToolboxSource) != d.ToolboxSource {
			return fmt.Errorf("root helper: toolbox source %q: want a clean absolute path", d.ToolboxSource)
		}
		// The copy's folder holds the copy alone, so no other folder of the
		// helper's may hold it or sit in it.
		for _, f := range folders {
			if dir := filepath.Dir(d.Toolbox); dir == f.dir || strings.HasPrefix(dir, f.dir+"/") || strings.HasPrefix(f.dir, dir+"/") {
				return fmt.Errorf("root helper: the toolbox copy's folder %s and the %s folder %s overlap", dir, f.name, f.dir)
			}
		}
	}
	return nil
}

func (d FileDirs) runscPath(name string) string { return filepath.Join(d.Runsc, name) }

// Validate checks the parts of the config the server uses. ConfigFromEnv
// also refuses a root agent; tests that run as root may not.
func (c Config) Validate() error {
	if !filepath.IsAbs(c.Socket) || filepath.Clean(c.Socket) != c.Socket {
		return fmt.Errorf("root helper: socket %q: want a clean absolute path", c.Socket)
	}
	if c.SocketGID < 0 {
		return fmt.Errorf("root helper: socket group %d: want a gid", c.SocketGID)
	}
	if err := c.Policy.Validate(); err != nil {
		return fmt.Errorf("root helper: %w", err)
	}
	if err := c.Network.validate(); err != nil {
		return err
	}
	if err := c.Hosts.validate(); err != nil {
		return err
	}
	if err := c.Files.validate(c.Policy, filepath.Dir(c.Socket)); err != nil {
		return err
	}
	return c.Mounts.validate(c)
}

// validate checks the mount folders: the policy's mounts root, and none
// inside another of the helper's folders or holding one (each folder has
// one job and one rule, as FileDirs.validate says).
func (m *MountsConfig) validate(c Config) error {
	if m == nil {
		return nil
	}
	if m.Root != c.Policy.MountsRoot {
		return fmt.Errorf("root helper: the mounts folder %q is not the policy's mounts root %q", m.Root, c.Policy.MountsRoot)
	}
	if m.UID == 0 || m.GID == 0 || m.WaitTimeout <= 0 {
		return fmt.Errorf("root helper: mount user %d:%d, wait %v: want a user and group other than root's, and a wait", m.UID, m.GID, m.WaitTimeout)
	}
	mine := []struct{ name, dir string }{{"mounts", m.Root}, {"mount key", m.CredDir}, {"mount cache", m.CacheDir}}
	others := []struct{ name, dir string }{{"hosts", c.Files.Hosts}, {"ready", c.Files.Ready}, {"runsc", c.Files.Runsc},
		{"agent ready", c.Files.AgentReady}, {"image root", c.Files.ImageRoot}, {"moves", c.Policy.MovesDir},
		{"FIFO", c.Policy.FIFODir}, {"socket", filepath.Dir(c.Socket)}}
	if c.Files.Toolbox != "" {
		others = append(others, struct{ name, dir string }{"toolbox", filepath.Dir(c.Files.Toolbox)})
	}
	// Root links, mounts and removes in the V8 jails' tree, and binds the
	// WASM hosts' sockets in their folder (M1 PR 9).
	if w := c.Hosts.Workerd; w != nil {
		others = append(others, struct{ name, dir string }{"V8 jail", w.Jail.ChrootBase})
	}
	if w := c.Hosts.Wasm; w != nil {
		others = append(others, struct{ name, dir string }{"WASM socket", w.SocketDir})
	}
	for i, a := range mine {
		if !filepath.IsAbs(a.dir) || filepath.Clean(a.dir) != a.dir || a.dir == "/" {
			return fmt.Errorf("root helper: %s folder %q: want a clean absolute folder other than /", a.name, a.dir)
		}
		for _, b := range append(slices.Clone(mine[i+1:]), others...) {
			if b.dir == "" {
				continue
			}
			if a.dir == b.dir || strings.HasPrefix(a.dir, b.dir+"/") || strings.HasPrefix(b.dir, a.dir+"/") {
				return fmt.Errorf("root helper: the %s folder %s and the %s folder %s overlap", a.name, a.dir, b.name, b.dir)
			}
		}
	}
	return nil
}

// maxMemoryMB keeps the node's memory in bytes within an int64.
const maxMemoryMB = math.MaxInt64 >> 20

// detectHost reads the node's memory and CPUs; tests replace it.
var detectHost = capacity.DetectHost

// ConfigFromEnv reads the helper's config. Unlike sandboxd's own loader,
// a value that does not parse is an error, not a fallback to the default:
// this config bounds what root does for the agent.
//
// The policy's names match sandboxd's (SB_CONTAINERD_NAMESPACE,
// SB_CONTAINERD_RUN_DIR, SB_CONTAINER_PRIVILEGED, ...) so the operator sets
// one value for both processes, but each reads its own copy. The helper's
// copy must come from somewhere only root can write: an env file the agent
// can edit (sandboxd's own, or one its upgrade path rewrites) would let it
// set SB_CONTAINER_PRIVILEGED for root.
func ConfigFromEnv(getenv func(string) string) (Config, error) {
	get := func(k, def string) string {
		if v := strings.TrimSpace(getenv(k)); v != "" {
			return v
		}
		return def
	}
	gid, err := lookupGroup(get("SB_ROOTD_SOCKET_GROUP", DefaultSocketGroup))
	if err != nil {
		return Config{}, fmt.Errorf("SB_ROOTD_SOCKET_GROUP: %w", err)
	}
	uid, err := lookupUser(get("SB_ROOTD_AGENT_UID", strconv.Itoa(DefaultAgentUID)))
	if err != nil {
		return Config{}, fmt.Errorf("SB_ROOTD_AGENT_UID: %w", err)
	}
	if uid == 0 {
		// A root agent is today's single mode with extra steps, and every
		// root process on the host would pass the peer check.
		return Config{}, errors.New("SB_ROOTD_AGENT_UID: the agent must not run as root")
	}
	if err := checkAgentUIDIsItsOwn(getenv, uid); err != nil {
		return Config{}, err
	}
	privileged, err := envBool(getenv, "SB_CONTAINER_PRIVILEGED")
	if err != nil {
		return Config{}, err
	}
	enterprise, err := envBool(getenv, "SB_ENTERPRISE_MODE")
	if err != nil {
		return Config{}, err
	}
	if privileged && enterprise {
		return Config{}, errors.New("SB_CONTAINER_PRIVILEGED must be false when SB_ENTERPRISE_MODE=true")
	}
	interconnect, err := envBool(getenv, "SB_SANDBOX_INTERCONNECT")
	if err != nil {
		return Config{}, err
	}
	if interconnect && enterprise {
		return Config{}, errors.New("SB_SANDBOX_INTERCONNECT must be false when SB_ENTERPRISE_MODE=true")
	}
	nodePorts, err := nodePortsFromEnv(getenv, enterprise, privileged)
	if err != nil {
		return Config{}, err
	}
	limits, err := limitsFromEnv(getenv)
	if err != nil {
		return Config{}, err
	}
	hostPorts, err := hostPortsFromEnv(getenv)
	if err != nil {
		return Config{}, err
	}

	// Every path is cleaned before it is compared or used: /srv/ctr/ and
	// /srv/ctr name one folder, and a prefix test on the raw text would
	// tell them apart (review N6). A relative path is refused.
	var pathErr error
	path := func(k, def string) string {
		raw := get(k, def)
		if !filepath.IsAbs(raw) && pathErr == nil {
			pathErr = fmt.Errorf("%s=%q: want an absolute path", k, raw)
		}
		return filepath.Clean(raw)
	}
	socket := path("SB_ROOTD_SOCKET", DefaultSocket)
	containerdSocket := path("SB_CONTAINERD_SOCKET", defaultContainerdSocket)
	// The agent's own folders: the helper makes nothing root opens in
	// them. TestHelperPolicyMatchesDriverLayout in
	// internal/runtime/containerd pins the names.
	runDir := path("SB_CONTAINERD_RUN_DIR", defaultRunDir)
	mountsRoot := path("SB_MOUNTS_ROOT", defaultMountsRoot)
	credDir := path("SB_MOUNTS_CRED_DIR", defaultCredDir)
	dataDir := filepath.Dir(path("SB_DB_PATH", defaultDBPath))
	stateDir := path("SB_ROOTD_STATE_DIR", DefaultStateDir)
	fifoDir := path("SB_ROOTD_FIFO_DIR", defaultFIFODir)
	readyDir := path("SB_ROOTD_READY_DIR", defaultReadyDir)
	toolbox := path("SB_TOOLBOX_BINARY_PATH", defaultToolbox)
	toolboxSource := ""
	if strings.TrimSpace(getenv("SB_ROOTD_TOOLBOX_SOURCE")) != "" {
		// The agent's copy, which the helper copies into its state folder;
		// specs bind the helper's copy (toolbox.go).
		toolboxSource = path("SB_ROOTD_TOOLBOX_SOURCE", "")
		toolbox = filepath.Join(stateDir, "toolbox", toolboxFile)
	}
	// External mounts (mounts.go): the helper's own folders, never the
	// agent's SB_MOUNTS_ROOT, which the agent can write.
	mountsDir := path("SB_ROOTD_MOUNTS_DIR", filepath.Join(stateDir, "mounts"))
	mountCredDir := path("SB_ROOTD_MOUNT_CRED_DIR", DefaultMountCredDir)
	snapshotterRoot := path("SB_ROOTD_SNAPSHOTTER_ROOT", defaultSnapshotterRoot)
	netnsDir := path("SB_ROOTD_NETNS_DIR", DefaultNetnsDir)
	cniPlugins := path("SB_CONTAINERD_CNI_PLUGIN_DIR", defaultCNIPluginDir)
	cniConf := path("SB_CONTAINERD_CNI_CONF_PATH", defaultCNIConfPath)
	if pathErr != nil {
		return Config{}, pathErr
	}
	if sharedNetnsDirs[netnsDir] {
		return Config{}, fmt.Errorf("SB_ROOTD_NETNS_DIR: %s is the node's shared namespace folder (`ip netns`); "+
			"the helper keeps sandboxes' namespaces in a folder of its own", netnsDir)
	}
	dirs := FileDirs{
		Hosts: filepath.Join(stateDir, "hosts"),
		Ready: readyDir,
		Runsc: filepath.Join(stateDir, "runsc"),
		// sandboxd's config.DockerReadySocketDir.
		AgentReady:    filepath.Join(credDir, "docker", "ready"),
		Toolbox:       toolbox,
		ToolboxSource: toolboxSource,
		ImageRoot:     filepath.Join(stateDir, "imageroot"),
	}
	// The agent owns its folders and can rename anything below them, a
	// folder root made included, so nothing root trusts may sit there.
	for _, h := range []struct{ name, dir string }{
		{"SB_ROOTD_SOCKET", filepath.Dir(socket)},
		{"SB_ROOTD_STATE_DIR", stateDir},
		{"SB_ROOTD_FIFO_DIR", fifoDir},
		{"SB_ROOTD_READY_DIR", readyDir},
		// Root mounts external storage and writes mount keys here.
		{"SB_ROOTD_MOUNTS_DIR", mountsDir},
		{"SB_ROOTD_MOUNT_CRED_DIR", mountCredDir},
		// Root makes sandboxes' namespaces, runs the CNI plugins and reads
		// the CNI config that names them.
		{"SB_ROOTD_NETNS_DIR", netnsDir},
		{"SB_CONTAINERD_CNI_PLUGIN_DIR", cniPlugins},
		{"SB_CONTAINERD_CNI_CONF_PATH", filepath.Dir(cniConf)},
	} {
		for _, a := range []string{runDir, mountsRoot, credDir, dataDir} {
			if h.dir == a || strings.HasPrefix(h.dir, a+"/") {
				return Config{}, fmt.Errorf("%s: %s is inside %s, which the agent writes", h.name, h.dir, a)
			}
		}
	}
	cfg := Config{
		Socket:           socket,
		SocketGID:        gid,
		AgentUID:         uid,
		AgentCgroup:      strings.TrimSpace(getenv("SB_ROOTD_AGENT_CGROUP")),
		ContainerdSocket: containerdSocket,
		Policy: rootpolicy.Policy{
			Namespace:       get("SB_CONTAINERD_NAMESPACE", defaultNamespace),
			Snapshotter:     "overlayfs",
			SnapshotterRoot: snapshotterRoot,
			NetnsDir:        netnsDir,
			// From the helper's own environment only. On Kubernetes the
			// supervisor works the parent out and must hand it to the
			// helper itself: the copy it leaves for the agent in
			// /run/aerolvm/cgroup-parent sits in a folder every worker
			// container can write (review L6).
			CgroupParent: strings.TrimSpace(getenv("SB_CONTAINERD_CGROUP_PARENT")),
			// Binds come from the external mounts, which the helper makes
			// in its own mounts folder (a container binds only its own
			// mount points, MountsRoot), and from the files the helper
			// makes in its own folders (host files, the egress CA among
			// them, and ready socket names), one read-only file each. The
			// agent's run dir, ready dir, mounts root and database folder
			// are no bind roots: the agent can swap anything in them.
			BindRoots:       []string{mountsDir},
			MountsRoot:      mountsDir,
			BindFiles:       []string{toolbox},
			HelperFileRoots: []string{dirs.Hosts, dirs.Ready},
			// The two sockets that are as good as root: this helper's and
			// containerd's.
			ForbiddenRoots:   []string{filepath.Dir(socket), filepath.Dir(containerdSocket)},
			MovesDir:         filepath.Join(stateDir, "moves"),
			FIFODir:          fifoDir,
			RunscConfigPaths: []string{dirs.runscPath(runscDefaultFile), dirs.runscPath(runscRestoreFile)},
			Privileged:       privileged,
			Limits:           limits,
		},
		Files: dirs,
		Network: NetworkConfig{
			PluginDir: cniPlugins,
			ConfPath:  cniConf,
			Subnet:    strings.TrimSpace(getenv("SB_CONTAINERD_BRIDGE_SUBNET")),
		},
		Firewall:  FirewallConfig{Backend: strings.ToLower(get("SB_NETRULES_BACKEND", "netlink")), Interconnect: interconnect, NodePorts: nodePorts},
		HostPorts: hostPorts,
	}
	if cfg.Mounts, err = mountsFromEnv(getenv, uid, mountsDir, mountCredDir, filepath.Join(stateDir, "mountcache")); err != nil {
		return Config{}, err
	}
	if cfg.Reclaim, err = reclaimFromEnv(getenv, filepath.Join(stateDir, "reclaim")); err != nil {
		return Config{}, err
	}
	if cfg.Hosts, err = hostsFromEnv(getenv, path, stateDir, uid, gid, enterprise, nodePorts, []string{runDir, mountsRoot, credDir, dataDir}); err != nil {
		return Config{}, err
	}
	if pathErr != nil {
		return Config{}, pathErr
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// selfExecutable is the helper's own binary, the V8 jail's shim; tests
// stand one in.
var selfExecutable = os.Executable

// hostsFromEnv is Config.Hosts, read under sandboxd's names so the operator
// sets one value for both. The V8 jail's chroot base must not be inside a
// folder the agent writes: root links, mounts and removes in it.
func hostsFromEnv(getenv func(string) string, path func(k, def string) string, stateDir string, agentUID uint32, agentGID int,
	enterprise bool, nodePorts []rootpolicy.NodePort, agentDirs []string) (HostsConfig, error) {
	get := func(k, def string) string {
		if v := strings.TrimSpace(getenv(k)); v != "" {
			return v
		}
		return def
	}
	var h HostsConfig
	isolateOn, err := envBool(getenv, "SB_ENABLE_ISOLATE")
	if err != nil {
		return h, err
	}
	wasmOn, err := envBool(getenv, "SB_ENABLE_WASM")
	if err != nil {
		return h, err
	}
	fcOn, err := envBool(getenv, "SB_ENABLE_FIRECRACKER")
	if err != nil || (!isolateOn && !wasmOn && !fcOn) {
		return h, err
	}
	h.CgroupParent = get("SB_HOST_PROCESS_CGROUP_PARENT", strings.TrimSpace(getenv("SB_CONTAINERD_CGROUP_PARENT")))
	h.LogPath = filepath.Join(stateDir, "hosts.log")
	if wasmOn {
		if h.Wasm, err = wasmHostsFromEnv(getenv, path, agentUID, agentGID, enterprise, nodePorts, agentDirs); err != nil {
			return h, err
		}
	}
	if fcOn {
		if h.Firecracker, err = firecrackerHostsFromEnv(getenv, path, agentUID, agentDirs); err != nil {
			return h, err
		}
	}
	if !isolateOn {
		return h, nil
	}
	jailOn, err := envBoolDefault(getenv, "SB_ISOLATE_USE_JAIL", true)
	if err != nil {
		return h, err
	}
	if !jailOn {
		// Unjailed, workerd would run as root; the helper starts no host
		// as root.
		return h, errors.New("SB_ISOLATE_USE_JAIL=false: the root helper runs every V8 group in its jail; an unjailed group is privilege mode single only")
	}
	jailUID, err := envInt(getenv, "SB_ISOLATE_JAIL_UID", defaultJailUID)
	if err != nil {
		return h, err
	}
	jailGID, err := envInt(getenv, "SB_ISOLATE_JAIL_GID", defaultJailUID)
	if err != nil {
		return h, err
	}
	jitless, err := envBool(getenv, "SB_ISOLATE_JITLESS")
	if err != nil {
		return h, err
	}
	pids, err := envInt(getenv, "SB_ISOLATE_JAIL_PIDS_MAX", 512)
	if err != nil {
		return h, err
	}
	if pids <= 0 || pids > math.MaxUint32 {
		return h, fmt.Errorf("SB_ISOLATE_JAIL_PIDS_MAX=%d: want a limit above 0", pids)
	}
	shim, err := selfExecutable()
	if err != nil {
		return h, fmt.Errorf("root helper: its own binary, the V8 jail's shim: %w", err)
	}
	// The jail takes the agent's uid as an int, which is 32 bits on a
	// 32-bit build.
	if agentUID > math.MaxInt32 {
		return h, fmt.Errorf("SB_ROOTD_AGENT_UID=%d: the V8 jail takes uids up to %d", agentUID, math.MaxInt32)
	}
	base := path("SB_ISOLATE_JAIL_CHROOT_BASE", "/srv/isolate-jail")
	for _, a := range agentDirs {
		if base == a || strings.HasPrefix(base, a+"/") {
			return h, fmt.Errorf("SB_ISOLATE_JAIL_CHROOT_BASE: %s is inside %s, which the agent writes", base, a)
		}
	}
	h.Workerd = &WorkerdHostsConfig{
		Jail: isolate.RootJail{
			ChrootBase:  base,
			WorkerdPath: path("SB_ISOLATE_WORKERD_PATH", "/usr/local/bin/workerd"),
			UID:         jailUID,
			GID:         jailGID,
			AgentUID:    int(agentUID),
			Jitless:     jitless,
			SeccompMode: strings.ToLower(get("SB_ISOLATE_SECCOMP_MODE", isolate.SeccompEnforce)),
			ShimPath:    filepath.Clean(shim),
		},
		PidsMax: uint32(pids),
	}
	return h, nil
}

// wasmHostsFromEnv is the WASM hosts' settings, under sandboxd's names.
func wasmHostsFromEnv(getenv func(string) string, path func(k, def string) string, agentUID uint32, agentGID int,
	enterprise bool, nodePorts []rootpolicy.NodePort, agentDirs []string) (*WasmHostsConfig, error) {
	uid, err := envInt(getenv, "SB_WASM_WORKER_UID", defaultWasmWorkerID)
	if err != nil {
		return nil, err
	}
	gid, err := envInt(getenv, "SB_WASM_WORKER_GID", defaultWasmWorkerID)
	if err != nil {
		return nil, err
	}
	jail, err := envInt(getenv, "SB_ISOLATE_JAIL_UID", defaultJailUID)
	if err != nil {
		return nil, err
	}
	if uid == jail {
		return nil, fmt.Errorf("SB_WASM_WORKER_UID=%d is the V8 jail's too: a worker could signal and read a jailed workerd", uid)
	}
	rules, err := envBoolDefault(getenv, "SB_ENABLE_NETWORK_RULES", true)
	if err != nil {
		return nil, err
	}
	shim, err := selfExecutable()
	if err != nil {
		return nil, fmt.Errorf("root helper: its own binary, the WASM hosts': %w", err)
	}
	socketDir := path("SB_ROOTD_WASM_SOCKET_DIR", DefaultWasmSocketDir)
	for _, a := range agentDirs {
		if socketDir == a || strings.HasPrefix(socketDir, a+"/") {
			return nil, fmt.Errorf("SB_ROOTD_WASM_SOCKET_DIR: %s is inside %s, which the agent writes", socketDir, a)
		}
	}
	w := &WasmHostsConfig{
		Binary: filepath.Clean(shim), UID: uid, GID: gid, SocketDir: socketDir, SocketGID: agentGID,
		CacheRoot: wasmCacheRoot(getenv, path), AgentUID: agentUID, ReadyWait: 10 * time.Second,
		Fence: rules || enterprise, OperatorFile: strings.TrimSpace(getenv("SB_EGRESS_OPERATOR_FILE")),
	}
	for _, name := range []string{"PATH", "TMPDIR", "LANG", "LC_ALL", "TZ", "SSL_CERT_FILE", "SSL_CERT_DIR",
		"SB_EGRESS_OPERATOR_FILE", egresspolicy.FloorFileEnv} {
		if v := strings.TrimSpace(getenv(name)); v != "" {
			w.Env = append(w.Env, name+"="+v)
		}
	}
	for _, p := range nodePorts {
		if p.Proto == "tcp" && p.Dst == "" && !slices.Contains(w.NodePorts, uint16(p.Port)) {
			w.NodePorts = append(w.NodePorts, uint16(p.Port))
		}
	}
	return w, nil
}

// wasmCacheRoot is the WASM compile cache root as sandboxd works it out
// (pkg/daemon effectiveWasmCompileCacheDir): SB_WASM_COMPILE_CACHE_DIR when
// set (empty: none), else SB_WASM_CACHE_DIR, or SB_WASM_MODULES_DIR/cache,
// then wazero-compile.
func wasmCacheRoot(getenv func(string) string, path func(k, def string) string) string {
	if v, set := lookupEnv(getenv, "SB_WASM_COMPILE_CACHE_DIR"); set {
		if strings.TrimSpace(v) == "" {
			return ""
		}
		return path("SB_WASM_COMPILE_CACHE_DIR", "")
	}
	cache := strings.TrimSpace(getenv("SB_WASM_CACHE_DIR"))
	if cache == "" {
		cache = filepath.Join(path("SB_WASM_MODULES_DIR", defaultWasmModulesDir), "cache")
	} else {
		cache = path("SB_WASM_CACHE_DIR", "")
	}
	return filepath.Join(cache, "wazero-compile")
}

// firecrackerHostsFromEnv is the Firecracker VMs' settings, under sandboxd's
// names. The helper always runs the jailer: an unjailed VM would be root.
// The chroot base must not be inside a folder the agent writes: root
// makes, links and removes in it.
func firecrackerHostsFromEnv(getenv func(string) string, path func(k, def string) string, agentUID uint32,
	agentDirs []string) (*FirecrackerHostsConfig, error) {
	jailer, err := envBoolDefault(getenv, "SB_FIRECRACKER_USE_JAILER", true)
	if err != nil {
		return nil, err
	}
	if !jailer {
		return nil, errors.New("SB_FIRECRACKER_USE_JAILER=false: the root helper runs every Firecracker VM through the jailer; an unjailed VM is privilege mode single only")
	}
	uid, err := envInt(getenv, "SB_JAILER_UID", defaultJailUID)
	if err != nil {
		return nil, err
	}
	gid, err := envInt(getenv, "SB_JAILER_GID", defaultJailUID)
	if err != nil {
		return nil, err
	}
	pool, err := envInt(getenv, "SB_FIRECRACKER_TAP_POOL_SIZE", 256)
	if err != nil {
		return nil, err
	}
	shim, err := selfExecutable()
	if err != nil {
		return nil, fmt.Errorf("root helper: its own binary, the jailer's shim: %w", err)
	}
	c := &FirecrackerHostsConfig{
		JailerBinary:      path("SB_JAILER_BINARY", "/usr/local/bin/jailer"),
		FirecrackerBinary: path("SB_FIRECRACKER_BINARY", "/usr/local/bin/firecracker"),
		ChrootBase:        path("SB_JAILER_CHROOT_BASE", "/srv/jailer"),
		UID:               uid,
		GID:               gid,
		Kernel:            path("SB_FIRECRACKER_KERNEL", "/var/lib/sandboxd/firecracker/vmlinux"),
		Mkfs4Bin:          path("SB_FIRECRACKER_MKFS_BIN", "/sbin/mkfs.ext4"),
		Shim:              filepath.Clean(shim),
		AgentUID:          agentUID,
		SocketWait:        5 * time.Second,
		TapBase:           strings.TrimSpace(getenv("SB_FIRECRACKER_TAP_BASE_CIDR")),
		TapPoolSize:       pool,
	}
	if c.TapBase == "" {
		c.TapBase = "172.16.0.0/20"
	}
	if v := strings.TrimSpace(getenv("SB_FIRECRACKER_IP_BINARY")); v != "" {
		c.IPBinary = path("SB_FIRECRACKER_IP_BINARY", "")
	}
	for _, a := range agentDirs {
		if c.ChrootBase == a || strings.HasPrefix(c.ChrootBase, a+"/") {
			return nil, fmt.Errorf("SB_JAILER_CHROOT_BASE: %s is inside %s, which the agent writes", c.ChrootBase, a)
		}
		// Root links the kernel into every VM's jail and gives it to the
		// jailer's group: one the agent could swap would be any file.
		if strings.HasPrefix(c.Kernel, a+"/") {
			return nil, fmt.Errorf("SB_FIRECRACKER_KERNEL: %s is inside %s, which the agent writes; "+
				"put the kernel in a folder only root writes", c.Kernel, a)
		}
	}
	return c, nil
}

// lookupEnv tells an unset name from an empty one, where getenv is the
// process's own; a test's map has no unset names it set empty.
var lookupEnv = func(getenv func(string) string, k string) (string, bool) {
	v := getenv(k)
	if v != "" {
		return v, true
	}
	return os.LookupEnv(k)
}

// hostPortsFromEnv is Config.HostPorts, checked as sandboxd checks the
// range (it refuses to start on a bad one too). The redirect port is
// checked when a forward uses it.
func hostPortsFromEnv(getenv func(string) string) (rootpolicy.HostPortBounds, error) {
	var b rootpolicy.HostPortBounds
	var err error
	if b.RangeStart, err = envInt(getenv, "SB_L4_PORT_RANGE_START", 22000); err != nil {
		return b, err
	}
	if b.RangeEnd, err = envInt(getenv, "SB_L4_PORT_RANGE_END", 23000); err != nil {
		return b, err
	}
	if b.RedirectPort, err = envInt(getenv, "SB_HOSTPORT_REDIRECT_PORT", 21215); err != nil {
		return b, err
	}
	if err := b.Check(); err != nil {
		return b, fmt.Errorf("SB_L4_PORT_RANGE_START/END: %w", err)
	}
	return b, nil
}

// limitsFromEnv bounds one sandbox by the node: no sandbox can use more
// memory or CPUs than the machine has, and its host pids limit is what the
// agent sets for the node's SB_SANDBOX_PIDS_LIMIT, gVisor's larger host
// limit included (pkg/gvisorpids). SB_HOST_MEMORY_MB and SB_HOST_CPU_CORES
// override detection, as they do for sandboxd's admission.
func limitsFromEnv(getenv func(string) string) (rootpolicy.Limits, error) {
	memMB, err := envInt(getenv, "SB_HOST_MEMORY_MB", 0)
	if err != nil {
		return rootpolicy.Limits{}, err
	}
	cpus, err := envInt(getenv, "SB_HOST_CPU_CORES", 0)
	if err != nil {
		return rootpolicy.Limits{}, err
	}
	pids, err := envInt(getenv, "SB_SANDBOX_PIDS_LIMIT", defaultPidsLimit)
	if err != nil {
		return rootpolicy.Limits{}, err
	}
	if memMB > maxMemoryMB {
		return rootpolicy.Limits{}, fmt.Errorf("SB_HOST_MEMORY_MB=%d is more than a machine can have", memMB)
	}
	if pids <= 0 {
		// The gate requires every sandbox to have a pids limit; with none
		// the agent's creates would all be refused.
		return rootpolicy.Limits{}, errors.New("SB_SANDBOX_PIDS_LIMIT must be above 0 for the root helper")
	}
	if memMB <= 0 {
		// DetectHost's error can be about the disk alone; only the memory
		// matters here.
		host, err := detectHost()
		if host.MemoryTotalMB <= 0 {
			if err == nil {
				err = errors.New("not detected")
			}
			return rootpolicy.Limits{}, fmt.Errorf("node memory: %w (set SB_HOST_MEMORY_MB)", err)
		}
		memMB = host.MemoryTotalMB
	}
	if cpus <= 0 {
		cpus = runtime.NumCPU()
	}
	_, hostPids := gvisorpids.Limits(int64(pids), 0)
	return rootpolicy.Limits{MemoryBytes: int64(memMB) << 20, Pids: hostPids, CPUs: float64(cpus)}, nil
}

func envBool(getenv func(string) string, k string) (bool, error) {
	v := strings.TrimSpace(getenv(k))
	if v == "" {
		return false, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("%s=%q: want true or false", k, v)
	}
	return b, nil
}

func envInt(getenv func(string) string, k string, def int) (int, error) {
	v := strings.TrimSpace(getenv(k))
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s=%q: want a whole number", k, v)
	}
	return n, nil
}

// lookupUser takes a uid or a user name.
func lookupUser(s string) (uint32, error) {
	if n, err := strconv.ParseUint(s, 10, 32); err == nil {
		return uint32(n), nil
	}
	u, err := user.Lookup(s)
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("user %s has uid %q", s, u.Uid)
	}
	return uint32(n), nil
}

// lookupGroup takes a gid or a group name.
func lookupGroup(s string) (int, error) {
	if n, err := strconv.ParseUint(s, 10, 31); err == nil {
		return int(n), nil
	}
	g, err := user.LookupGroup(s)
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseUint(g.Gid, 10, 31)
	if err != nil {
		return 0, fmt.Errorf("group %s has gid %q", s, g.Gid)
	}
	return int(n), nil
}

// reclaimFromEnv is Config.Reclaim, from sandboxd's own names for the
// platform volume backend, checked as sandboxd checks them at start
// (config.PlatformVolumesConfig.Validate): the server and export set, the
// options on the NFS allow list.
func reclaimFromEnv(getenv func(string) string, scratch string) (*ReclaimConfig, error) {
	on, err := envBool(getenv, "SB_PLATFORM_VOLUMES_ENABLED")
	if err != nil || !on || !strings.EqualFold(strings.TrimSpace(getenv("SB_PLATFORM_VOLUMES_BACKEND")), "nfs") {
		return nil, err
	}
	server := strings.TrimSpace(getenv("SB_PLATFORM_VOLUMES_NFS_SERVER"))
	export := strings.TrimSpace(getenv("SB_PLATFORM_VOLUMES_NFS_EXPORT"))
	if server == "" || strings.ContainsAny(server, ":/ ") || strings.Trim(export, "/") == "" {
		return nil, errors.New("SB_PLATFORM_VOLUMES_NFS_SERVER and SB_PLATFORM_VOLUMES_NFS_EXPORT: want a server name or address and an export path")
	}
	opts := strings.TrimSpace(getenv("SB_PLATFORM_VOLUMES_NFS_OPTIONS"))
	spec := models.MountSpec{Type: models.MountTypeNFS, Options: map[string]string{"opts": opts}}
	if err := spec.ValidateToolOptions(); err != nil {
		return nil, fmt.Errorf("SB_PLATFORM_VOLUMES_NFS_OPTIONS: %w", err)
	}
	return &ReclaimConfig{Export: rootpolicy.NFSExport{Server: server, Export: export}, Options: opts, ScratchDir: scratch}, nil
}

// DefaultMountCredDir holds sshfs's key files: on /run, never on disk.
const DefaultMountCredDir = "/run/aerolvm-rootd/mountcreds"

// mountsFromEnv is Config.Mounts: nil when SB_ROOTD_MOUNT_USER is unset and
// this node has no DefaultMountUser, so the helper serves no mount call
// and the agent refuses mounts by name. A set value that does not resolve,
// or names a uid another process here runs as, is an error: the tools'
// user must be one nothing else is.
func mountsFromEnv(getenv func(string) string, agentUID uint32, root, credDir, cacheDir string) (*MountsConfig, error) {
	uid, gid, ok, err := mountUser(strings.TrimSpace(getenv("SB_ROOTD_MOUNT_USER")))
	if err != nil || !ok {
		return nil, err
	}
	if uid == 0 || gid == 0 {
		return nil, errors.New("SB_ROOTD_MOUNT_USER: mount tools must not run as root or in root's group")
	}
	if uid == agentUID {
		return nil, fmt.Errorf("SB_ROOTD_MOUNT_USER: uid %d is the agent's; mount tools need a user of their own", uid)
	}
	who, err := uidSharedWith(getenv, uid)
	if err != nil {
		return nil, err
	}
	if len(who) > 0 {
		return nil, fmt.Errorf("SB_ROOTD_MOUNT_USER: uid %d is also the uid of %s; mount tools need a user of their own", uid, strings.Join(who, " and "))
	}
	wait := 30 * time.Second
	if v := strings.TrimSpace(getenv("SB_MOUNT_WAIT_TIMEOUT")); v != "" {
		if wait, err = time.ParseDuration(v); err != nil || wait <= 0 {
			return nil, fmt.Errorf("SB_MOUNT_WAIT_TIMEOUT=%q: want a duration above 0", v)
		}
	}
	// sandboxd's own rule (config.HostProcessCgroupRoot).
	cgroupRoot := ""
	parent := strings.TrimSpace(getenv("SB_HOST_PROCESS_CGROUP_PARENT"))
	if parent == "" {
		parent = strings.TrimSpace(getenv("SB_CONTAINERD_CGROUP_PARENT"))
	}
	if parent != "" {
		cgroupRoot = filepath.Join(defaultCgroupRoot, parent)
	}
	nodeCreds, err := envBool(getenv, "SB_MOUNTS_ALLOW_NODE_CREDENTIALS")
	if err != nil {
		return nil, err
	}
	return &MountsConfig{Root: root, CredDir: credDir, CacheDir: cacheDir, UID: uid, GID: gid,
		CgroupRoot: cgroupRoot, WaitTimeout: wait, NodeCredentials: nodeCreds}, nil
}

// mountUser reads SB_ROOTD_MOUNT_USER: a user name, a uid, or uid:gid.
// ok is false when the value is unset and this node has no default user.
func mountUser(raw string) (uid, gid uint32, ok bool, err error) {
	set := raw != ""
	if !set {
		raw = DefaultMountUser
	}
	uidText, gidText, hasGID := strings.Cut(raw, ":")
	if n, perr := strconv.ParseUint(uidText, 10, 32); perr == nil {
		uid, gid = uint32(n), uint32(n)
		if hasGID {
			g, perr := strconv.ParseUint(gidText, 10, 32)
			if perr != nil {
				return 0, 0, false, fmt.Errorf("SB_ROOTD_MOUNT_USER=%q: want a user name, a uid or uid:gid", raw)
			}
			gid = uint32(g)
		}
		return uid, gid, true, nil
	}
	if hasGID {
		return 0, 0, false, fmt.Errorf("SB_ROOTD_MOUNT_USER=%q: want a user name, a uid or uid:gid", raw)
	}
	u, err := user.Lookup(raw)
	if err != nil {
		if !set {
			return 0, 0, false, nil
		}
		return 0, 0, false, fmt.Errorf("SB_ROOTD_MOUNT_USER: %w", err)
	}
	n, err1 := strconv.ParseUint(u.Uid, 10, 32)
	g, err2 := strconv.ParseUint(u.Gid, 10, 32)
	if err1 != nil || err2 != nil {
		return 0, 0, false, fmt.Errorf("SB_ROOTD_MOUNT_USER: user %s has uid %q and gid %q", raw, u.Uid, u.Gid)
	}
	return uint32(n), uint32(g), true, nil
}

// checkAgentUIDIsItsOwn refuses an agent uid another AerolVM process runs
// as: those this config names, and 65532, which the chart and images use
// for several. The peer check goes by uid, so on a shared uid that other
// process, which may parse tenant traffic (the egress gateway does), would
// pass for the agent (review H3).
func checkAgentUIDIsItsOwn(getenv func(string) string, uid uint32) error {
	who, err := uidSharedWith(getenv, uid)
	if err != nil {
		return err
	}
	if len(who) > 0 {
		return fmt.Errorf("SB_ROOTD_AGENT_UID: uid %d is also the uid of %s; the agent needs one of its own", uid, strings.Join(who, " and "))
	}
	return nil
}

// uidSharedWith names the other AerolVM processes that run as uid.
func uidSharedWith(getenv func(string) string, uid uint32) ([]string, error) {
	var who []string
	switch uid {
	case nobodyUID:
		who = append(who, "nobody")
	case imageUID:
		who = append(who, "the egress gateway, edge and the operator in the chart and images")
	}
	// The WASM worker runs guests' code; in split mode the helper starts it
	// (M1 PR 9), so it shares no uid with the agent or the mount tools.
	for _, id := range []struct {
		k   string
		def int
	}{{"SB_ISOLATE_JAIL_UID", defaultJailUID}, {"SB_JAILER_UID", defaultJailUID}, {"SB_WASM_WORKER_UID", defaultWasmWorkerID}} {
		k := id.k
		n, err := envInt(getenv, k, id.def)
		if err != nil {
			return nil, err
		}
		// A value outside uid_t would wrap in the conversion and be compared
		// as some other uid.
		if n < 0 || n > math.MaxUint32 {
			return nil, fmt.Errorf("%s=%d: not a uid", k, n)
		}
		if uint32(n) == uid {
			who = append(who, k)
		}
	}
	if gw, ok := gatewayUID(strings.TrimSpace(getenv("SB_EGRESS_GATEWAY_USER"))); ok && gw == uid {
		who = append(who, "SB_EGRESS_GATEWAY_USER")
	}
	return who, nil
}

// gatewayUID reads SB_EGRESS_GATEWAY_USER as sandboxd does: "uid",
// "uid:gid" or a user name (default aerolvm-egress). A name this machine
// does not know is a gateway in another container, which says nothing
// about this uid.
func gatewayUID(v string) (uint32, bool) {
	if v == "" {
		v = "aerolvm-egress"
	}
	uidText, _, _ := strings.Cut(v, ":")
	if n, err := strconv.ParseUint(uidText, 10, 32); err == nil {
		return uint32(n), true
	}
	n, err := lookupUser(v)
	return n, err == nil
}

// ingressRole reports whether SB_NODE_ROLE gives this node the ingress
// role, read as sandboxd reads it: empty is "mixed", which includes it.
func ingressRole(raw string) (bool, error) {
	if strings.TrimSpace(raw) == "" {
		return true, nil
	}
	ingress := false
	for _, f := range strings.Split(raw, ",") {
		switch strings.ToLower(strings.TrimSpace(f)) {
		case "ingress", "mixed":
			ingress = true
		case "server", "worker":
		default:
			return false, fmt.Errorf("SB_NODE_ROLE=%q: want server, worker, ingress or mixed, comma-separated", raw)
		}
	}
	return ingress, nil
}

// envBoolDefault is envBool with a default for an unset name.
func envBoolDefault(getenv func(string) string, k string, def bool) (bool, error) {
	if strings.TrimSpace(getenv(k)) == "" {
		return def, nil
	}
	return envBool(getenv, k)
}

// nodePortsFromEnv is FirewallConfig.NodePorts, built as sandboxd's
// single mode builds what sandboxes may reach on their node
// (Service.SandboxNodeAllowlist), from the same settings (PR 5 review 2):
// the egress gateway's ports only when the gateway runs
// (SB_EGRESS_FQDN_ENABLED, never with SB_CONTAINER_PRIVILEGED); 80 and 443
// only on an ingress node with Caddy that leaves them open to sandboxes
// (SB_NODE_ROLE, SB_ENABLE_CADDY, SB_SANDBOX_NODE_INGRESS); and the
// operator's SB_SANDBOX_NODE_PORTS_ALLOW. DNS is no setting: it is open
// only to the resolvers sandboxes are handed that are this node's own,
// read when the agent sets the guard (nodeDNSPorts).
func nodePortsFromEnv(getenv func(string) string, enterprise, privileged bool) ([]rootpolicy.NodePort, error) {
	dns, err := envInt(getenv, "SB_EGRESS_DNS_PORT", 53054)
	if err != nil {
		return nil, err
	}
	proxy, err := envInt(getenv, "SB_EGRESS_PROXY_PORT", 15080)
	if err != nil {
		return nil, err
	}
	gateway, err := envBoolDefault(getenv, "SB_EGRESS_FQDN_ENABLED", true)
	if err != nil {
		return nil, err
	}
	caddy, err := envBoolDefault(getenv, "SB_ENABLE_CADDY", true)
	if err != nil {
		return nil, err
	}
	nodeIngress, err := envBoolDefault(getenv, "SB_SANDBOX_NODE_INGRESS", true)
	if err != nil {
		return nil, err
	}
	ingress, err := ingressRole(getenv("SB_NODE_ROLE"))
	if err != nil {
		return nil, err
	}
	var out []rootpolicy.NodePort
	if gateway && !privileged {
		for _, p := range []struct {
			proto string
			port  int
		}{{"udp", dns}, {"tcp", dns}, {"tcp", proxy}} {
			if p.port > 0 && p.port <= 65535 {
				out = append(out, rootpolicy.NodePort{Proto: p.proto, Port: uint32(p.port)})
			}
		}
	}
	if ingress && caddy && nodeIngress {
		out = append(out, rootpolicy.NodePort{Proto: "tcp", Port: 80}, rootpolicy.NodePort{Proto: "tcp", Port: 443})
	}
	raw := strings.TrimSpace(getenv("SB_SANDBOX_NODE_PORTS_ALLOW"))
	if raw != "" && enterprise {
		return nil, errors.New("SB_SANDBOX_NODE_PORTS_ALLOW must be empty when SB_ENTERPRISE_MODE=true")
	}
	for _, f := range strings.Split(raw, ",") {
		f = strings.ToLower(strings.TrimSpace(f))
		if f == "" {
			continue
		}
		port, proto, _ := strings.Cut(f, "/")
		if proto == "" {
			proto = "tcp"
		}
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == 0 || (proto != "tcp" && proto != "udp") {
			return nil, fmt.Errorf("SB_SANDBOX_NODE_PORTS_ALLOW entry %q: want a port 1-65535, optionally /tcp or /udp", f)
		}
		out = append(out, rootpolicy.NodePort{Proto: proto, Port: uint32(n)})
	}
	return rootpolicy.CheckNodePorts(out)
}
