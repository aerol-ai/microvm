package rootd

import (
	"errors"
	"fmt"
	"math"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/aerol-ai/microvm/internal/rootpolicy"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/gvisorpids"
)

// Defaults for the socket and its peer (plans/security-gaps-m1-m4.md §3.3).
// The folders the agent fills default to sandboxd's own defaults
// (internal/config), so a helper beside an agent with default settings
// needs none either. The files root itself reads or runs default to the
// helper's own folders, which the agent cannot write (review H2).
const (
	// DefaultSocket sits in a folder of the helper's own: the socket's
	// folder must be root's alone (listen), and /run/aerolvm, where it was
	// first meant to go, is an emptyDir every worker container can write.
	DefaultSocket      = "/run/aerolvm-rootd/root.sock"
	DefaultSocketGroup = "aerolvm"
	// DefaultAgentUID is a uid nothing else in AerolVM runs as. The peer
	// check goes by uid, so the agent's must be its own: 65532 is the
	// egress gateway's, edge's and the operator's, and 65534 is nobody's.
	DefaultAgentUID = 65531
	// DefaultStateDir holds what root reads on the agent's word: the runsc
	// configs and the gVisor moves folder.
	DefaultStateDir = "/var/lib/aerolvm-rootd"

	defaultContainerdSocket = "/run/containerd/containerd.sock"
	defaultNamespace        = "aerolvm"
	defaultSnapshotterRoot  = "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs"
	defaultNetnsDir         = "/run/netns"
	defaultRunDir           = "/var/lib/sandboxd/containerd"
	defaultMountsRoot       = "/var/lib/sandboxd/mounts"
	defaultCredDir          = "/run/sandboxd"
	defaultDBPath           = "/var/lib/sandboxd/state.db"
	defaultToolbox          = "/usr/local/bin/toolboxd"
	defaultFIFODir          = "/run/aerolvm-rootd/fifo"
	defaultPidsLimit        = 4096
	// sandboxd's defaults for the users its jails run as.
	defaultJailUID = 1000
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
}

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
	limits, err := limitsFromEnv(getenv)
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
	// The agent's containerd driver keeps its per-sandbox host files under
	// its run dir (internal/runtime/containerd hosts.go);
	// TestHelperPolicyMatchesDriverLayout there pins the names.
	runDir := path("SB_CONTAINERD_RUN_DIR", defaultRunDir)
	mountsRoot := path("SB_MOUNTS_ROOT", defaultMountsRoot)
	credDir := path("SB_MOUNTS_CRED_DIR", defaultCredDir)
	dataDir := filepath.Dir(path("SB_DB_PATH", defaultDBPath))
	stateDir := path("SB_ROOTD_STATE_DIR", DefaultStateDir)
	fifoDir := path("SB_ROOTD_FIFO_DIR", defaultFIFODir)
	toolbox := path("SB_TOOLBOX_BINARY_PATH", defaultToolbox)
	snapshotterRoot := path("SB_ROOTD_SNAPSHOTTER_ROOT", defaultSnapshotterRoot)
	netnsDir := path("SB_NETNS_DIR", defaultNetnsDir)
	if pathErr != nil {
		return Config{}, pathErr
	}
	// The agent owns its folders and can rename anything below them, a
	// folder root made included, so nothing root trusts may sit there.
	for _, h := range []struct{ name, dir string }{
		{"SB_ROOTD_SOCKET", filepath.Dir(socket)},
		{"SB_ROOTD_STATE_DIR", stateDir},
		{"SB_ROOTD_FIFO_DIR", fifoDir},
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
			CgroupParent:    strings.TrimSpace(getenv("SB_CONTAINERD_CGROUP_PARENT")),
			BindRoots: []string{
				filepath.Join(runDir, "hosts"),
				mountsRoot,
				// config.DockerReadySocketDir and the egress CA beside the
				// database (internal/service/egress_inspect.go).
				filepath.Join(credDir, "docker", "ready"),
				filepath.Join(dataDir, "egress-ca"),
			},
			BindFiles: []string{toolbox},
			// The two sockets that are as good as root: this helper's and
			// containerd's.
			ForbiddenRoots: []string{filepath.Dir(socket), filepath.Dir(containerdSocket)},
			MovesDir:       filepath.Join(stateDir, "moves"),
			FIFODir:        fifoDir,
			RunscConfigPaths: []string{
				filepath.Join(stateDir, "runsc", "config.toml"),
				filepath.Join(stateDir, "runsc", "restore.toml"),
			},
			Privileged: privileged,
			Limits:     limits,
		},
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
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

// checkAgentUIDIsItsOwn refuses an agent uid another AerolVM process runs
// as: those this config names, and 65532, which the chart and images use
// for several. The peer check goes by uid, so on a shared uid that other
// process, which may parse tenant traffic (the egress gateway does), would
// pass for the agent (review H3).
func checkAgentUIDIsItsOwn(getenv func(string) string, uid uint32) error {
	var who []string
	switch uid {
	case nobodyUID:
		who = append(who, "nobody")
	case imageUID:
		who = append(who, "the egress gateway, edge and the operator in the chart and images")
	}
	for _, k := range []string{"SB_ISOLATE_JAIL_UID", "SB_JAILER_UID"} {
		n, err := envInt(getenv, k, defaultJailUID)
		if err != nil {
			return err
		}
		// A value outside uid_t would wrap in the conversion and be compared
		// as some other uid.
		if n < 0 || n > math.MaxUint32 {
			return fmt.Errorf("%s=%d: not a uid", k, n)
		}
		if uint32(n) == uid {
			who = append(who, k)
		}
	}
	if gw, ok := gatewayUID(strings.TrimSpace(getenv("SB_EGRESS_GATEWAY_USER"))); ok && gw == uid {
		who = append(who, "SB_EGRESS_GATEWAY_USER")
	}
	if len(who) > 0 {
		return fmt.Errorf("SB_ROOTD_AGENT_UID: uid %d is also the uid of %s; the agent needs one of its own", uid, strings.Join(who, " and "))
	}
	return nil
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
