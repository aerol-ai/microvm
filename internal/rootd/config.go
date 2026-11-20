package rootd

import (
	"errors"
	"fmt"
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
// The policy's folders default to sandboxd's own defaults (internal/config),
// so a helper beside an agent with default settings needs none either.
const (
	DefaultSocket      = "/run/aerolvm/root.sock"
	DefaultSocketGroup = "aerolvm"
	// DefaultAgentUID is the agent's uid on Kubernetes (runAsUser 65532).
	DefaultAgentUID = 65532

	defaultContainerdSocket = "/run/containerd/containerd.sock"
	defaultNamespace        = "aerolvm"
	defaultSnapshotterRoot  = "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs"
	defaultNetnsDir         = "/run/netns"
	defaultRunDir           = "/var/lib/sandboxd/containerd"
	defaultMountsRoot       = "/var/lib/sandboxd/mounts"
	defaultCredDir          = "/run/sandboxd"
	defaultDBPath           = "/var/lib/sandboxd/state.db"
	defaultToolbox          = "/usr/local/bin/toolboxd"
	defaultFIFODir          = "/run/aerolvm/fifo"
	defaultPidsLimit        = 4096
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

// detectHost reads the node's memory and CPUs; tests replace it.
var detectHost = capacity.DetectHost

// ConfigFromEnv reads the helper's config. Unlike sandboxd's own loader,
// a value that does not parse is an error, not a fallback to the default:
// this config bounds what root does for the agent.
//
// The policy's names match sandboxd's (SB_CONTAINERD_NAMESPACE,
// SB_CONTAINERD_RUN_DIR, SB_CONTAINER_PRIVILEGED, ...) so one setting in the
// chart or the unit reaches both processes, but each reads its own copy.
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

	socket := get("SB_ROOTD_SOCKET", DefaultSocket)
	containerdSocket := get("SB_CONTAINERD_SOCKET", defaultContainerdSocket)
	// The agent's containerd driver keeps its per-sandbox files under its
	// run dir (internal/runtime/containerd: hosts.go, gvisor_move.go,
	// runsc_config.go); TestHelperPolicyMatchesDriverLayout there pins
	// these names.
	runDir := get("SB_CONTAINERD_RUN_DIR", defaultRunDir)
	cfg := Config{
		Socket:           socket,
		SocketGID:        gid,
		AgentUID:         uid,
		AgentCgroup:      strings.TrimSpace(getenv("SB_ROOTD_AGENT_CGROUP")),
		ContainerdSocket: containerdSocket,
		Policy: rootpolicy.Policy{
			Namespace:       get("SB_CONTAINERD_NAMESPACE", defaultNamespace),
			Snapshotter:     "overlayfs",
			SnapshotterRoot: get("SB_ROOTD_SNAPSHOTTER_ROOT", defaultSnapshotterRoot),
			NetnsDir:        get("SB_NETNS_DIR", defaultNetnsDir),
			CgroupParent:    strings.TrimSpace(getenv("SB_CONTAINERD_CGROUP_PARENT")),
			BindRoots: []string{
				filepath.Join(runDir, "hosts"),
				get("SB_MOUNTS_ROOT", defaultMountsRoot),
				// config.DockerReadySocketDir and the egress CA beside the
				// database (internal/service/egress_inspect.go).
				filepath.Join(get("SB_MOUNTS_CRED_DIR", defaultCredDir), "docker", "ready"),
				filepath.Join(filepath.Dir(get("SB_DB_PATH", defaultDBPath)), "egress-ca"),
			},
			BindFiles: []string{get("SB_TOOLBOX_BINARY_PATH", defaultToolbox)},
			// The two sockets that are as good as root: this helper's and
			// containerd's.
			ForbiddenRoots: []string{filepath.Dir(socket), filepath.Dir(containerdSocket)},
			MovesDir:       filepath.Join(runDir, "moves"),
			FIFODir:        get("SB_ROOTD_FIFO_DIR", defaultFIFODir),
			RunscConfigPaths: []string{
				filepath.Join(runDir, "runsc", "config.toml"),
				filepath.Join(runDir, "runsc", "restore.toml"),
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
