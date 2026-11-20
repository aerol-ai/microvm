package rootd

import (
	"errors"
	"io/fs"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
	"github.com/aerol-ai/microvm/pkg/capacity"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func stubHost(t *testing.T, memMB int, err error) {
	t.Helper()
	old := detectHost
	detectHost = func() (capacity.HostInfo, error) { return capacity.HostInfo{MemoryTotalMB: memMB}, err }
	t.Cleanup(func() { detectHost = old })
}

// TestConfigFromEnv: the policy comes from the helper's own environment
// and from nothing else (eng review D6). With nothing set it is sandboxd's
// default layout; each setting moves exactly its part.
func TestConfigFromEnv(t *testing.T) {
	stubHost(t, 8192, nil)
	gid := strconv.Itoa(os.Getgid())
	defaults := Config{
		Socket:           DefaultSocket,
		SocketGID:        os.Getgid(),
		AgentUID:         DefaultAgentUID,
		ContainerdSocket: "/run/containerd/containerd.sock",
		Policy: rootpolicy.Policy{
			Namespace:       "aerolvm",
			Snapshotter:     "overlayfs",
			SnapshotterRoot: "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs",
			NetnsDir:        "/run/netns",
			BindRoots: []string{
				"/var/lib/sandboxd/containerd/hosts",
				"/var/lib/sandboxd/mounts",
				"/run/sandboxd/docker/ready",
				"/var/lib/sandboxd/egress-ca",
			},
			BindFiles:      []string{"/usr/local/bin/toolboxd"},
			ForbiddenRoots: []string{"/run/aerolvm-rootd", "/run/containerd"},
			// What root reads on the agent's word lives in the helper's
			// own folders, never the agent's (review H2).
			MovesDir: "/var/lib/aerolvm-rootd/moves",
			FIFODir:  "/run/aerolvm-rootd/fifo",
			RunscConfigPaths: []string{
				"/var/lib/aerolvm-rootd/runsc/config.toml",
				"/var/lib/aerolvm-rootd/runsc/restore.toml",
			},
			// Pids: gVisor's host limit for the node's 4096 (pkg/gvisorpids:
			// two host tasks per sandbox task, plus headroom).
			Limits: rootpolicy.Limits{MemoryBytes: 8192 << 20, Pids: 2*4096 + 1024, CPUs: float64(runtime.NumCPU())},
		},
	}
	for _, tc := range []struct {
		name string
		env  map[string]string
		want func(*Config)
	}{
		{"defaults", map[string]string{}, func(*Config) {}},
		{"socket and peer", map[string]string{
			"SB_ROOTD_SOCKET":       "/run/helper/h.sock",
			"SB_ROOTD_AGENT_UID":    "1001",
			"SB_ROOTD_AGENT_CGROUP": " sandboxd.service ",
			"SB_CONTAINERD_SOCKET":  "/run/k3s/containerd/containerd.sock",
		}, func(c *Config) {
			c.Socket, c.AgentUID, c.AgentCgroup = "/run/helper/h.sock", 1001, "sandboxd.service"
			c.ContainerdSocket = "/run/k3s/containerd/containerd.sock"
			c.Policy.ForbiddenRoots = []string{"/run/helper", "/run/k3s/containerd"}
		}},
		{"folders", map[string]string{
			"SB_CONTAINERD_NAMESPACE":     "tenant-a",
			"SB_CONTAINERD_RUN_DIR":       "/data/ctr",
			"SB_CONTAINERD_CGROUP_PARENT": "/aerolvm.slice",
			"SB_ROOTD_SNAPSHOTTER_ROOT":   "/data/containerd/snap",
			"SB_NETNS_DIR":                "/var/run/netns",
			"SB_MOUNTS_ROOT":              "/data/mounts",
			"SB_MOUNTS_CRED_DIR":          "/run/sbd",
			"SB_DB_PATH":                  "/data/state/state.db",
			"SB_TOOLBOX_BINARY_PATH":      "/opt/aerolvm/toolboxd",
			"SB_ROOTD_FIFO_DIR":           "/run/rootd-io",
			"SB_ROOTD_STATE_DIR":          "/data/rootd",
		}, func(c *Config) {
			p := &c.Policy
			p.Namespace, p.CgroupParent, p.SnapshotterRoot, p.NetnsDir = "tenant-a", "/aerolvm.slice", "/data/containerd/snap", "/var/run/netns"
			p.BindRoots = []string{"/data/ctr/hosts", "/data/mounts", "/run/sbd/docker/ready", "/data/state/egress-ca"}
			p.BindFiles = []string{"/opt/aerolvm/toolboxd"}
			p.MovesDir, p.FIFODir = "/data/rootd/moves", "/run/rootd-io"
			p.RunscConfigPaths = []string{"/data/rootd/runsc/config.toml", "/data/rootd/runsc/restore.toml"}
		}},
		{"node limits", map[string]string{
			"SB_HOST_MEMORY_MB":     "1024",
			"SB_HOST_CPU_CORES":     "3",
			"SB_SANDBOX_PIDS_LIMIT": "100",
		}, func(c *Config) {
			c.Policy.Limits = rootpolicy.Limits{MemoryBytes: 1 << 30, Pids: 2*100 + 1024, CPUs: 3}
		}},
		{"privileged, not in enterprise mode", map[string]string{"SB_CONTAINER_PRIVILEGED": "true", "SB_ENTERPRISE_MODE": "false"}, func(c *Config) {
			c.Policy.Privileged = true
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := map[string]string{"SB_ROOTD_SOCKET_GROUP": gid}
			for k, v := range tc.env {
				e[k] = v
			}
			got, err := ConfigFromEnv(env(e))
			if err != nil {
				t.Fatal(err)
			}
			want := defaults
			want.Policy.BindRoots = slices.Clone(defaults.Policy.BindRoots)
			tc.want(&want)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("config\n got %+v\nwant %+v", got, want)
			}
		})
	}
}

func TestConfigFromEnvRefuses(t *testing.T) {
	gid := strconv.Itoa(os.Getgid())
	for _, tc := range []struct {
		name string
		env  map[string]string
		host error // detectHost's answer, with no memory
		want string
	}{
		{"a root agent", map[string]string{"SB_ROOTD_AGENT_UID": "0"}, nil, "must not run as root"},
		{"an unknown agent user", map[string]string{"SB_ROOTD_AGENT_UID": "no-such-user-aerolvm"}, nil, "SB_ROOTD_AGENT_UID"},
		{"an unknown socket group", map[string]string{"SB_ROOTD_SOCKET_GROUP": "no-such-group-aerolvm"}, nil, "SB_ROOTD_SOCKET_GROUP"},
		{"privileged in enterprise mode", map[string]string{"SB_CONTAINER_PRIVILEGED": "1", "SB_ENTERPRISE_MODE": "true"}, nil, "SB_ENTERPRISE_MODE"},
		{"a bool that does not parse", map[string]string{"SB_CONTAINER_PRIVILEGED": "yes please"}, nil, "SB_CONTAINER_PRIVILEGED"},
		{"enterprise that does not parse", map[string]string{"SB_ENTERPRISE_MODE": "maybe"}, nil, "SB_ENTERPRISE_MODE"},
		{"memory that does not parse", map[string]string{"SB_HOST_MEMORY_MB": "lots"}, nil, "SB_HOST_MEMORY_MB"},
		{"cpus that do not parse", map[string]string{"SB_HOST_CPU_CORES": "1.5"}, nil, "SB_HOST_CPU_CORES"},
		{"pids that do not parse", map[string]string{"SB_SANDBOX_PIDS_LIMIT": "x"}, nil, "SB_SANDBOX_PIDS_LIMIT"},
		{"no pids limit", map[string]string{"SB_SANDBOX_PIDS_LIMIT": "0"}, nil, "above 0"},
		{"memory not detected", map[string]string{}, errors.New("no /proc/meminfo"), "no /proc/meminfo"},
		{"memory not detected, no reason", map[string]string{}, nil, "not detected"},
		{"a relative socket", map[string]string{"SB_ROOTD_SOCKET": "root.sock", "SB_HOST_MEMORY_MB": "1"}, nil, "clean absolute path"},
		{"a relative netns folder", map[string]string{"SB_NETNS_DIR": "netns", "SB_HOST_MEMORY_MB": "1"}, nil, "netns dir"},
		{"more memory than an int64 of bytes", map[string]string{"SB_HOST_MEMORY_MB": "9007199254740992"}, nil, "more than a machine can have"},
		// Review H3: the peer check goes by uid, so the agent's must be its
		// own.
		{"the agent as nobody", map[string]string{"SB_ROOTD_AGENT_UID": "65534", "SB_HOST_MEMORY_MB": "1"}, nil, "nobody"},
		{"the agent as the egress gateway", map[string]string{"SB_ROOTD_AGENT_UID": "65532", "SB_EGRESS_GATEWAY_USER": "65532", "SB_HOST_MEMORY_MB": "1"}, nil, "SB_EGRESS_GATEWAY_USER"},
		{"the agent as the egress gateway, uid:gid", map[string]string{"SB_ROOTD_AGENT_UID": "4000", "SB_EGRESS_GATEWAY_USER": "4000:4001", "SB_HOST_MEMORY_MB": "1"}, nil, "SB_EGRESS_GATEWAY_USER"},
		{"the agent as the jails' default user", map[string]string{"SB_ROOTD_AGENT_UID": "1000", "SB_HOST_MEMORY_MB": "1"}, nil, "SB_ISOLATE_JAIL_UID"},
		{"the agent as the jailer", map[string]string{"SB_ROOTD_AGENT_UID": "2000", "SB_JAILER_UID": "2000", "SB_ISOLATE_JAIL_UID": "3000", "SB_HOST_MEMORY_MB": "1"}, nil, "SB_JAILER_UID"},
		{"a jail uid that does not parse", map[string]string{"SB_ISOLATE_JAIL_UID": "x", "SB_HOST_MEMORY_MB": "1"}, nil, "SB_ISOLATE_JAIL_UID"},
		// Review H2: what root reads must not sit where the agent writes.
		{"runsc configs in the agent's run dir", map[string]string{"SB_ROOTD_STATE_DIR": "/var/lib/sandboxd/containerd/rootd", "SB_HOST_MEMORY_MB": "1"}, nil, "SB_ROOTD_STATE_DIR"},
		{"the helper's state in the agent's data dir", map[string]string{"SB_ROOTD_STATE_DIR": "/var/lib/sandboxd", "SB_HOST_MEMORY_MB": "1"}, nil, "which the agent writes"},
		{"FIFOs in the agent's run folder", map[string]string{"SB_ROOTD_FIFO_DIR": "/run/sandboxd/fifo", "SB_HOST_MEMORY_MB": "1"}, nil, "SB_ROOTD_FIFO_DIR"},
		{"the socket in the agent's mounts", map[string]string{"SB_ROOTD_SOCKET": "/var/lib/sandboxd/mounts/root.sock", "SB_HOST_MEMORY_MB": "1"}, nil, "SB_ROOTD_SOCKET"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubHost(t, 0, tc.host)
			e := map[string]string{"SB_ROOTD_SOCKET_GROUP": gid}
			for k, v := range tc.env {
				e[k] = v
			}
			if _, err := ConfigFromEnv(env(e)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ConfigFromEnv = %v, want an error naming %q", err, tc.want)
			}
		})
	}
}

// TestLookupByName: the agent's user and the socket's group may be given
// by name, as a unit file or install script would.
func TestLookupByName(t *testing.T) {
	u, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	if uid, err := lookupUser(u.Username); err != nil || strconv.FormatUint(uint64(uid), 10) != u.Uid {
		t.Fatalf("lookupUser(%s) = %d, %v; want %s", u.Username, uid, err, u.Uid)
	}
	g, err := user.LookupGroupId(strconv.Itoa(os.Getgid()))
	if err != nil {
		t.Skip(err)
	}
	if gid, err := lookupGroup(g.Name); err != nil || gid != os.Getgid() {
		t.Fatalf("lookupGroup(%s) = %d, %v; want %d", g.Name, gid, err, os.Getgid())
	}
}

// TestSocketModeAndGroup: the socket is 0660, owned by the helper and the
// configured group, and nothing of the private folder it was made in is
// left beside it.
func TestSocketModeAndGroup(t *testing.T) {
	gid := os.Getgid()
	if os.Geteuid() == 0 {
		gid = 4242 // root, as the helper is, can hand it any group
	} else if groups, _ := os.Getgroups(); len(groups) > 0 {
		for _, g := range groups {
			if g != gid {
				gid = g // a supplementary group, so the chown is not a no-op
				break
			}
		}
	}
	r := newRig(t, func(c *Config, _ *Options) { c.SocketGID = gid })
	fi, err := os.Lstat(r.cfg.Socket)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Type() != fs.ModeSocket || fi.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode %v, want a socket with 0660", fi.Mode())
	}
	st := fi.Sys().(*syscall.Stat_t)
	if int(st.Gid) != gid || int(st.Uid) != os.Geteuid() {
		t.Fatalf("socket owner %d:%d, want %d:%d", st.Uid, st.Gid, os.Geteuid(), gid)
	}
	entries, err := os.ReadDir(filepath.Dir(r.cfg.Socket))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("socket folder holds %v, want only the socket", entries)
	}
}

// TestStaleSocketIsReplaced: a socket left by a helper that died is
// replaced, and the new helper serves on the same path.
func TestStaleSocketIsReplaced(t *testing.T) {
	path := filepath.Join(shortDir(t), "root.sock")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	l.SetUnlinkOnClose(false)
	_ = l.Close()
	r := newRig(t, func(c *Config, _ *Options) { c.Socket = path })
	if _, err := rootdpbVersion(t, r); err != nil {
		t.Fatalf("Version on the replaced socket: %v", err)
	}
}

func rootdpbVersion(t *testing.T, r *rig) (*rootdpb.VersionResponse, error) {
	return rootdpb.NewRootHelperClient(r.conn).Version(callCtx(t), &rootdpb.VersionRequest{})
}

// TestListenFails: each way the socket cannot be made is an error, and
// leaves no listener or private folder behind.
func TestListenFails(t *testing.T) {
	root := os.Geteuid() == 0
	for _, tc := range []struct {
		name  string
		skip  bool
		setup func(t *testing.T, dir string) (path string, gid int)
	}{
		{"a group this user is not in", root, func(t *testing.T, dir string) (string, int) {
			groups, _ := os.Getgroups()
			gid := 4242
			for slices.Contains(groups, gid) || gid == os.Getgid() {
				gid++
			}
			return filepath.Join(dir, "root.sock"), gid
		}},
		{"a path too long for a socket", false, func(t *testing.T, dir string) (string, int) {
			long := filepath.Join(dir, strings.Repeat("d", 100))
			if err := os.Mkdir(long, 0o755); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(long, "root.sock"), os.Getgid()
		}},
		{"a folder this user cannot write", root, func(t *testing.T, dir string) (string, int) {
			ro := filepath.Join(dir, "ro")
			if err := os.Mkdir(ro, 0o500); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(ro, "root.sock"), os.Getgid()
		}},
		{"a path under a file", false, func(t *testing.T, dir string) (string, int) {
			f := filepath.Join(dir, "f")
			if err := os.WriteFile(f, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(f, "sub", "root.sock"), os.Getgid()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.skip {
				t.Skip("root may do this")
			}
			dir := shortDir(t)
			path, gid := tc.setup(t, dir)
			if ln, _, err := listen(path, gid); err == nil {
				_ = ln.Close()
				t.Fatal("listen succeeded")
			}
			if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, syscall.ENOTDIR) {
				t.Fatalf("something was left at %s: %v", path, err)
			}
			leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".root.sock.*"))
			if len(leftovers) != 0 {
				t.Fatalf("half-made sockets left: %v", leftovers)
			}
		})
	}
}
