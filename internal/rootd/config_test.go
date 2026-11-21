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
			NetnsDir:        DefaultNetnsDir,
			// Binds come from the external mounts and the helper's own
			// files, never from the agent's run dir, ready dir or
			// database folder (T2b).
			BindRoots: []string{"/var/lib/sandboxd/mounts"},
			BindFiles: []string{"/usr/local/bin/toolboxd"},
			HelperFileRoots: []string{
				"/var/lib/aerolvm-rootd/hosts",
				"/run/aerolvm-rootd/ready",
			},
			ForbiddenRoots: []string{"/run/aerolvm-rootd/sock", "/run/containerd"},
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
		Files: FileDirs{
			Hosts:      "/var/lib/aerolvm-rootd/hosts",
			Ready:      "/run/aerolvm-rootd/ready",
			Runsc:      "/var/lib/aerolvm-rootd/runsc",
			AgentReady: "/run/sandboxd/docker/ready",
		},
		// sandboxd's own CNI settings, read under the same names.
		Network: NetworkConfig{PluginDir: "/opt/cni/bin", ConfPath: "/etc/cni/net.d/aerolvm.conflist"},
		Firewall: FirewallConfig{Backend: "netlink", NodePorts: []rootpolicy.NodePort{
			{Proto: "udp", Port: 53054}, {Proto: "tcp", Port: 53054}, {Proto: "tcp", Port: 15080},
			{Proto: "tcp", Port: 80}, {Proto: "tcp", Port: 443}}},
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
			"SB_ROOTD_NETNS_DIR":          "/run/rootd-netns",
			"SB_MOUNTS_ROOT":              "/data/mounts",
			"SB_MOUNTS_CRED_DIR":          "/run/sbd",
			"SB_DB_PATH":                  "/data/state/state.db",
			"SB_TOOLBOX_BINARY_PATH":      "/opt/aerolvm/toolboxd",
			"SB_ROOTD_FIFO_DIR":           "/run/rootd-io",
			"SB_ROOTD_READY_DIR":          "/run/rootd-ready",
			"SB_ROOTD_STATE_DIR":          "/data/rootd",
		}, func(c *Config) {
			p := &c.Policy
			p.Namespace, p.CgroupParent, p.SnapshotterRoot, p.NetnsDir = "tenant-a", "/aerolvm.slice", "/data/containerd/snap", "/run/rootd-netns"
			p.BindRoots, p.HelperFileRoots = []string{"/data/mounts"}, []string{"/data/rootd/hosts", "/run/rootd-ready"}
			p.BindFiles = []string{"/opt/aerolvm/toolboxd"}
			p.MovesDir, p.FIFODir = "/data/rootd/moves", "/run/rootd-io"
			p.RunscConfigPaths = []string{"/data/rootd/runsc/config.toml", "/data/rootd/runsc/restore.toml"}
			c.Files = FileDirs{Hosts: "/data/rootd/hosts", Ready: "/run/rootd-ready", Runsc: "/data/rootd/runsc", AgentReady: "/run/sbd/docker/ready"}
		}},
		{"network", map[string]string{
			"SB_CONTAINERD_CNI_PLUGIN_DIR": "/usr/lib/cni",
			"SB_CONTAINERD_CNI_CONF_PATH":  "/etc/aerolvm/cni/sandboxes.conflist",
			"SB_CONTAINERD_BRIDGE_SUBNET":  " 10.200.0.0/16 ",
		}, func(c *Config) {
			c.Network = NetworkConfig{PluginDir: "/usr/lib/cni", ConfPath: "/etc/aerolvm/cni/sandboxes.conflist", Subnet: "10.200.0.0/16"}
		}},
		{"firewall", map[string]string{"SB_NETRULES_BACKEND": " IPTables ", "SB_SANDBOX_INTERCONNECT": "true"}, func(c *Config) {
			c.Firewall.Backend, c.Firewall.Interconnect = "iptables", true
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
			// No egress gateway runs with privileged containers.
			c.Firewall.NodePorts = []rootpolicy.NodePort{{Proto: "tcp", Port: 80}, {Proto: "tcp", Port: 443}}
		}},
		{"paths written untidily are used clean", map[string]string{
			"SB_ROOTD_STATE_DIR": "/var/lib/aerolvm-rootd/",
			"SB_ROOTD_SOCKET":    "/run//aerolvm-rootd/./sock/root.sock",
		}, func(*Config) {}},
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
			want.Policy.HelperFileRoots = slices.Clone(defaults.Policy.HelperFileRoots)
			tc.want(&want)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("config\n got %+v\nwant %+v", got, want)
			}
		})
	}
}

// TestHelperPolicyBindsOnlyItsFiles: from its own folders the helper's
// policy binds one file the helper makes, <root>/<id>/<name>, and nothing
// else: not a container's folder, nothing deeper, no other name. Those
// folders are root's alone; a bind of one would hand it to a sandbox.
func TestHelperPolicyBindsOnlyItsFiles(t *testing.T) {
	stubHost(t, 1024, nil)
	cfg, err := ConfigFromEnv(env(map[string]string{"SB_ROOTD_SOCKET_GROUP": strconv.Itoa(os.Getgid())}))
	if err != nil {
		t.Fatal(err)
	}
	hosts, ready := cfg.Files.Hosts, cfg.Files.Ready
	for src, ok := range map[string]bool{
		hosts + "/sb-1/resolv.conf":   true,
		hosts + "/sb-1/egress-ca.pem": true,
		ready + "/sb-1/0a1b.sock":     true,
		ready + "/park-1/ready.sock":  true,
		// The external mounts are folders, as today.
		"/var/lib/sandboxd/mounts/sb-1/0": true,

		hosts + "/sb-1":                           false,
		ready + "/sb-1":                           false,
		hosts + "/sb-1/sub/resolv.conf":           false,
		hosts + "/sb-1/.resolv.conf.0123456789ab": false,
		ready + "/sb-1/x.sock":                    false,
		hosts + "/sb-1/passwd":                    false,
	} {
		if err := rootpolicy.CheckBindSource(cfg.Policy, src); (err == nil) != ok {
			t.Errorf("CheckBindSource(%s) = %v, want ok=%v", src, err, ok)
		}
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
		{"interconnect that does not parse", map[string]string{"SB_SANDBOX_INTERCONNECT": "sometimes"}, nil, "SB_SANDBOX_INTERCONNECT"},
		{"interconnect in enterprise mode", map[string]string{"SB_SANDBOX_INTERCONNECT": "true", "SB_ENTERPRISE_MODE": "true"}, nil, "SB_SANDBOX_INTERCONNECT"},
		{"memory that does not parse", map[string]string{"SB_HOST_MEMORY_MB": "lots"}, nil, "SB_HOST_MEMORY_MB"},
		{"cpus that do not parse", map[string]string{"SB_HOST_CPU_CORES": "1.5"}, nil, "SB_HOST_CPU_CORES"},
		{"pids that do not parse", map[string]string{"SB_SANDBOX_PIDS_LIMIT": "x"}, nil, "SB_SANDBOX_PIDS_LIMIT"},
		{"no pids limit", map[string]string{"SB_SANDBOX_PIDS_LIMIT": "0"}, nil, "above 0"},
		{"memory not detected", map[string]string{}, errors.New("no /proc/meminfo"), "no /proc/meminfo"},
		{"memory not detected, no reason", map[string]string{}, nil, "not detected"},
		{"a relative socket", map[string]string{"SB_ROOTD_SOCKET": "root.sock", "SB_HOST_MEMORY_MB": "1"}, nil, "SB_ROOTD_SOCKET"},
		{"a relative netns folder", map[string]string{"SB_ROOTD_NETNS_DIR": "netns", "SB_HOST_MEMORY_MB": "1"}, nil, "SB_ROOTD_NETNS_DIR"},
		// PR 4 review: the node's shared folder holds namespaces that are
		// not the helper's.
		{"the shared netns folder", map[string]string{"SB_ROOTD_NETNS_DIR": "/run/netns", "SB_HOST_MEMORY_MB": "1"}, nil, "shared namespace folder"},
		{"the shared netns folder by its old name", map[string]string{"SB_ROOTD_NETNS_DIR": "/var/run/netns", "SB_HOST_MEMORY_MB": "1"}, nil, "shared namespace folder"},
		{"a relative agent run dir", map[string]string{"SB_CONTAINERD_RUN_DIR": "data/ctr", "SB_HOST_MEMORY_MB": "1"}, nil, "want an absolute path"},
		{"a relative CNI plugin folder", map[string]string{"SB_CONTAINERD_CNI_PLUGIN_DIR": "cni/bin", "SB_HOST_MEMORY_MB": "1"}, nil, "SB_CONTAINERD_CNI_PLUGIN_DIR"},
		{"a sandbox range that is no network", map[string]string{"SB_CONTAINERD_BRIDGE_SUBNET": "10.88.0.1/16", "SB_HOST_MEMORY_MB": "1"}, nil, "sandbox range"},
		{"an IPv6 sandbox range", map[string]string{"SB_CONTAINERD_BRIDGE_SUBNET": "fd00::/64", "SB_HOST_MEMORY_MB": "1"}, nil, "sandbox range"},
		{"a sandbox range too small", map[string]string{"SB_CONTAINERD_BRIDGE_SUBNET": "10.88.0.0/28", "SB_HOST_MEMORY_MB": "1"}, nil, "sandbox range"},
		// The agent writes its own folders; root must not run or trust
		// anything in them.
		{"the netns folder in the agent's", map[string]string{"SB_ROOTD_NETNS_DIR": "/var/lib/sandboxd/netns", "SB_HOST_MEMORY_MB": "1"}, nil, "SB_ROOTD_NETNS_DIR"},
		{"CNI plugins in the agent's folder", map[string]string{"SB_CONTAINERD_CNI_PLUGIN_DIR": "/run/sandboxd/cni", "SB_HOST_MEMORY_MB": "1"}, nil, "SB_CONTAINERD_CNI_PLUGIN_DIR"},
		{"the CNI config in the agent's folder", map[string]string{"SB_CONTAINERD_CNI_CONF_PATH": "/var/lib/sandboxd/cni/a.conflist", "SB_HOST_MEMORY_MB": "1"}, nil, "SB_CONTAINERD_CNI_CONF_PATH"},
		{"more memory than an int64 of bytes", map[string]string{"SB_HOST_MEMORY_MB": "9007199254740992"}, nil, "more than a machine can have"},
		// Review H3: the peer check goes by uid, so the agent's must be its
		// own.
		{"the agent as nobody", map[string]string{"SB_ROOTD_AGENT_UID": "65534", "SB_HOST_MEMORY_MB": "1"}, nil, "nobody"},
		// 65532 is the chart's egress gateway, edge and operator, though
		// the helper's own environment names none of them.
		{"the agent as the chart's shared uid", map[string]string{"SB_ROOTD_AGENT_UID": "65532", "SB_HOST_MEMORY_MB": "1"}, nil, "egress gateway, edge and the operator"},
		{"the agent as the egress gateway", map[string]string{"SB_ROOTD_AGENT_UID": "65532", "SB_EGRESS_GATEWAY_USER": "65532", "SB_HOST_MEMORY_MB": "1"}, nil, "SB_EGRESS_GATEWAY_USER"},
		{"the agent as the egress gateway, uid:gid", map[string]string{"SB_ROOTD_AGENT_UID": "4000", "SB_EGRESS_GATEWAY_USER": "4000:4001", "SB_HOST_MEMORY_MB": "1"}, nil, "SB_EGRESS_GATEWAY_USER"},
		{"the agent as the jails' default user", map[string]string{"SB_ROOTD_AGENT_UID": "1000", "SB_HOST_MEMORY_MB": "1"}, nil, "SB_ISOLATE_JAIL_UID"},
		{"the agent as the jailer", map[string]string{"SB_ROOTD_AGENT_UID": "2000", "SB_JAILER_UID": "2000", "SB_ISOLATE_JAIL_UID": "3000", "SB_HOST_MEMORY_MB": "1"}, nil, "SB_JAILER_UID"},
		{"a jail uid that does not parse", map[string]string{"SB_ISOLATE_JAIL_UID": "x", "SB_HOST_MEMORY_MB": "1"}, nil, "SB_ISOLATE_JAIL_UID"},
		// Review H2: what root reads must not sit where the agent writes.
		{"runsc configs in the agent's run dir", map[string]string{"SB_ROOTD_STATE_DIR": "/var/lib/sandboxd/containerd/rootd", "SB_HOST_MEMORY_MB": "1"}, nil, "SB_ROOTD_STATE_DIR"},
		{"the helper's state in the agent's data dir", map[string]string{"SB_ROOTD_STATE_DIR": "/var/lib/sandboxd", "SB_HOST_MEMORY_MB": "1"}, nil, "which the agent writes"},
		{"FIFOs in the agent's run folder", map[string]string{"SB_ROOTD_FIFO_DIR": "/run/sandboxd/fifo", "SB_HOST_MEMORY_MB": "1"}, nil, "SB_ROOTD_FIFO_DIR"},
		{"ready names in the agent's ready folder", map[string]string{"SB_ROOTD_READY_DIR": "/run/sandboxd/docker/ready/helper", "SB_HOST_MEMORY_MB": "1"}, nil, "SB_ROOTD_READY_DIR"},
		// The socket's folder is no bind root's: the ready names are binds.
		{"ready names beside the socket", map[string]string{"SB_ROOTD_READY_DIR": "/run/aerolvm-rootd/sock/ready", "SB_HOST_MEMORY_MB": "1"}, nil, "forbidden"},
		{"a relative ready folder", map[string]string{"SB_ROOTD_READY_DIR": "ready", "SB_HOST_MEMORY_MB": "1"}, nil, "SB_ROOTD_READY_DIR"},
		// The helper's folders never hold one another: a folder a spec
		// binds from must not hold what root reads, the FIFOs or the socket.
		{"ready names in the state folder", map[string]string{"SB_ROOTD_READY_DIR": "/var/lib/aerolvm-rootd", "SB_HOST_MEMORY_MB": "1"}, nil, "overlap"},
		{"ready names around the FIFOs and the socket", map[string]string{"SB_ROOTD_READY_DIR": "/run/aerolvm-rootd", "SB_HOST_MEMORY_MB": "1"}, nil, "overlap"},
		{"FIFOs in the ready folder", map[string]string{"SB_ROOTD_FIFO_DIR": "/run/aerolvm-rootd/ready/fifo", "SB_HOST_MEMORY_MB": "1"}, nil, "overlap"},
		{"FIFOs in the hosts folder", map[string]string{"SB_ROOTD_FIFO_DIR": "/var/lib/aerolvm-rootd/hosts/fifo", "SB_HOST_MEMORY_MB": "1"}, nil, "overlap"},
		{"the state folder in the ready folder", map[string]string{"SB_ROOTD_STATE_DIR": "/run/aerolvm-rootd/ready/state", "SB_HOST_MEMORY_MB": "1"}, nil, "overlap"},
		{"FIFOs beside the runsc configs", map[string]string{"SB_ROOTD_FIFO_DIR": "/var/lib/aerolvm-rootd/runsc", "SB_HOST_MEMORY_MB": "1"}, nil, "overlap"},
		{"the socket in the agent's mounts", map[string]string{"SB_ROOTD_SOCKET": "/var/lib/sandboxd/mounts/root.sock", "SB_HOST_MEMORY_MB": "1"}, nil, "SB_ROOTD_SOCKET"},
		// Review N6: the same folder written another way is the same folder.
		{"the agent's run dir with a trailing slash", map[string]string{"SB_DB_PATH": "/data/state.db", "SB_CONTAINERD_RUN_DIR": "/srv/ctr/", "SB_ROOTD_STATE_DIR": "/srv/ctr/rootd", "SB_HOST_MEMORY_MB": "1"}, nil, "SB_ROOTD_STATE_DIR"},
		{"the agent's mounts with a doubled slash", map[string]string{"SB_DB_PATH": "/data/state.db", "SB_MOUNTS_ROOT": "/srv//mounts", "SB_ROOTD_STATE_DIR": "/srv/mounts/rootd", "SB_HOST_MEMORY_MB": "1"}, nil, "SB_ROOTD_STATE_DIR"},
		{"FIFOs through a dot", map[string]string{"SB_DB_PATH": "/data/state.db", "SB_ROOTD_FIFO_DIR": "/data/./fifo", "SB_HOST_MEMORY_MB": "1"}, nil, "SB_ROOTD_FIFO_DIR"},
		{"the helper's state reached by climbing out", map[string]string{"SB_ROOTD_STATE_DIR": "/var/lib/aerolvm-rootd/../sandboxd/x", "SB_HOST_MEMORY_MB": "1"}, nil, "SB_ROOTD_STATE_DIR"},
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

// TestNodePortsFromEnv (PR 5 reviews): the node ports sandboxes may ever
// reach come from the helper's own settings, by single mode's rules
// (Service.SandboxNodeAllowlist): the gateway's ports when it runs, 80 and
// 443 on an ingress node with Caddy that leaves them open, the operator's
// ports, and DNS never as a setting.
func TestNodePortsFromEnv(t *testing.T) {
	np := func(proto string, port uint32) rootpolicy.NodePort {
		return rootpolicy.NodePort{Proto: proto, Port: port}
	}
	gateway := []rootpolicy.NodePort{np("udp", 5353), np("tcp", 5353), np("tcp", 8080)}
	web := []rootpolicy.NodePort{np("tcp", 80), np("tcp", 443)}
	for _, tc := range []struct {
		name       string
		env        map[string]string
		privileged bool
		want, not  []rootpolicy.NodePort
	}{
		{"defaults: a mixed node, the gateway on", nil, false, append(append([]rootpolicy.NodePort{}, gateway...), web...), []rootpolicy.NodePort{np("udp", 53), np("tcp", 53)}},
		{"the gateway off", map[string]string{"SB_EGRESS_FQDN_ENABLED": "false"}, false, web, gateway},
		{"privileged containers (no gateway)", nil, true, web, gateway},
		{"sandboxes kept off the node's ingress", map[string]string{"SB_SANDBOX_NODE_INGRESS": "false"}, false, gateway, web},
		{"no Caddy", map[string]string{"SB_ENABLE_CADDY": "false"}, false, gateway, web},
		{"a worker node", map[string]string{"SB_NODE_ROLE": "worker"}, false, gateway, web},
		{"a worker and ingress node", map[string]string{"SB_NODE_ROLE": "worker, ingress"}, false, append(append([]rootpolicy.NodePort{}, gateway...), web...), nil},
		{"the operator's ports", map[string]string{"SB_SANDBOX_NODE_PORTS_ALLOW": "9000, 9001/udp", "SB_NODE_ROLE": "worker"}, false,
			append([]rootpolicy.NodePort{np("tcp", 9000), np("udp", 9001)}, gateway...), web},
	} {
		e := map[string]string{"SB_EGRESS_DNS_PORT": "5353", "SB_EGRESS_PROXY_PORT": "8080"}
		for k, v := range tc.env {
			e[k] = v
		}
		got, err := nodePortsFromEnv(env(e), false, tc.privileged)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		for _, w := range tc.want {
			if !slices.Contains(got, w) {
				t.Errorf("%s: %v lacks %v", tc.name, got, w)
			}
		}
		for _, n := range tc.not {
			if slices.Contains(got, n) {
				t.Errorf("%s: %v holds %v", tc.name, got, n)
			}
		}
		if len(got) != len(tc.want) {
			t.Errorf("%s: %v, want exactly %v", tc.name, got, tc.want)
		}
	}
	for _, bad := range []map[string]string{
		{"SB_SANDBOX_NODE_PORTS_ALLOW": "x"},
		{"SB_SANDBOX_NODE_PORTS_ALLOW": "80/sctp"},
		{"SB_EGRESS_DNS_PORT": "lots"},
		{"SB_EGRESS_PROXY_PORT": "lots"},
		{"SB_EGRESS_FQDN_ENABLED": "maybe"},
		{"SB_ENABLE_CADDY": "maybe"},
		{"SB_SANDBOX_NODE_INGRESS": "maybe"},
		{"SB_NODE_ROLE": "worker,gateway"},
	} {
		if _, err := nodePortsFromEnv(env(bad), false, false); err == nil {
			t.Errorf("%v passed", bad)
		}
	}
	if _, err := nodePortsFromEnv(env(map[string]string{"SB_SANDBOX_NODE_PORTS_ALLOW": "9000"}), true, false); err == nil {
		t.Fatal("an operator's node ports passed in enterprise mode")
	}
}
