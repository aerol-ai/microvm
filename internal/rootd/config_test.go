package rootd

import (
	"errors"
	"io/fs"
	"maps"
	"math"
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
	"time"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
	"github.com/aerol-ai/microvm/pkg/capacity"

	"github.com/aerol-ai/microvm/pkg/isolate"
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
			// Binds come from the external mounts the helper makes, in
			// its own folder, and the helper's own files, never from the
			// agent's run dir, ready dir, mounts root or database folder
			// (T2b, M1 PR 8).
			BindRoots:  []string{"/var/lib/aerolvm-rootd/mounts"},
			MountsRoot: "/var/lib/aerolvm-rootd/mounts",
			BindFiles:  []string{"/usr/local/bin/toolboxd"},
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
			Toolbox:    "/usr/local/bin/toolboxd",
			ImageRoot:  "/var/lib/aerolvm-rootd/imageroot",
		},
		// sandboxd's own CNI settings, read under the same names.
		Network: NetworkConfig{PluginDir: "/opt/cni/bin", ConfPath: "/etc/cni/net.d/aerolvm.conflist"},
		Firewall: FirewallConfig{Backend: "netlink", NodePorts: []rootpolicy.NodePort{
			{Proto: "udp", Port: 53054}, {Proto: "tcp", Port: 53054}, {Proto: "tcp", Port: 15080},
			{Proto: "tcp", Port: 80}, {Proto: "tcp", Port: 443}}},
		// sandboxd's host-port range and redirect listener, its defaults.
		HostPorts: rootpolicy.HostPortBounds{RangeStart: 22000, RangeEnd: 23000, RedirectPort: 21215},
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
			p.BindRoots, p.HelperFileRoots = []string{"/data/rootd/mounts"}, []string{"/data/rootd/hosts", "/run/rootd-ready"}
			p.MountsRoot = "/data/rootd/mounts"
			p.BindFiles = []string{"/opt/aerolvm/toolboxd"}
			p.MovesDir, p.FIFODir = "/data/rootd/moves", "/run/rootd-io"
			p.RunscConfigPaths = []string{"/data/rootd/runsc/config.toml", "/data/rootd/runsc/restore.toml"}
			c.Files = FileDirs{Hosts: "/data/rootd/hosts", Ready: "/run/rootd-ready", Runsc: "/data/rootd/runsc", AgentReady: "/run/sbd/docker/ready",
				Toolbox: "/opt/aerolvm/toolboxd", ImageRoot: "/data/rootd/imageroot"}
		}},
		// M1 PR 7: the agent's toolbox copy sits in a folder it writes (the
		// chart's); the helper keeps its own copy, which specs bind.
		{"toolbox copied from the agent", map[string]string{
			"SB_TOOLBOX_BINARY_PATH":  "/opt/aerolvm/toolbox/toolboxd",
			"SB_ROOTD_TOOLBOX_SOURCE": "/opt/aerolvm/toolbox/toolboxd",
		}, func(c *Config) {
			c.Policy.BindFiles = []string{"/var/lib/aerolvm-rootd/toolbox/toolboxd"}
			c.Files.Toolbox, c.Files.ToolboxSource = "/var/lib/aerolvm-rootd/toolbox/toolboxd", "/opt/aerolvm/toolbox/toolboxd"
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
		// The external mounts are folders, in the helper's own folder,
		// never the agent's mounts root.
		"/var/lib/aerolvm-rootd/mounts/sb-1/0": true,
		"/var/lib/sandboxd/mounts/sb-1/0":      false,

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
		// WASM workers run guests' code as their own user (M1 PR 9).
		{"the agent as the WASM worker", map[string]string{"SB_ROOTD_AGENT_UID": "61000", "SB_HOST_MEMORY_MB": "1"}, nil, "SB_WASM_WORKER_UID"},
		{"a WASM worker uid that does not parse", map[string]string{"SB_WASM_WORKER_UID": "x", "SB_HOST_MEMORY_MB": "1"}, nil, "SB_WASM_WORKER_UID"},
		{"a jail uid that does not parse", map[string]string{"SB_ISOLATE_JAIL_UID": "x", "SB_HOST_MEMORY_MB": "1"}, nil, "SB_ISOLATE_JAIL_UID"},
		// 2^32 + 65531 would wrap to the agent's uid in a plain conversion.
		{"a jail uid past uid_t", map[string]string{"SB_ROOTD_AGENT_UID": "65531", "SB_JAILER_UID": "4295032827", "SB_HOST_MEMORY_MB": "1"}, nil, "SB_JAILER_UID=4295032827: not a uid"},
		{"a negative jail uid", map[string]string{"SB_ISOLATE_JAIL_UID": "-1", "SB_HOST_MEMORY_MB": "1"}, nil, "SB_ISOLATE_JAIL_UID=-1: not a uid"},
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
		// M1 PR 9: the V8 group hosts. The helper jails every group, from
		// its own settings, in a chroot base the agent cannot write.
		{"V8 unjailed", map[string]string{"SB_ENABLE_ISOLATE": "true", "SB_ISOLATE_USE_JAIL": "false", "SB_HOST_MEMORY_MB": "1"}, nil, "SB_ISOLATE_USE_JAIL=false"},
		{"V8 that does not parse", map[string]string{"SB_ENABLE_ISOLATE": "si", "SB_HOST_MEMORY_MB": "1"}, nil, "SB_ENABLE_ISOLATE"},
		{"V8 jail that does not parse", map[string]string{"SB_ENABLE_ISOLATE": "true", "SB_ISOLATE_USE_JAIL": "x", "SB_HOST_MEMORY_MB": "1"}, nil, "SB_ISOLATE_USE_JAIL"},
		{"V8 jail gid that does not parse", map[string]string{"SB_ENABLE_ISOLATE": "true", "SB_ISOLATE_JAIL_GID": "x", "SB_HOST_MEMORY_MB": "1"}, nil, "SB_ISOLATE_JAIL_GID"},
		{"V8 jitless that does not parse", map[string]string{"SB_ENABLE_ISOLATE": "true", "SB_ISOLATE_JITLESS": "x", "SB_HOST_MEMORY_MB": "1"}, nil, "SB_ISOLATE_JITLESS"},
		{"V8 pids that do not parse", map[string]string{"SB_ENABLE_ISOLATE": "true", "SB_ISOLATE_JAIL_PIDS_MAX": "x", "SB_HOST_MEMORY_MB": "1"}, nil, "SB_ISOLATE_JAIL_PIDS_MAX"},
		{"V8 groups with no pids limit", map[string]string{"SB_ENABLE_ISOLATE": "true", "SB_ISOLATE_JAIL_PIDS_MAX": "0", "SB_HOST_MEMORY_MB": "1"}, nil, "above 0"},
		{"the V8 chroots in the agent's folder", map[string]string{"SB_ENABLE_ISOLATE": "true", "SB_ISOLATE_JAIL_CHROOT_BASE": "/var/lib/sandboxd/jail", "SB_HOST_MEMORY_MB": "1"}, nil, "SB_ISOLATE_JAIL_CHROOT_BASE"},
		{"a relative V8 chroot base", map[string]string{"SB_ENABLE_ISOLATE": "true", "SB_ISOLATE_JAIL_CHROOT_BASE": "jail", "SB_HOST_MEMORY_MB": "1"}, nil, "SB_ISOLATE_JAIL_CHROOT_BASE"},
		{"a relative workerd", map[string]string{"SB_ENABLE_ISOLATE": "true", "SB_ISOLATE_WORKERD_PATH": "workerd", "SB_HOST_MEMORY_MB": "1"}, nil, "SB_ISOLATE_WORKERD_PATH"},
		{"a V8 seccomp mode no jail has", map[string]string{"SB_ENABLE_ISOLATE": "true", "SB_ISOLATE_SECCOMP_MODE": "loose", "SB_HOST_MEMORY_MB": "1"}, nil, "seccomp mode"},
		{"the V8 jail as the agent", map[string]string{"SB_ENABLE_ISOLATE": "true", "SB_ROOTD_AGENT_UID": "4000", "SB_ISOLATE_JAIL_UID": "4000", "SB_HOST_MEMORY_MB": "1"}, nil, "SB_ISOLATE_JAIL_UID"},
		{"a host-process cgroup parent at the root", map[string]string{"SB_ENABLE_ISOLATE": "true", "SB_HOST_PROCESS_CGROUP_PARENT": "/", "SB_HOST_MEMORY_MB": "1"}, nil, "host-process cgroup parent"},
		// The V8 jail takes the agent's uid as an int.
		{"a V8 agent uid past MaxInt32", map[string]string{"SB_ENABLE_ISOLATE": "true", "SB_ROOTD_AGENT_UID": "2147483648", "SB_HOST_MEMORY_MB": "1"}, nil, "the V8 jail takes uids up to"},
		// A worker id past uid_t would wrap: 4294967296 onto root, and
		// 4295032827 onto the agent (65531). The uids stop at the shared uid
		// check; the gid at the hosts' own (TestHostsConfigRefusesWrappingIDs).
		{"a WASM worker uid that wraps onto root", map[string]string{"SB_ENABLE_WASM": "true", "SB_WASM_WORKER_UID": "4294967296", "SB_HOST_MEMORY_MB": "1"}, nil, "not a uid"},
		{"a WASM worker uid that wraps onto the agent", map[string]string{"SB_ENABLE_WASM": "true", "SB_WASM_WORKER_UID": "4295032827", "SB_HOST_MEMORY_MB": "1"}, nil, "not a uid"},
		{"a WASM worker gid that wraps", map[string]string{"SB_ENABLE_WASM": "true", "SB_WASM_WORKER_GID": "4294967296", "SB_HOST_MEMORY_MB": "1"}, nil, "want ids below"},
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

// TestHostsConfigRefusesWrappingIDs: the hosts' own check compares the
// WASM worker's ids with the agent's as int64, so a value past uid_t, set
// in code or through the environment, never wraps onto root or the agent.
func TestHostsConfigRefusesWrappingIDs(t *testing.T) {
	good := func() HostsConfig {
		return HostsConfig{LogPath: "/var/lib/aerolvm-rootd/hosts.log", Wasm: &WasmHostsConfig{
			Binary: "/usr/local/bin/aerolvm-rootd", UID: 61000, GID: 61000, SocketDir: DefaultWasmSocketDir,
			AgentUID: 65531, ReadyWait: time.Second}}
	}
	if err := good().validate(); err != nil {
		t.Fatalf("a good config: %v", err)
	}
	var big int64 = math.MaxUint32
	for _, tc := range []struct {
		name     string
		uid, gid int64
		want     string
	}{
		{"uid (uid_t)-1", big, 61000, "want ids below"},
		{"uid wrapping onto root", big + 1, 61000, "want ids below"},
		{"uid wrapping onto the agent", big + 1 + 65531, 61000, "want ids below"},
		{"gid (gid_t)-1", 61000, big, "want ids below"},
		{"uid the agent's", 65531, 61000, "neither root nor the agent"},
		{"uid root", 0, 61000, "neither root nor the agent"},
	} {
		h := good()
		h.Wasm.UID, h.Wasm.GID = int(tc.uid), int(tc.gid)
		if err := h.validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want an error naming %q", tc.name, err, tc.want)
		}
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

// TestHostPortsFromEnv: the helper reads the host-port range and the
// redirect listener under sandboxd's names, and refuses a range sandboxd
// would refuse.
func TestHostPortsFromEnv(t *testing.T) {
	env := func(kv map[string]string) func(string) string { return func(k string) string { return kv[k] } }
	b, err := hostPortsFromEnv(env(map[string]string{"SB_L4_PORT_RANGE_START": "30000", "SB_L4_PORT_RANGE_END": "30100", "SB_HOSTPORT_REDIRECT_PORT": "29999"}))
	if err != nil || b != (rootpolicy.HostPortBounds{RangeStart: 30000, RangeEnd: 30100, RedirectPort: 29999}) {
		t.Fatalf("= %+v %v", b, err)
	}
	for _, bad := range []map[string]string{
		{"SB_L4_PORT_RANGE_START": "80"},
		{"SB_L4_PORT_RANGE_START": "24000"},
		{"SB_L4_PORT_RANGE_END": "x"},
		{"SB_L4_PORT_RANGE_START": "x"},
		{"SB_HOSTPORT_REDIRECT_PORT": "x"},
	} {
		if _, err := hostPortsFromEnv(env(bad)); err == nil {
			t.Errorf("%v passed", bad)
		}
	}
}

// TestHostsFromEnv: with SB_ENABLE_ISOLATE the helper serves V8 group
// hosts, jailed from its own settings under sandboxd's names, with its own
// binary as the shim; without it, none.
func TestHostsFromEnv(t *testing.T) {
	gid := strconv.Itoa(os.Getgid())
	stubHost(t, 1024, nil)
	old := selfExecutable
	selfExecutable = func() (string, error) { return "/usr/local/bin/aerolvm-rootd", nil }
	t.Cleanup(func() { selfExecutable = old })
	cfg, err := ConfigFromEnv(env(map[string]string{"SB_ROOTD_SOCKET_GROUP": gid}))
	if err != nil || cfg.Hosts.any() || cfg.Hosts != (HostsConfig{}) {
		t.Fatalf("no host kind: %+v, %v", cfg.Hosts, err)
	}
	cfg, err = ConfigFromEnv(env(map[string]string{"SB_ROOTD_SOCKET_GROUP": gid, "SB_ENABLE_ISOLATE": "true",
		"SB_CONTAINERD_CGROUP_PARENT": "/kubepods/pod1/sandboxes", "SB_ISOLATE_JAIL_UID": "2000", "SB_ISOLATE_JAIL_GID": "2001",
		"SB_ISOLATE_JITLESS": "true", "SB_ISOLATE_SECCOMP_MODE": "AUDIT", "SB_ISOLATE_JAIL_PIDS_MAX": "300"}))
	if err != nil {
		t.Fatal(err)
	}
	want := HostsConfig{
		CgroupParent: "/kubepods/pod1/sandboxes",
		LogPath:      "/var/lib/aerolvm-rootd/hosts.log",
		Workerd: &WorkerdHostsConfig{
			Jail: isolate.RootJail{ChrootBase: "/srv/isolate-jail", WorkerdPath: "/usr/local/bin/workerd", UID: 2000, GID: 2001,
				AgentUID: DefaultAgentUID, Jitless: true, SeccompMode: isolate.SeccompAudit, ShimPath: "/usr/local/bin/aerolvm-rootd"},
			PidsMax:  300,
			MaxJails: defaultMaxV8Jails,
		},
	}
	if cfg.Hosts.CgroupParent != want.CgroupParent || cfg.Hosts.LogPath != want.LogPath || *cfg.Hosts.Workerd != *want.Workerd {
		t.Fatalf("hosts %+v %+v, want %+v %+v", cfg.Hosts, cfg.Hosts.Workerd, want, want.Workerd)
	}
	// The host-process parent may be its own.
	cfg, err = ConfigFromEnv(env(map[string]string{"SB_ROOTD_SOCKET_GROUP": gid, "SB_ENABLE_ISOLATE": "true",
		"SB_CONTAINERD_CGROUP_PARENT": "/a", "SB_HOST_PROCESS_CGROUP_PARENT": "/b"}))
	if err != nil || cfg.Hosts.CgroupParent != "/b" {
		t.Fatalf("parent %q, %v", cfg.Hosts.CgroupParent, err)
	}
	// The V8 jail limit: the default, a value of the operator's, and
	// values that are no limit.
	for _, tc := range []struct {
		v    string
		want int
		err  string
	}{{"", defaultMaxV8Jails, ""}, {"8", 8, ""}, {"32768", 32768, ""}, {"x", 0, "SB_ROOTD_ISOLATE_MAX_JAILS"},
		{"0", 0, "want 1 to 32768"}, {"-1", 0, "want 1 to 32768"}, {"32769", 0, "want 1 to 32768"}} {
		cfg, err := ConfigFromEnv(env(map[string]string{"SB_ROOTD_SOCKET_GROUP": gid, "SB_ENABLE_ISOLATE": "true", "SB_ROOTD_ISOLATE_MAX_JAILS": tc.v}))
		if tc.err != "" {
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Errorf("SB_ROOTD_ISOLATE_MAX_JAILS=%q: %v, want an error naming %q", tc.v, err, tc.err)
			}
			continue
		}
		if err != nil || cfg.Hosts.Workerd.MaxJails != tc.want {
			t.Errorf("SB_ROOTD_ISOLATE_MAX_JAILS=%q: %v, want %d jails", tc.v, err, tc.want)
		}
	}
	// Root links, mounts and removes in the jail base, and reads and
	// copies workerd: neither may be in a folder the agent writes.
	for _, tc := range []struct{ k, v string }{
		{"SB_ISOLATE_JAIL_CHROOT_BASE", "/var/lib/sandboxd/isolate-jail"},
		{"SB_ISOLATE_WORKERD_PATH", "/var/lib/sandboxd/bin/workerd"},
		{"SB_ISOLATE_WORKERD_PATH", "/run/sandboxd/workerd"},
	} {
		_, err := ConfigFromEnv(env(map[string]string{"SB_ROOTD_SOCKET_GROUP": gid, "SB_ENABLE_ISOLATE": "true", tc.k: tc.v}))
		if err == nil || !strings.Contains(err.Error(), tc.k) || !strings.Contains(err.Error(), "which the agent writes") {
			t.Errorf("%s=%s: %v, want a refusal naming it", tc.k, tc.v, err)
		}
	}
	selfExecutable = func() (string, error) { return "", errors.New("no /proc/self/exe") }
	if _, err := ConfigFromEnv(env(map[string]string{"SB_ROOTD_SOCKET_GROUP": gid, "SB_ENABLE_ISOLATE": "true"})); err == nil ||
		!strings.Contains(err.Error(), "shim") {
		t.Fatalf("no binary of its own: %v", err)
	}
}

// TestWasmHostsFromEnv: the WASM hosts' settings come from the helper's own
// environment, under sandboxd's names. The worker may not share the V8
// jail's user, and the hosts' sockets may not sit in a folder the agent
// writes (root binds them there).
func TestWasmHostsFromEnv(t *testing.T) {
	old := selfExecutable
	selfExecutable = func() (string, error) { return "/usr/local/bin/aerolvm-rootd", nil }
	t.Cleanup(func() { selfExecutable = old })
	path := func(m map[string]string) func(k, def string) string {
		return func(k, def string) string {
			if v := strings.TrimSpace(m[k]); v != "" {
				return filepath.Clean(v)
			}
			return filepath.Clean(def)
		}
	}
	agentDirs := []string{"/var/lib/sandboxd", "/run/sandboxd"}
	ports := []rootpolicy.NodePort{{Proto: "tcp", Port: 8080}, {Proto: "udp", Port: 53}, {Proto: "tcp", Port: 9090, Dst: "10.0.0.1"}, {Proto: "tcp", Port: 8080}}
	read := func(m map[string]string, enterprise bool) (*WasmHostsConfig, error) {
		return wasmHostsFromEnv(env(m), path(m), 65531, 990, enterprise, ports, agentDirs)
	}

	w, err := read(map[string]string{"PATH": "/usr/bin", "LANG": "C.UTF-8", "SB_EGRESS_OPERATOR_FILE": " /etc/aerolvm/operator.yaml ",
		"LD_PRELOAD": "/tmp/x.so"}, false)
	if err != nil {
		t.Fatal(err)
	}
	want := &WasmHostsConfig{Binary: "/usr/local/bin/aerolvm-rootd", UID: 61000, GID: 61000, SocketDir: DefaultWasmSocketDir, SocketGID: 990,
		CacheRoot: "/var/lib/sandboxd/wasm/modules/cache/wazero-compile", AgentUID: 65531, ReadyWait: 10 * time.Second, Fence: true,
		OperatorFile: "/etc/aerolvm/operator.yaml",
		Env:          []string{"PATH=/usr/bin", "LANG=C.UTF-8", "SB_EGRESS_OPERATOR_FILE=/etc/aerolvm/operator.yaml"},
		NodePorts:    []uint16{8080}}
	if !reflect.DeepEqual(w, want) {
		t.Fatalf("defaults:\n got %+v\nwant %+v", w, want)
	}

	// The fence: network rules on by default; enterprise mode keeps it on.
	for _, tc := range []struct {
		rules      string
		enterprise bool
		fence      bool
	}{{"false", false, false}, {"false", true, true}, {"true", false, true}} {
		w, err := read(map[string]string{"SB_ENABLE_NETWORK_RULES": tc.rules}, tc.enterprise)
		if err != nil || w.Fence != tc.fence {
			t.Errorf("rules %s enterprise %v: fence %v, %v; want %v", tc.rules, tc.enterprise, w != nil && w.Fence, err, tc.fence)
		}
	}

	// The compile cache root, worked out as sandboxd does.
	for _, tc := range []struct {
		m    map[string]string
		want string
	}{
		{map[string]string{"SB_WASM_COMPILE_CACHE_DIR": "/c/"}, "/c"},
		{map[string]string{"SB_WASM_CACHE_DIR": "/d"}, "/d/wazero-compile"},
		{map[string]string{"SB_WASM_MODULES_DIR": "/m"}, "/m/cache/wazero-compile"},
		{map[string]string{"SB_WASM_CACHE_DIR": "/d", "SB_WASM_COMPILE_CACHE_DIR": "/c"}, "/c"},
	} {
		if w, err := read(tc.m, false); err != nil || w.CacheRoot != tc.want {
			t.Errorf("%v: cache root %q, %v; want %q", tc.m, w.CacheRoot, err, tc.want)
		}
	}
	// Set and empty: no compile cache at all.
	t.Setenv("SB_WASM_COMPILE_CACHE_DIR", "")
	if w, err := read(map[string]string{}, false); err != nil || w.CacheRoot != "" {
		t.Errorf("compile cache set empty: %q, %v; want none", w.CacheRoot, err)
	}

	for _, tc := range []struct {
		name string
		m    map[string]string
		want string
	}{
		{"the worker is the V8 jail's user", map[string]string{"SB_WASM_WORKER_UID": "1000"}, "V8 jail's too"},
		{"the V8 jail is the worker's user", map[string]string{"SB_ISOLATE_JAIL_UID": "61000"}, "V8 jail's too"},
		{"sockets in the agent's folder", map[string]string{"SB_ROOTD_WASM_SOCKET_DIR": "/run/sandboxd/wasm"}, "which the agent writes"},
		{"sockets as the agent's folder", map[string]string{"SB_ROOTD_WASM_SOCKET_DIR": "/var/lib/sandboxd"}, "which the agent writes"},
		{"a worker uid that is no number", map[string]string{"SB_WASM_WORKER_UID": "aerolvm-wasm"}, "SB_WASM_WORKER_UID"},
		{"a worker gid that is no number", map[string]string{"SB_WASM_WORKER_GID": "x"}, "SB_WASM_WORKER_GID"},
		{"a jail uid that is no number", map[string]string{"SB_ISOLATE_JAIL_UID": "x"}, "SB_ISOLATE_JAIL_UID"},
		{"network rules that are no bool", map[string]string{"SB_ENABLE_NETWORK_RULES": "maybe"}, "SB_ENABLE_NETWORK_RULES"},
	} {
		if _, err := read(tc.m, false); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want an error naming %q", tc.name, err, tc.want)
		}
	}
	// A socket folder beside the agent's, sharing only a name's start, is fine.
	if _, err := read(map[string]string{"SB_ROOTD_WASM_SOCKET_DIR": "/run/sandboxd-helper"}, false); err != nil {
		t.Errorf("a folder beside the agent's: %v", err)
	}

	selfExecutable = func() (string, error) { return "", errors.New("no /proc/self/exe") }
	if _, err := read(map[string]string{}, false); err == nil || !strings.Contains(err.Error(), "WASM hosts'") {
		t.Fatalf("no binary of its own: %v", err)
	}
}

// TestFirecrackerHostsFromEnv: the Firecracker VMs' settings come from the
// helper's own environment, under sandboxd's names. The helper always
// runs the jailer, and its chroot base is never a folder the agent writes.
func TestFirecrackerHostsFromEnv(t *testing.T) {
	old := selfExecutable
	selfExecutable = func() (string, error) { return "/usr/local/bin/aerolvm-rootd", nil }
	t.Cleanup(func() { selfExecutable = old })
	path := func(m map[string]string) func(k, def string) string {
		return func(k, def string) string {
			if v := strings.TrimSpace(m[k]); v != "" {
				return filepath.Clean(v)
			}
			return filepath.Clean(def)
		}
	}
	agentDirs := []string{"/var/lib/sandboxd", "/run/sandboxd"}
	read := func(m map[string]string) (*FirecrackerHostsConfig, error) {
		if _, set := m["SB_FIRECRACKER_KERNEL"]; !set {
			m = maps.Clone(m)
			if m == nil {
				m = map[string]string{}
			}
			m["SB_FIRECRACKER_KERNEL"] = "/var/lib/aerolvm-rootd/vmlinux"
		}
		return firecrackerHostsFromEnv(env(m), path(m), 65531, agentDirs)
	}
	c, err := read(map[string]string{"SB_FIRECRACKER_KERNEL": "/var/lib/aerolvm-rootd/vmlinux", "SB_JAILER_UID": "1500",
		"SB_JAILER_GID": "1501", "SB_FIRECRACKER_IP_BINARY": "/usr/sbin/ip"})
	if err != nil {
		t.Fatal(err)
	}
	want := FirecrackerHostsConfig{JailerBinary: "/usr/local/bin/jailer", FirecrackerBinary: "/usr/local/bin/firecracker",
		ChrootBase: "/srv/jailer", UID: 1500, GID: 1501, Kernel: "/var/lib/aerolvm-rootd/vmlinux", Mkfs4Bin: "/usr/sbin/mkfs.ext4",
		Shim: "/usr/local/bin/aerolvm-rootd", AgentUID: 65531, SocketWait: 5 * time.Second, IPBinary: "/usr/sbin/ip",
		TapBase: "172.16.0.0/20", TapPoolSize: 256}
	if *c != want {
		t.Fatalf("\n got %+v\nwant %+v", *c, want)
	}
	if err := c.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	for _, tc := range []struct {
		name string
		m    map[string]string
		want string
	}{
		{"no jailer", map[string]string{"SB_FIRECRACKER_USE_JAILER": "false"}, "jailer"},
		{"a chroot base in the agent's folder", map[string]string{"SB_JAILER_CHROOT_BASE": "/var/lib/sandboxd/jail"}, "which the agent writes"},
		{"a jailer uid that is no number", map[string]string{"SB_JAILER_UID": "x"}, "SB_JAILER_UID"},
		{"a jailer gid that is no number", map[string]string{"SB_JAILER_GID": "x"}, "SB_JAILER_GID"},
		{"a pool size that is no number", map[string]string{"SB_FIRECRACKER_TAP_POOL_SIZE": "x"}, "SB_FIRECRACKER_TAP_POOL_SIZE"},
		{"a jailer flag that is no bool", map[string]string{"SB_FIRECRACKER_USE_JAILER": "maybe"}, "SB_FIRECRACKER_USE_JAILER"},
		{"a kernel in the agent's folder (sandboxd's default)", map[string]string{"SB_FIRECRACKER_KERNEL": ""}, "SB_FIRECRACKER_KERNEL"},
		// Root runs each of these (the jailer copies firecracker).
		{"a jailer in the agent's folder", map[string]string{"SB_JAILER_BINARY": "/var/lib/sandboxd/bin/jailer"}, "SB_JAILER_BINARY"},
		{"a firecracker in the agent's folder", map[string]string{"SB_FIRECRACKER_BINARY": "/run/sandboxd/firecracker"}, "SB_FIRECRACKER_BINARY"},
		{"a mkfs.ext4 in the agent's folder", map[string]string{"SB_FIRECRACKER_MKFS_BIN": "/var/lib/sandboxd/mkfs.ext4"}, "SB_FIRECRACKER_MKFS_BIN"},
		{"an ip in the agent's folder", map[string]string{"SB_FIRECRACKER_IP_BINARY": "/var/lib/sandboxd/ip"}, "SB_FIRECRACKER_IP_BINARY"},
	} {
		if _, err := read(tc.m); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want an error naming %q", tc.name, err, tc.want)
		}
	}
	selfExecutable = func() (string, error) { return "", errors.New("no /proc/self/exe") }
	if _, err := read(nil); err == nil || !strings.Contains(err.Error(), "shim") {
		t.Fatalf("no binary of its own: %v", err)
	}
}

func TestFirecrackerHostsValidate(t *testing.T) {
	good := FirecrackerHostsConfig{JailerBinary: "/j", FirecrackerBinary: "/f", ChrootBase: "/srv/jailer", UID: 1500, GID: 1500,
		Kernel: "/k", Mkfs4Bin: "/m", Shim: "/s", AgentUID: 65531, SocketWait: time.Second, TapBase: "172.16.0.0/20", TapPoolSize: 256}
	for _, tc := range []struct {
		name string
		edit func(*FirecrackerHostsConfig)
	}{
		{"a relative jailer", func(c *FirecrackerHostsConfig) { c.JailerBinary = "jailer" }},
		{"a relative ip", func(c *FirecrackerHostsConfig) { c.IPBinary = "ip" }},
		{"a chroot base of /", func(c *FirecrackerHostsConfig) { c.ChrootBase = "/" }},
		{"a root jailer", func(c *FirecrackerHostsConfig) { c.UID = 0 }},
		{"the agent as the jailer", func(c *FirecrackerHostsConfig) { c.UID = 65531 }},
		{"no socket wait", func(c *FirecrackerHostsConfig) { c.SocketWait = 0 }},
		{"a TAP base too small", func(c *FirecrackerHostsConfig) { c.TapBase = "172.16.0.0/28" }},
		// Ids that would wrap in a uint32: onto root, onto the agent.
		{"a jailer uid that wraps onto root", func(c *FirecrackerHostsConfig) { c.UID = 1 << 32 }},
		{"a jailer uid that wraps onto the agent", func(c *FirecrackerHostsConfig) { c.UID = 1<<32 + 65531 }},
		{"a jailer gid that wraps onto root", func(c *FirecrackerHostsConfig) { c.GID = 1 << 32 }},
		{"an agent uid past an int on a 32-bit build", func(c *FirecrackerHostsConfig) { c.AgentUID = 1 << 31 }},
	} {
		c := good
		tc.edit(&c)
		if err := c.validate(); err == nil {
			t.Errorf("%s: no error", tc.name)
		}
	}
	// The jailer shares no user with the V8 jail or the WASM worker.
	h := HostsConfig{LogPath: "/var/lib/aerolvm-rootd/hosts.log", Firecracker: &good,
		Workerd: &WorkerdHostsConfig{Jail: testHostsConfig(t).Workerd.Jail, PidsMax: 512, MaxJails: defaultMaxV8Jails}}
	h.Workerd.Jail.UID = good.UID
	if err := h.validate(); err == nil || !strings.Contains(err.Error(), "V8 jail") {
		t.Errorf("the jailer as the V8 jail's user: %v", err)
	}
	h.Workerd = nil
	h.Wasm = &WasmHostsConfig{Binary: "/b", UID: good.UID, GID: 61000, SocketDir: "/run/w", AgentUID: 65531, ReadyWait: time.Second}
	if err := h.validate(); err == nil || !strings.Contains(err.Error(), "WASM worker") {
		t.Errorf("the jailer as the WASM worker: %v", err)
	}
	h.Wasm = nil
	if err := h.validate(); err != nil {
		t.Errorf("Firecracker alone: %v", err)
	}
}
