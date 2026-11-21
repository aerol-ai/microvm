package containerd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/internal/rootclient"
	"github.com/aerol-ai/microvm/internal/rootd"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
	"github.com/aerol-ai/microvm/internal/runtime/resolvconf"
)

// startHelper runs the root helper's server as this test's user, its
// folders in a temporary folder, and returns the agent's client to it.
func startHelper(t *testing.T) *rootclient.Client {
	t.Helper()
	dir, err := os.MkdirTemp("", "dh") // short enough for sun_path
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if dir, err = filepath.EvalSymlinks(dir); err != nil { // macOS: /var is a link
		t.Fatal(err)
	}
	files := rootd.FileDirs{
		Hosts: filepath.Join(dir, "state", "hosts"), Ready: filepath.Join(dir, "run", "ready"),
		Runsc: filepath.Join(dir, "state", "runsc"), AgentReady: filepath.Join(dir, "agent", "ready"),
	}
	cfg := rootd.Config{
		Socket: filepath.Join(dir, "sock", "root.sock"), SocketGID: os.Getgid(), AgentUID: uint32(os.Getuid()), Files: files,
		Policy: rootpolicy.Policy{
			Namespace: "aerolvm", Snapshotter: "overlayfs", SnapshotterRoot: "/var/lib/containerd/snap",
			NetnsDir: "/run/netns", MovesDir: filepath.Join(dir, "state", "moves"), FIFODir: filepath.Join(dir, "run", "fifo"),
			HelperFileRoots:  []string{files.Hosts, files.Ready},
			RunscConfigPaths: []string{filepath.Join(files.Runsc, "config.toml"), filepath.Join(files.Runsc, "restore.toml")},
			Limits:           rootpolicy.Limits{MemoryBytes: 1 << 30, Pids: 4096, CPUs: 2},
		},
	}
	srv, err := rootd.New(cfg, rootd.Options{
		Containerd: func(any, grpc.ServerStream) error { return nil },
		Peer:       egress.UnixPeerCheck([]uint32{uint32(os.Getuid())}, ""),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	})
	c := rootclient.New(rootclient.Config{Socket: cfg.Socket, HelperUID: uint32(os.Getuid())})
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func readString(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestHelperHostFilesMatchTheDriver: the host files the root helper
// writes from typed values are the ones this driver writes today
// (prepareSandboxHostFiles), byte for byte, given what the driver reads
// from the host: the resolver settings in resolvconf.HostPath, the
// localhost lines, and the container ID as hostname. T4 sends exactly
// these values in split mode.
func TestHelperHostFilesMatchTheDriver(t *testing.T) {
	own, err := prepareSandboxHostFiles(t.TempDir(), "sb-1")
	if err != nil {
		t.Fatal(err)
	}
	dns, err := resolvconf.Parse(resolvconf.HostPath)
	if err != nil {
		t.Fatal(err)
	}
	helper, err := startHelper(t).EnsureHostFiles(context.Background(), &rootdpb.EnsureHostFilesRequest{
		ContainerId: "sb-1", Hostname: "sb-1",
		Hosts: []*rootdpb.HostEntry{
			{Address: "127.0.0.1", Names: []string{"localhost"}},
			{Address: "::1", Names: []string{"localhost", "ip6-localhost", "ip6-loopback"}},
		},
		Nameservers: dns.Nameservers, Search: dns.Search, DnsOptions: dns.Options,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{
		{own.ResolvConf, helper.GetResolvConfPath()},
		{own.Hosts, helper.GetHostsPath()},
		{own.Hostname, helper.GetHostnamePath()},
	} {
		if a, b := readString(t, pair[0]), readString(t, pair[1]); a != b {
			t.Errorf("%s: the driver writes %q, the helper %q", filepath.Base(pair[0]), a, b)
		}
	}
}

// TestHelperResolvConfShapes: for host resolv.conf files as nodes have
// them, the odd ones included, the helper writes what this driver writes
// today (prepareSandboxHostFiles copies resolvconf.Generate of the host's
// file), byte for byte, from the values T4 sends (resolvconf.Parse of the
// same file). None is refused: a refusal would fail the create in split
// mode and raise the helper's alarm for a broken agent over a host file.
func TestHelperResolvConfShapes(t *testing.T) {
	helper := startHelper(t)
	for name, body := range map[string]string{
		"systemd-resolved stub":      "nameserver 127.0.0.53\noptions edns0 trust-ad\nsearch ec2.internal\n",
		"kubernetes pod":             "search ns.svc.cluster.local svc.cluster.local cluster.local\nnameserver 10.96.0.10\noptions ndots:5\n",
		"IPv6":                       "nameserver fd00::53\nnameserver 2001:db8::1\n",
		"IPv6 in capitals":           "nameserver 2001:DB8::1\n",
		"IPv4-mapped IPv6":           "nameserver ::ffff:10.0.0.2\n",
		"options with values":        "options timeout:2 attempts:3 rotate\nnameserver 10.0.0.2\n",
		"a comment after search":     "search corp.example # set by dhcp\nnameserver 10.0.0.2\n",
		"a search domain not ASCII":  "search ex\u00e4mple.com\nnameserver 10.0.0.2\n",
		"more nameservers than read": strings.Repeat("nameserver 10.0.0.2\n", 17),
		"comments and loopback only": "# generated\n; old\nnameserver 127.0.0.1\n",
	} {
		t.Run(name, func(t *testing.T) {
			host := filepath.Join(t.TempDir(), "resolv.conf")
			if err := os.WriteFile(host, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
			driver, err := resolvconf.Generate(host)
			if err != nil {
				t.Fatal(err)
			}
			dns, err := resolvconf.Parse(host)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := helper.EnsureHostFiles(context.Background(), &rootdpb.EnsureHostFilesRequest{
				ContainerId: "sb-1", Hostname: "sb-1",
				Nameservers: dns.Nameservers, Search: dns.Search, DnsOptions: dns.Options,
			})
			if err != nil {
				t.Fatalf("the helper refused a host file the driver copies: %v", err)
			}
			if got := readString(t, resp.GetResolvConfPath()); got != driver {
				t.Errorf("the driver writes %q, the helper %q", driver, got)
			}
		})
	}
}

// TestHelperRunscConfigsMatchTheDriver: the runsc shim configs the helper
// owns set what this driver's own do: the same flags, and for a restored
// sandbox the same aerolvm-runsc. Only the comment naming who wrote the
// file differs.
func TestHelperRunscConfigsMatchTheDriver(t *testing.T) {
	d := &Driver{cfg: Config{RunDir: t.TempDir()}}
	helper := startHelper(t)
	settings := func(body string) string {
		var keep []string
		for _, line := range strings.Split(body, "\n") {
			if !strings.HasPrefix(strings.TrimSpace(line), "#") {
				keep = append(keep, line)
			}
		}
		return strings.Join(keep, "\n")
	}
	for _, tc := range []struct {
		own    func() (string, error)
		config rootdpb.RunscConfig
	}{
		{d.ensureRunscConfig, rootdpb.RunscConfig_RUNSC_CONFIG_DEFAULT},
		{d.ensureRunscRestoreConfig, rootdpb.RunscConfig_RUNSC_CONFIG_RESTORE},
	} {
		ownPath, err := tc.own()
		if err != nil {
			t.Fatal(err)
		}
		helperPath, err := helper.EnsureRunscConfig(context.Background(), tc.config)
		if err != nil {
			t.Fatal(err)
		}
		if a, b := settings(readString(t, ownPath)), settings(readString(t, helperPath)); a != b {
			t.Errorf("%v: the driver sets %q, the helper %q", tc.config, a, b)
		}
	}
}
