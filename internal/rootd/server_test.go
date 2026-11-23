package rootd

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
	"github.com/aerol-ai/microvm/internal/version"
)

// shortDir is a folder for a socket. A socket path must fit in sun_path
// (104 bytes on macOS), and t.TempDir's often does not.
func shortDir(t testing.TB) string {
	t.Helper()
	d, err := os.MkdirTemp("", "rd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	// The helper follows no link to its socket (macOS: /var is one).
	if d, err = filepath.EvalSymlinks(d); err != nil {
		t.Fatal(err)
	}
	return d
}

func testPolicy() rootpolicy.Policy {
	return rootpolicy.Policy{
		Namespace:       "aerolvm",
		Snapshotter:     "overlayfs",
		SnapshotterRoot: defaultSnapshotterRoot,
		NetnsDir:        DefaultNetnsDir,
		MovesDir:        defaultRunDir + "/moves",
		FIFODir:         defaultFIFODir,
		Limits:          rootpolicy.Limits{MemoryBytes: 1 << 30, Pids: 4096, CPUs: 2},
	}
}

func testConfig(t testing.TB) Config {
	dir := shortDir(t)
	return withFiles(Config{
		// The socket's folder holds the socket alone (TestSocketModeAndGroup).
		Socket:    filepath.Join(dir, "sock", "root.sock"),
		SocketGID: os.Getgid(),
		AgentUID:  uint32(os.Getuid()),
		Policy:    testPolicy(),
		// The helper's own node port list, as ConfigFromEnv's defaults.
		Firewall:  FirewallConfig{NodePorts: testNodePorts()},
		HostPorts: rootpolicy.HostPortBounds{RangeStart: 22000, RangeEnd: 23000, RedirectPort: 21215},
	}, dir)
}

func testNodePorts() []rootpolicy.NodePort {
	p, err := nodePortsFromEnv(func(string) string { return "" }, false, false)
	if err != nil {
		panic(err)
	}
	return p
}

// withFiles puts the helper's folders for the files it makes under base,
// with the policy entries that let the gate accept them, as
// ConfigFromEnv lays them out under the state and run folders.
func withFiles(c Config, base string) Config {
	c.Files = FileDirs{
		Hosts:      filepath.Join(base, "state", "hosts"),
		Ready:      filepath.Join(base, "run", "ready"),
		Runsc:      filepath.Join(base, "state", "runsc"),
		AgentReady: filepath.Join(base, "agent", "ready"),
	}
	c.Policy.FIFODir = filepath.Join(base, "run", "fifo")
	// The operator's toolbox binary (a VM's layout): specs bind it as it
	// is. TestToolboxCopy covers the copy the chart's layout needs.
	c.Files.Toolbox = filepath.Join(base, "opt", "toolboxd")
	c.Files.ImageRoot = filepath.Join(base, "state", "imageroot")
	c.Policy.BindFiles = []string{c.Files.Toolbox}
	c.Policy.HelperFileRoots = []string{c.Files.Hosts, c.Files.Ready}
	c.Policy.RunscConfigPaths = []string{c.Files.runscPath(runscDefaultFile), c.Files.runscPath(runscRestoreFile)}
	return c
}

// stubContainerd stands where the gate goes: it records each call handed
// to it and answers it empty, after hold returns.
type stubContainerd struct {
	mu   sync.Mutex
	seen []string
	hold func(ctx context.Context, method string) error
}

func (s *stubContainerd) handle(_ any, ss grpc.ServerStream) error {
	name, _ := grpc.MethodFromServerStream(ss)
	var in emptypb.Empty
	if err := ss.RecvMsg(&in); err != nil {
		return err
	}
	s.mu.Lock()
	s.seen = append(s.seen, name)
	hold := s.hold
	s.mu.Unlock()
	if hold != nil {
		if err := hold(ss.Context(), name); err != nil {
			return err
		}
	}
	return ss.SendMsg(&emptypb.Empty{})
}

func (s *stubContainerd) methods() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.seen)
}

type rig struct {
	t          testing.TB
	cfg        Config
	srv        *Server
	containerd *stubContainerd
	conn       *grpc.ClientConn
	mu         sync.Mutex
	refusals   []Refusal
}

// newRig serves a helper on a real socket. The peer check is
// egress.UnixPeerCheck for this process's uid: the real one on Linux, a
// pass-through elsewhere (peer_linux_test.go has the refusals).
func newRig(t testing.TB, mutate func(*Config, *Options)) *rig {
	t.Helper()
	r := &rig{t: t, cfg: testConfig(t), containerd: &stubContainerd{}}
	opts := Options{
		Containerd: r.containerd.handle,
		Peer:       egress.UnixPeerCheck([]uint32{uint32(os.Getuid())}, ""),
		OnRefusal: func(_ context.Context, ref Refusal) {
			r.mu.Lock()
			r.refusals = append(r.refusals, ref)
			r.mu.Unlock()
		},
	}
	if mutate != nil {
		mutate(&r.cfg, &opts)
	}
	srv, err := New(r.cfg, opts, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.srv = srv
	served := make(chan error, 1)
	go func() { served <- srv.Serve() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		srv.Shutdown(ctx)
		if err := <-served; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	r.conn = dialSocket(t, r.cfg.Socket)
	return r
}

func dialSocket(t testing.TB, sock string) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient("passthrough:///rootd", grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func (r *rig) refused() []Refusal {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.refusals)
}

func callCtx(t testing.TB) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestVersion(t *testing.T) {
	r := newRig(t, nil)
	var trailer metadata.MD
	resp, err := rootdpb.NewRootHelperClient(r.conn).Version(callCtx(t), &rootdpb.VersionRequest{AgentVersion: "v9", AgentApi: rootdpb.APIVersion}, grpc.Trailer(&trailer))
	if err != nil {
		t.Fatal(err)
	}
	if len(trailer.Get(rootdpb.AnsweredTrailer)) == 0 {
		t.Fatal("Version carries no answered trailer")
	}
	if resp.GetHelperVersion() != version.Version || resp.GetApi() != rootdpb.APIVersion {
		t.Fatalf("Version = %v", resp)
	}
	// EnsureHost is a placeholder, so it is never served; a helper with
	// no network configuration (this rig) serves no network call either,
	// and one whose settings name no host kind no host call.
	want := slices.DeleteFunc(rootdpb.Features(), func(f string) bool {
		return slices.Contains(networkFeatures, f) || slices.Contains(firewallFeatures, f) || slices.Contains(egressFeatures, f) ||
			slices.Contains(hostPortFeatures, f) || slices.Contains(mountFeatures, f) || f == rootdpb.FeatureReclaimVolume ||
			slices.Contains(hostFeatures, f) || slices.Contains(tapFeatures, f) || slices.Contains(guestFeatures, f)
	})
	if !slices.Equal(resp.GetFeatures(), want) {
		t.Fatalf("features %v, want %v", resp.GetFeatures(), want)
	}
	if m := r.containerd.methods(); len(m) != 0 {
		t.Fatalf("the helper's own call reached containerd: %v", m)
	}
	t.Run("with a network", func(t *testing.T) {
		// With mounts, reclaim and a host kind too (M1 PRs 8 and 9): every call.
		r := newRig(t, func(c *Config, o *Options) {
			o.Network, o.Mounts = newFakeNet(), &fakeMounts{}
			c.Reclaim = &ReclaimConfig{Export: rootpolicy.NFSExport{Server: "h", Export: "/e"}, ScratchDir: filepath.Join(t.TempDir(), "r")}
			c.Hosts = testHostsConfig(t)
			c.Hosts.Firecracker = testFirecrackerConfig(t)
			c.Hosts.Firecracker.UID += 2000
			o.TapDevices = &fakeTaps{}
		})
		resp, err := rootdpb.NewRootHelperClient(r.conn).Version(callCtx(t), &rootdpb.VersionRequest{})
		served := []string{rootdpb.FeatureEnsureHostFiles, rootdpb.FeatureEnsureTaskFIFOs, rootdpb.FeatureEnsureRunscConfig,
			rootdpb.FeatureEnsureReadySocket, rootdpb.FeatureRemoveContainerFiles}
		served = append(append(append(served, networkFeatures...), firewallFeatures...), rootdpb.FeaturePrepareSandbox, rootdpb.FeatureReleaseSandbox)
		served = append(append(append(served, egressFeatures...), hostPortFeatures...), mountFeatures...)
		served = append(append(append(append(served, rootdpb.FeatureReclaimVolume), hostFeatures...), tapFeatures...), guestFeatures...)
		// No cgroup parent here: no cgroup part. Every helper serves the
		// container's files part (M1 PR 7).
		netParts := []string{rootdpb.PartNetns, rootdpb.PartFirewall, rootdpb.PartFiles}
		if err != nil || !slices.Equal(resp.GetFeatures(), served) || !slices.Equal(resp.GetParts(), netParts) {
			t.Fatalf("features %v parts %v (%v), want %v and %v", resp.GetFeatures(), resp.GetParts(), err, served, netParts)
		}
		got := slices.Sorted(slices.Values(resp.GetFeatures()))
		if all := slices.Sorted(slices.Values(rootdpb.Features())); !slices.Equal(got, all) {
			t.Fatalf("a helper with a network serves %v, every call is %v", got, all)
		}
	})
	// M1 PR 6: a helper with a cgroup parent lists the cgroup part; one
	// with a parent and no network serves PrepareSandbox for it and for the
	// container's files part (M1 PR 7), and ReleaseSandbox for the latter.
	t.Run("with a cgroup parent", func(t *testing.T) {
		parent := func(c *Config, _ *Options) { c.Policy.CgroupParent = "/sandboxes" }
		// With containerd's snapshots too (M1 PR 7): every part.
		r := newRig(t, func(c *Config, o *Options) { parent(c, o); o.Network, o.Snapshots = newFakeNet(), newFakeSnapshots() })
		resp, err := rootdpb.NewRootHelperClient(r.conn).Version(callCtx(t), &rootdpb.VersionRequest{})
		if err != nil || !slices.Equal(resp.GetParts(), rootdpb.Parts()) {
			t.Fatalf("parts %v (%v), want every part", resp.GetParts(), err)
		}
		alone := newRig(t, parent)
		resp, err = rootdpb.NewRootHelperClient(alone.conn).Version(callCtx(t), &rootdpb.VersionRequest{})
		if err != nil || !slices.Equal(resp.GetParts(), []string{rootdpb.PartCgroup, rootdpb.PartFiles}) ||
			!slices.Contains(resp.GetFeatures(), rootdpb.FeaturePrepareSandbox) || !slices.Contains(resp.GetFeatures(), rootdpb.FeatureReleaseSandbox) {
			t.Fatalf("no network: features %v parts %v (%v)", resp.GetFeatures(), resp.GetParts(), err)
		}
	})
}

// TestEnsureHostNeedsANetwork: a helper with no network configuration
// (only tests build one) serves no host firewall: Unimplemented, not a
// refusal.
func TestEnsureHostNeedsANetwork(t *testing.T) {
	r := newRig(t, nil)
	_, err := rootdpb.NewRootHelperClient(r.conn).EnsureHost(callCtx(t), &rootdpb.EnsureHostRequest{})
	if status.Code(err) != codes.Unimplemented || !strings.Contains(err.Error(), "CNI configuration") {
		t.Fatalf("EnsureHost = %v, want Unimplemented", err)
	}
	if len(r.refused()) != 0 {
		t.Fatal("a call this helper lacks is not a refusal")
	}
}

// TestRoute: the helper's own calls stay with the helper, and one it does
// not have is Unimplemented (agent N on helper N-1), not a gate refusal;
// everything else goes to containerd's handler, the gate.
func TestRoute(t *testing.T) {
	for _, tc := range []struct {
		method     string
		code       codes.Code
		containerd bool
	}{
		{"/aerolvm.rootd.v1.RootHelper/Realize", codes.Unimplemented, false},
		{"/aerolvm.rootd.v2.RootHelper/Version", codes.Unimplemented, false},
		{"/aerolvm.rootd.v1.Other/Call", codes.Unimplemented, false},
		{"/containerd.services.version.v1.Version/Version", codes.OK, true},
		{"/containerd.services.tasks.v1.Tasks/Exec", codes.OK, true}, // the gate's to refuse
		{"/grpc.health.v1.Health/Check", codes.OK, true},
	} {
		t.Run(tc.method, func(t *testing.T) {
			r := newRig(t, nil)
			var trailer metadata.MD
			err := r.conn.Invoke(callCtx(t), tc.method, &emptypb.Empty{}, &emptypb.Empty{}, grpc.Trailer(&trailer))
			if status.Code(err) != tc.code {
				t.Fatalf("err %v, want %v", err, tc.code)
			}
			// Every answer, an error included, says the helper gave it.
			if len(trailer.Get(rootdpb.AnsweredTrailer)) == 0 {
				t.Fatalf("no %s trailer on %v", rootdpb.AnsweredTrailer, err)
			}
			if got := slices.Contains(r.containerd.methods(), tc.method); got != tc.containerd {
				t.Fatalf("containerd saw it: %v, want %v", got, tc.containerd)
			}
			if tc.code == codes.Unimplemented && !strings.Contains(err.Error(), "API 1") {
				t.Fatalf("%v does not say which helper answered", err)
			}
			if len(r.refused()) != 0 {
				t.Fatalf("refusals %v", r.refused())
			}
		})
	}
}

// TestPeerRefusedNeverReachesAHandler: a connection the peer check refuses
// gets no call through, to the helper or to containerd, and the refusal
// reaches the one callback.
func TestPeerRefusedNeverReachesAHandler(t *testing.T) {
	r := newRig(t, func(_ *Config, o *Options) {
		o.Peer = func(net.Conn) error { return errors.New("egress: peer uid 4242 not allowed") }
	})
	_, err := rootdpb.NewRootHelperClient(r.conn).Version(callCtx(t), &rootdpb.VersionRequest{})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("Version = %v, want Unavailable", err)
	}
	if err := r.conn.Invoke(callCtx(t), "/containerd.services.version.v1.Version/Version", &emptypb.Empty{}, &emptypb.Empty{}); status.Code(err) != codes.Unavailable {
		t.Fatalf("containerd call = %v, want Unavailable", err)
	}
	if m := r.containerd.methods(); len(m) != 0 {
		t.Fatalf("containerd saw %v", m)
	}
	refs := r.refused()
	if len(refs) == 0 {
		t.Fatal("no refusal reached the callback")
	}
	for _, ref := range refs {
		if ref.Method != MethodConnect || ref.Reason != ReasonPeer || !strings.Contains(ref.Detail, "4242") {
			t.Fatalf("refusal %+v", ref)
		}
	}
}

// TestCallsRunInParallel: n calls park in containerd's handler until all n
// have arrived, and the helper's own Version answers meanwhile. One lock
// around calls anywhere in the server would hang this (eng review D11).
func TestCallsRunInParallel(t *testing.T) {
	const n = 16
	var arrived sync.WaitGroup
	arrived.Add(n)
	all := make(chan struct{})
	go func() { arrived.Wait(); close(all) }()
	r := newRig(t, nil)
	r.containerd.hold = func(ctx context.Context, _ string) error {
		arrived.Done()
		select {
		case <-all:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	ctx := callCtx(t)
	errs := make(chan error, n)
	for range n {
		go func() {
			errs <- r.conn.Invoke(ctx, "/containerd.services.tasks.v1.Tasks/Get", &emptypb.Empty{}, &emptypb.Empty{})
		}()
	}
	if _, err := rootdpb.NewRootHelperClient(r.conn).Version(ctx, &rootdpb.VersionRequest{}); err != nil {
		t.Fatalf("Version while containerd calls wait: %v", err)
	}
	for range n {
		if err := <-errs; err != nil {
			t.Fatalf("parked call: %v", err)
		}
	}
}

func mkdir(dir string) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		panic(err)
	}
}

func TestNewRefuses(t *testing.T) {
	ok := func(*Config, *Options) {}
	for _, tc := range []struct {
		name   string
		mutate func(*Config, *Options)
		want   string
	}{
		{"no containerd handler", func(_ *Config, o *Options) { o.Containerd = nil }, "containerd handler"},
		{"relative socket", func(c *Config, _ *Options) { c.Socket = "root.sock" }, "clean absolute path"},
		{"unclean socket", func(c *Config, _ *Options) { c.Socket = filepath.Dir(c.Socket) + "/x/../root.sock" }, "clean absolute path"},
		{"no group", func(c *Config, _ *Options) { c.SocketGID = -1 }, "want a gid"},
		{"policy without limits", func(c *Config, _ *Options) { c.Policy.Limits = rootpolicy.Limits{} }, "limits"},
		{"a file where the socket goes", func(c *Config, _ *Options) {
			mkdir(filepath.Dir(c.Socket))
			if err := os.WriteFile(c.Socket, nil, 0o600); err != nil {
				panic(err)
			}
		}, "not a socket"},
		{"a socket folder that is a file", func(c *Config, _ *Options) {
			mkdir(filepath.Dir(c.Socket))
			f := filepath.Join(filepath.Dir(c.Socket), "f")
			if err := os.WriteFile(f, nil, 0o600); err != nil {
				panic(err)
			}
			c.Socket = filepath.Join(f, "root.sock")
		}, "socket folder"},
		{"no folders for the files", func(c *Config, _ *Options) { c.Files = FileDirs{} }, "hosts folder"},
		{"a hosts folder that is not a helper file root", func(c *Config, _ *Options) { c.Policy.HelperFileRoots = c.Policy.HelperFileRoots[1:] }, "helper file roots"},
		{"runsc configs the policy does not name", func(c *Config, _ *Options) { c.Policy.RunscConfigPaths = []string{"/x/config.toml"} }, "runsc configs"},
		// Each of the helper's folders has its own rule; none may hold
		// another.
		{"a ready folder holding the runsc folder", func(c *Config, _ *Options) {
			c.Files.Ready = filepath.Dir(c.Files.Runsc)
			c.Policy.HelperFileRoots = []string{c.Files.Ready}
		}, "overlaps the runsc config"},
		{"the socket in the ready folder", func(c *Config, _ *Options) { c.Socket = filepath.Join(c.Files.Ready, "s", "root.sock") }, "overlap"},
		{"the agent's ready folder in the helper's", func(c *Config, _ *Options) { c.Files.AgentReady = filepath.Join(c.Files.Ready, "agent") }, "overlap"},
		{"the moves folder in the runsc folder", func(c *Config, _ *Options) { c.Policy.MovesDir = filepath.Join(c.Files.Runsc, "moves") }, "overlap"},
		{"the FIFO folder in the hosts folder", func(c *Config, _ *Options) { c.Policy.FIFODir = filepath.Join(c.Files.Hosts, "fifo") }, "overlap"},
		// A layout someone else can write stops the helper before any agent
		// reaches it, and leaves no socket.
		{"a hosts folder others can write", func(c *Config, _ *Options) {
			mkdir(c.Files.Hosts)
			if err := os.Chmod(c.Files.Hosts, 0o777); err != nil {
				panic(err)
			}
		}, "written by others"},
		{"a FIFO folder under a file", func(c *Config, _ *Options) {
			mkdir(filepath.Dir(c.Policy.FIFODir))
			if err := os.WriteFile(c.Policy.FIFODir, nil, 0o600); err != nil {
				panic(err)
			}
		}, "fifo"},
		{"sound config", ok, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig(t)
			opts := Options{Containerd: (&stubContainerd{}).handle, Peer: func(net.Conn) error { return nil }}
			tc.mutate(&cfg, &opts)
			srv, err := New(cfg, opts, nil)
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				srv.Shutdown(context.Background())
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("New = %v, want an error naming %q", err, tc.want)
			}
			if _, err := os.Lstat(cfg.Socket); err == nil && tc.name != "a file where the socket goes" {
				t.Fatalf("a refused helper left its socket at %s", cfg.Socket)
			}
		})
	}
}

// TestDefaultPeerCheck: with no Peer given, Linux gets SO_PEERCRED for the
// configured uid (this process's, here). Elsewhere egress.UnixPeerCheck
// lets everyone in, so the helper refuses to start.
func TestDefaultPeerCheck(t *testing.T) {
	if runtime.GOOS != "linux" {
		_, err := New(testConfig(t), Options{Containerd: (&stubContainerd{}).handle}, nil)
		if err == nil || !strings.Contains(err.Error(), "Linux only") {
			t.Fatalf("New off Linux = %v, want a refusal", err)
		}
		return
	}
	r := newRig(t, func(_ *Config, o *Options) { o.Peer = nil })
	if _, err := rootdpb.NewRootHelperClient(r.conn).Version(callCtx(t), &rootdpb.VersionRequest{}); err != nil {
		t.Fatal(err)
	}
}

// TestShutdown: it waits for a call in flight, but not forever, and it
// removes the socket only while the socket is still this server's.
func TestShutdown(t *testing.T) {
	t.Run("cuts a call that never ends", func(t *testing.T) {
		r := newRig(t, nil)
		entered := make(chan struct{})
		r.containerd.hold = func(ctx context.Context, _ string) error {
			close(entered)
			<-ctx.Done()
			return ctx.Err()
		}
		go func() {
			_ = r.conn.Invoke(context.Background(), "/containerd.services.events.v1.Events/Subscribe", &emptypb.Empty{}, &emptypb.Empty{})
		}()
		<-entered
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		start := time.Now()
		r.srv.Shutdown(ctx)
		if d := time.Since(start); d > 5*time.Second {
			t.Fatalf("Shutdown took %v", d)
		}
		if _, err := os.Lstat(r.cfg.Socket); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("socket left behind: %v", err)
		}
		r.srv.Shutdown(context.Background()) // a second one is a no-op
	})
	t.Run("before Serve", func(t *testing.T) {
		cfg := testConfig(t)
		srv, err := New(cfg, Options{Containerd: (&stubContainerd{}).handle, Peer: func(net.Conn) error { return nil }}, nil)
		if err != nil {
			t.Fatal(err)
		}
		srv.Shutdown(context.Background())
		if err := srv.Serve(); err != nil {
			t.Fatalf("Serve after Shutdown = %v, want nil", err)
		}
	})
	t.Run("keeps a socket another helper made", func(t *testing.T) {
		r := newRig(t, nil)
		if err := os.Remove(r.cfg.Socket); err != nil {
			t.Fatal(err)
		}
		other, err := net.Listen("unix", r.cfg.Socket)
		if err != nil {
			t.Fatal(err)
		}
		defer other.Close()
		r.srv.Shutdown(context.Background())
		if _, err := os.Lstat(r.cfg.Socket); err != nil {
			t.Fatalf("Shutdown removed the other helper's socket: %v", err)
		}
	})
}

// TestLogRefusal: the helper's own line names the call in the agent's
// short form and in full, the reason and the detail, and counts refusals
// since start across every source that shares the one callback.
func TestLogRefusal(t *testing.T) {
	var buf bytes.Buffer
	log := LogRefusal(slog.New(slog.NewTextHandler(&buf, nil)))
	log(context.Background(), Refusal{Method: "/containerd.services.tasks.v1.Tasks/Exec", Reason: "method_not_allowed", Detail: "no"})
	for _, want := range []string{"level=ERROR", "call=Tasks.Exec", "method=/containerd.services.tasks.v1.Tasks/Exec",
		"reason=method_not_allowed", "detail=no", "refusals_since_start=1"} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("log %q lacks %q", buf.String(), want)
		}
	}
	buf.Reset()
	log(context.Background(), Refusal{Method: MethodConnect, Reason: ReasonPeer, Detail: "uid 1000"})
	if line := buf.String(); !strings.Contains(line, "call=connect") || !strings.Contains(line, "refusals_since_start=2") {
		t.Fatalf("second line %q", line)
	}
}

// TestPeerCredsClientSide: the credentials are the server's only.
func TestPeerCredsClientSide(t *testing.T) {
	p := peerCreds{}
	if _, _, err := p.ClientHandshake(context.Background(), "", nil); err == nil {
		t.Fatal("ClientHandshake must refuse")
	}
	if p.Info().SecurityProtocol != "peercred" || p.OverrideServerName("x") != nil {
		t.Fatal("Info / OverrideServerName")
	}
	if _, ok := p.Clone().(peerCreds); !ok {
		t.Fatal("Clone")
	}
	if (peerInfo{}).AuthType() != "peercred" {
		t.Fatal("AuthType")
	}
}
