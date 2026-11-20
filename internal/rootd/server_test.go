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
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
	"github.com/aerol-ai/microvm/internal/version"
)

// shortDir is a folder for a socket. A socket path must fit in sun_path
// (104 bytes on macOS), and t.TempDir's often does not.
func shortDir(t *testing.T) string {
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
		NetnsDir:        defaultNetnsDir,
		MovesDir:        defaultRunDir + "/moves",
		FIFODir:         defaultFIFODir,
		Limits:          rootpolicy.Limits{MemoryBytes: 1 << 30, Pids: 4096, CPUs: 2},
	}
}

func testConfig(t *testing.T) Config {
	return Config{
		Socket:    filepath.Join(shortDir(t), "root.sock"),
		SocketGID: os.Getgid(),
		AgentUID:  uint32(os.Getuid()),
		Policy:    testPolicy(),
	}
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
	t          *testing.T
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
func newRig(t *testing.T, mutate func(*Config, *Options)) *rig {
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

func dialSocket(t *testing.T, sock string) *grpc.ClientConn {
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

func callCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestVersion(t *testing.T) {
	r := newRig(t, nil)
	resp, err := rootdpb.NewRootHelperClient(r.conn).Version(callCtx(t), &rootdpb.VersionRequest{AgentVersion: "v9", AgentApi: rootdpb.APIVersion})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetHelperVersion() != version.Version || resp.GetApi() != rootdpb.APIVersion {
		t.Fatalf("Version = %v", resp)
	}
	// EnsureHost is a placeholder, so this helper serves no feature yet.
	if len(resp.GetFeatures()) != 0 {
		t.Fatalf("features %v, want none", resp.GetFeatures())
	}
	if m := r.containerd.methods(); len(m) != 0 {
		t.Fatalf("the helper's own call reached containerd: %v", m)
	}
}

func TestEnsureHostIsAPlaceholder(t *testing.T) {
	r := newRig(t, nil)
	_, err := rootdpb.NewRootHelperClient(r.conn).EnsureHost(callCtx(t), &rootdpb.EnsureHostRequest{})
	if status.Code(err) != codes.Unimplemented || !strings.Contains(err.Error(), "not built yet") {
		t.Fatalf("EnsureHost = %v, want Unimplemented", err)
	}
	if len(r.refused()) != 0 {
		t.Fatal("a placeholder is not a refusal")
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
			err := r.conn.Invoke(callCtx(t), tc.method, &emptypb.Empty{}, &emptypb.Empty{})
			if status.Code(err) != tc.code {
				t.Fatalf("err %v, want %v", err, tc.code)
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
			if err := os.WriteFile(c.Socket, nil, 0o600); err != nil {
				panic(err)
			}
		}, "not a socket"},
		{"a socket folder that is a file", func(c *Config, _ *Options) {
			f := filepath.Join(filepath.Dir(c.Socket), "f")
			if err := os.WriteFile(f, nil, 0o600); err != nil {
				panic(err)
			}
			c.Socket = filepath.Join(f, "root.sock")
		}, "socket folder"},
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

func TestLogRefusal(t *testing.T) {
	var buf bytes.Buffer
	LogRefusal(slog.New(slog.NewTextHandler(&buf, nil)))(context.Background(),
		Refusal{Method: "/containerd.services.tasks.v1.Tasks/Exec", Reason: "method_not_allowed", Detail: "no"})
	for _, want := range []string{"level=ERROR", "Tasks/Exec", "method_not_allowed"} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("log %q lacks %q", buf.String(), want)
		}
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
