package gate

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/containerd/containerd/v2/pkg/namespaces"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"

	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

const (
	testNS       = "aerolvm"
	testSnapRoot = "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs"
	testLayers   = testSnapRoot + "/snapshots"
	testRunDir   = "/var/lib/sandboxd/containerd"
	testToolbox  = "/usr/local/lib/aerolvm/toolboxd"
	testMounts   = "/var/lib/sandboxd/mounts"
	testFIFO     = "/run/aerolvm/fifo"
	testRunscCfg = testRunDir + "/runsc/config.toml"
)

func testPolicy() rootpolicy.Policy {
	return rootpolicy.Policy{
		Namespace:        testNS,
		Snapshotter:      "overlayfs",
		SnapshotterRoot:  testSnapRoot,
		NetnsDir:         "/run/netns",
		BindRoots:        []string{testRunDir + "/hosts", testMounts},
		BindFiles:        []string{testToolbox},
		ForbiddenRoots:   []string{"/run/aerolvm/sock", "/run/containerd"},
		MovesDir:         testRunDir + "/moves",
		FIFODir:          testFIFO,
		RunscConfigPaths: []string{testRunscCfg},
		Limits:           rootpolicy.Limits{MemoryBytes: 2 << 30, Pids: 8192, CPUs: 4},
	}
}

// call is one request the fake containerd received.
type call struct {
	method    string
	req       proto.Message
	namespace []string
	lease     []string
	other     []string // any other metadata key that reached containerd
}

// responder answers one call to the fake: the messages to send back (one
// for a unary method), or an error.
type responder func(ctx context.Context, req proto.Message) ([]proto.Message, error)

// fakeContainerd stands in for the real socket. It decodes each request
// with the gate's own table, records it, and answers from responders, or
// with one empty response.
type fakeContainerd struct {
	mu        sync.Mutex
	calls     []call
	responder map[string]responder
}

func (f *fakeContainerd) on(method string, r responder) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.responder == nil {
		f.responder = map[string]responder{}
	}
	f.responder[method] = r
}

func (f *fakeContainerd) seen() []call {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]call(nil), f.calls...)
}

func (f *fakeContainerd) methodsSeen() []string {
	var out []string
	for _, c := range f.seen() {
		out = append(out, c.method)
	}
	return out
}

func (f *fakeContainerd) handle(_ any, ss grpc.ServerStream) error {
	name, _ := grpc.MethodFromServerStream(ss)
	m := methods[name]
	if m == nil {
		return status.Errorf(codes.Unimplemented, "fake containerd: %s", name)
	}
	md, _ := metadata.FromIncomingContext(ss.Context())
	var other []string
	for k := range md {
		if k != namespaces.GRPCHeader && k != "containerd-lease" && k != ":authority" && k != "content-type" && k != "user-agent" && k != "grpc-accept-encoding" && k != "grpc-timeout" {
			other = append(other, k)
		}
	}
	for {
		req := m.newReq()
		if err := ss.RecvMsg(req); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		f.mu.Lock()
		f.calls = append(f.calls, call{method: name, req: req, namespace: md.Get(namespaces.GRPCHeader), lease: md.Get("containerd-lease"), other: other})
		r := f.responder[name]
		f.mu.Unlock()
		resps := []proto.Message{m.newResp()}
		if r != nil {
			var err error
			if resps, err = r(ss.Context(), req); err != nil {
				return err
			}
		}
		for _, resp := range resps {
			if err := ss.SendMsg(resp); err != nil {
				return err
			}
		}
		if !m.clientStream {
			return nil
		}
	}
}

// rig is the agent's view: a client connection to a gate in front of a
// fake containerd, both over in-memory listeners.
type rig struct {
	t        *testing.T
	fake     *fakeContainerd
	gate     *Gate
	conn     *grpc.ClientConn
	dial     func(context.Context, string) (net.Conn, error)
	stdio    *acceptStdio
	binds    *acceptBinds
	reads    *acceptReads
	mu       sync.Mutex
	refusals []Refusal
}

func bufServer(t *testing.T, opts ...grpc.ServerOption) (*grpc.Server, func(context.Context, string) (net.Conn, error)) {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer(opts...)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return srv, func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }
}

func bufConn(t *testing.T, dial func(context.Context, string) (net.Conn, error)) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient("passthrough:///bufnet", grpc.WithContextDialer(dial), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// acceptStdio stands in for the on-disk stdio check, which needs real
// FIFOs (stdio_linux_test.go has those), and records what it was asked.
type acceptStdio struct {
	mu   sync.Mutex
	seen []string
}

func (a *acceptStdio) CheckStdio(p string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.seen = append(a.seen, p)
	return nil
}

// acceptBinds stands in for the on-disk bind check (hostpath_linux_test.go
// has the real one on real files) and records root and source.
type acceptBinds struct {
	mu   sync.Mutex
	seen [][2]string
}

func (a *acceptBinds) CheckBind(root, src string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.seen = append(a.seen, [2]string{root, src})
	return nil
}

// acceptReads stands in for the on-disk check of paths root reads
// (hostpath_linux_test.go has the real one) and records what it was asked.
type acceptReads struct {
	mu   sync.Mutex
	seen []rootpolicy.RootRead
}

func (a *acceptReads) CheckRead(r rootpolicy.RootRead) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.seen = append(a.seen, r)
	return nil
}

// newRig builds the rig. The gate's on-disk stdio, bind and read checks
// accept every path unless an option says otherwise.
func newRig(t *testing.T, p rootpolicy.Policy, opts ...func(*Config)) *rig {
	t.Helper()
	r := &rig{t: t, fake: &fakeContainerd{}, stdio: &acceptStdio{}, binds: &acceptBinds{}, reads: &acceptReads{}}
	_, upDial := bufServer(t, grpc.UnknownServiceHandler(r.fake.handle))
	cfg := Config{Policy: p, Upstream: bufConn(t, upDial), Stdio: r.stdio, Binds: r.binds, Reads: r.reads, OnRefusal: func(_ context.Context, ref Refusal) {
		r.mu.Lock()
		r.refusals = append(r.refusals, ref)
		r.mu.Unlock()
	}}
	for _, o := range opts {
		o(&cfg)
	}
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r.gate = g
	_, r.dial = bufServer(t, g.ServerOptions()...)
	r.conn = bufConn(t, r.dial)
	return r
}

func (r *rig) refused() []Refusal {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Refusal(nil), r.refusals...)
}

// nsCtx is a call in the agent's namespace, as the containerd client sends it.
func nsCtx() context.Context {
	return metadata.AppendToOutgoingContext(context.Background(), namespaces.GRPCHeader, testNS)
}

// wantRefused checks err is the gate's PermissionDenied for method with
// reason, that the callback heard exactly that, and that containerd never
// saw the method.
func (r *rig) wantRefused(err error, method, reason string) {
	r.t.Helper()
	if status.Code(err) != codes.PermissionDenied {
		r.t.Fatalf("err %v, want PermissionDenied", err)
	}
	refs := r.refused()
	if len(refs) == 0 {
		r.t.Fatal("no refusal reached the callback")
	}
	last := refs[len(refs)-1]
	if last.Method != method || last.Reason != reason {
		r.t.Fatalf("refusal %+v, want method %s reason %s", last, method, reason)
	}
	if st := status.Convert(err).Message(); !strings.Contains(st, method) || !strings.Contains(st, reason) {
		r.t.Fatalf("error %q does not name the method and reason", st)
	}
	for _, c := range r.fake.seen() {
		if c.method == method {
			r.t.Fatalf("containerd saw the refused %s", method)
		}
	}
}
