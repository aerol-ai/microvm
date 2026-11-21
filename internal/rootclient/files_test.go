package rootclient

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
)

// fileCalls is every call that has the helper make files, with the
// feature each needs.
var fileCalls = []struct {
	feature string
	call    func(ctx context.Context, c *Client) error
}{
	{rootdpb.FeatureEnsureHostFiles, func(ctx context.Context, c *Client) error {
		_, err := c.EnsureHostFiles(ctx, &rootdpb.EnsureHostFilesRequest{ContainerId: "sb-1", Hostname: "sb-1"})
		return err
	}},
	{rootdpb.FeatureEnsureTaskFIFOs, func(ctx context.Context, c *Client) error {
		_, err := c.EnsureTaskFIFOs(ctx, "sb-1")
		return err
	}},
	{rootdpb.FeatureEnsureRunscConfig, func(ctx context.Context, c *Client) error {
		_, err := c.EnsureRunscConfig(ctx, rootdpb.RunscConfig_RUNSC_CONFIG_DEFAULT)
		return err
	}},
	{rootdpb.FeatureEnsureReadySocket, func(ctx context.Context, c *Client) error {
		_, err := c.EnsureReadySocket(ctx, "sb-1", "")
		return err
	}},
	{rootdpb.FeatureRemoveContainerFiles, func(ctx context.Context, c *Client) error {
		return c.RemoveContainerFiles(ctx, "sb-1")
	}},
}

// TestFileCallsWithTheRealHelper: each call against the helper's own
// server makes what it says, and answers with paths in the helper's
// folders.
func TestFileCallsWithTheRealHelper(t *testing.T) {
	sock := sockPath(t)
	realHelper(t, sock, nil)
	base := filepath.Dir(filepath.Dir(sock)) // where realHelper lays the helper's folders out
	c := newClient(t, sock)
	ctx := ctxT(t)

	hosts, err := c.EnsureHostFiles(ctx, &rootdpb.EnsureHostFilesRequest{ContainerId: "sb-1", Hostname: "sb-1",
		Hosts: []*rootdpb.HostEntry{{Address: "127.0.0.1", Names: []string{"localhost"}}}, Nameservers: []string{"10.0.0.2"}})
	if err != nil {
		t.Fatal(err)
	}
	if body, err := os.ReadFile(hosts.GetResolvConfPath()); err != nil || string(body) != "nameserver 10.0.0.2\n" ||
		!strings.HasPrefix(hosts.GetResolvConfPath(), filepath.Join(base, "state", "hosts")+"/") {
		t.Fatalf("resolv.conf %s: %q %v", hosts.GetResolvConfPath(), body, err)
	}
	fifos, err := c.EnsureTaskFIFOs(ctx, "sb-1")
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(fifos.GetStderrPath()); err != nil || fi.Mode().Type() != os.ModeNamedPipe {
		t.Fatalf("stderr %s: %v %v", fifos.GetStderrPath(), fi, err)
	}
	for _, rc := range []rootdpb.RunscConfig{rootdpb.RunscConfig_RUNSC_CONFIG_DEFAULT, rootdpb.RunscConfig_RUNSC_CONFIG_RESTORE} {
		p, err := c.EnsureRunscConfig(ctx, rc)
		if err != nil || filepath.Dir(p) != filepath.Join(base, "state", "runsc") {
			t.Fatalf("runsc config %v: %q %v", rc, p, err)
		}
	}
	agentReady := filepath.Join(base, "agent", "ready")
	if err := os.MkdirAll(agentReady, 0o700); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", filepath.Join(agentReady, "sb-1.ab.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ready, err := c.EnsureReadySocket(ctx, "sb-1", "ab")
	if err != nil || ready != filepath.Join(base, "run", "ready", "sb-1", "ab.sock") {
		t.Fatalf("ready socket %q, %v", ready, err)
	}
	if err := c.RemoveContainerFiles(ctx, "sb-1"); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{hosts.GetResolvConfPath(), fifos.GetStdoutPath(), ready} {
		if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s survived the remove: %v", p, err)
		}
	}

	// The helper's refusal of a value comes back as its own status, not as
	// a helper that is down.
	_, err = c.EnsureTaskFIFOs(ctx, "../etc")
	if status.Code(err) != codes.InvalidArgument || errors.Is(err, ErrUnavailable) || errors.Is(err, ErrUnsupported) {
		t.Fatalf("a refused ID = %v, want the helper's InvalidArgument", err)
	}
}

// countingHelper lists features and counts every call that reaches it.
type countingHelper struct {
	rootdpb.UnimplementedRootHelperServer
	features []string
	stuck    bool // every file call waits for its context
	mu       sync.Mutex
	calls    []string
}

func (h *countingHelper) Version(context.Context, *rootdpb.VersionRequest) (*rootdpb.VersionResponse, error) {
	return &rootdpb.VersionResponse{HelperVersion: "v-test", Api: rootdpb.APIVersion, Features: h.features}, nil
}

func (h *countingHelper) EnsureHostFiles(ctx context.Context, _ *rootdpb.EnsureHostFilesRequest) (*rootdpb.EnsureHostFilesResponse, error) {
	if h.stuck {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return nil, status.Error(codes.Unimplemented, "not here")
}

func (h *countingHelper) seen() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.calls...)
}

func serveCounting(t *testing.T, sock string, h *countingHelper) *grpc.Server {
	t.Helper()
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer(grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
		if info.FullMethod != rootdpb.RootHelper_Version_FullMethodName {
			h.mu.Lock()
			h.calls = append(h.calls, info.FullMethod)
			h.mu.Unlock()
		}
		return next(ctx, req)
	}))
	rootdpb.RegisterRootHelperServer(srv, h)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)
	return srv
}

// TestFileCallsNeedTheirFeature: against a helper one release back, which
// lists none of them, each call is refused here, before it is sent, with
// an UnsupportedError naming it (eng review D5).
func TestFileCallsNeedTheirFeature(t *testing.T) {
	sock := sockPath(t)
	h := &countingHelper{features: []string{rootdpb.FeatureEnsureHost}}
	serveCounting(t, sock, h)
	c := newClient(t, sock)
	for _, fc := range fileCalls {
		err := fc.call(ctxT(t), c)
		var ue *UnsupportedError
		if !errors.As(err, &ue) || ue.Feature != fc.feature || !errors.Is(err, ErrUnsupported) {
			t.Fatalf("%s = %v, want an UnsupportedError naming it", fc.feature, err)
		}
	}
	if seen := h.seen(); len(seen) != 0 {
		t.Fatalf("calls the helper does not serve were sent: %v", seen)
	}
}

// TestFileCallsHelperListsButLacks: a helper that lists a call it then
// answers Unimplemented for gets the same UnsupportedError, not an error
// the API would turn into a 400.
func TestFileCallsHelperListsButLacks(t *testing.T) {
	sock := sockPath(t)
	var all []string
	for _, fc := range fileCalls {
		all = append(all, fc.feature)
	}
	h := &countingHelper{features: all}
	serveCounting(t, sock, h)
	c := newClient(t, sock)
	for _, fc := range fileCalls {
		if err := fc.call(ctxT(t), c); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("%s = %v, want ErrUnsupported", fc.feature, err)
		}
	}
	if seen := h.seen(); len(seen) != len(fileCalls) {
		t.Fatalf("sent %v, want each call once", seen)
	}
}

// TestFileCallsHelperDownOrHung: a helper that is gone, or stuck inside a
// call, fails each call with ErrUnavailable (the API's 503), within the
// client's timeout even when the caller set no deadline.
func TestFileCallsHelperDownOrHung(t *testing.T) {
	t.Run("gone", func(t *testing.T) {
		c := newClient(t, sockPath(t))
		for _, fc := range fileCalls {
			if err := fc.call(ctxT(t), c); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("%s = %v, want ErrUnavailable", fc.feature, err)
			}
		}
	})
	t.Run("hung", func(t *testing.T) {
		sock := sockPath(t)
		serveCounting(t, sock, &countingHelper{features: []string{rootdpb.FeatureEnsureHostFiles}, stuck: true})
		c := newClient(t, sock)
		start := time.Now()
		_, err := c.EnsureHostFiles(context.Background(), &rootdpb.EnsureHostFilesRequest{ContainerId: "sb-1"})
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("EnsureHostFiles on a hung helper = %v, want ErrUnavailable", err)
		}
		if d := time.Since(start); d > 3*c.timeout {
			t.Fatalf("waited %v for a hung helper; the timeout is %v", d, c.timeout)
		}
	})
}
