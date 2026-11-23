package rootclient

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"

	"google.golang.org/grpc"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/pkg/mounts"
)

// lendHelper serves GrantWasmMounts, when it lists it, recording each
// request.
type lendHelper struct {
	fakeHelper
	mu   sync.Mutex
	reqs []*rootdpb.GrantWasmMountsRequest
}

func (l *lendHelper) GrantWasmMounts(_ context.Context, req *rootdpb.GrantWasmMountsRequest) (*rootdpb.GrantWasmMountsResponse, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.reqs = append(l.reqs, req)
	return &rootdpb.GrantWasmMountsResponse{Granted: 2}, nil
}

func serveLend(t *testing.T, sock string, l *lendHelper) {
	t.Helper()
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	rootdpb.RegisterRootHelperServer(srv, l)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)
}

// TestGrantWasmMountsClient: the agent asks the helper to lend a sandbox's
// mount points to the host that serves it, by kind and id, and a helper
// that lacks the call is told apart, as a node without the feature.
func TestGrantWasmMountsClient(t *testing.T) {
	sock := sockPath(t)
	l := &lendHelper{fakeHelper: *helperAt(rootdpb.APIVersion, rootdpb.FeatureGrantWasmMounts, rootdpb.FeatureMountExternal)}
	serveLend(t, sock, l)
	c := newClient(t, sock)
	ctx := ctxT(t)
	n, err := c.GrantWasmMounts(ctx, "sb-1", rootdpb.HostKind_HOST_KIND_WASM_RESIDENT, "o0123456789abcdef-b")
	if err != nil || n != 2 {
		t.Fatalf("grant = %d, %v", n, err)
	}
	if len(l.reqs) != 1 || l.reqs[0].GetSandboxId() != "sb-1" || l.reqs[0].GetKind() != rootdpb.HostKind_HOST_KIND_WASM_RESIDENT ||
		l.reqs[0].GetHostId() != "o0123456789abcdef-b" {
		t.Fatalf("requests %v", l.reqs)
	}
	if err := (Mounts{Client: func() *Client { return c }}).WasmReady(ctx); err != nil {
		t.Fatalf("WasmReady: %v", err)
	}

	// A helper one release back, with mounts and no loans.
	old := sockPath(t)
	serveFake(t, old, helperAt(rootdpb.APIVersion, rootdpb.FeatureMountExternal))
	oc := newClient(t, old)
	if _, err := oc.GrantWasmMounts(ctx, "sb-1", rootdpb.HostKind_HOST_KIND_WASM_WORKER, "sb-1"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("an older helper: %v", err)
	}
	err = (Mounts{Client: func() *Client { return oc }}).WasmReady(ctx)
	if !errors.Is(err, mounts.ErrMountsUnavailable) {
		t.Fatalf("WasmReady on an older helper: %v", err)
	}
	// No client yet: unavailable, never a node setting.
	if err := (Mounts{}).WasmReady(ctx); !errors.Is(err, ErrUnavailable) || errors.Is(err, mounts.ErrMountsUnavailable) {
		t.Fatalf("no client: %v", err)
	}
	// A helper that is down: unavailable too.
	down := newClient(t, sockPath(t)+".none")
	if err := (Mounts{Client: func() *Client { return down }}).WasmReady(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a helper that is down: %v", err)
	}
}
