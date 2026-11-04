package clustercreate

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/models"
)

// strictPlacementStub answers the authoritative read with only the
// placements it holds, so a reservation a failed create cancelled is gone
// (clusterStub fabricates one for any id it does not know).
type strictPlacementStub struct{ *clusterStub }

func (s strictPlacementStub) AuthoritativePlacementsByIDs(_ context.Context, ids []string) (map[string]cluster.Placement, error) {
	out := map[string]cluster.Placement{}
	for _, id := range ids {
		if p, ok := s.placements[id]; ok {
			out[id] = p
		}
	}
	return out, nil
}

type overlapResult struct {
	resp *models.CreateSandboxResponse
	err  error
}

// Case 4a on the node holding the reservation: a keyed retry routed here
// while the first create's reservation is pending waits for that create and
// replays it. Before the lease it ran its own create leg and seal leg, and a
// failed leg retracted the reservation and destroyed the sandbox under the id
// (the first request's).
func TestOverlapRetryWaitsForThePendingCreate(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	const id = "sb-overlap-wait01"
	tests := []struct {
		name string
		// firstErr fails the first create; the retry then finds the
		// reservation gone and answers a retryable 503.
		firstErr error
	}{
		{name: "first create succeeds: the retry replays it"},
		{name: "first create fails: the retry answers 503 to reserve afresh", firstErr: errors.New("image pull timed out")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stub := &clusterStub{Noop: cluster.NewNoop("node-a", "http://node-a", "")}
			seedReservedPlacement(stub, id)
			rt := newFakeRuntime()
			rt.hold, rt.entered, rt.failOnce = make(chan struct{}), make(chan struct{}), tt.firstErr
			svc, _ := newCreateServiceWithRuntime(t, strictPlacementStub{stub}, rt, true)
			ctx := service.WithIdempotencyKey(context.Background(), "job-9")
			req := models.CreateSandboxRequest{Image: "alpine:3.20", CreateRequestDigests: []string{"hmac:0:aaaa"}}

			first := make(chan overlapResult, 1)
			go func() {
				resp, err := OverlapCreateAndPromote(ctx, svc, logger, req, id, OverlapOptions{PromoteWithSpec: true})
				first <- overlapResult{resp, err}
			}()
			<-rt.entered
			retry := make(chan overlapResult, 1)
			go func() {
				resp, err := OverlapCreateAndPromote(ctx, svc, logger, req, id, OverlapOptions{PromoteWithSpec: true})
				retry <- overlapResult{resp, err}
			}()
			// The retry is waiting, not creating: one runtime create, and
			// nothing retracted or promoted under the first.
			time.Sleep(50 * time.Millisecond)
			if n := rt.creates.Load(); n != 1 {
				t.Fatalf("runtime creates while the first runs = %d, want 1", n)
			}
			if stub.cancels != 0 || stub.deletes != 0 || len(stub.recordCalls) != 0 {
				t.Fatalf("the waiting retry touched the reservation: cancels %d deletes %d promotes %d", stub.cancels, stub.deletes, len(stub.recordCalls))
			}
			close(rt.hold)

			f := <-first
			r := <-retry
			if n := rt.creates.Load(); n != 1 {
				t.Fatalf("runtime creates = %d, want exactly 1", n)
			}
			if tt.firstErr == nil {
				if f.err != nil || r.err != nil || r.resp.Sandbox.ID != f.resp.Sandbox.ID || !r.resp.Replayed {
					t.Fatalf("first %+v %v; retry %+v %v; want the retry to replay the first", f.resp, f.err, r.resp, r.err)
				}
				if len(stub.recordCalls) != 1 || stub.cancels != 0 || stub.deletes != 0 {
					t.Fatalf("promotes %d cancels %d deletes %d, want one promote and nothing undone", len(stub.recordCalls), stub.cancels, stub.deletes)
				}
				if _, err := svc.GetSandbox(context.Background(), id); err != nil {
					t.Fatalf("the sandbox is gone: %v", err)
				}
				return
			}
			if f.err == nil {
				t.Fatal("the first create succeeded; the test needs it to fail")
			}
			if !errors.Is(r.err, service.ErrReservedPlacementGone) {
				t.Fatalf("retry after the failure = %v, want ErrReservedPlacementGone (503, retry reserves afresh)", r.err)
			}
			// Only the first create's own retract cancelled; the retry did
			// not cancel a reservation it never held.
			if stub.cancels != 1 || len(stub.recordCalls) != 0 {
				t.Fatalf("cancels %d promotes %d, want the first's one cancel only", stub.cancels, len(stub.recordCalls))
			}
		})
	}
}

// The unreserved (local-image) keyed create holds the lease across its seal
// and promote: a retry waits for all three and replays without sealing,
// promoting or rolling back again.
func TestCreateOnSelectedNodeLocalKeyedRetryWaits(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	const id = "sb-local-wait001"
	stub := &clusterStub{Noop: cluster.NewNoop("node-a", "http://node-a", "")}
	rt := newFakeRuntime()
	rt.hold, rt.entered = make(chan struct{}), make(chan struct{})
	svc, _ := newCreateServiceWithRuntime(t, stub, rt, true)
	ctx := service.WithIdempotencyKey(context.Background(), "job-10")
	req := models.CreateSandboxRequest{Image: "alpine:3.20", CreateRequestDigests: []string{"hmac:0:aaaa"}}

	first := make(chan overlapResult, 1)
	go func() {
		resp, err := CreateOnSelectedNode(ctx, svc, logger, req, "", CreateOptions{PromoteWithSpec: true, SandboxID: id})
		first <- overlapResult{resp, err}
	}()
	<-rt.entered
	retry := make(chan overlapResult, 1)
	go func() {
		resp, err := CreateOnSelectedNode(ctx, svc, logger, req, "", CreateOptions{PromoteWithSpec: true, SandboxID: id})
		retry <- overlapResult{resp, err}
	}()
	time.Sleep(50 * time.Millisecond)
	if n := rt.creates.Load(); n != 1 {
		t.Fatalf("runtime creates while the first runs = %d, want 1", n)
	}
	close(rt.hold)
	f, r := <-first, <-retry
	if f.err != nil || r.err != nil || r.resp.Sandbox.ID != id || !r.resp.Replayed || f.resp.Replayed {
		t.Fatalf("first %+v %v; retry %+v %v", f.resp, f.err, r.resp, r.err)
	}
	if n := rt.creates.Load(); n != 1 || len(stub.recordCalls) != 1 || stub.deletes != 0 {
		t.Fatalf("creates %d promotes %d deletes %d, want 1, 1, 0", n, len(stub.recordCalls), stub.deletes)
	}

	// A different request under the key is refused, also outside a race.
	if _, err := CreateOnSelectedNode(ctx, svc, logger, models.CreateSandboxRequest{Image: "alpine:3.21", CreateRequestDigests: []string{"hmac:0:bbbb"}}, "", CreateOptions{SandboxID: id}); !errors.Is(err, models.ErrIdempotencyKeyReused) {
		t.Fatalf("different request = %v, want ErrIdempotencyKeyReused", err)
	}
}
