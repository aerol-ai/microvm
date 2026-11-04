package clustercreate

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/models"
)

// A keyed retry that reaches the owner through the reservation-conflict
// route (Prepare → routeExistingPlacement → OverlapCreateAndPromote) with a
// different request is refused before either leg runs. A leg that ran would
// fail on the existing sandbox, and a failed leg retracts the reservation and
// destroys the sandbox under the id — the first request's.
func TestOverlapRefusesAReusedKeyWithoutTouchingTheFirstSandbox(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	stub := &clusterStub{Noop: cluster.NewNoop("node-a", "http://node-a", "")}
	const id = "sb-keyed-overlap"
	seedReservedPlacement(stub, id)
	svc, _ := newCreateServiceWithRuntime(t, stub, newFakeRuntime(), true)
	ctx := service.WithIdempotencyKey(context.Background(), "job-42")

	first, err := OverlapCreateAndPromote(ctx, svc, logger, models.CreateSandboxRequest{Image: "alpine:3.20", CreateRequestDigests: []string{"hmac:0:aaaa"}}, id, OverlapOptions{PromoteWithSpec: true})
	if err != nil {
		t.Fatalf("first create: %v", err)
	}
	if spec := stub.recordCalls[len(stub.recordCalls)-1].spec; spec == nil || len(spec.CreateRequestDigests) != 1 || spec.CreateRequestDigests[0] != "hmac:0:aaaa" {
		t.Fatalf("promoted spec digests = %+v; a failover recreate needs them", spec)
	}
	promotes, cancels, deletes := len(stub.recordCalls), stub.cancels, stub.deletes

	tests := []struct {
		name      string
		digests   []string
		wantReuse bool
	}{
		{name: "a different request", digests: []string{"hmac:0:bbbb"}, wantReuse: true},
		{name: "the same request", digests: []string{"hmac:0:aaaa"}},
		{name: "a request digested by a router without a server key", digests: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := OverlapCreateAndPromote(ctx, svc, logger, models.CreateSandboxRequest{Image: "alpine:3.21", CreateRequestDigests: tt.digests}, id, OverlapOptions{PromoteWithSpec: true})
			if tt.wantReuse {
				if !errors.Is(err, models.ErrIdempotencyKeyReused) || resp != nil {
					t.Fatalf("retry = %+v, %v; want ErrIdempotencyKeyReused", resp, err)
				}
				if _, isLeg := AsOverlapFailure(err); isLeg {
					t.Fatal("the refusal came from a leg; no leg may run")
				}
			} else if err != nil || resp.Sandbox.ID != first.Sandbox.ID {
				t.Fatalf("retry = %+v, %v; want a replay", resp, err)
			}
			if len(stub.recordCalls) != promotes || stub.cancels != cancels || stub.deletes != deletes {
				t.Fatalf("the retry promoted, cancelled or deleted (records %d→%d, cancels %d→%d, deletes %d→%d)",
					promotes, len(stub.recordCalls), cancels, stub.cancels, deletes, stub.deletes)
			}
			if _, err := svc.GetSandbox(context.Background(), id); err != nil {
				t.Fatalf("the first sandbox is gone: %v", err)
			}
		})
	}
}
