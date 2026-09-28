package service

import (
	"context"
	"errors"
	"testing"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// DestroySandbox races its own side effects. rt.Destroy makes Docker emit
// die+destroy, handleDestroyEvent (events.go) reacts by removing the sandbox
// row, and DestroySandbox then reaches its own store.Delete and finds the row
// already gone. events.go tolerates the mirror-image race explicitly
// ("ErrNotFound is benign — the API-driven destroy path may have raced us");
// DestroySandbox did not, so a successful delete surfaced as
// DELETE /v1/sandboxes/{id} -> 404 "sandbox not found".
//
// That is not theoretical and it is not rare. On single-node against real AWS
// (2026-09-23) it reproduced 3/3: the sandbox and its container were fully
// gone every time, and the API reported 404 every time. It slipped past the
// offline suite because nothing exercised the ordering in which the event
// watcher wins, which is now the common ordering — the secret tomb, wasm
// cleanup and placement delete that run between rt.Destroy and store.Delete
// widened the window enough that the watcher gets there first.
func TestDestroySandboxToleratesEventWatcherWinningRowDelete(t *testing.T) {
	ctx := context.Background()
	svc, _, st := newCapacityHarness(t, nil, nil)

	sb := seedSandbox(t, st, "sb-destroy-event-race", models.SandboxStatusStarted, 1, 1024)

	// Stand in for handleDestroyEvent: remove the row underneath DestroySandbox
	// at exactly the point store.Delete is about to run.
	raced := false
	svc.testDuringSandboxRowDelete = func() {
		if err := st.Delete(ctx, sb.ID); err != nil {
			t.Errorf("simulated event-watcher delete: %v", err)
			return
		}
		raced = true
	}

	if err := svc.DestroySandbox(ctx, sb.ID); err != nil {
		t.Fatalf("DestroySandbox() error = %v, want nil — the row was already removed by the event watcher, which is success, not a 404", err)
	}
	if !raced {
		t.Fatal("the fixture never removed the row, so this no longer models the race")
	}
	if _, err := st.Get(ctx, sb.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("sandbox row still present after destroy: err = %v", err)
	}
}

// The tolerance must be scoped to ErrNotFound. Swallowing every store error
// here would report success for a destroy that left the authoritative row
// behind — a far worse failure than the 404, because the client believes the
// sandbox is gone while it still occupies capacity and holds its audit lease.
func TestDestroySandboxStillFailsOnNonNotFoundRowDeleteError(t *testing.T) {
	ctx := context.Background()
	svc, _, st := newCapacityHarness(t, nil, nil)

	sb := seedSandbox(t, st, "sb-destroy-store-broken", models.SandboxStatusStarted, 1, 1024)

	// Closing the store makes store.Delete fail with something that is NOT
	// ErrNotFound, which must still fail the destroy.
	svc.testDuringSandboxRowDelete = func() { _ = st.Close() }

	err := svc.DestroySandbox(ctx, sb.ID)
	if err == nil {
		t.Fatal("DestroySandbox() succeeded despite a failing row delete")
	}
	if errors.Is(err, store.ErrNotFound) {
		t.Fatalf("DestroySandbox() reported ErrNotFound for a broken store: %v", err)
	}
	_ = sb
}
