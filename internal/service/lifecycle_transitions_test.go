package service

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// PauseSandbox is the one definition of "can this be paused": started stops,
// already-stopped is an idempotent no-op, anything else is ErrSandboxNotRunning.
func TestPauseSandbox(t *testing.T) {
	ctx := context.Background()

	t.Run("started stops", func(t *testing.T) {
		svc, _, st := newCapacityHarness(t, nil, nil)
		seedSandbox(t, st, "sb-p1", models.SandboxStatusStarted, 1, 512)
		got, err := svc.PauseSandbox(ctx, "sb-p1")
		if err != nil {
			t.Fatalf("PauseSandbox: %v", err)
		}
		if got.Status != models.SandboxStatusStopped {
			t.Fatalf("status = %q, want stopped", got.Status)
		}
	})

	t.Run("stopped is a no-op", func(t *testing.T) {
		svc, _, st := newCapacityHarness(t, nil, nil)
		seedSandbox(t, st, "sb-p2", models.SandboxStatusStopped, 1, 512)
		got, err := svc.PauseSandbox(ctx, "sb-p2")
		if err != nil {
			t.Fatalf("PauseSandbox no-op: %v", err)
		}
		if got.Status != models.SandboxStatusStopped {
			t.Fatalf("status = %q, want stopped", got.Status)
		}
	})

	t.Run("creating is ErrSandboxNotRunning", func(t *testing.T) {
		svc, _, st := newCapacityHarness(t, nil, nil)
		seedSandbox(t, st, "sb-p3", models.SandboxStatusCreating, 1, 512)
		if _, err := svc.PauseSandbox(ctx, "sb-p3"); !errors.Is(err, ErrSandboxNotRunning) {
			t.Fatalf("PauseSandbox(creating) = %v, want ErrSandboxNotRunning", err)
		}
	})

	t.Run("missing is ErrNotFound", func(t *testing.T) {
		svc, _, _ := newCapacityHarness(t, nil, nil)
		if _, err := svc.PauseSandbox(ctx, "nope"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("PauseSandbox(missing) = %v, want ErrNotFound", err)
		}
	})
}

// ResumeSandbox is the one definition of "can this be resumed": stopped starts,
// already-started is an idempotent no-op, anything else is ErrSandboxNotResumable.
func TestResumeSandbox(t *testing.T) {
	ctx := context.Background()

	t.Run("stopped starts", func(t *testing.T) {
		svc, _, st := newCapacityHarness(t, nil, nil)
		// Drive what the fake runtime's Start returns so StartSandbox completes.
		svc.docker.(*fakeCapacityRuntime).startResult = &models.SandboxRuntimeState{
			ContainerID: "ctr-sb-r1", ContainerIP: "10.0.0.2", Status: models.SandboxStatusStarted,
		}
		seedSandbox(t, st, "sb-r1", models.SandboxStatusStopped, 1, 512)
		if _, err := svc.ResumeSandbox(ctx, "sb-r1"); err != nil {
			t.Fatalf("ResumeSandbox: %v", err)
		}
		got, err := st.Get(ctx, "sb-r1")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.Status != models.SandboxStatusStarted {
			t.Fatalf("status = %q, want started", got.Status)
		}
		if svc.docker.(*fakeCapacityRuntime).startCount != 1 {
			t.Fatalf("Start calls = %d, want 1", svc.docker.(*fakeCapacityRuntime).startCount)
		}
	})

	t.Run("started is a no-op", func(t *testing.T) {
		svc, _, st := newCapacityHarness(t, nil, nil)
		seedSandbox(t, st, "sb-r2", models.SandboxStatusStarted, 1, 512)
		got, err := svc.ResumeSandbox(ctx, "sb-r2")
		if err != nil {
			t.Fatalf("ResumeSandbox no-op: %v", err)
		}
		if got.Status != models.SandboxStatusStarted {
			t.Fatalf("status = %q, want started", got.Status)
		}
	})

	t.Run("creating is ErrSandboxNotResumable", func(t *testing.T) {
		svc, _, st := newCapacityHarness(t, nil, nil)
		seedSandbox(t, st, "sb-r3", models.SandboxStatusCreating, 1, 512)
		if _, err := svc.ResumeSandbox(ctx, "sb-r3"); !errors.Is(err, ErrSandboxNotResumable) {
			t.Fatalf("ResumeSandbox(creating) = %v, want ErrSandboxNotResumable", err)
		}
	})

	t.Run("missing is ErrNotFound", func(t *testing.T) {
		svc, _, _ := newCapacityHarness(t, nil, nil)
		if _, err := svc.ResumeSandbox(ctx, "nope"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("ResumeSandbox(missing) = %v, want ErrNotFound", err)
		}
	})
}

// ApplyLifecyclePatch reads the current lifecycle under the lock, applies the
// facade's patch and writes it back.
func TestApplyLifecyclePatch(t *testing.T) {
	ctx := context.Background()

	t.Run("applies and persists", func(t *testing.T) {
		svc, _, st := newCapacityHarness(t, nil, nil)
		seedSandbox(t, st, "sb-a1", models.SandboxStatusStarted, 1, 512)
		updated, changed, err := svc.ApplyLifecyclePatch(ctx, "sb-a1", func(sb *models.Sandbox) (models.Lifecycle, bool, error) {
			l := sb.Lifecycle
			l.StopAtAge = time.Hour
			return l, true, nil
		})
		if err != nil || !changed {
			t.Fatalf("ApplyLifecyclePatch = changed %v err %v", changed, err)
		}
		if updated.Lifecycle.StopAtAge != time.Hour {
			t.Fatalf("StopAtAge = %v, want 1h", updated.Lifecycle.StopAtAge)
		}
	})

	t.Run("no-op leaves the sandbox untouched", func(t *testing.T) {
		svc, _, st := newCapacityHarness(t, nil, nil)
		seedSandbox(t, st, "sb-a2", models.SandboxStatusStarted, 1, 512)
		updated, changed, err := svc.ApplyLifecyclePatch(ctx, "sb-a2", func(sb *models.Sandbox) (models.Lifecycle, bool, error) {
			return models.Lifecycle{StopAtAge: time.Hour}, false, nil
		})
		if err != nil || changed {
			t.Fatalf("ApplyLifecyclePatch no-op = changed %v err %v", changed, err)
		}
		if updated.Lifecycle.StopAtAge != 0 {
			t.Fatalf("no-op wrote StopAtAge = %v, want 0", updated.Lifecycle.StopAtAge)
		}
	})

	t.Run("patch error propagates, nothing written", func(t *testing.T) {
		svc, _, st := newCapacityHarness(t, nil, nil)
		seedSandbox(t, st, "sb-a3", models.SandboxStatusStarted, 1, 512)
		boom := errors.New("boom")
		if _, _, err := svc.ApplyLifecyclePatch(ctx, "sb-a3", func(sb *models.Sandbox) (models.Lifecycle, bool, error) {
			return models.Lifecycle{}, false, boom
		}); !errors.Is(err, boom) {
			t.Fatalf("patch error = %v, want boom", err)
		}
	})

	t.Run("invalid lifecycle is rejected", func(t *testing.T) {
		svc, _, st := newCapacityHarness(t, nil, nil)
		seedSandbox(t, st, "sb-a4", models.SandboxStatusStarted, 1, 512)
		if _, _, err := svc.ApplyLifecyclePatch(ctx, "sb-a4", func(sb *models.Sandbox) (models.Lifecycle, bool, error) {
			return models.Lifecycle{StopAtAge: -time.Hour}, true, nil
		}); err == nil {
			t.Fatalf("negative StopAtAge accepted; want validation error")
		}
	})

	t.Run("missing is ErrNotFound", func(t *testing.T) {
		svc, _, _ := newCapacityHarness(t, nil, nil)
		if _, _, err := svc.ApplyLifecyclePatch(ctx, "nope", func(sb *models.Sandbox) (models.Lifecycle, bool, error) {
			return models.Lifecycle{}, true, nil
		}); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("ApplyLifecyclePatch(missing) = %v, want ErrNotFound", err)
		}
	})
}

// Two concurrent patches that each set a different Lifecycle field must both
// survive: the locked read-fresh-then-write composes them. The pre-convergence
// facades read a stale base outside any lock, so one write dropped the other's
// field (D7). Run under -race, this also proves the mutation is serialized.
func TestApplyLifecyclePatchComposesConcurrentFields(t *testing.T) {
	ctx := context.Background()
	svc, _, st := newCapacityHarness(t, nil, nil)
	seedSandbox(t, st, "sb-compose", models.SandboxStatusStarted, 1, 512)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _, _ = svc.ApplyLifecyclePatch(ctx, "sb-compose", func(sb *models.Sandbox) (models.Lifecycle, bool, error) {
			l := sb.Lifecycle
			l.StopAtAge = time.Hour
			return l, true, nil
		})
	}()
	go func() {
		defer wg.Done()
		_, _, _ = svc.ApplyLifecyclePatch(ctx, "sb-compose", func(sb *models.Sandbox) (models.Lifecycle, bool, error) {
			l := sb.Lifecycle
			l.DestroyAtAge = 2 * time.Hour
			return l, true, nil
		})
	}()
	wg.Wait()

	got, err := st.Get(ctx, "sb-compose")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Lifecycle.StopAtAge != time.Hour || got.Lifecycle.DestroyAtAge != 2*time.Hour {
		t.Fatalf("concurrent patches did not compose: StopAtAge=%v DestroyAtAge=%v",
			got.Lifecycle.StopAtAge, got.Lifecycle.DestroyAtAge)
	}
}

// The lifecycle transitions go through scopedGet, so a scoped caller cannot
// touch another owner's sandbox — it reads as not-found (D13: the owner check
// lives in the shared helper, not the caller).
func TestLifecycleTransitionsEnforceOwner(t *testing.T) {
	ctx := context.Background()
	svc, _, st := newCapacityHarness(t, nil, nil)

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-owned", Image: "ubuntu:22.04", Status: models.SandboxStatusStarted,
		ContainerID: "ctr-sb-owned", ContainerIP: "10.0.0.1", Runtime: models.RuntimeDocker,
		CPU: 1, MemoryMB: 512, OwnerRef: "acme",
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatalf("seed owned sandbox: %v", err)
	}
	intruder := userCtx("globex")

	if _, err := svc.PauseSandbox(intruder, "sb-owned"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("PauseSandbox cross-owner = %v, want ErrNotFound", err)
	}
	if _, err := svc.ResumeSandbox(intruder, "sb-owned"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("ResumeSandbox cross-owner = %v, want ErrNotFound", err)
	}
	if _, _, err := svc.ApplyLifecyclePatch(intruder, "sb-owned", func(sb *models.Sandbox) (models.Lifecycle, bool, error) {
		return models.Lifecycle{}, true, nil
	}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("ApplyLifecyclePatch cross-owner = %v, want ErrNotFound", err)
	}
}
