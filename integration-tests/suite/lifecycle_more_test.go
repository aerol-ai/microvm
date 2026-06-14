//go:build integration

package suite

import (
	"context"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// waitStatus polls a sandbox until it reaches want or the deadline passes.
// Shared by the stop/start use cases where the transition is async.
func waitStatus(t *testing.T, c *harness.Client, id string, want string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last string
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		sb, err := c.SDK().Get(ctx, id)
		cancel()
		if err != nil {
			t.Fatalf("get %s: %v", id, err)
		}
		last = string(sb.Status)
		if last == want {
			return
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("sandbox %s never reached %q (last %q)", id, want, last)
}

// UC-12 — Get a sandbox by id returns the same record.
func TestGetSandboxByID(t *testing.T) {
	harness.Require(t, sc, "UC-12")
	c := client(t)
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t)})
	waitRunning(t, sb)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	got, err := c.SDK().Get(ctx, sb.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ID != sb.ID {
		t.Fatalf("get returned id %q, want %q", got.ID, sb.ID)
	}
}

// UC-13 — List sandboxes includes a freshly created one.
func TestListIncludesSandbox(t *testing.T) {
	harness.Require(t, sc, "UC-13")
	c := client(t)
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t)})
	waitRunning(t, sb)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	list, err := c.SDK().List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, s := range list {
		if s.ID == sb.ID {
			return
		}
	}
	t.Fatalf("list (%d sandboxes) did not include %s", len(list), sb.ID)
}

// UC-14 — Stop a running sandbox; it reaches stopped.
func TestStopSandbox(t *testing.T) {
	harness.Require(t, sc, "UC-14")
	c := client(t)
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t)})
	waitRunning(t, sb)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := c.SDK().Stop(ctx, sb.ID); err != nil {
		t.Fatalf("stop: %v", err)
	}
	waitStatus(t, c, sb.ID, "stopped", 60*time.Second)
}

// UC-15 — Start a stopped sandbox; it returns to started.
func TestStartStoppedSandbox(t *testing.T) {
	harness.Require(t, sc, "UC-15")
	c := client(t)
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t)})
	waitRunning(t, sb)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if _, err := c.SDK().Stop(ctx, sb.ID); err != nil {
		t.Fatalf("stop: %v", err)
	}
	waitStatus(t, c, sb.ID, "stopped", 60*time.Second)
	if _, err := c.SDK().Start(ctx, sb.ID); err != nil {
		t.Fatalf("start: %v", err)
	}
	waitStatus(t, c, sb.ID, "started", 90*time.Second)
}

// UC-17 — Duplicate name is rejected: the unique-name index is the idempotency
// guardrail that stops a retried create from spawning a second sandbox.
func TestDuplicateNameRejected(t *testing.T) {
	harness.Require(t, sc, "UC-17")
	c := client(t)
	name := harness.UniqueName(sc, t)
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: name})
	waitRunning(t, sb)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	dup, err := c.SDK().Create(ctx, sdktypes.CreateSandboxOptions{
		Image: harness.DefaultImage,
		Name:  name,
	})
	if err == nil {
		// Clean up the unexpected second sandbox so it doesn't leak.
		_ = c.SDK().Destroy(ctx, dup.ID)
		t.Fatalf("second create with duplicate name %q succeeded; expected conflict", name)
	}
}

// UC-18 — Resize CPU/memory/disk is accepted and reflected.
func TestResizeSandbox(t *testing.T) {
	harness.Require(t, sc, "UC-18")
	c := client(t)
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Name: harness.UniqueName(sc, t),
		CPU:  1, MemoryMB: 256, DiskGB: 2,
	})
	waitRunning(t, sb)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	resized, err := c.SDK().Resize(ctx, sb.ID, sdktypes.ResizeSandboxOptions{
		CPU: 2, MemoryMB: 512, DiskGB: 4,
	})
	if err != nil {
		t.Fatalf("resize: %v", err)
	}
	if resized.MemoryMB != 512 {
		t.Fatalf("resize: memory_mb=%d, want 512", resized.MemoryMB)
	}
}

// UC-19 — Update lifecycle (idle auto-stop) persists on the sandbox.
func TestUpdateLifecycle(t *testing.T) {
	harness.Require(t, sc, "UC-19")
	c := client(t)
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t)})
	waitRunning(t, sb)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	updated, err := c.SDK().UpdateLifecycle(ctx, sb.ID, sdktypes.Lifecycle{
		StopIfIdleFor: 10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("update lifecycle: %v", err)
	}
	if updated.Lifecycle.StopIfIdleFor != 10*time.Minute {
		t.Fatalf("lifecycle.stop_if_idle_for=%v, want 10m", updated.Lifecycle.StopIfIdleFor)
	}
}

// UC-20 — Snapshot create returns a reusable image reference.
func TestSnapshotCreate(t *testing.T) {
	harness.Require(t, sc, "UC-20")
	c := client(t)
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t)})
	waitRunning(t, sb)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	snap, err := c.SDK().CreateSnapshot(ctx, sb.ID, harness.UniqueName(sc, t)+"-snap")
	if err != nil {
		t.Fatalf("create snapshot: %v", err)
	}
	if snap.Image == "" {
		t.Fatal("snapshot has empty image reference")
	}
}

// UC-21 — Register a snapshot, then create a sandbox from it.
func TestRegisterSnapshotAndCreateFrom(t *testing.T) {
	harness.Require(t, sc, "UC-21")
	c := client(t)
	src := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t)})
	waitRunning(t, src)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	snap, err := c.SDK().CreateSnapshot(ctx, src.ID, harness.UniqueName(sc, t)+"-snap")
	if err != nil {
		t.Fatalf("create snapshot: %v", err)
	}

	// Create a new sandbox directly from the snapshot's image reference.
	derived := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Image: snap.Image,
		Name:  harness.UniqueName(sc, t),
	})
	waitRunning(t, derived)
}
