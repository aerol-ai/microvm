package service

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// TestDestroyAtOnCreate is plan L6 on the create path: a future destroy_at
// is stored as the age the sandbox will have then, a past one is refused,
// and the caller's request is not changed behind its back.
func TestDestroyAtOnCreate(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})

	at := time.Now().UTC().Add(2 * time.Hour)
	lc := &models.Lifecycle{DestroyAt: &at, StopIfIdleFor: time.Minute}
	req := models.CreateSandboxRequest{Image: "alpine", Lifecycle: lc}
	resp, err := svc.CreateSandbox(ctx, req)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if lc.DestroyAt == nil || lc.DestroyAtAge != 0 {
		t.Fatal("create changed the caller's lifecycle")
	}
	stored, err := st.Get(ctx, resp.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Lifecycle.DestroyAt != nil || stored.Lifecycle.StopIfIdleFor != time.Minute {
		t.Fatalf("stored lifecycle = %+v", stored.Lifecycle)
	}
	// The age is measured from the stored creation time, within the moment
	// between the conversion and the row being built.
	if got := stored.CreatedAt.Add(stored.Lifecycle.DestroyAtAge); got.Sub(at).Abs() > 5*time.Second {
		t.Fatalf("created %v + age %s = %v, want about %v", stored.CreatedAt, stored.Lifecycle.DestroyAtAge, got, at)
	}

	past := time.Now().UTC().Add(-time.Minute)
	if _, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine", Lifecycle: &models.Lifecycle{DestroyAt: &past}}); err == nil ||
		!strings.Contains(err.Error(), "not in the future") {
		t.Fatalf("past destroy_at create = %v", err)
	}

	// A create with only destroy_at has a timer of its own: the server's
	// default timers stay out.
	svc.cfg.DefaultDestroyIfIdleFor = time.Hour
	only, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine", Lifecycle: &models.Lifecycle{DestroyAt: &at}})
	if err != nil {
		t.Fatal(err)
	}
	if only.Lifecycle.DestroyIfIdleFor != 0 || only.Lifecycle.DestroyAtAge == 0 {
		t.Fatalf("destroy_at-only lifecycle = %+v", only.Lifecycle)
	}

	if err := NormalizeCreateLifecycle(nil, time.Now()); err != nil {
		t.Fatal(err)
	}
}

// TestDestroyAtOnUpdate: on a lifecycle update the age is measured from the
// sandbox's own creation; a past time, or a time with an age, is refused.
func TestDestroyAtOnUpdate(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	created := time.Now().UTC().Add(-3 * time.Hour).Truncate(time.Second)
	if err := st.Create(ctx, &models.Sandbox{ID: "sb-at", Image: "alpine", Runtime: models.RuntimeDocker, Status: models.SandboxStatusStarted,
		CreatedAt: created, UpdatedAt: created, LastActiveAt: created}); err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	got, err := svc.UpdateLifecycle(ctx, "sb-at", models.Lifecycle{DestroyAt: &at})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if got.Lifecycle.DestroyAtAge != at.Sub(created) || got.Lifecycle.DestroyAt != nil {
		t.Fatalf("lifecycle after update = %+v, want age %s", got.Lifecycle, at.Sub(created))
	}

	past := time.Now().UTC().Add(-time.Minute)
	for name, l := range map[string]models.Lifecycle{
		"past":       {DestroyAt: &past},
		"with age":   {DestroyAt: &at, DestroyAtAge: time.Hour},
		"stop after": {DestroyAt: &at, StopAtAge: 10 * time.Hour},
	} {
		if _, err := svc.UpdateLifecycle(ctx, "sb-at", l); err == nil {
			t.Fatalf("%s: update accepted", name)
		}
	}
	if _, err := svc.UpdateLifecycle(ctx, "sb-missing", models.Lifecycle{DestroyAt: &at}); err == nil {
		t.Fatal("update of a missing sandbox accepted")
	}

	// The facades' patch path converts the same way.
	later := at.Add(time.Hour)
	patched, _, err := svc.ApplyLifecyclePatch(ctx, "sb-at", func(sb *models.Sandbox) (models.Lifecycle, bool, error) {
		l := sb.Lifecycle
		l.DestroyAtAge, l.DestroyAt = 0, &later
		return l, true, nil
	})
	if err != nil || patched.Lifecycle.DestroyAtAge != later.Sub(created) {
		t.Fatalf("patch = %+v, %v", patched, err)
	}
	if _, _, err := svc.ApplyLifecyclePatch(ctx, "sb-at", func(*models.Sandbox) (models.Lifecycle, bool, error) {
		return models.Lifecycle{DestroyAt: &past}, true, nil
	}); err == nil {
		t.Fatal("patch with a past destroy_at accepted")
	}
}
