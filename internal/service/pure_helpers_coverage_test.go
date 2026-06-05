package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Covers small pure helpers that carry rationale comments but had no
// direct unit coverage: ID generation shape, audit-field shaping, the
// stopMode String mapping, and the coalescer debug stringer.

func TestGenerateTemplateIDShape(t *testing.T) {
	id, err := generateTemplateID()
	if err != nil {
		t.Fatalf("generateTemplateID: %v", err)
	}
	if !strings.HasPrefix(id, "tpl-") {
		t.Fatalf("want tpl- prefix, got %q", id)
	}
	// "tpl-" + 16 hex chars (8 bytes).
	if len(id) != len("tpl-")+16 {
		t.Fatalf("want length %d, got %d (%q)", len("tpl-")+16, len(id), id)
	}
	// Two calls must not collide.
	id2, err := generateTemplateID()
	if err != nil {
		t.Fatalf("generateTemplateID 2: %v", err)
	}
	if id == id2 {
		t.Fatalf("expected distinct IDs, both %q", id)
	}
}

func TestFormatStopAuditFields(t *testing.T) {
	fields := formatStopAuditFields("sbx-1", stopModeLifecycle, true)
	// slog field slices are flat key/value pairs.
	if len(fields)%2 != 0 {
		t.Fatalf("expected even number of fields, got %d", len(fields))
	}
	got := map[string]any{}
	for i := 0; i < len(fields); i += 2 {
		key, ok := fields[i].(string)
		if !ok {
			t.Fatalf("field key %d not a string: %v", i, fields[i])
		}
		got[key] = fields[i+1]
	}
	if got["sandbox_id"] != "sbx-1" {
		t.Fatalf("sandbox_id = %v", got["sandbox_id"])
	}
	if got["stop_mode"] != "lifecycle" {
		t.Fatalf("stop_mode = %v", got["stop_mode"])
	}
	if got["wake_armed"] != true {
		t.Fatalf("wake_armed = %v", got["wake_armed"])
	}
}

func TestStopModeString(t *testing.T) {
	cases := map[stopMode]string{
		stopModeManual:      "manual",
		stopModeLifecycle:   "lifecycle",
		stopModeInvoluntary: "involuntary",
	}
	for mode, want := range cases {
		if got := mode.String(); got != want {
			t.Fatalf("stopMode(%d).String() = %q, want %q", int(mode), got, want)
		}
	}
	// Unknown value falls through to the formatted default.
	if got := stopMode(99).String(); !strings.Contains(got, "99") {
		t.Fatalf("unknown stopMode String() = %q, want it to contain 99", got)
	}
}

func TestIsSandboxStartedStatesAndCache(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)

	now := time.Now().UTC()
	seed := func(id string, status models.SandboxStatus) {
		if err := st.Create(ctx, &models.Sandbox{
			ID:           id,
			Image:        "alpine:3.20",
			Status:       status,
			Runtime:      models.RuntimeDocker,
			CPU:          1,
			MemoryMB:     512,
			DiskGB:       5,
			CreatedAt:    now,
			UpdatedAt:    now,
			LastActiveAt: now,
		}); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}

	seed("sb-started", models.SandboxStatusStarted)
	seed("sb-stopped", models.SandboxStatusStopped)

	started, err := svc.IsSandboxStarted(ctx, "sb-started")
	if err != nil || !started {
		t.Fatalf("IsSandboxStarted(started) = %v, %v; want true, nil", started, err)
	}
	// Second call should hit the warm-cache positive path.
	started2, err := svc.IsSandboxStarted(ctx, "sb-started")
	if err != nil || !started2 {
		t.Fatalf("IsSandboxStarted(started, cached) = %v, %v; want true, nil", started2, err)
	}

	stopped, err := svc.IsSandboxStarted(ctx, "sb-stopped")
	if err != nil || stopped {
		t.Fatalf("IsSandboxStarted(stopped) = %v, %v; want false, nil", stopped, err)
	}

	_, err = svc.IsSandboxStarted(ctx, "sb-missing")
	if !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("IsSandboxStarted(missing) err = %v, want ErrNotFound", err)
	}
}

func TestWakeAwarePortTarget(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID:           "sb-port",
		Image:        "alpine:3.20",
		Status:       models.SandboxStatusStarted,
		Runtime:      models.RuntimeDocker,
		ContainerIP:  "10.0.0.42",
		CPU:          1,
		MemoryMB:     512,
		DiskGB:       5,
		CreatedAt:    now,
		UpdatedAt:    now,
		LastActiveAt: now,
	}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}
	if err := st.UpsertPort(ctx, models.ExposedPort{
		SandboxID: "sb-port",
		Port:      8080,
		Protocol:  models.ExposedPortProtocolHTTP,
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("seed exposed port: %v", err)
	}

	ep, err := svc.WakeAwarePortTarget(ctx, "sb-port", 8080)
	if err != nil {
		t.Fatalf("WakeAwarePortTarget: %v", err)
	}
	if ep.URL != "http://10.0.0.42:8080" {
		t.Fatalf("URL = %q, want http://10.0.0.42:8080", ep.URL)
	}

	// Port that is not exposed → error.
	if _, err := svc.WakeAwarePortTarget(ctx, "sb-port", 9090); err == nil {
		t.Fatalf("expected error for unexposed port 9090")
	}
}

func TestCaddyCoalescerString(t *testing.T) {
	c := newCaddyCoalescer(nil, 100*time.Millisecond)
	s := c.String()
	if !strings.Contains(s, "caddyCoalescer{") {
		t.Fatalf("String() = %q", s)
	}
	if !strings.Contains(s, "pending=0") {
		t.Fatalf("fresh coalescer should report pending=0, got %q", s)
	}
}
