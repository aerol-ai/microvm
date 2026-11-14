package service

import (
	"context"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// TestDefaultLifecycleAppliesOnlyWithoutTimers is plan L4: the server's
// default destroy timers fill a create with no timers of its own and never
// change one that has its own.
func TestDefaultLifecycleAppliesOnlyWithoutTimers(t *testing.T) {
	const (
		idle = 2 * time.Hour
		age  = 7 * 24 * time.Hour
	)
	cases := []struct {
		name       string
		idle, age  time.Duration
		legacyMins int
		in         *models.Lifecycle
		want       *models.Lifecycle
	}{
		{name: "defaults off", in: nil, want: nil},
		{name: "defaults off keeps a lifecycle", in: &models.Lifecycle{StopAtAge: time.Hour}, want: &models.Lifecycle{StopAtAge: time.Hour}},
		{name: "no lifecycle gets both", idle: idle, age: age, in: nil, want: &models.Lifecycle{DestroyIfIdleFor: idle, DestroyAtAge: age}},
		{name: "empty lifecycle gets the idle default", idle: idle, in: &models.Lifecycle{}, want: &models.Lifecycle{DestroyIfIdleFor: idle}},
		{name: "only max age", age: age, in: nil, want: &models.Lifecycle{DestroyAtAge: age}},
		{name: "own timers untouched", idle: idle, age: age, in: &models.Lifecycle{StopIfIdleFor: time.Minute}, want: &models.Lifecycle{StopIfIdleFor: time.Minute}},
		{name: "own destroy untouched", idle: idle, age: age, in: &models.Lifecycle{DestroyAtAge: time.Hour}, want: &models.Lifecycle{DestroyAtAge: time.Hour}},
		{name: "after-exit is a timer of its own", idle: idle, in: &models.Lifecycle{DestroyAfterExitFor: time.Minute}, want: &models.Lifecycle{DestroyAfterExitFor: time.Minute}},
		{name: "serverless untouched", idle: idle, in: &models.Lifecycle{StopIfIdleFor: time.Minute, Serverless: true}, want: &models.Lifecycle{StopIfIdleFor: time.Minute, Serverless: true}},
		{name: "restart flag kept, defaults added", idle: idle, in: &models.Lifecycle{RestartOnFailure: true}, want: &models.Lifecycle{DestroyIfIdleFor: idle, RestartOnFailure: true}},
		{name: "legacy idle stop written when it comes first", idle: idle, legacyMins: 30, in: nil, want: &models.Lifecycle{StopIfIdleFor: 30 * time.Minute, DestroyIfIdleFor: idle}},
		{name: "legacy idle stop with only max age", age: age, legacyMins: 30, in: nil, want: &models.Lifecycle{StopIfIdleFor: 30 * time.Minute, DestroyAtAge: age}},
		{name: "legacy idle stop after the destroy is left out", idle: idle, legacyMins: 180, in: nil, want: &models.Lifecycle{DestroyIfIdleFor: idle}},
		{name: "legacy idle stop over 30 days is left out", age: age, legacyMins: 31 * 24 * 60, in: nil, want: &models.Lifecycle{DestroyAtAge: age}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := &Service{}
			svc.cfg.DefaultDestroyIfIdleFor, svc.cfg.MaxAge, svc.cfg.IdleTimeoutMinutes = tc.idle, tc.age, tc.legacyMins
			got := svc.withDefaultLifecycle(tc.in)
			switch {
			case tc.want == nil && got != nil:
				t.Fatalf("got %+v, want nil", *got)
			case tc.want != nil && (got == nil || *got != *tc.want):
				t.Fatalf("got %+v, want %+v", got, *tc.want)
			}
			if got != nil {
				if err := got.Validate(); err != nil {
					t.Fatalf("result fails validation: %v", err)
				}
			}
		})
	}
}

// TestDefaultLifecycleOnCreate: a real create stores the defaults on a
// sandbox that set none and leaves one with its own timers alone; turning
// the defaults on does not reach a sandbox created before.
func TestDefaultLifecycleOnCreate(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	before, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine"})
	if err != nil {
		t.Fatalf("create before: %v", err)
	}
	svc.cfg.DefaultDestroyIfIdleFor, svc.cfg.MaxAge = time.Hour, 24*time.Hour

	plain, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine"})
	if err != nil {
		t.Fatalf("create plain: %v", err)
	}
	if plain.Lifecycle.DestroyIfIdleFor != time.Hour || plain.Lifecycle.DestroyAtAge != 24*time.Hour {
		t.Fatalf("create response lifecycle = %+v", plain.Lifecycle)
	}
	stored, err := st.Get(ctx, plain.ID)
	if err != nil || stored.Lifecycle.DestroyIfIdleFor != time.Hour || stored.Lifecycle.DestroyAtAge != 24*time.Hour {
		t.Fatalf("stored lifecycle = %+v, %v", stored, err)
	}

	own, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine", Lifecycle: &models.Lifecycle{StopAtAge: time.Minute}})
	if err != nil {
		t.Fatalf("create own: %v", err)
	}
	if own.Lifecycle != (models.Lifecycle{StopAtAge: time.Minute}) {
		t.Fatalf("own timers changed: %+v", own.Lifecycle)
	}
	old, err := st.Get(ctx, before.ID)
	if err != nil || !old.Lifecycle.IsZero() {
		t.Fatalf("a sandbox created before the defaults got them: %+v %v", old, err)
	}
}
