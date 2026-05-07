package service

import (
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestLifecycleActionFor(t *testing.T) {
	now := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)
	// helper to build a sandbox with explicit timestamps
	mk := func(status models.SandboxStatus, ageHours, idleHours float64, l models.Lifecycle) *models.Sandbox {
		return &models.Sandbox{
			Status:       status,
			CreatedAt:    now.Add(-time.Duration(ageHours * float64(time.Hour))),
			LastActiveAt: now.Add(-time.Duration(idleHours * float64(time.Hour))),
			Lifecycle:    l,
		}
	}

	cases := []struct {
		name       string
		sandbox    *models.Sandbox
		globalIdle time.Duration
		want       lifecycleAction
	}{
		{
			name:    "nil_sandbox_returns_none",
			sandbox: nil,
			want:    lifecycleNone,
		},
		{
			name:    "destroyed_sandbox_returns_none_even_with_timers",
			sandbox: mk(models.SandboxStatusDestroyed, 100, 100, models.Lifecycle{DestroyAtAge: time.Hour}),
			want:    lifecycleNone,
		},
		{
			name:    "no_timers_no_global_idle_returns_none",
			sandbox: mk(models.SandboxStatusStarted, 100, 100, models.Lifecycle{}),
			want:    lifecycleNone,
		},
		{
			name:    "stop_if_idle_fires_when_idle_exceeds",
			sandbox: mk(models.SandboxStatusStarted, 5, 2, models.Lifecycle{StopIfIdleFor: time.Hour}),
			want:    lifecycleStop,
		},
		{
			name:    "stop_if_idle_does_not_fire_when_idle_below",
			sandbox: mk(models.SandboxStatusStarted, 5, 0.5, models.Lifecycle{StopIfIdleFor: time.Hour}),
			want:    lifecycleNone,
		},
		{
			name:    "destroy_if_idle_fires_when_idle_exceeds",
			sandbox: mk(models.SandboxStatusStarted, 5, 4, models.Lifecycle{DestroyIfIdleFor: 2 * time.Hour}),
			want:    lifecycleDestroy,
		},
		{
			name: "destroy_if_idle_takes_priority_over_stop_if_idle",
			// Both timers fired; destroy should win.
			sandbox: mk(models.SandboxStatusStarted, 5, 4, models.Lifecycle{
				StopIfIdleFor:    time.Hour,
				DestroyIfIdleFor: 2 * time.Hour,
			}),
			want: lifecycleDestroy,
		},
		{
			name:    "stop_at_age_fires_when_age_exceeds",
			sandbox: mk(models.SandboxStatusStarted, 3, 0, models.Lifecycle{StopAtAge: 2 * time.Hour}),
			want:    lifecycleStop,
		},
		{
			name:    "destroy_at_age_fires_when_age_exceeds",
			sandbox: mk(models.SandboxStatusStarted, 25, 0, models.Lifecycle{DestroyAtAge: 24 * time.Hour}),
			want:    lifecycleDestroy,
		},
		{
			name: "destroy_at_age_takes_priority_over_stop_at_age",
			sandbox: mk(models.SandboxStatusStarted, 25, 0, models.Lifecycle{
				StopAtAge:    2 * time.Hour,
				DestroyAtAge: 24 * time.Hour,
			}),
			want: lifecycleDestroy,
		},
		{
			name: "destroy_at_age_fires_for_stopped_sandbox_too",
			// Stopped sandboxes still age. Destroy must fire so they
			// don't accumulate forever.
			sandbox: mk(models.SandboxStatusStopped, 25, 0, models.Lifecycle{DestroyAtAge: 24 * time.Hour}),
			want:    lifecycleDestroy,
		},
		{
			name: "stop_at_age_does_not_fire_for_already_stopped",
			// Stopping an already-stopped sandbox is a no-op; we skip it
			// to avoid pointless Docker calls + log noise.
			sandbox: mk(models.SandboxStatusStopped, 3, 0, models.Lifecycle{StopAtAge: 2 * time.Hour}),
			want:    lifecycleNone,
		},
		{
			name:       "global_idle_fires_when_no_per_sandbox_config",
			sandbox:    mk(models.SandboxStatusStarted, 5, 2, models.Lifecycle{}),
			globalIdle: time.Hour,
			want:       lifecycleStop,
		},
		{
			name: "global_idle_ignored_when_per_sandbox_config_present",
			// User set DestroyAtAge but no idle stop. Global idle
			// fallback must NOT fire — explicit per-sandbox config
			// supersedes global, even when only one axis is set.
			sandbox:    mk(models.SandboxStatusStarted, 5, 2, models.Lifecycle{DestroyAtAge: 24 * time.Hour}),
			globalIdle: time.Hour,
			want:       lifecycleNone,
		},
		{
			name:       "global_idle_does_not_apply_to_non_started",
			sandbox:    mk(models.SandboxStatusStopped, 5, 2, models.Lifecycle{}),
			globalIdle: time.Hour,
			want:       lifecycleNone,
		},
		{
			name: "wall_clock_destroy_after_stopped_still_destroys",
			// Restart-resets-clock scenario: sandbox is stopped, age 25h,
			// DestroyAtAge=24h. Even though stop already happened,
			// destroy fires to release the row + image.
			sandbox: mk(models.SandboxStatusStopped, 25, 0, models.Lifecycle{
				StopAtAge:    2 * time.Hour,
				DestroyAtAge: 24 * time.Hour,
			}),
			want: lifecycleDestroy,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := lifecycleActionFor(tc.sandbox, now, tc.globalIdle)
			if got != tc.want {
				t.Fatalf("lifecycleActionFor = %v, want %v", got, tc.want)
			}
		})
	}
}
