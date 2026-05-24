package service

import (
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
)

// TestChooseRouteShape exercises every branch of the decision tree.
// The function is pure, so the harness is just two cfg knobs and a
// constructed sandbox row — no store, no Caddy. Each cell of
// (status × wake_armed × bypass_on × serverless × container_ip) is
// represented so a regression in any one branch produces a single
// labeled failure.
func TestChooseRouteShape(t *testing.T) {
	mk := func(status models.SandboxStatus, ip string, wakeArmed, serverless bool) *models.Sandbox {
		return &models.Sandbox{
			Status:      status,
			ContainerIP: ip,
			WakeArmed:   wakeArmed,
			Lifecycle:   models.Lifecycle{Serverless: serverless},
		}
	}

	cases := []struct {
		name             string
		enableServerless bool
		bypassEnabled    bool
		sandbox          *models.Sandbox
		want             RouteShape
	}{
		{
			name: "nil_sandbox",
			want: RouteShapeNone,
		},
		{
			name:    "destroyed_serverless_returns_none",
			sandbox: mk(models.SandboxStatusDestroyed, "10.0.0.1", true, true),
			want:    RouteShapeNone,
		},
		{
			name:             "destroyed_non_serverless_returns_none",
			enableServerless: true,
			sandbox:          mk(models.SandboxStatusDestroyed, "10.0.0.1", false, false),
			want:             RouteShapeNone,
		},
		{
			// Non-serverless always gets direct, even when bypass is off —
			// the bypass flag is a serverless-only knob.
			name:    "non_serverless_started_direct",
			sandbox: mk(models.SandboxStatusStarted, "10.0.0.1", false, false),
			want:    RouteShapeDirect,
		},
		{
			// Serverless flag on the row but rollout gate off → falls back
			// to non-serverless behavior (direct).
			name:    "serverless_but_rollout_gate_off_direct",
			sandbox: mk(models.SandboxStatusStarted, "10.0.0.1", false, true),
			want:    RouteShapeDirect,
		},
		{
			// Bypass off → every serverless route is wake-shape regardless
			// of running state. This is today's behavior pre-rollout.
			name:             "serverless_bypass_off_started_wake",
			enableServerless: true,
			sandbox:          mk(models.SandboxStatusStarted, "10.0.0.1", false, true),
			want:             RouteShapeWake,
		},
		{
			name:             "serverless_bypass_off_stopped_armed_wake",
			enableServerless: true,
			sandbox:          mk(models.SandboxStatusStopped, "", true, true),
			want:             RouteShapeWake,
		},
		{
			name:             "serverless_bypass_off_stopped_unarmed_wake",
			enableServerless: true,
			sandbox:          mk(models.SandboxStatusStopped, "", false, true),
			want:             RouteShapeWake,
		},
		{
			// Bypass on + warm row with IP → direct (the whole point).
			name:             "serverless_bypass_on_started_with_ip_direct",
			enableServerless: true,
			bypassEnabled:    true,
			sandbox:          mk(models.SandboxStatusStarted, "10.0.0.1", false, true),
			want:             RouteShapeDirect,
		},
		{
			// Bypass on + Started but no IP yet → none. Callsite is in a
			// transient window between status flip and IP discovery; the
			// event/reconcile path retries once the IP lands.
			name:             "serverless_bypass_on_started_no_ip_none",
			enableServerless: true,
			bypassEnabled:    true,
			sandbox:          mk(models.SandboxStatusStarted, "", false, true),
			want:             RouteShapeNone,
		},
		{
			// Bypass on + Stopped + armed → wake-shape (the warm/cold
			// switch in action).
			name:             "serverless_bypass_on_stopped_armed_wake",
			enableServerless: true,
			bypassEnabled:    true,
			sandbox:          mk(models.SandboxStatusStopped, "", true, true),
			want:             RouteShapeWake,
		},
		{
			// Bypass on + Stopped + UNARMED → none. The sandbox was
			// manually stopped, so it must not auto-resume on the next
			// request. Caddy's 404 fallback handles inbound traffic.
			name:             "serverless_bypass_on_stopped_unarmed_none",
			enableServerless: true,
			bypassEnabled:    true,
			sandbox:          mk(models.SandboxStatusStopped, "", false, true),
			want:             RouteShapeNone,
		},
		{
			// Bypass on + transient state (Creating) → none. Lets the
			// caller wait one tick before publishing anything.
			name:             "serverless_bypass_on_creating_none",
			enableServerless: true,
			bypassEnabled:    true,
			sandbox:          mk(models.SandboxStatusCreating, "", false, true),
			want:             RouteShapeNone,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := &Service{cfg: config.Config{
				EnableServerless:            tc.enableServerless,
				HTTPWakeDirectBypassEnabled: tc.bypassEnabled,
			}}
			got := svc.chooseRouteShape(tc.sandbox)
			if got != tc.want {
				t.Fatalf("chooseRouteShape = %s, want %s", got, tc.want)
			}
		})
	}
}

// TestRouteShapeString covers the String() helper since the slog audit
// lines depend on the labels matching the documented enum names.
func TestRouteShapeString(t *testing.T) {
	cases := []struct {
		shape RouteShape
		want  string
	}{
		{RouteShapeNone, "none"},
		{RouteShapeDirect, "direct"},
		{RouteShapeWake, "wake"},
		{RouteShape(99), "none"},
	}
	for _, tc := range cases {
		if got := tc.shape.String(); got != tc.want {
			t.Errorf("RouteShape(%d).String() = %q, want %q", int(tc.shape), got, tc.want)
		}
	}
}
