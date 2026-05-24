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
		kind             RouteKind
		sandbox          *models.Sandbox
		want             RouteShape
	}{
		{
			name: "nil_sandbox",
			kind: RouteKindHTTP,
			want: RouteShapeNone,
		},
		{
			name:    "destroyed_serverless_returns_none",
			kind:    RouteKindHTTP,
			sandbox: mk(models.SandboxStatusDestroyed, "10.0.0.1", true, true),
			want:    RouteShapeNone,
		},
		{
			name:             "destroyed_non_serverless_returns_none",
			enableServerless: true,
			kind:             RouteKindHTTP,
			sandbox:          mk(models.SandboxStatusDestroyed, "10.0.0.1", false, false),
			want:             RouteShapeNone,
		},
		{
			// Non-serverless always gets direct, even when bypass is off —
			// the bypass flag is a serverless-only knob.
			name:    "non_serverless_started_direct",
			kind:    RouteKindHTTP,
			sandbox: mk(models.SandboxStatusStarted, "10.0.0.1", false, false),
			want:    RouteShapeDirect,
		},
		{
			// Serverless flag on the row but rollout gate off → falls back
			// to non-serverless behavior (direct).
			name:    "serverless_but_rollout_gate_off_direct",
			kind:    RouteKindHTTP,
			sandbox: mk(models.SandboxStatusStarted, "10.0.0.1", false, true),
			want:    RouteShapeDirect,
		},
		{
			// Bypass off → every serverless route is wake-shape regardless
			// of running state. This is today's behavior pre-rollout.
			name:             "serverless_bypass_off_started_wake",
			enableServerless: true,
			kind:             RouteKindHTTP,
			sandbox:          mk(models.SandboxStatusStarted, "10.0.0.1", false, true),
			want:             RouteShapeWake,
		},
		{
			name:             "serverless_bypass_off_stopped_armed_wake",
			enableServerless: true,
			kind:             RouteKindHTTP,
			sandbox:          mk(models.SandboxStatusStopped, "", true, true),
			want:             RouteShapeWake,
		},
		{
			name:             "serverless_bypass_off_stopped_unarmed_wake",
			enableServerless: true,
			kind:             RouteKindHTTP,
			sandbox:          mk(models.SandboxStatusStopped, "", false, true),
			want:             RouteShapeWake,
		},
		{
			// Bypass on + warm row with IP → direct (the whole point).
			name:             "serverless_bypass_on_started_with_ip_direct",
			enableServerless: true,
			bypassEnabled:    true,
			kind:             RouteKindHTTP,
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
			kind:             RouteKindHTTP,
			sandbox:          mk(models.SandboxStatusStarted, "", false, true),
			want:             RouteShapeNone,
		},
		{
			// Bypass on + Stopped + armed → wake-shape (the warm/cold
			// switch in action).
			name:             "serverless_bypass_on_stopped_armed_wake",
			enableServerless: true,
			bypassEnabled:    true,
			kind:             RouteKindHTTP,
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
			kind:             RouteKindHTTP,
			sandbox:          mk(models.SandboxStatusStopped, "", false, true),
			want:             RouteShapeNone,
		},
		{
			// Bypass on + transient state (Creating) → none. Lets the
			// caller wait one tick before publishing anything.
			name:             "serverless_bypass_on_creating_none",
			enableServerless: true,
			bypassEnabled:    true,
			kind:             RouteKindHTTP,
			sandbox:          mk(models.SandboxStatusCreating, "", false, true),
			want:             RouteShapeNone,
		},
		{
			// L4 with its own bypass off but HTTP bypass on → wake.
			// Each kind reads only its own flag; cross-kind leakage would
			// break the independent rollout the two env vars promise.
			name:             "l4_bypass_off_started_with_ip_wake_even_when_http_on",
			enableServerless: true,
			bypassEnabled:    true,
			kind:             RouteKindL4,
			sandbox:          mk(models.SandboxStatusStarted, "10.0.0.1", false, true),
			want:             RouteShapeWake,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := &Service{cfg: config.Config{
				EnableServerless:            tc.enableServerless,
				HTTPWakeDirectBypassEnabled: tc.bypassEnabled,
			}}
			got := svc.chooseRouteShape(tc.sandbox, tc.kind)
			if got != tc.want {
				t.Fatalf("chooseRouteShape = %s, want %s", got, tc.want)
			}
		})
	}
}

// TestChooseRouteShapeL4 covers the L4-kind branches that mirror HTTP
// once SB_L4_WAKE_DIRECT_BYPASS_ENABLED is on. The cross-kind isolation
// case (HTTP on, L4 off) lives in TestChooseRouteShape — these focus on
// proving the L4 decision tree itself agrees with HTTP once the L4 flag
// is on.
func TestChooseRouteShapeL4(t *testing.T) {
	mk := func(status models.SandboxStatus, ip string, wakeArmed bool) *models.Sandbox {
		return &models.Sandbox{
			Status:      status,
			ContainerIP: ip,
			WakeArmed:   wakeArmed,
			Lifecycle:   models.Lifecycle{Serverless: true},
		}
	}
	svc := &Service{cfg: config.Config{
		EnableServerless:          true,
		L4WakeDirectBypassEnabled: true,
	}}
	cases := []struct {
		name    string
		sandbox *models.Sandbox
		want    RouteShape
	}{
		{"l4_bypass_on_started_with_ip_direct", mk(models.SandboxStatusStarted, "10.0.0.1", false), RouteShapeDirect},
		{"l4_bypass_on_started_no_ip_none", mk(models.SandboxStatusStarted, "", false), RouteShapeNone},
		{"l4_bypass_on_stopped_armed_wake", mk(models.SandboxStatusStopped, "", true), RouteShapeWake},
		{"l4_bypass_on_stopped_unarmed_none", mk(models.SandboxStatusStopped, "", false), RouteShapeNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := svc.chooseRouteShape(tc.sandbox, RouteKindL4); got != tc.want {
				t.Fatalf("chooseRouteShape(L4) = %s, want %s", got, tc.want)
			}
		})
	}
}

// TestAnyBypassEnabled proves the OR helper that activityFloorFor /
// netstatsPollIsStale rely on — when either protocol's bypass is on,
// the netstats activity floor must be live since warm traffic of that
// protocol no longer bumps LastActiveAt through the per-request path.
func TestAnyBypassEnabled(t *testing.T) {
	cases := []struct {
		name string
		http bool
		l4   bool
		want bool
	}{
		{"both_off", false, false, false},
		{"http_only", true, false, true},
		{"l4_only", false, true, true},
		{"both_on", true, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := &Service{cfg: config.Config{
				HTTPWakeDirectBypassEnabled: tc.http,
				L4WakeDirectBypassEnabled:   tc.l4,
			}}
			if got := svc.anyBypassEnabled(); got != tc.want {
				t.Fatalf("anyBypassEnabled = %v, want %v", got, tc.want)
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
