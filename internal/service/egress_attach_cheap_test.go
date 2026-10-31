package service

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/pkg/createtiming"
	"github.com/aerol-ai/microvm/pkg/models"
)

// TestAttachStagesAreTimed: a hostname-rule create reports the attach's
// sub-stages next to svc_egress_attach, so a live run (UC-185) can tell the
// gateway round trip from the store reads and the host-firewall lift.
func TestAttachStagesAreTimed(t *testing.T) {
	svc, _, _ := newEgressHarness(t)
	var seen []string
	svc.testAttachStage = func(stage string, d time.Duration) {
		if d < 0 {
			t.Errorf("stage %s: negative duration", stage)
		}
		seen = append(seen, stage)
	}
	ctx, timing := createtiming.With(context.Background())
	if _, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine", NetworkAllowOut: []string{"pypi.org"}}); err != nil {
		t.Fatal(err)
	}
	want := []string{attachStageLookup, attachStageReady, attachStageRPC, attachStageRelease, attachStageUnblock}
	if !slices.Equal(seen, want) {
		t.Fatalf("stages %v, want %v in order", seen, want)
	}
	got := map[string]bool{}
	for _, st := range timing.Stages() {
		got[st.Name] = true
	}
	for _, name := range append([]string{"svc_egress_attach", "svc_egress_join"}, prefixed("svc_egress_attach_", want)...) {
		if !got[name] {
			t.Errorf("Server-Timing lacks %s (have %v)", name, timing.Stages())
		}
	}
	// No create, no Server-Timing: an attach from start or reconcile
	// times its stages into the span only.
	seen = nil
	sb := &models.Sandbox{ID: "sb-recon", ContainerIP: "10.0.0.40", Runtime: models.RuntimeDocker, NetworkAllowOut: []string{"pypi.org"}}
	if err := svc.attachSandboxEgress(context.Background(), sb, svc.docker.(*holdRuntime)); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(seen, want) {
		t.Fatalf("stages outside a create %v, want %v", seen, want)
	}
}

func prefixed(p string, xs []string) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = p + x
	}
	return out
}

// TestAttachHoldRelease is the hold contract of one attach, as a table. A
// hold the attach read is lifted when the attach resolves its class (a
// gateway hold) and kept otherwise; a hold recorded after the attach read
// the store is never lifted by it (fail closed: its own retry lifts it),
// which is what lets a create skip the second store read.
func TestAttachHoldRelease(t *testing.T) {
	for _, tc := range []struct {
		name       string
		before     string // hold recorded before the attach
		midAttach  string // hold recorded between the read and the release
		wantHold   string
		wantUnhold int
	}{
		{name: "none", wantHold: ""},
		{name: "gateway hold before: lifted", before: egressHoldAttachFailed, wantHold: "", wantUnhold: 1},
		{name: "apply hold before: kept", before: egressHoldApplyFailed, wantHold: egressHoldApplyFailed},
		{name: "profile hold before: kept", before: egressHoldProfileUnavailable, wantHold: egressHoldProfileUnavailable},
		{name: "gateway hold during: kept for its retry", midAttach: egressHoldUnavailable, wantHold: egressHoldUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, gw, rt := newEgressHarness(t)
			ctx := context.Background()
			now := time.Now().UTC()
			sb := &models.Sandbox{ID: "sb-hold", Image: "alpine", Status: models.SandboxStatusStarted, ContainerID: "ctr-hold", ContainerIP: "10.0.0.41",
				Runtime: models.RuntimeDocker, NetworkAllowOut: []string{"pypi.org"}, CreatedAt: now, UpdatedAt: now, LastActiveAt: now}
			if err := svc.store.Create(ctx, sb); err != nil {
				t.Fatal(err)
			}
			if tc.before != "" {
				svc.holdSandboxEgress(ctx, sb, rt, tc.before)
			}
			if tc.midAttach != "" {
				svc.testAttachStage = func(stage string, _ time.Duration) {
					if stage == attachStageRPC {
						svc.holdSandboxEgress(ctx, sb, rt, tc.midAttach)
					}
				}
			}
			if err := svc.attachSandboxEgress(ctx, sb, rt); err != nil {
				t.Fatal(err)
			}
			st, err := svc.store.GetEgressState(ctx, sb.ID)
			if err != nil {
				t.Fatal(err)
			}
			if st.HoldReason != tc.wantHold {
				t.Fatalf("hold = %q, want %q", st.HoldReason, tc.wantHold)
			}
			if len(rt.unhold) != tc.wantUnhold {
				t.Fatalf("hold DROP lifted %d times, want %d", len(rt.unhold), tc.wantUnhold)
			}
			if tc.wantHold != "" && gw.blocked[sb.ID]&egress.BlockHold == 0 {
				t.Fatal("a held sandbox must stay blocked at the gateway")
			}
			// The driver's block-all is lifted whatever the hold: the hold
			// has its own DROP and gateway block.
			if !slices.Contains(rt.clearNetworkBlockEgresses, sb.ContainerIP) {
				t.Fatal("the attach must lift the driver block")
			}
		})
	}
}

// TestAttachErrorsKeepTheirClass: the stage instrumentation is not on any
// error path's way: each failure still returns before the driver block is
// lifted, with the error class callers map (503, hold).
func TestAttachErrorsKeepTheirClass(t *testing.T) {
	svc, gw, rt := newEgressHarness(t)
	ctx := context.Background()
	sb := &models.Sandbox{ID: "sb-err", ContainerIP: "10.0.0.42", Runtime: models.RuntimeDocker, NetworkAllowOut: []string{"pypi.org"}}
	gw.attachErr = egress.ErrUnavailable
	err := svc.attachSandboxEgress(ctx, sb, rt)
	if err == nil || !strings.Contains(err.Error(), egress.ErrUnavailable.Error()) {
		t.Fatalf("err = %v, want the gateway's unavailable", err)
	}
	if slices.Contains(rt.clearNetworkBlockEgresses, sb.ContainerIP) {
		t.Fatal("a failed attach must never lift the driver block")
	}
	if svc.egressReady.Load() {
		t.Fatal("an unavailable gateway must drop the ready latch")
	}
}
