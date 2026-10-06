package service

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// firewalledFC is a Firecracker runtime whose node has the guest firewall
// (egress Phase 4).
type firewalledFC struct{ *policyRuntime }

func (firewalledFC) NetRulesEnabled() bool { return true }

// TestFirecrackerEgress (Phase 4): with the guest firewall, block-all and
// CIDR lists reach the driver at create and change live; hostname entries,
// profiles, learn mode and rules stay 501 until the gateway reaches the
// TAPs.
func TestFirecrackerEgress(t *testing.T) {
	ctx := context.Background()
	svc, _, rt := newPolicyHarness(t)
	svc.cfg.EnableFirecracker = true
	svc.admitter = nil
	fc := firewalledFC{rt}
	svc.SetFirecrackerRuntime(fc)

	resp, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Runtime: models.RuntimeFirecracker, Image: "docker://alpine",
		NetworkAllowOut: []string{"1.1.1.0/24"}, NetworkDenyOut: []string{"0.0.0.0/0"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := rt.lastCreateReq; !slices.Equal(got.NetworkAllowOut, []string{"1.1.1.0/24"}) {
		t.Fatalf("driver got %+v", got)
	}
	putProfile(t, svc, ctx, "p", "1.1.1.0/24")
	for name, req := range map[string]models.CreateSandboxRequest{
		"hostname": {NetworkAllowOut: []string{"pypi.org"}},
		"profiles": {EgressProfiles: []string{"p"}},
		"learn":    {NetworkEgressMode: models.NetworkEgressModeLearn},
		"rules":    {NetworkAllowOut: []string{"1.1.1.0/24"}, NetworkEgressRules: []models.EgressRule{{Host: "x"}}},
	} {
		req.Runtime, req.Image = models.RuntimeFirecracker, "docker://alpine"
		if _, err := svc.CreateSandbox(ctx, req); !errors.Is(err, models.ErrRuntimeNotImplemented) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if err := svc.checkFirecrackerEgress(&models.CreateSandboxRequest{NetworkAllowOut: []string{"bad entry"}}); err == nil {
		t.Fatal("a bad entry is a 400, not a pass")
	}

	// Live: block-all, then back to a CIDR list, through the guest firewall.
	row, _ := svc.store.Get(ctx, resp.ID)
	row.Status = models.SandboxStatusStarted
	if err := svc.store.Upsert(ctx, row); err != nil {
		t.Fatal(err)
	}
	before := rt.blockCalls
	if _, err := svc.UpdateNetworkPolicy(ctx, resp.ID, models.NetworkPolicyRequest{NetworkBlockAll: true}); err != nil {
		t.Fatal(err)
	}
	if rt.blockCalls == before {
		t.Fatal("block-all must reach the guest firewall")
	}
	if _, err := svc.UpdateNetworkPolicy(ctx, resp.ID, models.NetworkPolicyRequest{NetworkAllowOut: []string{"8.8.8.0/24"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.UpdateNetworkPolicy(ctx, resp.ID, models.NetworkPolicyRequest{NetworkAllowOut: []string{"pypi.org"}}); !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Fatalf("hostname live: %v", err)
	}

	// No firewall on the node: refused, as before.
	svc.SetFirecrackerRuntime(rt)
	if _, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Runtime: models.RuntimeFirecracker, Image: "docker://alpine", NetworkBlockAll: true}); !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Fatalf("no firewall: %v", err)
	}
}
