package service

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/pkg/egresspolicy"
	"github.com/aerol-ai/microvm/pkg/models"
)

// TestLearnModeLifecycle (P2-7, EF-48): a learn-mode create attaches the
// gateway in learn mode, GET and the policy answer say so, learn → enforce
// and back move the gateway, and destroy drops the recording.
func TestLearnModeLifecycle(t *testing.T) {
	svc, gw, _ := newPolicyHarness(t)
	ctx := context.Background()
	resp, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine", NetworkEgressMode: models.NetworkEgressModeLearn})
	if err != nil {
		t.Fatal(err)
	}
	if spec := gw.attached[resp.ID]; !spec.Learn || len(spec.AllowOut) != 0 {
		t.Fatalf("gateway spec = %+v", spec)
	}
	if resp.NetworkEgressMode != models.NetworkEgressModeLearn {
		t.Fatalf("create response mode = %q", resp.NetworkEgressMode)
	}
	got, err := svc.GetSandbox(ctx, resp.ID)
	if err != nil || got.NetworkEgressMode != models.NetworkEgressModeLearn || got.EgressStatus != EgressStatusActive {
		t.Fatalf("GET = %+v %v", got, err)
	}
	if list, _ := svc.ListSandboxes(ctx, nil); len(list) != 1 || list[0].NetworkEgressMode != models.NetworkEgressModeLearn {
		t.Fatalf("list must carry the mode: %+v", list)
	}
	spec, _ := svc.specFromSandbox(ctx, got)
	if spec.NetworkEgressMode != models.NetworkEgressModeLearn {
		t.Fatal("a replay must keep learn mode")
	}

	gw.learned = map[string]json.RawMessage{resp.ID: json.RawMessage(`{"truncated":true,"entries":[{"host":"pypi.org","ports":[443],"hits":2}],"cidrs":["203.0.113.9/32"],"suggested_allow_out":["pypi.org","203.0.113.9/32"],"suggested_profile":null}`)}
	learned, err := svc.GetNetworkLearned(ctx, resp.ID)
	if err != nil || learned.Mode != models.NetworkEgressModeLearn || !learned.Truncated || len(learned.Entries) != 1 || learned.Entries[0].Hits != 2 || len(learned.SuggestedAllowOut) != 2 {
		t.Fatalf("learned = %+v %v", learned, err)
	}

	// Lock it down with the suggestion: enforce mode, the learned list.
	pol, err := svc.UpdateNetworkPolicy(ctx, resp.ID, models.NetworkPolicyRequest{NetworkAllowOut: learned.SuggestedAllowOut})
	if err != nil || pol.NetworkEgressMode != models.NetworkEgressModeEnforce {
		t.Fatalf("lock = %+v %v", pol, err)
	}
	if spec := gw.attached[resp.ID]; spec.Learn || len(spec.AllowOut) != 2 {
		t.Fatalf("enforced gateway spec = %+v", spec)
	}
	// The recording stays readable after the switch.
	if learned, err := svc.GetNetworkLearned(ctx, resp.ID); err != nil || learned.Mode != models.NetworkEgressModeEnforce || len(learned.Entries) != 1 {
		t.Fatalf("after enforce = %+v %v", learned, err)
	}
	// Back to learn, then a repeat is a no-op.
	if pol, err := svc.UpdateNetworkPolicy(ctx, resp.ID, models.NetworkPolicyRequest{NetworkEgressMode: "learn"}); err != nil || pol.NetworkEgressMode != "learn" {
		t.Fatalf("relearn = %+v %v", pol, err)
	}
	if !gw.attached[resp.ID].Learn {
		t.Fatal("the gateway must be back in learn mode")
	}
	if err := svc.DestroySandbox(ctx, resp.ID); err != nil {
		t.Fatal(err)
	}
	if len(gw.forgotten) != 1 || gw.forgotten[0] != resp.ID {
		t.Fatalf("destroy must drop the recording: %v", gw.forgotten)
	}
}

func TestLearnModeRejects(t *testing.T) {
	svc, gw, _ := newPolicyHarness(t)
	ctx := ownerCtx("acct")
	putProfile(t, svc, ctx, "python", "pypi.org")
	for _, req := range []models.CreateSandboxRequest{
		{Image: "alpine", NetworkEgressMode: "learn", NetworkAllowOut: []string{"pypi.org"}},
		{Image: "alpine", NetworkEgressMode: "learn", NetworkBlockAll: true},
		{Image: "alpine", NetworkEgressMode: "learn", EgressProfiles: []string{"python"}},
		{Image: "alpine", NetworkEgressMode: "sometimes"},
	} {
		if _, err := svc.CreateSandbox(ctx, req); !errors.Is(err, egresspolicy.ErrInvalid) {
			t.Fatalf("%+v: err = %v", req, err)
		}
	}
	if _, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine", Runtime: models.RuntimeFirecracker, NetworkEgressMode: "learn"}); !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Fatalf("firecracker: err = %v", err)
	}
	// An explicit "enforce" is the default spelled out.
	resp, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine", NetworkEgressMode: "enforce"})
	if err != nil || resp.NetworkEgressMode != "" {
		t.Fatalf("enforce create = %+v %v", resp, err)
	}

	// A WASM driver that can't read recordings answers 501.
	seedPolicySandbox(t, svc, models.Sandbox{ID: "sb-wasm", Runtime: models.RuntimeWasm, OwnerRef: "acct"})
	if _, err := svc.GetNetworkLearned(ctx, "sb-wasm"); !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Fatalf("wasm learned: %v", err)
	}
	seedPolicySandbox(t, svc, models.Sandbox{ID: "sb-fc", Runtime: models.RuntimeFirecracker, OwnerRef: "acct"})
	if _, err := svc.GetNetworkLearned(ctx, "sb-fc"); !errors.Is(err, models.ErrRuntimeNotImplemented) {
		t.Fatalf("firecracker learned: %v", err)
	}
	gw.learnedErr = egress.ErrUnavailable
	if _, err := svc.GetNetworkLearned(ctx, resp.ID); !errors.Is(err, ErrEgressGatewayUnavailable) {
		t.Fatalf("gateway down: %v", err)
	}
	gw.learnedErr = nil
	gw.learned = map[string]json.RawMessage{resp.ID: json.RawMessage(`not json`)}
	if _, err := svc.GetNetworkLearned(ctx, resp.ID); err == nil {
		t.Fatal("an unreadable recording must be an error")
	}
	svc.cfg.EgressFQDNEnabled = false
	if _, err := svc.GetNetworkLearned(ctx, resp.ID); !errors.Is(err, ErrEgressGatewayRequired) {
		t.Fatalf("no gateway: %v", err)
	}
}

// TestUpdateNetworkListsLearnMode: a facade can't express learn mode, so its
// update keeps it, and setting lists on a learn-mode sandbox is a 409.
func TestUpdateNetworkListsLearnMode(t *testing.T) {
	svc, gw, _ := newPolicyHarness(t)
	ctx := context.Background()
	resp, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine", NetworkEgressMode: "learn"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.UpdateNetworkLists(ctx, resp.ID, false, []string{"1.1.1.0/24"}, nil); !errors.Is(err, ErrEgressLearnConflict) {
		t.Fatalf("lists on learn: %v", err)
	}
	if pol, err := svc.UpdateNetworkLists(ctx, resp.ID, false, nil, nil); err != nil || pol.NetworkEgressMode != "learn" || !gw.attached[resp.ID].Learn {
		t.Fatalf("empty update keeps learn: %+v %v", pol, err)
	}
}

func TestLearnedModelSuggestedProfile(t *testing.T) {
	m := learnedModel("", egresspolicy.Learned{SuggestedProfile: &egresspolicy.SuggestedProfile{AllowOut: []string{"a.example"}, Description: "d"}})
	if m.Mode != models.NetworkEgressModeEnforce || m.SuggestedProfile == nil || m.SuggestedProfile.Description != "d" || m.Entries == nil || m.SuggestedAllowOut == nil {
		t.Fatalf("model = %+v", m)
	}
}

// TestLearnModeMediatedRuntimes (P2-7): WASM and isolate take learn mode
// live and serve the recording their own mediators keep.
func TestLearnModeMediatedRuntimes(t *testing.T) {
	svc, _, rt := newPolicyHarness(t)
	ctx := context.Background()
	wasm, iso := newMediator(), newMediator()
	svc.wasm, svc.isolate = wasm, iso
	seedPolicySandbox(t, svc, models.Sandbox{ID: "sb-wasm", Runtime: models.RuntimeWasm})
	seedPolicySandbox(t, svc, models.Sandbox{ID: "sb-iso", Runtime: models.RuntimeIsolate})
	for _, id := range []string{"sb-wasm", "sb-iso"} {
		pol, err := svc.UpdateNetworkPolicy(ctx, id, models.NetworkPolicyRequest{NetworkEgressMode: "learn"})
		if err != nil || pol.NetworkEgressMode != "learn" {
			t.Fatalf("%s: %+v %v", id, pol, err)
		}
		learned, err := svc.GetNetworkLearned(ctx, id)
		if err != nil || learned.Mode != "learn" || len(learned.Entries) != 1 || learned.Entries[0].Host != id+".example" {
			t.Fatalf("%s learned = %+v %v", id, learned, err)
		}
	}
	if !wasm.learn["sb-wasm"] || !iso.learn["sb-iso"] {
		t.Fatal("the drivers must be told learn mode")
	}
	if rt.blockCalls != 0 {
		t.Fatal("mediated runtimes must not touch container netrules")
	}
	wasm.err = errors.New("worker gone")
	if _, err := svc.GetNetworkLearned(ctx, "sb-wasm"); err == nil {
		t.Fatal("a failed read must be an error")
	}
}
