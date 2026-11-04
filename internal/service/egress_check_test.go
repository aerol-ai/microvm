package service

import (
	"context"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// TestCheckNetworkPolicy (P2-9): the matcher's answer, the operator default
// for a policy-less check, and a ceiling breach reported, not refused.
func TestCheckNetworkPolicy(t *testing.T) {
	svc, _, _ := newEgressHarness(t)
	ctx := context.Background()
	got, err := svc.CheckNetworkPolicy(ctx, models.NetworkPolicyCheckRequest{NetworkAllowOut: []string{"pypi.org"}, Destination: "pypi.org:443"})
	if err != nil || !got.Allowed || got.MatchedRule != "pypi.org" || got.DefaultVerdict != "deny" {
		t.Fatalf("got %+v, %v", got, err)
	}
	if got, _ := svc.CheckNetworkPolicy(ctx, models.NetworkPolicyCheckRequest{NetworkBlockAll: true, NetworkAllowOut: []string{"pypi.org"}, Destination: "pypi.org"}); got.Allowed {
		t.Fatal("block-all wins")
	}

	svc.SetEgressOperator(operatorWatcher(t, "version: 1\nceiling: {allow_out: [\"*.corp.bank.internal\"]}\ndefault_policy: {mode: allowlist, allow_out: [git.corp.bank.internal]}\n"))
	got, err = svc.CheckNetworkPolicy(ctx, models.NetworkPolicyCheckRequest{Destination: "git.corp.bank.internal"})
	if err != nil || !got.Allowed || got.OutsideCeiling != "" {
		t.Fatalf("a policy-less check sees the operator default: %+v, %v", got, err)
	}
	got, err = svc.CheckNetworkPolicy(ctx, models.NetworkPolicyCheckRequest{NetworkAllowOut: []string{"pypi.org"}, Destination: "pypi.org"})
	if err != nil || !got.Allowed || got.OutsideCeiling != "pypi.org" {
		t.Fatalf("ceiling breach must be reported: %+v, %v", got, err)
	}
	got, _ = svc.CheckNetworkPolicy(ctx, models.NetworkPolicyCheckRequest{NetworkDenyOut: []string{"10.0.0.0/8"}, Destination: "a.example"})
	if got.OutsideCeiling == "" {
		t.Fatal("a default-accept policy can't fit a ceiling")
	}
	if _, err := svc.CheckNetworkPolicy(ctx, models.NetworkPolicyCheckRequest{Destination: "bad host!"}); err == nil {
		t.Fatal("a bad destination is an error")
	}
}
