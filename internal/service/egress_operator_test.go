package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/egress/operator"
	"github.com/aerol-ai/microvm/pkg/models"
)

func operatorWatcher(t *testing.T, body string) *operator.Watcher {
	t.Helper()
	path := filepath.Join(t.TempDir(), "egress-policy.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return operator.NewWatcher(path, nil, nil)
}

// TestOperatorDefaultPolicyIsStored (EF-80): a create with no egress fields
// gets the operator default written into its spec; one that says anything
// about egress keeps what it said; a failover replay is never rewritten.
func TestOperatorDefaultPolicyIsStored(t *testing.T) {
	svc, _, _ := newEgressHarness(t)
	svc.SetEgressOperator(operatorWatcher(t, "version: 1\ndefault_policy: {mode: allowlist, allow_out: [pypi.org, \"org:mirrors\"]}\norg_profiles:\n  mirrors: {allow_out: [\"*.npmjs.org\"]}\n"))
	ctx := context.Background()
	resp, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine"})
	if err != nil {
		t.Fatal(err)
	}
	sb, _ := svc.store.Get(ctx, resp.ID)
	if len(sb.NetworkAllowOut) != 2 || sb.NetworkAllowOut[0] != "pypi.org" || sb.NetworkAllowOut[1] != "*.npmjs.org" {
		t.Fatalf("stored allow_out = %v, want the default with org refs expanded", sb.NetworkAllowOut)
	}
	req := models.CreateSandboxRequest{NetworkAllowOut: []string{"10.0.0.0/8"}}
	if err := svc.applyEgressOperatorPolicy(&req, false); err != nil || len(req.NetworkAllowOut) != 1 {
		t.Fatalf("explicit policy rewritten: %v %v", req.NetworkAllowOut, err)
	}
	replay := models.CreateSandboxRequest{}
	if err := svc.applyEgressOperatorPolicy(&replay, true); err != nil || hasEgressFields(&replay) {
		t.Fatal("a replayed stored spec must not get today's default")
	}

	svc.SetEgressOperator(operatorWatcher(t, "version: 1\ndefault_policy: {mode: block_all}\n"))
	blocked := models.CreateSandboxRequest{}
	if err := svc.applyEgressOperatorPolicy(&blocked, false); err != nil || !blocked.NetworkBlockAll {
		t.Fatal("block_all default")
	}
	svc.SetEgressOperator(operatorWatcher(t, "version: 1\n"))
	open := models.CreateSandboxRequest{}
	if err := svc.applyEgressOperatorPolicy(&open, false); err != nil || hasEgressFields(&open) {
		t.Fatal("open default keeps today's behavior")
	}
}

// TestOperatorCeiling (EF-80): entries outside the ceiling are refused
// naming the entry; a default-accept policy can't fit; block-all fits.
func TestOperatorCeiling(t *testing.T) {
	svc, _, _ := newEgressHarness(t)
	svc.SetEgressOperator(operatorWatcher(t, "version: 1\nceiling: {allow_out: [\"*.corp.bank.internal\", 10.0.0.0/8]}\ndefault_policy: {mode: block_all}\n"))
	for _, tc := range []struct {
		req models.CreateSandboxRequest
		ok  bool
	}{
		{models.CreateSandboxRequest{NetworkAllowOut: []string{"git.corp.bank.internal:22", "10.1.0.0/16"}}, true},
		{models.CreateSandboxRequest{NetworkAllowOut: []string{"evil.example"}}, false},
		{models.CreateSandboxRequest{NetworkDenyOut: []string{"10.9.0.0/16"}}, false},
		{models.CreateSandboxRequest{NetworkBlockAll: true}, true},
		{models.CreateSandboxRequest{}, true}, // gets the block_all default
	} {
		req := tc.req
		err := svc.applyEgressOperatorPolicy(&req, false)
		if (err == nil) != tc.ok {
			t.Fatalf("%+v: err = %v, want ok=%v", tc.req, err, tc.ok)
		}
	}
	req := models.CreateSandboxRequest{NetworkAllowOut: []string{"evil.example"}}
	if err := svc.applyEgressOperatorPolicy(&req, false); err == nil || !containsAll(err.Error(), "evil.example", "ceiling") {
		t.Fatalf("error must name the entry: %v", err)
	}
	if _, err := svc.CreateSandbox(context.Background(), models.CreateSandboxRequest{Image: "alpine", NetworkAllowOut: []string{"evil.example"}}); err == nil {
		t.Fatal("create outside the ceiling must fail")
	}
}

// TestOperatorInvalidAtBootRefusesCreates (EF-81): fail closed with the
// dedicated sentinel; the info metric tracks the live file's hash.
func TestOperatorInvalidAtBootRefusesCreates(t *testing.T) {
	svc, _, _ := newEgressHarness(t)
	w := operatorWatcher(t, "version: 1\ndefault_policy: {mode: sometimes}\n")
	svc.SetEgressOperator(w)
	if _, err := svc.CreateSandbox(context.Background(), models.CreateSandboxRequest{Image: "alpine"}); !errors.Is(err, ErrEgressOperatorConfigInvalid) {
		t.Fatalf("err = %v, want ErrEgressOperatorConfigInvalid", err)
	}
	good := operatorWatcher(t, "version: 1\n")
	svc.SetEgressOperator(good)
	if egressOperatorInfo.Get(good.Current().Hash()) == nil {
		t.Fatal("info metric must carry the live hash")
	}
	svc.OnEgressOperatorChange(nil)
	if expvarFloat(t, "aerolvm_egress_operator_config_load_failures_total") != float64(good.Failures()) {
		t.Fatal("load failures metric")
	}
	svc.SetEgressOperator(nil)
	if svc.egressOperator() != nil {
		t.Fatal("no watcher, no operator")
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}
