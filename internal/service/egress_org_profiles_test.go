package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/egress/operator"
	"github.com/aerol-ai/microvm/pkg/egresspolicy"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Org profiles from the operator file (plans/egress-domain-filtering.md
// §5.10 PC-3, P2-10): readable by every tenant, not pinned, re-applied on
// reload, and held with org_profile_invalid when they stop resolving.

// orgFile writes body as the operator file and returns its watcher, wired to
// the service like the daemon wires it.
func orgFile(t *testing.T, svc *Service, body string) (*operator.Watcher, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "egress-policy.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	w := operator.NewWatcher(path, nil, svc.OnEgressOperatorChange)
	svc.SetEgressOperator(w)
	return w, path
}

func rewriteOrgFile(t *testing.T, w *operator.Watcher, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := w.Reload(); err != nil {
		t.Fatal(err)
	}
}

const mirrorsFile = "version: 1\norg_profiles:\n  mirrors: {allow_out: [pypi.org], description: bank mirrors}\n"

func TestOrgProfileReferences(t *testing.T) {
	svc, gw, _ := newPolicyHarness(t)
	orgFile(t, svc, mirrorsFile)
	ctx := ownerCtx("acct")

	// Every tenant reads it; nobody writes it through the API.
	for _, owner := range []string{"acct", "other"} {
		p, err := svc.GetEgressProfile(ownerCtx(owner), "org:mirrors")
		if err != nil || p.Name != "org:mirrors" || !slices.Equal(p.AllowOut, []string{"pypi.org"}) || p.Description != "bank mirrors" || p.Generation <= 0 {
			t.Fatalf("%s: GET = %+v %v", owner, p, err)
		}
	}
	if _, err := svc.GetEgressProfile(ctx, "org:nope"); !errors.Is(err, ErrEgressProfileNotFound) {
		t.Fatalf("unknown org profile GET: %v", err)
	}
	if _, err := svc.PutEgressProfile(ctx, "org:mirrors", models.EgressProfileRequest{AllowOut: []string{"x.example"}}); !errors.Is(err, egresspolicy.ErrInvalid) {
		t.Fatalf("org profiles have no API write: %v", err)
	}

	resp, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine", EgressProfiles: []string{"org:mirrors"}})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(resp.EgressProfiles, []string{"org:mirrors"}) || !slices.Contains(gw.attached[resp.ID].AllowOut, "pypi.org") {
		t.Fatalf("create = %v, gateway %v", resp.EgressProfiles, gw.attached[resp.ID].AllowOut)
	}
	_, err = svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine", EgressProfiles: []string{"org:nope"}})
	if !errors.Is(err, egresspolicy.ErrInvalid) || !errors.Is(err, ErrOrgProfileInvalid) {
		t.Fatalf("unknown org profile at create: %v", err)
	}
}

// TestOrgProfileReloadReappliesAndHolds (EF-81): an edited org profile is
// re-applied to this node's referencing sandboxes after a reload; a removed
// one holds them with org_profile_invalid, counted for the alert, until it
// comes back.
func TestOrgProfileReloadReappliesAndHolds(t *testing.T) {
	svc, gw, _ := newPolicyHarness(t)
	w, path := orgFile(t, svc, mirrorsFile)
	ctx := ownerCtx("acct")
	seedPolicySandbox(t, svc, models.Sandbox{OwnerRef: "acct"})
	if _, err := svc.UpdateNetworkPolicy(ctx, "sb-pol", models.NetworkPolicyRequest{EgressProfiles: []string{"org:mirrors"}}); err != nil {
		t.Fatal(err)
	}
	before, _ := svc.store.GetSandboxEgressProfiles(ctx, "sb-pol")
	// Drain any kick from wiring the watcher.
	select {
	case <-svc.profileKick():
	default:
	}

	rewriteOrgFile(t, w, path, "version: 1\norg_profiles:\n  mirrors: {allow_out: [pypi.org, \"*.npmjs.org\"]}\n")
	select {
	case <-svc.profileKick():
	default:
		t.Fatal("a reload must wake the re-apply pass")
	}
	svc.reapplyEgressProfiles(ctx)
	row, _ := svc.store.Get(ctx, "sb-pol")
	if !slices.Equal(row.NetworkAllowOut, []string{"pypi.org", "*.npmjs.org"}) || !slices.Contains(gw.attached["sb-pol"].AllowOut, "*.npmjs.org") {
		t.Fatalf("after the edit: row %v, gateway %v", row.NetworkAllowOut, gw.attached["sb-pol"].AllowOut)
	}
	after, _ := svc.store.GetSandboxEgressProfiles(ctx, "sb-pol")
	if after.Refs[0].Generation == before.Refs[0].Generation {
		t.Fatalf("an edit must change the generation: %+v", after.Refs)
	}

	failed := egressProfileApplyFailedTotal.Value()
	rewriteOrgFile(t, w, path, "version: 1\n")
	svc.reapplyEgressProfiles(ctx)
	if st, _ := svc.store.GetEgressState(ctx, "sb-pol"); st.HoldReason != egressHoldOrgProfileInvalid {
		t.Fatalf("hold after removal = %+v", st)
	}
	if got, _ := svc.GetSandbox(ctx, "sb-pol"); got.EgressStatus != EgressStatusHeld {
		t.Fatalf("status = %q", got.EgressStatus)
	}
	if egressProfileApplyFailedTotal.Value() <= failed {
		t.Fatal("the hold must be counted for the alert")
	}
	svc.retryEgressHolds(ctx)
	if st, _ := svc.store.GetEgressState(ctx, "sb-pol"); st.HoldReason != egressHoldOrgProfileInvalid {
		t.Fatal("the hold retry must not lift an org profile hold")
	}

	rewriteOrgFile(t, w, path, mirrorsFile)
	svc.reapplyEgressProfiles(ctx)
	if st, _ := svc.store.GetEgressState(ctx, "sb-pol"); st.HoldReason != "" || !gw.isAttached("sb-pol") {
		t.Fatalf("hold after the profile came back = %+v", st)
	}
}

// TestOrgProfileOverCapHolds: nothing checks an org profile edit against the
// sandboxes using it before the reload lands, so one that pushes a sandbox
// past the union cap holds it with org_profile_invalid.
func TestOrgProfileOverCapHolds(t *testing.T) {
	svc, _, _ := newPolicyHarness(t)
	hosts := func(prefix string, n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("%s%d.example.com", prefix, i)
		}
		return out
	}
	orgYAML := func(n int) string {
		return "version: 1\norg_profiles:\n  big: {allow_out: [" + strings.Join(hosts("o", n), ", ") + "]}\n"
	}
	w, path := orgFile(t, svc, orgYAML(500))
	ctx := ownerCtx("acct")
	putProfile(t, svc, ctx, "named", hosts("n", 500)...)
	seedPolicySandbox(t, svc, models.Sandbox{OwnerRef: "acct"})
	// 20 inline + 500 + 500 fits; the edit to 512 makes it 1032.
	if _, err := svc.UpdateNetworkPolicy(ctx, "sb-pol", models.NetworkPolicyRequest{NetworkAllowOut: hosts("i", 20),
		EgressProfiles: []string{"named", "org:big"}}); err != nil {
		t.Fatal(err)
	}
	rewriteOrgFile(t, w, path, orgYAML(512))
	svc.reapplyEgressProfiles(ctx)
	if st, _ := svc.store.GetEgressState(ctx, "sb-pol"); st.HoldReason != egressHoldOrgProfileInvalid {
		t.Fatalf("hold = %+v", st)
	}
}

func TestProfileHoldReason(t *testing.T) {
	for _, tc := range []struct {
		err  error
		refs []string
		want string
	}{
		{ErrOrgProfileInvalid, []string{"org:x"}, egressHoldOrgProfileInvalid},
		{egresspolicy.ErrInvalid, []string{"named", "org:x"}, egressHoldOrgProfileInvalid},
		{egresspolicy.ErrInvalid, []string{"named"}, egressHoldProfileUnavailable},
		{ErrEgressProfileUnavailable, []string{"org:x"}, egressHoldProfileUnavailable},
	} {
		if got := profileHoldReason(tc.err, tc.refs); got != tc.want {
			t.Fatalf("%v %v = %s, want %s", tc.err, tc.refs, got, tc.want)
		}
	}
}

// TestCheckResolvesDefaultOrgProfiles: the check endpoint sees the default's
// org profiles as a create would.
func TestCheckResolvesDefaultOrgProfiles(t *testing.T) {
	svc, _, _ := newPolicyHarness(t)
	orgFile(t, svc, "version: 1\ndefault_policy: {mode: allowlist, allow_out: [\"org:mirrors\"]}\norg_profiles:\n  mirrors: {allow_out: [pypi.org]}\n")
	got, err := svc.CheckNetworkPolicy(ownerCtx("acct"), models.NetworkPolicyCheckRequest{Destination: "pypi.org:443"})
	if err != nil || !got.Allowed || got.MatchedRule != "pypi.org" {
		t.Fatalf("check = %+v %v", got, err)
	}
}
