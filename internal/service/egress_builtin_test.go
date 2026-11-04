package service

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/egresspolicy"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Built-in egress profiles (plans/egress-domain-filtering.md P2-8, CEO D3,
// D11): pinned at create, failing closed on a node without the version.

const pypiPinned = "builtin:pypi@20261006"

// futurePypi is a version a newer node pinned that this catalogue lacks.
const futurePypi = "builtin:pypi@29991231"

func TestCreateWithBuiltinProfile(t *testing.T) {
	svc, gw, _ := newPolicyHarness(t)
	ctx := ownerCtx("acct")
	putProfile(t, svc, ctx, "corp", "artifactory.corp.example")
	resp, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine", NetworkAllowOut: []string{"10.0.0.0/8"},
		EgressProfiles: []string{"builtin:pypi", "corp"}})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(resp.EgressProfiles, []string{pypiPinned, "corp"}) {
		t.Fatalf("a bare built-in is pinned in the response: %v", resp.EgressProfiles)
	}
	row, _ := svc.store.Get(ctx, resp.ID)
	if !slices.Equal(row.NetworkAllowOut, []string{"10.0.0.0/8", "pypi.org", "files.pythonhosted.org", "artifactory.corp.example"}) {
		t.Fatalf("effective = %v", row.NetworkAllowOut)
	}
	if spec := gw.attached[resp.ID]; !slices.Contains(spec.AllowOut, "files.pythonhosted.org") {
		t.Fatalf("gateway spec = %v", spec.AllowOut)
	}
	got, err := svc.GetSandbox(ctx, resp.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.EgressProfiles, []string{pypiPinned, "corp"}) ||
		got.EgressProfilesApplied[0] != (models.EgressProfileRef{Name: pypiPinned, Generation: 20261006}) {
		t.Fatalf("GET = %v %+v", got.EgressProfiles, got.EgressProfilesApplied)
	}
	if spec, err := svc.specFromSandbox(ctx, row); err != nil || !slices.Equal(spec.EgressProfiles, []string{pypiPinned, "corp"}) {
		t.Fatalf("a replay keeps the pin: %+v %v", spec, err)
	}
	// A pinned version never moves, so an idle pass re-applies nothing.
	n := len(gw.attached)
	svc.reapplyEgressProfiles(ctx)
	if len(gw.attached) != n {
		t.Fatal("a built-in reference must not look stale")
	}
	if st, _ := svc.store.GetEgressState(ctx, resp.ID); st.HoldReason != "" {
		t.Fatalf("hold = %+v", st)
	}

	for _, tc := range []struct {
		name string
		refs []string
		want error
	}{
		{"unknown built-in", []string{"builtin:nope"}, egresspolicy.ErrInvalid},
		{"version that never existed", []string{"builtin:pypi@20200101"}, egresspolicy.ErrInvalid},
		{"same built-in twice", []string{"builtin:pypi", pypiPinned}, egresspolicy.ErrInvalid},
		{"version newer than this node's", []string{futurePypi}, ErrEgressProfileUnavailable},
	} {
		if _, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine", EgressProfiles: tc.refs}); !errors.Is(err, tc.want) {
			t.Fatalf("%s: err = %v, want %v", tc.name, err, tc.want)
		}
	}
}

func TestGetBuiltinEgressProfile(t *testing.T) {
	svc, _, _ := newPolicyHarness(t)
	ctx := ownerCtx("acct")
	for _, name := range []string{"builtin:pypi", pypiPinned} {
		p, err := svc.GetEgressProfile(ctx, name)
		if err != nil || p.Name != pypiPinned || p.Generation != 20261006 || !slices.Contains(p.AllowOut, "pypi.org") ||
			!strings.Contains(p.Description, "built-in") {
			t.Fatalf("%s = %+v %v", name, p, err)
		}
	}
	for _, name := range []string{"builtin:nope", futurePypi} {
		if _, err := svc.GetEgressProfile(ctx, name); !errors.Is(err, ErrEgressProfileNotFound) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// Read-only: the prefix is reserved for writes.
	if _, err := svc.PutEgressProfile(ctx, "builtin:pypi", models.EgressProfileRequest{AllowOut: []string{"x.example"}}); !errors.Is(err, egresspolicy.ErrInvalid) {
		t.Fatalf("put built-in: %v", err)
	}
	if err := svc.DeleteEgressProfile(ctx, "builtin:pypi"); !errors.Is(err, egresspolicy.ErrInvalid) {
		t.Fatalf("delete built-in: %v", err)
	}
}

// TestUpdatePolicyMovesBuiltinVersion: owners move to a newer list by
// updating the policy, which pins the bare name again; re-sending the pin is
// a no-op.
func TestUpdatePolicyMovesBuiltinVersion(t *testing.T) {
	svc, gw, _ := newPolicyHarness(t)
	ctx := ownerCtx("acct")
	seedPolicySandbox(t, svc, models.Sandbox{OwnerRef: "acct"})
	got, err := svc.UpdateNetworkPolicy(ctx, "sb-pol", models.NetworkPolicyRequest{EgressProfiles: []string{"builtin:npm"}})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.EgressProfiles, []string{"builtin:npm@20261006"}) || !gw.isAttached("sb-pol") {
		t.Fatalf("policy = %+v", got)
	}
	state, _ := svc.store.GetSandboxEgressProfiles(ctx, "sb-pol")
	if state.Refs[0].Name != "builtin:npm@20261006" {
		t.Fatalf("stored refs = %+v", state.Refs)
	}
	n := len(gw.attached)
	if _, err := svc.UpdateNetworkPolicy(ctx, "sb-pol", models.NetworkPolicyRequest{EgressProfiles: []string{"builtin:npm@20261006"}}); err != nil || len(gw.attached) != n {
		t.Fatalf("re-sending the pin must be a no-op: %v", err)
	}
}

// TestBuiltinProfilesSwitch (EF-83, §5.10 PC-3): builtin_profiles: false
// refuses new built-in references and leaves running sandboxes alone.
func TestBuiltinProfilesSwitch(t *testing.T) {
	svc, _, _ := newPolicyHarness(t)
	ctx := ownerCtx("acct")
	seedPolicySandbox(t, svc, models.Sandbox{OwnerRef: "acct"})
	if _, err := svc.UpdateNetworkPolicy(ctx, "sb-pol", models.NetworkPolicyRequest{EgressProfiles: []string{"builtin:pypi"}}); err != nil {
		t.Fatal(err)
	}
	svc.SetEgressOperator(operatorWatcher(t, "version: 1\nbuiltin_profiles: false\n"))

	_, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine", EgressProfiles: []string{"builtin:pypi"}})
	if !errors.Is(err, egresspolicy.ErrInvalid) || !strings.Contains(err.Error(), "built-in profiles disabled on this deployment") {
		t.Fatalf("create: %v", err)
	}
	if _, err := svc.UpdateNetworkPolicy(ctx, "sb-pol", models.NetworkPolicyRequest{EgressProfiles: []string{pypiPinned}}); !errors.Is(err, egresspolicy.ErrInvalid) {
		t.Fatalf("policy PUT: %v", err)
	}
	// A facade list update keeps the references it can't see.
	if _, err := svc.UpdateNetworkLists(ctx, "sb-pol", false, []string{"10.0.0.0/8"}, nil); err != nil {
		t.Fatalf("facade update: %v", err)
	}
	// A failover replay keeps what was decided at create.
	if _, err := svc.CreateSandboxWithID(contextWithStoredSpecReplay(ctx), models.CreateSandboxRequest{Image: "alpine", EgressProfiles: []string{pypiPinned}}, "sb-replay"); err != nil {
		t.Fatalf("replay: %v", err)
	}
}

// unreadableProfiles fails every profile read, as a cluster without a
// leader would.
type unreadableProfiles struct{ *store.Store }

func (unreadableProfiles) GetEgressProfile(context.Context, string, string) (models.EgressProfile, error) {
	return models.EgressProfile{}, errors.New("raft: no leader")
}

// TestReplayRunsBlockAllUntilProfilesResolve (EF-60): a failover replay on a
// node that lacks a pinned built-in version runs block-all, held, with
// egress_status "unavailable", and the re-apply pass lifts it once the
// profiles resolve.
func TestReplayRunsBlockAllUntilProfilesResolve(t *testing.T) {
	svc, gw, _ := newPolicyHarness(t)
	ctx := ownerCtx("acct")
	replay := contextWithStoredSpecReplay(ctx)

	if _, err := svc.CreateSandboxWithID(replay, models.CreateSandboxRequest{Image: "alpine", NetworkDenyOut: []string{"10.9.0.0/16"},
		EgressProfiles: []string{futurePypi}}, "sb-old-node"); err != nil {
		t.Fatal(err)
	}
	row, _ := svc.store.Get(ctx, "sb-old-node")
	if !row.NetworkBlockAll || len(row.NetworkAllowOut) != 0 || gw.isAttached("sb-old-node") {
		t.Fatalf("row = %+v", row)
	}
	if got, _ := svc.GetSandbox(ctx, "sb-old-node"); got.EgressStatus != EgressStatusUnavailable || !slices.Equal(got.EgressProfiles, []string{futurePypi}) {
		t.Fatalf("GET status=%q profiles=%v", got.EgressStatus, got.EgressProfiles)
	}
	if spec, err := svc.specFromSandbox(ctx, row); err != nil || spec.NetworkBlockAll || !slices.Equal(spec.EgressProfiles, []string{futurePypi}) {
		t.Fatalf("the spec must keep the owner's policy, not the stand-in: %+v %v", spec, err)
	}
	// Still missing: the pass keeps it held.
	svc.reapplyEgressProfiles(ctx)
	if st, _ := svc.store.GetEgressState(ctx, "sb-old-node"); st.HoldReason != egressHoldProfileUnavailable {
		t.Fatalf("hold = %+v", st)
	}

	// A named profile that can't be read takes the same path, and lifts
	// once the read succeeds.
	putProfile(t, svc, ctx, "python", "pypi.org")
	svc.egressProfiles = unreadableProfiles{svc.store}
	if _, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine", EgressProfiles: []string{"python"}}); !errors.Is(err, ErrEgressProfileUnavailable) {
		t.Fatalf("a new create is refused, not held: %v", err)
	}
	if _, err := svc.CreateSandboxWithID(replay, models.CreateSandboxRequest{Image: "alpine", NetworkDenyOut: []string{"10.9.0.0/16"},
		EgressProfiles: []string{"python"}}, "sb-replay"); err != nil {
		t.Fatal(err)
	}
	if st, _ := svc.store.GetEgressState(ctx, "sb-replay"); st.HoldReason != egressHoldProfileUnavailable {
		t.Fatalf("hold = %+v", st)
	}
	svc.egressProfiles = nil
	svc.reapplyEgressProfiles(ctx)
	row, _ = svc.store.Get(ctx, "sb-replay")
	if row.NetworkBlockAll || !slices.Equal(row.NetworkAllowOut, []string{"pypi.org"}) || !slices.Equal(row.NetworkDenyOut, []string{"10.9.0.0/16"}) {
		t.Fatalf("row after the profile resolved = %+v", row)
	}
	if st, _ := svc.store.GetEgressState(ctx, "sb-replay"); st.HoldReason != "" || !gw.isAttached("sb-replay") {
		t.Fatalf("hold after the profile resolved = %+v", st)
	}
	if got, _ := svc.GetSandbox(ctx, "sb-replay"); got.EgressStatus != EgressStatusActive {
		t.Fatalf("status = %q", got.EgressStatus)
	}
}

// TestReapplyLiftsMediatedReplayHold: a WASM or isolate replay held for its
// profiles has only the record to clear once they resolve.
func TestReapplyLiftsMediatedReplayHold(t *testing.T) {
	svc, _, _ := newPolicyHarness(t)
	ctx := ownerCtx("acct")
	wasm := newMediator()
	svc.wasm = wasm
	putProfile(t, svc, ctx, "python", "pypi.org")
	seedPolicySandbox(t, svc, models.Sandbox{ID: "sb-wasm", OwnerRef: "acct", Runtime: models.RuntimeWasm, NetworkBlockAll: true})
	if err := svc.store.SetSandboxEgressProfiles(ctx, "sb-wasm", store.NetworkPolicyWrite{Profiles: []string{"python"}, OwnerRef: "acct"}); err != nil {
		t.Fatal(err)
	}
	if err := svc.store.SetEgressHold(ctx, "sb-wasm", egressHoldProfileUnavailable, time.Now()); err != nil {
		t.Fatal(err)
	}
	svc.reapplyEgressProfiles(ctx)
	if !slices.Equal(wasm.set["sb-wasm"], []string{"pypi.org"}) || wasm.blocked["sb-wasm"] {
		t.Fatalf("mediator: set=%v blocked=%v", wasm.set, wasm.blocked)
	}
	if st, _ := svc.store.GetEgressState(ctx, "sb-wasm"); st.HoldReason != "" {
		t.Fatalf("hold = %+v", st)
	}
}

func TestNormalizeCreateEgressProfiles(t *testing.T) {
	refs := []string{"builtin:pypi", "corp", futurePypi, "builtin:nope"}
	req := models.CreateSandboxRequest{EgressProfiles: refs}
	NormalizeCreateEgressProfiles(&req)
	if !slices.Equal(req.EgressProfiles, []string{pypiPinned, "corp", futurePypi, "builtin:nope"}) {
		t.Fatalf("pinned = %v", req.EgressProfiles)
	}
	if refs[0] != "builtin:pypi" {
		t.Fatal("the caller's slice must not be rewritten")
	}
	none := models.CreateSandboxRequest{EgressProfiles: []string{"corp"}}
	NormalizeCreateEgressProfiles(&none)
	if !slices.Equal(none.EgressProfiles, []string{"corp"}) {
		t.Fatalf("no built-ins = %v", none.EgressProfiles)
	}
}
