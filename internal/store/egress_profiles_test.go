package store

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func openEgressProfileStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestEgressProfileCRUD(t *testing.T) {
	st := openEgressProfileStore(t)
	ctx := context.Background()
	now := time.Now()
	p, changed, err := st.PutEgressProfile(ctx, "acct", "python", []string{"pypi.org"}, "pip", now)
	if err != nil || !changed || p.Generation != 1 || !p.CreatedAt.Equal(now.UTC()) {
		t.Fatalf("create = %+v %v %v", p, changed, err)
	}
	if p, changed, _ = st.PutEgressProfile(ctx, "acct", "python", []string{"pypi.org"}, "pip", now.Add(time.Second)); changed || p.Generation != 1 {
		t.Fatalf("same body must be a no-op: %+v %v", p, changed)
	}
	if p, changed, _ = st.PutEgressProfile(ctx, "acct", "python", []string{"pypi.org", "*.pythonhosted.org"}, "pip", now.Add(time.Second)); !changed || p.Generation != 2 || !p.CreatedAt.Equal(now.UTC()) {
		t.Fatalf("update = %+v %v", p, changed)
	}
	// Owners are separate namespaces.
	if _, err := st.GetEgressProfile(ctx, "other", "python"); !errors.Is(err, ErrEgressProfileNotFound) {
		t.Fatalf("other owner: %v", err)
	}
	got, err := st.GetEgressProfile(ctx, "acct", "python")
	if err != nil || got.Generation != 2 || !slices.Equal(got.AllowOut, []string{"pypi.org", "*.pythonhosted.org"}) {
		t.Fatalf("get = %+v %v", got, err)
	}
	for _, name := range []string{"a", "b", "c"} {
		if _, _, err := st.PutEgressProfile(ctx, "acct", name, nil, "", now); err != nil {
			t.Fatal(err)
		}
	}
	page, err := st.ListEgressProfiles(ctx, "acct", "a", 2)
	if err != nil || len(page) != 2 || page[0].Name != "b" || page[1].Name != "c" {
		t.Fatalf("page = %+v %v", page, err)
	}
	if err := st.DeleteEgressProfile(ctx, "acct", "a"); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteEgressProfile(ctx, "acct", "a"); err != nil {
		t.Fatalf("a repeated delete must succeed: %v", err)
	}
}

func TestEgressProfileReferences(t *testing.T) {
	st := openEgressProfileStore(t)
	ctx := context.Background()
	now := time.Now()
	for _, id := range []string{"sb-1", "sb-2"} {
		if err := st.Create(ctx, &models.Sandbox{ID: id, Image: "alpine", Status: models.SandboxStatusStarted, OwnerRef: "acct"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := st.PutEgressProfile(ctx, "acct", "python", []string{"pypi.org"}, "", now); err != nil {
		t.Fatal(err)
	}
	write := NetworkPolicyWrite{AllowOut: []string{"10.0.0.0/8", "pypi.org"}, Inline: []string{"10.0.0.0/8"}, Profiles: []string{"python", "extra"}, OwnerRef: "acct"}
	if err := st.WriteNetworkPolicy(ctx, "sb-1", write); err != nil {
		t.Fatal(err)
	}
	if err := st.SetSandboxEgressProfiles(ctx, "sb-2", NetworkPolicyWrite{Profiles: []string{"python"}, OwnerRef: "acct"}); err != nil {
		t.Fatal(err)
	}
	row, _ := st.Get(ctx, "sb-1")
	if !slices.Equal(row.NetworkAllowOut, write.AllowOut) {
		t.Fatalf("row keeps the effective list: %v", row.NetworkAllowOut)
	}
	state, err := st.GetSandboxEgressProfiles(ctx, "sb-1")
	if err != nil || len(state.Refs) != 2 || state.Refs[0].Name != "python" || state.Refs[1].Name != "extra" || !slices.Equal(state.Inline, []string{"10.0.0.0/8"}) {
		t.Fatalf("state = %+v %v", state, err)
	}
	if state, _ := st.GetSandboxEgressProfiles(ctx, "sb-2"); state.Inline == nil || len(state.Inline) != 0 {
		t.Fatalf("an empty inline list reads back empty, not absent: %+v", state)
	}

	if err := st.DeleteEgressProfile(ctx, "acct", "python"); !errors.Is(err, ErrEgressProfileInUse) {
		t.Fatalf("in use: %v", err)
	}
	refs, err := st.SandboxesReferencingProfile(ctx, "acct", "python")
	if err != nil || len(refs) != 2 {
		t.Fatalf("referencing = %+v %v", refs, err)
	}
	if err := st.SetEgressProfilesApplied(ctx, "sb-1", []models.EgressProfileRef{{Name: "python", Generation: 3}}); err != nil {
		t.Fatal(err)
	}
	// Replacing the references keeps the applied generation of one that stays.
	write.Profiles = []string{"python"}
	if err := st.WriteNetworkPolicy(ctx, "sb-1", write); err != nil {
		t.Fatal(err)
	}
	all, err := st.ProfileReferences(ctx)
	if err != nil || len(all) != 2 || all[0].SandboxID != "sb-1" || all[0].AppliedGeneration != 3 {
		t.Fatalf("references = %+v %v", all, err)
	}

	// Dropping every profile clears the inline copy; destroyed sandboxes
	// don't hold a profile.
	write.Profiles = nil
	if err := st.WriteNetworkPolicy(ctx, "sb-1", write); err != nil {
		t.Fatal(err)
	}
	if state, _ := st.GetSandboxEgressProfiles(ctx, "sb-1"); state.Refs != nil || state.Inline != nil {
		t.Fatalf("no profiles left: %+v", state)
	}
	if err := st.UpdateStatus(ctx, "sb-2", models.SandboxStatusDestroyed, ""); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteEgressProfile(ctx, "acct", "python"); err != nil {
		t.Fatalf("only destroyed sandboxes reference it: %v", err)
	}
	if err := st.WriteNetworkPolicy(ctx, "missing", write); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing sandbox: %v", err)
	}
	if got, err := st.GetSandboxesEgressProfiles(ctx, nil); err != nil || len(got) != 0 {
		t.Fatalf("no ids: %v %v", got, err)
	}
}
