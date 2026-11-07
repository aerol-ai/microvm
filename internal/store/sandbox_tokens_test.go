package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// tokens_not_before (sandbox token revoke) round-trips through every read
// path, and only ever moves forward: a revoke with an older clock reading
// and a whole-row Upsert from a read taken before a revoke both keep the
// later value, so nothing can bring a revoked token back.
func TestTokensNotBeforeRoundTripsAndOnlyMovesForward(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	sb := sampleSandbox("sb-nb")
	sb.OwnerRef = "team:payments"
	sb.Runtime = models.RuntimeDocker
	sb.TokensNotBefore = 1_800_000_000
	if err := st.Create(ctx, sb); err != nil {
		t.Fatal(err)
	}
	plain := sampleSandbox("sb-nb-zero")
	if err := st.Create(ctx, plain); err != nil {
		t.Fatal(err)
	}

	want := map[string]int64{"sb-nb": 1_800_000_000, "sb-nb-zero": 0}
	check := func(label string, rows []*models.Sandbox) {
		t.Helper()
		seen := 0
		for _, r := range rows {
			if w, ok := want[r.ID]; ok {
				seen++
				if r.TokensNotBefore != w {
					t.Fatalf("%s: %s tokens_not_before = %d, want %d", label, r.ID, r.TokensNotBefore, w)
				}
			}
		}
		if seen == 0 {
			t.Fatalf("%s: no row read back", label)
		}
	}
	got, err := st.Get(ctx, sb.ID)
	if err != nil {
		t.Fatal(err)
	}
	check("Get", []*models.Sandbox{got})
	all, err := st.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	check("List", all)
	owned, err := st.ListByOwner(ctx, "team:payments")
	if err != nil {
		t.Fatal(err)
	}
	check("ListByOwner", owned)
	byRuntime, err := st.ListByRuntime(ctx, models.RuntimeDocker)
	if err != nil {
		t.Fatal(err)
	}
	check("ListByRuntime", byRuntime)
	stale := *got

	// A revoke moves it forward and answers the stored value.
	if nb, err := st.RevokeSandboxTokens(ctx, sb.ID, 1_800_000_100); err != nil || nb != 1_800_000_100 {
		t.Fatalf("revoke = %d, %v", nb, err)
	}
	// A second revoke with an older reading keeps the later value.
	if nb, err := st.RevokeSandboxTokens(ctx, sb.ID, 1_800_000_050); err != nil || nb != 1_800_000_100 {
		t.Fatalf("an older revoke = %d, %v; want the stored 1800000100", nb, err)
	}
	// A whole-row write from the read before the revoke keeps it too.
	stale.LastError = "a later unrelated write"
	if err := st.Upsert(ctx, &stale); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.Get(ctx, sb.ID); got.TokensNotBefore != 1_800_000_100 || got.LastError != "a later unrelated write" {
		t.Fatalf("after a stale Upsert: nb=%d last_error=%q", got.TokensNotBefore, got.LastError)
	}
	// An Upsert with a later value raises it; an Upsert that inserts a row
	// stores what it carries.
	stale.TokensNotBefore = 1_800_000_200
	if err := st.Upsert(ctx, &stale); err != nil {
		t.Fatal(err)
	}
	fresh := sampleSandbox("sb-nb-upsert")
	fresh.TokensNotBefore = 42
	if err := st.Upsert(ctx, fresh); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.Get(ctx, sb.ID); got.TokensNotBefore != 1_800_000_200 {
		t.Fatalf("a later Upsert = %d", got.TokensNotBefore)
	}
	if got, _ := st.Get(ctx, fresh.ID); got.TokensNotBefore != 42 {
		t.Fatalf("an inserting Upsert = %d", got.TokensNotBefore)
	}

	if _, err := st.RevokeSandboxTokens(ctx, "sb-missing", 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing row = %v, want ErrNotFound", err)
	}
	_ = st.Close()
	if _, err := st.RevokeSandboxTokens(ctx, sb.ID, 1); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("closed store = %v, want a write error", err)
	}
}

// The column is added on Open to a database from before it existed, rows
// from then read 0 (nothing was revoked), and opening again is a no-op that
// keeps a stored value.
func TestTokensNotBeforeMigrationIsIdempotent(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Create(ctx, sampleSandbox("sb-old")); err != nil {
		t.Fatal(err)
	}
	// Make it a database from before the column.
	if _, err := st.db.Exec(`ALTER TABLE sandboxes DROP COLUMN tokens_not_before`); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()

	for round := 1; round <= 2; round++ {
		st, err = Open(path)
		if err != nil {
			t.Fatalf("open %d: %v", round, err)
		}
		got, err := st.Get(ctx, "sb-old")
		if err != nil {
			t.Fatalf("open %d: %v", round, err)
		}
		want := int64(0)
		if round == 2 {
			want = 77
		}
		if got.TokensNotBefore != want {
			t.Fatalf("open %d: tokens_not_before = %d, want %d", round, got.TokensNotBefore, want)
		}
		if round == 1 {
			if _, err := st.RevokeSandboxTokens(ctx, "sb-old", 77); err != nil {
				t.Fatal(err)
			}
		}
		_ = st.Close()
	}
}
