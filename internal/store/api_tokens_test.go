package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/identity"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/identitywire"
)

func storeTokenRecord(t *testing.T, name, team string, role controlplane.Role, expires time.Time) identity.TokenRecord {
	t.Helper()
	tok, err := identitywire.NewAPIToken(nil)
	if err != nil {
		t.Fatal(err)
	}
	hash := tok.SecretHash()
	return identity.TokenRecord{
		ID: tok.ID, Name: name, Role: role, OwnerRef: identity.OwnerRefForTeam(team), CreatedBy: "operator",
		CreatedAt: time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC), ExpiresAt: expires, SecretHash: hash[:],
	}
}

// TestAPITokenStore: the single-node token table round-trips every field,
// keeps names unique per team, never overwrites a row, and deletes
// idempotently (plans/identity-and-access.md §5.4).
func TestAPITokenStore(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	soon := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	ci := storeTokenRecord(t, "ci-deploy", "payments", controlplane.RoleRunner, soon)
	if err := st.InsertAPIToken(ctx, ci); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertAPIToken(ctx, storeTokenRecord(t, "ci-deploy", "payments", controlplane.RoleViewer, soon)); !errors.Is(err, ErrAPITokenNameTaken) {
		t.Fatalf("same name, same team: %v", err)
	}
	other := storeTokenRecord(t, "ci-deploy", "checkout", controlplane.RoleRunner, soon)
	fleet := storeTokenRecord(t, "ci-deploy", controlplane.FleetTeam, controlplane.RoleAuditor, soon.Add(time.Hour))
	for _, rec := range []identity.TokenRecord{other, fleet} {
		if err := st.InsertAPIToken(ctx, rec); err != nil {
			t.Fatalf("the same name in another team: %v", err)
		}
	}
	clash := storeTokenRecord(t, "else", "payments", controlplane.RoleRunner, soon)
	clash.ID = ci.ID
	if err := st.InsertAPIToken(ctx, clash); !errors.Is(err, ErrAPITokenIDTaken) {
		t.Fatalf("id clash: %v", err)
	}
	bad := ci
	bad.Name = "bad name"
	if err := st.InsertAPIToken(ctx, bad); !errors.Is(err, identity.ErrInvalidTokenRecord) {
		t.Fatalf("invalid record: %v", err)
	}

	list, err := st.ListAPITokens(ctx)
	if err != nil || len(list) != 3 {
		t.Fatalf("list = %d %v", len(list), err)
	}
	// Sorted by team then name: fleet ('') first.
	if list[0].ID != fleet.ID || list[1].ID != other.ID || list[2].ID != ci.ID {
		t.Fatalf("order = %s %s %s", list[0].ID, list[1].ID, list[2].ID)
	}
	got := list[2]
	if got.Name != ci.Name || got.Role != ci.Role || got.OwnerRef != ci.OwnerRef || got.CreatedBy != ci.CreatedBy ||
		!got.CreatedAt.Equal(ci.CreatedAt) || !got.ExpiresAt.Equal(ci.ExpiresAt) || string(got.SecretHash) != string(ci.SecretHash) {
		t.Fatalf("round trip = %+v, want %+v", got, ci)
	}

	removed, err := st.DeleteAPIToken(ctx, ci.ID)
	if err != nil || !removed {
		t.Fatalf("delete: %v %v", removed, err)
	}
	if removed, err := st.DeleteAPIToken(ctx, ci.ID); err != nil || removed {
		t.Fatalf("a repeat delete is a no-op: %v %v", removed, err)
	}
	if err := st.InsertAPIToken(ctx, storeTokenRecord(t, "ci-deploy", "payments", controlplane.RoleRunner, soon)); err != nil {
		t.Fatalf("a revoked name is free again: %v", err)
	}

	// The expiry sweep removes exactly what expired before the cutoff.
	ids, err := st.DeleteAPITokensExpiredBefore(ctx, soon.Add(time.Minute))
	if err != nil || len(ids) != 2 {
		t.Fatalf("sweep = %v %v", ids, err)
	}
	if ids, err := st.DeleteAPITokensExpiredBefore(ctx, soon.Add(time.Minute)); err != nil || ids != nil {
		t.Fatalf("a second sweep finds nothing: %v %v", ids, err)
	}
	if list, _ := st.ListAPITokens(ctx); len(list) != 1 || list[0].ID != fleet.ID {
		t.Fatalf("after the sweep: %+v", list)
	}
}

// The table is created idempotently, so a store reopened by a new binary
// keeps its tokens (warm upgrade), and a closed store reports errors.
func TestAPITokenStoreReopenAndErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	rec := storeTokenRecord(t, "keep", controlplane.FleetTeam, controlplane.RoleAdmin, time.Now().Add(time.Hour))
	if err := st.InsertAPIToken(ctx, rec); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	st, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if list, err := st.ListAPITokens(ctx); err != nil || len(list) != 1 || list[0].ID != rec.ID {
		t.Fatalf("after reopen: %v %v", list, err)
	}
	_ = st.Close()
	if err := st.InsertAPIToken(ctx, storeTokenRecord(t, "x", controlplane.FleetTeam, controlplane.RoleAdmin, time.Now().Add(time.Hour))); err == nil {
		t.Fatal("insert on a closed store")
	}
	if _, err := st.ListAPITokens(ctx); err == nil {
		t.Fatal("list on a closed store")
	}
	if _, err := st.DeleteAPIToken(ctx, rec.ID); err == nil {
		t.Fatal("delete on a closed store")
	}
	if _, err := st.DeleteAPITokensExpiredBefore(ctx, time.Now()); err == nil {
		t.Fatal("sweep on a closed store")
	}
}

// A row no current binary wrote (a hand edit, a corrupt file) fails the
// list and the sweep loudly instead of being skipped.
func TestAPITokenStoreCorruptRows(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	if _, err := st.db.ExecContext(ctx, `INSERT INTO api_tokens (id, name, role, owner_ref, created_by, created_at, expires_at, secret_hash)
		VALUES ('tok_aaaaaaaaaaaa', 'n', 'viewer', '', '', 'not-a-number', 0, x'00')`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ListAPITokens(ctx); err == nil {
		t.Fatal("a corrupt created_at must fail the list")
	}
	if _, err := st.db.ExecContext(ctx, `INSERT INTO api_tokens (id, name, role, owner_ref, created_by, created_at, expires_at, secret_hash)
		VALUES (NULL, 'm', 'viewer', '', '', 0, 0, x'00')`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DeleteAPITokensExpiredBefore(ctx, time.Now()); err == nil {
		t.Fatal("a NULL id must fail the sweep")
	}
}
