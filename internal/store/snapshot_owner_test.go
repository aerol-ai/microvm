package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

func ownedSandbox(id, owner string) *models.Sandbox {
	sb := sampleSandbox(id)
	sb.OwnerRef = owner
	return sb
}

// TestSnapshotOwnerRefRoundTrip pins sandbox_snapshots.owner_ref: written on
// insert, read back by every snapshot reader.
func TestSnapshotOwnerRefRoundTrip(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	if err := st.Create(ctx, ownedSandbox("sb-own", "acme")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := st.CreateSnapshot(ctx, &models.SandboxSnapshot{Name: "snap-own", Image: "snap-own", SourceSandboxID: "sb-own", OwnerRef: " acme ", PushState: models.SnapshotPushStatePending}); err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	got, err := st.GetSnapshot(ctx, "snap-own")
	if err != nil || got.OwnerRef != "acme" {
		t.Fatalf("GetSnapshot = %+v, %v; want owner acme", got, err)
	}
	listed, err := st.ListSnapshots(ctx)
	if err != nil || len(listed) != 1 || listed[0].OwnerRef != "acme" {
		t.Fatalf("ListSnapshots = %+v, %v", listed, err)
	}
	pending, err := st.ListSnapshotsPendingPush(ctx)
	if err != nil || len(pending) != 1 || pending[0].OwnerRef != "acme" {
		t.Fatalf("ListSnapshotsPendingPush = %+v, %v", pending, err)
	}
}

// TestSnapshotOwnerRefWarmUpgrade opens a database whose sandbox_snapshots
// predates owner_ref. Open must add the column and attribute each row to its
// source sandbox's owner while that sandbox exists; a row whose source is
// gone, or whose source is operator-owned, stays in the operator namespace.
func TestSnapshotOwnerRefWarmUpgrade(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	for _, sb := range []*models.Sandbox{ownedSandbox("sb-tenant", "acme"), ownedSandbox("sb-operator", "")} {
		if err := st.Create(ctx, sb); err != nil {
			t.Fatalf("Create %s: %v", sb.ID, err)
		}
	}
	for _, snap := range []*models.SandboxSnapshot{
		{Name: "snap-tenant", Image: "snap-tenant", SourceSandboxID: "sb-tenant"},
		{Name: "snap-operator", Image: "snap-operator", SourceSandboxID: "sb-operator"},
		{Name: "snap-orphan", Image: "snap-orphan", SourceSandboxID: "sb-gone"},
		// Already attributed: the backfill must never overwrite an owner.
		{Name: "snap-kept", Image: "snap-kept", SourceSandboxID: "sb-tenant", OwnerRef: "globex"},
	} {
		if err := st.CreateSnapshot(ctx, snap); err != nil {
			t.Fatalf("CreateSnapshot %s: %v", snap.Name, err)
		}
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Turn the table back into its pre-owner shape.
	raw, err := sql.Open("sqlite3", "file:"+path+"?_busy_timeout=5000")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	for _, stmt := range []string{
		`DROP INDEX IF EXISTS idx_sandbox_snapshots_owner_name;`,
		`ALTER TABLE sandbox_snapshots DROP COLUMN owner_ref;`,
	} {
		if _, err := raw.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close raw: %v", err)
	}

	st, err = Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	// snap-kept lost its owner with the column; re-stamp it to check the
	// next open's backfill leaves an attributed row alone.
	if _, err := st.db.ExecContext(ctx, `UPDATE sandbox_snapshots SET owner_ref = 'globex' WHERE name = 'snap-kept'`); err != nil {
		t.Fatalf("restamp: %v", err)
	}
	if err := backfillSnapshotOwners(st.db); err != nil {
		t.Fatalf("second backfill: %v", err)
	}

	for name, want := range map[string]string{
		"snap-tenant":   "acme",
		"snap-operator": "",
		"snap-orphan":   "",
		"snap-kept":     "globex",
	} {
		got, err := st.GetSnapshot(ctx, name)
		if err != nil {
			t.Fatalf("GetSnapshot %s: %v", name, err)
		}
		if got.OwnerRef != want {
			t.Errorf("%s owner = %q, want %q", name, got.OwnerRef, want)
		}
	}
}

func seedSnapshotCatalogue(t *testing.T, st *Store) {
	t.Helper()
	ctx := context.Background()
	for _, sb := range []*models.Sandbox{ownedSandbox("sb-a1", "acme"), ownedSandbox("sb-a2", "acme"), ownedSandbox("sb-g1", "globex")} {
		if err := st.Create(ctx, sb); err != nil {
			t.Fatalf("Create %s: %v", sb.ID, err)
		}
	}
	for _, snap := range []*models.SandboxSnapshot{
		{Name: "snap-1", Image: "snap-1", SourceSandboxID: "sb-a1", OwnerRef: "acme"},
		{Name: "snap-2", Image: "snap-2", SourceSandboxID: "sb-g1", OwnerRef: "globex"},
		{Name: "snap-3", Image: "snap-3", SourceSandboxID: "sb-a2", OwnerRef: "acme"},
		{Name: "snap-4", Image: "snap-4", SourceSandboxID: "sb-a1", OwnerRef: "acme"},
		{Name: "snap-5", Image: "snap-5", SourceSandboxID: "sb-gone", OwnerRef: ""},
	} {
		if err := st.CreateSnapshot(ctx, snap); err != nil {
			t.Fatalf("CreateSnapshot %s: %v", snap.Name, err)
		}
	}
	for _, alias := range []models.SnapshotAlias{
		{Alias: "rl-1b", SnapshotName: "snap-1", Facade: models.FacadeRunloop, StateJSON: `{"name":"b"}`},
		// A second runloop alias on the same snapshot: the page must still
		// carry snap-1 once, joined with the smallest alias.
		{Alias: "rl-1a", SnapshotName: "snap-1", Facade: models.FacadeRunloop, StateJSON: `{"name":"a"}`, ExtraNames: []string{"extra"}},
		{Alias: "e2b-3", SnapshotName: "snap-3", Facade: models.FacadeE2B},
		{Alias: "rl-4", SnapshotName: "snap-4", Facade: models.FacadeRunloop},
	} {
		if err := st.UpsertSnapshotAlias(ctx, alias); err != nil {
			t.Fatalf("UpsertSnapshotAlias %s: %v", alias.Alias, err)
		}
	}
}

func pageNames(rows []SnapshotPageRow) []string {
	names := make([]string, 0, len(rows))
	for _, row := range rows {
		names = append(names, row.Snapshot.Name)
	}
	return names
}

func TestListSnapshotPage(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	seedSnapshotCatalogue(t, st)

	tests := []struct {
		name  string
		query SnapshotPageQuery
		want  []string
	}{
		{name: "unscoped sees every owner", query: SnapshotPageQuery{Limit: 10}, want: []string{"snap-1", "snap-2", "snap-3", "snap-4", "snap-5"}},
		{name: "scoped sees only its own", query: SnapshotPageQuery{OwnerRef: "acme", Scoped: true, Limit: 10}, want: []string{"snap-1", "snap-3", "snap-4"}},
		{name: "scoped operator namespace", query: SnapshotPageQuery{OwnerRef: "", Scoped: true, Limit: 10}, want: []string{"snap-5"}},
		{name: "cursor is exclusive", query: SnapshotPageQuery{OwnerRef: "acme", Scoped: true, AfterName: "snap-1", Limit: 10}, want: []string{"snap-3", "snap-4"}},
		{name: "limit bounds the page", query: SnapshotPageQuery{OwnerRef: "acme", Scoped: true, Limit: 2}, want: []string{"snap-1", "snap-3"}},
		{name: "source filter", query: SnapshotPageQuery{SourceSandboxID: "sb-a1", Limit: 10}, want: []string{"snap-1", "snap-4"}},
		{name: "source filter outside scope", query: SnapshotPageQuery{OwnerRef: "acme", Scoped: true, SourceSandboxID: "sb-g1", Limit: 10}, want: []string{}},
		{name: "cursor past the end", query: SnapshotPageQuery{AfterName: "snap-9", Limit: 10}, want: []string{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rows, err := st.ListSnapshotPage(ctx, tc.query)
			if err != nil {
				t.Fatalf("ListSnapshotPage: %v", err)
			}
			got := pageNames(rows)
			if len(got) != len(tc.want) {
				t.Fatalf("names = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("names = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

func TestListSnapshotPageAliasJoin(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	seedSnapshotCatalogue(t, st)

	rows, err := st.ListSnapshotPage(ctx, SnapshotPageQuery{AliasFacade: models.FacadeRunloop, Limit: 10})
	if err != nil {
		t.Fatalf("ListSnapshotPage: %v", err)
	}
	if got := pageNames(rows); len(got) != 5 {
		t.Fatalf("names = %v, want one row per snapshot", got)
	}
	aliases := map[string]*models.SnapshotAlias{}
	for _, row := range rows {
		aliases[row.Snapshot.Name] = row.Alias
	}
	if a := aliases["snap-1"]; a == nil || a.Alias != "rl-1a" || a.StateJSON != `{"name":"a"}` || len(a.ExtraNames) != 1 || a.ExtraNames[0] != "extra" || a.CreatedAt.IsZero() {
		t.Fatalf("snap-1 alias = %+v, want the smallest runloop alias rl-1a", a)
	}
	if a := aliases["snap-4"]; a == nil || a.Alias != "rl-4" || a.ExtraNames == nil {
		t.Fatalf("snap-4 alias = %+v", a)
	}
	// Another facade's alias is not joined.
	if a := aliases["snap-3"]; a != nil {
		t.Fatalf("snap-3 joined %+v, want no runloop alias", a)
	}

	// No facade: nothing is joined.
	rows, err = st.ListSnapshotPage(ctx, SnapshotPageQuery{Limit: 10})
	if err != nil {
		t.Fatalf("ListSnapshotPage: %v", err)
	}
	for _, row := range rows {
		if row.Alias != nil {
			t.Fatalf("%s joined %+v with no facade", row.Snapshot.Name, row.Alias)
		}
	}
}

func TestListSnapshotPageLimits(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	for _, limit := range []int{0, -1} {
		if _, err := st.ListSnapshotPage(ctx, SnapshotPageQuery{Limit: limit}); err == nil {
			t.Fatalf("limit %d accepted", limit)
		}
	}
	// A huge limit is clamped, never handed to an allocation.
	if rows, err := st.ListSnapshotPage(ctx, SnapshotPageQuery{Limit: int(^uint(0) >> 1)}); err != nil || len(rows) != 0 {
		t.Fatalf("max limit = %v, %v", rows, err)
	}
}

func TestCountSnapshots(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	seedSnapshotCatalogue(t, st)
	tests := []struct {
		name   string
		owner  string
		scoped bool
		source string
		want   int
	}{
		{name: "unscoped", want: 5},
		{name: "acme", owner: "acme", scoped: true, want: 3},
		{name: "globex", owner: "globex", scoped: true, want: 1},
		{name: "acme one source", owner: "acme", scoped: true, source: "sb-a1", want: 2},
		{name: "unscoped one source", source: "sb-g1", want: 1},
		{name: "unknown owner", owner: "nobody", scoped: true, want: 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := st.CountSnapshots(ctx, tc.owner, tc.scoped, tc.source)
			if err != nil || got != tc.want {
				t.Fatalf("CountSnapshots = %d, %v; want %d", got, err, tc.want)
			}
		})
	}
}

func TestListSnapshotAliasesForOwner(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	seedSnapshotCatalogue(t, st)

	got, err := st.ListSnapshotAliasesForOwner(ctx, models.FacadeRunloop, "acme")
	if err != nil {
		t.Fatalf("ListSnapshotAliasesForOwner: %v", err)
	}
	if len(got) != 3 || got["rl-1a"].SnapshotName != "snap-1" || got["rl-4"].SnapshotName != "snap-4" {
		t.Fatalf("acme runloop aliases = %+v", got)
	}
	all, err := st.ListSnapshotAliasesForOwner(ctx, "", "acme")
	if err != nil || len(all) != 4 {
		t.Fatalf("acme all-facade aliases = %+v, %v", all, err)
	}
	none, err := st.ListSnapshotAliasesForOwner(ctx, models.FacadeRunloop, "globex")
	if err != nil || len(none) != 0 {
		t.Fatalf("globex aliases = %+v, %v", none, err)
	}
}

// The lookup answers with the earliest listed name that exists, whatever
// order the rows come back in.
func TestGetSnapshotByNames(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	seedSnapshotCatalogue(t, st)
	for _, tc := range []struct {
		names []string
		want  string
	}{
		{[]string{"snap-3", "snap-1"}, "snap-3"},
		{[]string{"missing", "snap-4", "snap-2"}, "snap-4"},
		{[]string{" snap-5 "}, "snap-5"},
	} {
		got, err := st.GetSnapshotByNames(ctx, tc.names)
		if err != nil || got.Name != tc.want {
			t.Errorf("GetSnapshotByNames(%v) = %v, %v; want %s", tc.names, got, err, tc.want)
		}
	}
	for _, names := range [][]string{nil, {"missing", "also-missing"}} {
		if _, err := st.GetSnapshotByNames(ctx, names); !errors.Is(err, ErrNotFound) {
			t.Errorf("GetSnapshotByNames(%v) = %v, want ErrNotFound", names, err)
		}
	}
	if _, err := st.db.ExecContext(ctx, `UPDATE sandbox_snapshots SET entrypoint_json = '{' WHERE name = 'snap-2'`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetSnapshotByNames(ctx, []string{"snap-2"}); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("corrupt row = %v, want the scan error", err)
	}
	_ = st.Close()
	if _, err := st.GetSnapshotByNames(ctx, []string{"snap-1"}); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("closed store = %v", err)
	}
}

// queryPlan returns SQLite's plan for query, one detail line per step.
func queryPlan(t *testing.T, st *Store, query string, args []any) string {
	t.Helper()
	rows, err := st.db.Query("EXPLAIN QUERY PLAN "+query, args...)
	if err != nil {
		t.Fatalf("explain: %v", err)
	}
	defer rows.Close()
	var steps []string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatalf("scan plan: %v", err)
		}
		steps = append(steps, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("plan rows: %v", err)
	}
	return strings.Join(steps, "; ")
}

// A page and its count must narrow through the owner or source index, never
// by walking the whole catalogue by name and filtering each row: LIMIT
// bounds the rows returned, not the rows examined, so a tenant with no
// matches would otherwise read every other tenant's rows on each page.
func TestSnapshotPageAndCountSeekTheirIndex(t *testing.T) {
	st := newTestStore(t)
	seedSnapshotCatalogue(t, st)
	for _, tc := range []struct {
		name  string
		query SnapshotPageQuery
		index string
	}{
		{"scoped", SnapshotPageQuery{OwnerRef: "acme", Scoped: true, AliasFacade: models.FacadeRunloop}, "idx_sandbox_snapshots_owner_name"},
		{"scoped operator namespace", SnapshotPageQuery{Scoped: true}, "idx_sandbox_snapshots_owner_name"},
		{"one source", SnapshotPageQuery{SourceSandboxID: "sb-a1"}, "idx_sandbox_snapshots_source_sandbox_id"},
		{"scoped one source", SnapshotPageQuery{OwnerRef: "acme", Scoped: true, SourceSandboxID: "sb-a1"}, "idx_sandbox_snapshots_"},
		{"unscoped", SnapshotPageQuery{AfterName: "snap-2"}, "sqlite_autoindex_sandbox_snapshots_1 (name>?)"},
	} {
		page, args := snapshotPageSQL(tc.query, 10)
		plan := queryPlan(t, st, page, args)
		if !strings.Contains(plan, tc.index) || strings.Contains(plan, "SCAN s") {
			t.Errorf("%s page plan %q, want a seek of %s", tc.name, plan, tc.index)
		}
		count, countArgs := countSnapshotsSQL(tc.query.OwnerRef, tc.query.Scoped, tc.query.SourceSandboxID)
		if plan := queryPlan(t, st, count, countArgs); tc.query.Scoped || tc.query.SourceSandboxID != "" {
			if !strings.Contains(plan, "SEARCH s USING") {
				t.Errorf("%s count plan %q, want an index search", tc.name, plan)
			}
		}
	}
}

// The catalogue readers surface store failures rather than an empty page.
func TestSnapshotCatalogueReadErrors(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	seedSnapshotCatalogue(t, st)
	// A JSON null names list reads back as an empty list, not nil.
	if _, err := st.db.ExecContext(ctx, `UPDATE snapshot_aliases SET extra_names_json = 'null' WHERE alias = 'rl-4'`); err != nil {
		t.Fatalf("null alias names: %v", err)
	}
	rows, err := st.ListSnapshotPage(ctx, SnapshotPageQuery{AliasFacade: models.FacadeRunloop, AfterName: "snap-3", Limit: 1})
	if err != nil || len(rows) != 1 || rows[0].Alias == nil || rows[0].Alias.ExtraNames == nil {
		t.Fatalf("null alias names page = %+v, %v", rows, err)
	}
	if _, err := st.db.ExecContext(ctx, `UPDATE snapshot_aliases SET extra_names_json = '{' WHERE alias = 'rl-4'`); err != nil {
		t.Fatalf("corrupt alias: %v", err)
	}
	if _, err := st.ListSnapshotPage(ctx, SnapshotPageQuery{AliasFacade: models.FacadeRunloop, Limit: 10}); err == nil {
		t.Fatal("corrupt alias names decoded without error")
	}
	if _, err := st.ListSnapshotAliasesForOwner(ctx, models.FacadeRunloop, "acme"); err == nil {
		t.Fatal("corrupt alias row listed without error")
	}
	if _, err := st.db.ExecContext(ctx, `UPDATE sandbox_snapshots SET entrypoint_json = '{' WHERE name = 'snap-2'`); err != nil {
		t.Fatalf("corrupt snapshot: %v", err)
	}
	if _, err := st.ListSnapshotPage(ctx, SnapshotPageQuery{Limit: 10}); err == nil {
		t.Fatal("corrupt entrypoint decoded without error")
	}
	if _, err := st.db.ExecContext(ctx, `UPDATE sandbox_snapshots SET entrypoint_json = '[]', created_at = ? WHERE name = 'snap-2'`, []byte{1, 2, 3}); err != nil {
		t.Fatalf("corrupt created_at: %v", err)
	}
	if _, err := st.ListSnapshotPage(ctx, SnapshotPageQuery{Limit: 10}); err == nil {
		t.Fatal("unscannable row listed without error")
	}

	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := st.ListSnapshotPage(ctx, SnapshotPageQuery{Limit: 10}); err == nil {
		t.Fatal("ListSnapshotPage on a closed store succeeded")
	}
	if _, err := st.CountSnapshots(ctx, "", false, ""); err == nil {
		t.Fatal("CountSnapshots on a closed store succeeded")
	}
	if _, err := st.ListSnapshotAliasesForOwner(ctx, "", "acme"); err == nil {
		t.Fatal("ListSnapshotAliasesForOwner on a closed store succeeded")
	}
	if err := backfillSnapshotOwners(st.db); err == nil {
		t.Fatal("backfill on a closed store succeeded")
	}
}
