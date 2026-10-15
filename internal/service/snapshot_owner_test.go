package service

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// newSnapshotOwnerService seeds two tenants' sandboxes, each with one
// snapshot, plus an operator snapshot whose source is gone.
func newSnapshotOwnerService(t *testing.T) (*Service, *store.Store, *fakeSnapshotRuntime) {
	svc, st, rt, _ := newSnapshotOwnerServiceAt(t)
	return svc, st, rt
}

func newSnapshotOwnerServiceAt(t *testing.T) (*Service, *store.Store, *fakeSnapshotRuntime, string) {
	t.Helper()
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "state.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	now := time.Now().UTC()
	for _, sb := range []*models.Sandbox{
		{ID: "sb-acme", OwnerRef: "acme", ContainerID: "ctr-acme"},
		{ID: "sb-globex", OwnerRef: "globex", ContainerID: "ctr-globex"},
	} {
		sb.Image, sb.Status, sb.CPU, sb.MemoryMB, sb.DiskGB, sb.OSUser = "ubuntu:22.04", models.SandboxStatusStarted, 1, 1024, 10, "root"
		sb.Env, sb.ToolboxEnabled, sb.Runtime = map[string]string{}, true, models.RuntimeDocker
		sb.CreatedAt, sb.UpdatedAt, sb.LastActiveAt = now, now, now
		if err := st.Create(ctx, sb); err != nil {
			t.Fatalf("seed sandbox %s: %v", sb.ID, err)
		}
	}
	for _, snap := range []*models.SandboxSnapshot{
		{Name: "snap-acme", Image: "snap-acme", ImageID: "sha256:acme", SourceSandboxID: "sb-acme", OwnerRef: "acme", CreatedAt: now},
		{Name: "snap-globex", Image: "snap-globex", ImageID: "sha256:globex", SourceSandboxID: "sb-globex", OwnerRef: "globex", CreatedAt: now},
		{Name: "snap-shared", Image: "snap-shared", ImageID: "sha256:shared", SourceSandboxID: "sb-gone", CreatedAt: now},
	} {
		if err := st.CreateSnapshot(ctx, snap); err != nil {
			t.Fatalf("seed snapshot %s: %v", snap.Name, err)
		}
	}
	for _, alias := range []models.SnapshotAlias{
		{Alias: "alias-acme", SnapshotName: "snap-acme", Facade: models.FacadeRunloop, StateJSON: `{"name":"acme"}`},
		{Alias: "alias-globex", SnapshotName: "snap-globex", Facade: models.FacadeRunloop, StateJSON: `{"name":"globex"}`},
	} {
		if err := st.UpsertSnapshotAlias(ctx, alias); err != nil {
			t.Fatalf("seed alias %s: %v", alias.Alias, err)
		}
	}
	rt := &fakeSnapshotRuntime{imageID: "sha256:new"}
	svc := &Service{store: st, docker: rt, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	return svc, st, rt, dbPath
}

func TestSnapshotVisible(t *testing.T) {
	own := &models.SandboxSnapshot{Name: "s", OwnerRef: "acme"}
	tests := []struct {
		name string
		ctx  context.Context
		snap *models.SandboxSnapshot
		want bool
	}{
		{name: "internal caller", ctx: context.Background(), snap: own, want: true},
		{name: "operator", ctx: operatorCtx(), snap: own, want: true},
		{name: "owner", ctx: userCtx("acme"), snap: own, want: true},
		{name: "other tenant", ctx: userCtx("globex"), snap: own, want: false},
		{name: "operator row vs user", ctx: userCtx("acme"), snap: &models.SandboxSnapshot{Name: "s"}, want: false},
		{name: "nil row vs user", ctx: userCtx("acme"), snap: nil, want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := snapshotVisible(tc.ctx, tc.snap); got != tc.want {
				t.Fatalf("snapshotVisible = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestGetSnapshotOwnerScoped(t *testing.T) {
	svc, _, _ := newSnapshotOwnerService(t)
	tests := []struct {
		name    string
		ctx     context.Context
		lookup  string
		wantErr bool
	}{
		{name: "owner by name", ctx: userCtx("acme"), lookup: "snap-acme"},
		{name: "owner by image id", ctx: userCtx("acme"), lookup: "sha256:acme"},
		{name: "other tenant by name", ctx: userCtx("acme"), lookup: "snap-globex", wantErr: true},
		{name: "other tenant by image id", ctx: userCtx("acme"), lookup: "sha256:globex", wantErr: true},
		{name: "operator row hidden from user", ctx: userCtx("acme"), lookup: "snap-shared", wantErr: true},
		{name: "operator sees every row", ctx: operatorCtx(), lookup: "snap-globex"},
		{name: "internal sees by image id", ctx: context.Background(), lookup: "sha256:globex"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := svc.GetSnapshot(tc.ctx, tc.lookup)
			if tc.wantErr {
				if !errors.Is(err, store.ErrNotFound) {
					t.Fatalf("GetSnapshot = %+v, %v; want ErrNotFound", got, err)
				}
				return
			}
			if err != nil || got == nil {
				t.Fatalf("GetSnapshot = %+v, %v", got, err)
			}
		})
	}
}

func TestListSnapshotsOwnerScoped(t *testing.T) {
	svc, _, _ := newSnapshotOwnerService(t)
	tests := []struct {
		name string
		ctx  context.Context
		want int
	}{
		{name: "acme", ctx: userCtx("acme"), want: 1},
		{name: "globex", ctx: userCtx("globex"), want: 1},
		{name: "unknown tenant", ctx: userCtx("nobody"), want: 0},
		{name: "operator", ctx: operatorCtx(), want: 3},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := svc.ListSnapshots(tc.ctx)
			if err != nil || len(got) != tc.want {
				t.Fatalf("ListSnapshots = %d rows, %v; want %d", len(got), err, tc.want)
			}
			if _, scoped := ownerScope(tc.ctx); scoped {
				owner, _ := ownerScope(tc.ctx)
				for _, snap := range got {
					if snap.OwnerRef != owner {
						t.Fatalf("leaked %s (owner %q)", snap.Name, snap.OwnerRef)
					}
				}
			}
		})
	}
}

func TestSnapshotPageAndCountOwnerScoped(t *testing.T) {
	svc, _, _ := newSnapshotOwnerService(t)
	rows, err := svc.ListSnapshotPage(userCtx("acme"), "", models.FacadeRunloop, "", 10)
	if err != nil || len(rows) != 1 || rows[0].Snapshot.Name != "snap-acme" || rows[0].Alias == nil || rows[0].Alias.Alias != "alias-acme" {
		t.Fatalf("acme page = %+v, %v", rows, err)
	}
	if rows, err := svc.ListSnapshotPage(userCtx("acme"), "sb-globex", "", "", 10); err != nil || len(rows) != 0 {
		t.Fatalf("acme page over globex source = %+v, %v", rows, err)
	}
	if rows, err := svc.ListSnapshotPage(operatorCtx(), "", "", "", 10); err != nil || len(rows) != 3 {
		t.Fatalf("operator page = %d rows, %v", len(rows), err)
	}
	if n, err := svc.CountSnapshots(userCtx("globex"), ""); err != nil || n != 1 {
		t.Fatalf("globex count = %d, %v", n, err)
	}
	if n, err := svc.CountSnapshots(context.Background(), "sb-acme"); err != nil || n != 1 {
		t.Fatalf("internal count by source = %d, %v", n, err)
	}
}

func TestDeleteSnapshotOwnerScoped(t *testing.T) {
	svc, st, rt := newSnapshotOwnerService(t)
	ctx := context.Background()
	if err := svc.DeleteSnapshot(userCtx("acme"), "snap-globex"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cross-tenant delete = %v, want ErrNotFound", err)
	}
	if rt.removeHits != 0 {
		t.Fatalf("cross-tenant delete removed image %q", rt.lastRemoved)
	}
	if _, err := st.GetSnapshot(ctx, "snap-globex"); err != nil {
		t.Fatalf("cross-tenant delete removed the row: %v", err)
	}
	if err := svc.DeleteSnapshot(userCtx("acme"), "snap-acme"); err != nil {
		t.Fatalf("owner delete: %v", err)
	}
	if _, err := st.GetSnapshot(ctx, "snap-acme"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("owner delete left the row: %v", err)
	}
}

func TestCreateSnapshotWithOwnershipOwnerScoped(t *testing.T) {
	svc, st, rt := newSnapshotOwnerService(t)

	// An operator snapshotting a tenant sandbox makes a tenant snapshot.
	created, isNew, err := svc.CreateSnapshotWithOwnership(operatorCtx(), "sb-globex", models.CreateSandboxSnapshotRequest{Name: "snap-new"})
	if err != nil || !isNew || created.OwnerRef != "globex" {
		t.Fatalf("operator create = %+v, %v, %v; want owner globex", created, isNew, err)
	}
	if stored, err := st.GetSnapshot(context.Background(), "snap-new"); err != nil || stored.OwnerRef != "globex" {
		t.Fatalf("stored owner = %+v, %v", stored, err)
	}

	tests := []struct {
		name    string
		ctx     context.Context
		sandbox string
		snap    string
		wantErr error
	}{
		// The fast path runs before the source sandbox is loaded: it must not
		// hand another tenant's snapshot to a caller naming its sandbox.
		{name: "other tenant's retry", ctx: userCtx("acme"), sandbox: "sb-globex", snap: "snap-new", wantErr: store.ErrNotFound},
		{name: "name taken by another source", ctx: userCtx("acme"), sandbox: "sb-acme", snap: "snap-new", wantErr: store.ErrSnapshotNameConflict},
		{name: "owner's retry", ctx: userCtx("globex"), sandbox: "sb-globex", snap: "snap-new"},
		{name: "internal retry", ctx: context.Background(), sandbox: "sb-globex", snap: "snap-new"},
		{name: "cross-tenant new snapshot", ctx: userCtx("acme"), sandbox: "sb-globex", snap: "snap-fresh", wantErr: store.ErrNotFound},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, isNew, err := svc.CreateSnapshotWithOwnership(tc.ctx, tc.sandbox, models.CreateSandboxSnapshotRequest{Name: tc.snap})
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) || got != nil {
					t.Fatalf("CreateSnapshotWithOwnership = %+v, %v; want %v", got, err, tc.wantErr)
				}
				return
			}
			if err != nil || isNew || got.Name != tc.snap {
				t.Fatalf("CreateSnapshotWithOwnership = %+v, %v, %v; want replay", got, isNew, err)
			}
		})
	}
	if rt.hits != 1 {
		t.Fatalf("runtime snapshot hits = %d, want 1 (only the first create commits)", rt.hits)
	}
}

// The post-insert conflict re-read applies the same rule as the fast path: a
// concurrent create that won the name answers only a caller who may see it.
func TestCreateSnapshotWithOwnershipConflictReread(t *testing.T) {
	tests := []struct {
		name    string
		ctx     context.Context
		race    *models.SandboxSnapshot
		wantErr error
	}{
		{name: "same source, visible", ctx: userCtx("acme"), race: &models.SandboxSnapshot{SourceSandboxID: "sb-acme", OwnerRef: "acme"}},
		{name: "same source, hidden", ctx: userCtx("acme"), race: &models.SandboxSnapshot{SourceSandboxID: "sb-acme", OwnerRef: "globex"}, wantErr: store.ErrNotFound},
		{name: "other source", ctx: userCtx("acme"), race: &models.SandboxSnapshot{SourceSandboxID: "sb-globex", OwnerRef: "globex"}, wantErr: store.ErrSnapshotNameConflict},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc, st, _ := newSnapshotOwnerService(t)
			svc.testBeforeStoreCreateSnapshot = func(snap *models.SandboxSnapshot) {
				race := *tc.race
				race.Name, race.Image, race.CreatedAt = snap.Name, snap.Name, time.Now().UTC()
				if err := st.CreateSnapshot(context.Background(), &race); err != nil {
					t.Fatalf("racing insert: %v", err)
				}
			}
			got, isNew, err := svc.CreateSnapshotWithOwnership(tc.ctx, "sb-acme", models.CreateSandboxSnapshotRequest{Name: "snap-race"})
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("CreateSnapshotWithOwnership = %+v, %v; want %v", got, err, tc.wantErr)
				}
				return
			}
			if err != nil || isNew || got == nil {
				t.Fatalf("CreateSnapshotWithOwnership = %+v, %v, %v; want the racing row", got, isNew, err)
			}
		})
	}
}

func TestRegisterSnapshotOwnerScoped(t *testing.T) {
	svc, st, _ := newSnapshotOwnerService(t)
	registered, err := svc.RegisterSnapshot(userCtx("acme"), &models.SandboxSnapshot{Name: "reg-acme", Image: "alpine:3.20"})
	if err != nil || registered.OwnerRef != "acme" {
		t.Fatalf("register = %+v, %v; want owner acme", registered, err)
	}
	if stored, err := st.GetSnapshot(context.Background(), "reg-acme"); err != nil || stored.OwnerRef != "acme" {
		t.Fatalf("stored = %+v, %v", stored, err)
	}
	tests := []struct {
		name    string
		ctx     context.Context
		image   string
		wantErr bool
	}{
		{name: "owner retry", ctx: userCtx("acme"), image: "alpine:3.20"},
		{name: "operator retry", ctx: operatorCtx(), image: "alpine:3.20"},
		{name: "other tenant, same image", ctx: userCtx("globex"), image: "alpine:3.20", wantErr: true},
		{name: "owner, different image", ctx: userCtx("acme"), image: "alpine:3.21", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := svc.RegisterSnapshot(tc.ctx, &models.SandboxSnapshot{Name: "reg-acme", Image: tc.image})
			if tc.wantErr {
				if !errors.Is(err, store.ErrSnapshotNameConflict) || got != nil {
					t.Fatalf("RegisterSnapshot = %+v, %v; want ErrSnapshotNameConflict", got, err)
				}
				return
			}
			if err != nil || got.OwnerRef != "acme" {
				t.Fatalf("RegisterSnapshot = %+v, %v; want the acme row", got, err)
			}
		})
	}
	// An operator registration stays in the operator namespace.
	if got, err := svc.RegisterSnapshot(operatorCtx(), &models.SandboxSnapshot{Name: "reg-op", Image: "alpine:3.20"}); err != nil || got.OwnerRef != "" {
		t.Fatalf("operator register = %+v, %v", got, err)
	}
}

func TestSnapshotAliasesOwnerScoped(t *testing.T) {
	svc, st, _ := newSnapshotOwnerService(t)
	acme, globex := userCtx("acme"), userCtx("globex")

	if got, err := svc.GetSnapshotAlias(acme, "alias-acme"); err != nil || got.StateJSON != `{"name":"acme"}` {
		t.Fatalf("own alias = %+v, %v", got, err)
	}
	if got, err := svc.GetSnapshotAlias(acme, "alias-globex"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cross-tenant alias = %+v, %v; want ErrNotFound", got, err)
	}
	if _, err := svc.GetSnapshotAlias(acme, "alias-missing"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing alias = %v", err)
	}
	if got, err := svc.GetSnapshotAlias(operatorCtx(), "alias-globex"); err != nil || got.SnapshotName != "snap-globex" {
		t.Fatalf("operator alias = %+v, %v", got, err)
	}

	listed, err := svc.ListSnapshotAliases(acme, models.FacadeRunloop)
	if err != nil || len(listed) != 1 || listed["alias-acme"].SnapshotName != "snap-acme" {
		t.Fatalf("acme list = %+v, %v", listed, err)
	}
	if listed, err := svc.ListSnapshotAliases(operatorCtx(), models.FacadeRunloop); err != nil || len(listed) != 2 {
		t.Fatalf("operator list = %+v, %v", listed, err)
	}

	upserts := []struct {
		name    string
		ctx     context.Context
		alias   models.SnapshotAlias
		wantErr bool
	}{
		{name: "onto another tenant's snapshot", ctx: acme, alias: models.SnapshotAlias{Alias: "steal", SnapshotName: "snap-globex", Facade: models.FacadeRunloop}, wantErr: true},
		// Retargeting another tenant's alias at one's own snapshot would take
		// the alias over.
		{name: "retarget another tenant's alias", ctx: acme, alias: models.SnapshotAlias{Alias: "alias-globex", SnapshotName: "snap-acme", Facade: models.FacadeRunloop}, wantErr: true},
		{name: "onto a missing snapshot", ctx: acme, alias: models.SnapshotAlias{Alias: "ghost", SnapshotName: "snap-missing", Facade: models.FacadeRunloop}, wantErr: true},
		{name: "new alias on own snapshot", ctx: acme, alias: models.SnapshotAlias{Alias: "acme-2", SnapshotName: "snap-acme", Facade: models.FacadeRunloop}},
		{name: "update own alias", ctx: acme, alias: models.SnapshotAlias{Alias: "alias-acme", SnapshotName: "snap-acme", Facade: models.FacadeRunloop, StateJSON: `{"name":"renamed"}`}},
		{name: "operator writes anywhere", ctx: operatorCtx(), alias: models.SnapshotAlias{Alias: "op-alias", SnapshotName: "snap-globex", Facade: models.FacadeRunloop}},
	}
	for _, tc := range upserts {
		t.Run(tc.name, func(t *testing.T) {
			err := svc.UpsertSnapshotAlias(tc.ctx, tc.alias)
			if tc.wantErr != (err != nil) {
				t.Fatalf("UpsertSnapshotAlias = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr && !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("UpsertSnapshotAlias = %v, want ErrNotFound", err)
			}
		})
	}
	if got, err := st.GetSnapshotAlias(context.Background(), "alias-globex"); err != nil || got.SnapshotName != "snap-globex" {
		t.Fatalf("globex alias after retarget attempt = %+v, %v", got, err)
	}

	if err := svc.DeleteSnapshotAlias(acme, "alias-globex"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cross-tenant alias delete = %v, want ErrNotFound", err)
	}
	if err := svc.DeleteSnapshotAlias(acme, "alias-missing"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing alias delete = %v", err)
	}
	if err := svc.DeleteSnapshotAlias(globex, "alias-globex"); err != nil {
		t.Fatalf("owner alias delete: %v", err)
	}
	if err := svc.DeleteSnapshotAlias(context.Background(), "op-alias"); err != nil {
		t.Fatalf("internal alias delete: %v", err)
	}
}

// Store failures surface from the scoped alias paths instead of reading as
// "not yours".
func TestSnapshotAliasesOwnerScopedStoreErrors(t *testing.T) {
	svc, st, _ := newSnapshotOwnerService(t)
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	acme := userCtx("acme")
	if err := svc.UpsertSnapshotAlias(acme, models.SnapshotAlias{Alias: "a", SnapshotName: "snap-acme"}); err == nil || errors.Is(err, store.ErrNotFound) {
		t.Fatalf("upsert on closed store = %v", err)
	}
	if _, err := svc.ListSnapshotAliases(acme, ""); err == nil {
		t.Fatal("list on closed store succeeded")
	}
	if _, err := svc.ListSnapshots(acme); err == nil {
		t.Fatal("ListSnapshots on closed store succeeded")
	}
}

// An existing alias row read failure (not "missing") stops the upsert.
func TestUpsertSnapshotAliasExistingReadError(t *testing.T) {
	svc, st, _, dbPath := newSnapshotOwnerServiceAt(t)
	if err := st.UpsertSnapshotAlias(context.Background(), models.SnapshotAlias{Alias: "broken", SnapshotName: "snap-acme", Facade: models.FacadeRunloop}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	raw, err := sql.Open("sqlite3", dbPath+"?_busy_timeout=5000")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer raw.Close()
	if _, err := raw.Exec(`UPDATE snapshot_aliases SET extra_names_json = '{' WHERE alias = 'broken'`); err != nil {
		t.Fatalf("corrupt: %v", err)
	}
	err = svc.UpsertSnapshotAlias(userCtx("acme"), models.SnapshotAlias{Alias: "broken", SnapshotName: "snap-acme", Facade: models.FacadeRunloop})
	if err == nil || errors.Is(err, store.ErrNotFound) {
		t.Fatalf("upsert over unreadable alias = %v, want the read error", err)
	}
}

// A user token reaches a snapshot only through a snapshot it owns, under
// every spelling of a reference the engine would accept: its name in any
// equivalent form, an image id (resolved by content, a prefix is enough),
// or a ref into the cluster's snapshot registry. A snapshot with no owner is
// the operator's. Operator and internal callers may start anything.
func TestNormalizeCreateImageDistributionSnapshotOwner(t *testing.T) {
	svc, _, _ := newSnapshotOwnerService(t)
	registry := func(owner, name string) string {
		return snapshotAOCRRef("aocr.test", "c1", owner, name, "")
	}
	tests := []struct {
		name        string
		ctx         context.Context
		image       string
		registryRef string
		wantErr     bool
		wantImage   string
	}{
		{name: "own snapshot", ctx: userCtx("acme"), image: "snap-acme"},
		{name: "own snapshot by tag", ctx: userCtx("acme"), image: "snap-acme:latest", wantImage: "snap-acme"},
		{name: "own snapshot by registry spelling", ctx: userCtx("acme"), image: "docker.io/library/snap-acme", wantImage: "snap-acme"},
		{name: "own registry namespace", ctx: userCtx("acme"), image: registry("acme", "snap-acme")},
		{name: "another tenant's snapshot", ctx: userCtx("acme"), image: "snap-globex", wantErr: true},
		{name: "another tenant's by tag", ctx: userCtx("acme"), image: "snap-globex:latest", wantErr: true},
		{name: "another tenant's by registry spelling", ctx: userCtx("acme"), image: "index.docker.io/library/snap-globex:latest", wantErr: true},
		{name: "another tenant's image id", ctx: userCtx("acme"), image: "sha256:globex", wantErr: true},
		{name: "own image id", ctx: userCtx("acme"), image: "sha256:acme", wantErr: true},
		{name: "image id prefix", ctx: userCtx("acme"), image: "4f1a", wantErr: true},
		{name: "another tenant's registry namespace", ctx: userCtx("acme"), image: registry("globex", "snap-globex"), wantErr: true},
		{name: "operator registry namespace", ctx: userCtx("acme"), image: registry("", "snap-shared"), wantErr: true},
		{name: "forged registry ref", ctx: userCtx("acme"), image: "ubuntu:22.04", registryRef: registry("globex", "snap-globex"), wantErr: true},
		{name: "operator snapshot", ctx: userCtx("acme"), image: "snap-shared", wantErr: true},
		{name: "operator caller", ctx: operatorCtx(), image: "snap-globex"},
		{name: "operator caller, operator snapshot", ctx: operatorCtx(), image: "snap-shared"},
		{name: "operator caller, image id", ctx: operatorCtx(), image: "sha256:globex", wantImage: "sha256:globex"},
		{name: "operator caller, any namespace", ctx: operatorCtx(), image: registry("globex", "snap-globex")},
		{name: "internal caller", ctx: context.Background(), image: "snap-globex"},
		{name: "plain image", ctx: userCtx("acme"), image: "ubuntu:22.04"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := models.CreateSandboxRequest{Image: tc.image, ImageRegistryRef: tc.registryRef}
			err := svc.NormalizeCreateImageDistribution(tc.ctx, &req)
			if tc.wantErr {
				if !errors.Is(err, store.ErrNotFound) {
					t.Fatalf("NormalizeCreateImageDistribution = %v (image %q), want ErrNotFound", err, req.Image)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeCreateImageDistribution = %v", err)
			}
			if tc.wantImage != "" && req.Image != tc.wantImage {
				t.Fatalf("image = %q, want %q", req.Image, tc.wantImage)
			}
		})
	}
}

// A node with no row for a snapshot cannot check its owner, so the ref it
// builds carries the authorization: a user token's lands in that tenant's
// own registry namespace, where only its own snapshots were ever pushed, and
// two tenants asking for the same name get different refs. An operator gets
// the unnamespaced path, and a replayed spec keeps the ref it resolved to.
func TestCrossNodeSnapshotRefIsOwnerBound(t *testing.T) {
	svc, _, _ := newSnapshotOwnerService(t)
	pusher, err := NewSnapshotPusher(SnapshotPushConfig{Enabled: true, Host: "aocr.test", ClusterID: "cluster-7", PATPath: writePATFile(t, "token")}, &fakeSnapshotPushDocker{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	svc.snapshotPusher = pusher
	resolve := func(ctx context.Context, req models.CreateSandboxRequest) string {
		t.Helper()
		if err := svc.NormalizeCreateImageDistribution(ctx, &req); err != nil {
			t.Fatalf("NormalizeCreateImageDistribution(%q) = %v", req.Image, err)
		}
		return req.Image
	}
	acme := resolve(userCtx("acme"), models.CreateSandboxRequest{Image: "remote-snap"})
	globex := resolve(userCtx("globex"), models.CreateSandboxRequest{Image: "remote-snap"})
	if acme != pusher.DestRefFor("acme", "remote-snap") || !strings.Contains(acme, "/snapshots/"+snapshotOwnerNamespace("acme")+"/remote-snap:") {
		t.Fatalf("acme resolved %q, want its own namespace", acme)
	}
	if globex == acme {
		t.Fatalf("two tenants resolved one name to the same ref %q", acme)
	}
	if got := resolve(operatorCtx(), models.CreateSandboxRequest{Image: "remote-snap"}); got != pusher.DestRefFor("", "remote-snap") {
		t.Fatalf("operator resolved %q", got)
	}
	replayed := models.CreateSandboxRequest{Image: "remote-snap", ImageDistributionMode: models.ImageDistributionAOCR, ImageRegistryRef: acme}
	if got := resolve(context.Background(), replayed); got != acme {
		t.Fatalf("a replayed spec resolved %q, want its stored ref %q", got, acme)
	}
	// A user token cannot carry another tenant's ref in through the spec.
	forged := models.CreateSandboxRequest{Image: "remote-snap", ImageDistributionMode: models.ImageDistributionAOCR, ImageRegistryRef: acme}
	if err := svc.NormalizeCreateImageDistribution(userCtx("globex"), &forged); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("forged spec = %v (image %q), want ErrNotFound", err, forged.Image)
	}
}

// A tenant's snapshot is pushed under its owner's namespace; an operator's
// keeps the unnamespaced path.
func TestSnapshotPushUsesTheOwnerNamespace(t *testing.T) {
	fake := &fakeSnapshotPushDocker{}
	pusher, err := NewSnapshotPusher(SnapshotPushConfig{Enabled: true, Host: "aocr.test", ClusterID: "cluster-7", PATPath: writePATFile(t, "token")}, fake, nil)
	if err != nil {
		t.Fatal(err)
	}
	for owner, want := range map[string]string{
		"acme": pusher.DestRefFor("acme", "snap"),
		"":     "aocr.test/cluster/cluster-7/snapshots/snap:latest" + archTagSuffix(snapshotRefArch()),
	} {
		res, err := pusher.PushOnce(context.Background(), &models.SandboxSnapshot{Name: "snap", Image: "snap", OwnerRef: owner})
		if err != nil || res.RegistryRef != want {
			t.Fatalf("owner %q pushed to %q (%v), want %q", owner, res.RegistryRef, err, want)
		}
		namespace, ok := snapshotRefNamespace(res.RegistryRef)
		if !ok || namespace != snapshotOwnerNamespace(owner) {
			t.Fatalf("owner %q ref %q parses to namespace %q, %v", owner, res.RegistryRef, namespace, ok)
		}
	}
	for _, ref := range []string{"ubuntu:22.04", "aocr.test/cluster/c/templates/x:latest", "aocr.test/cluster/c/snapshots", "Not A Ref"} {
		if _, ok := snapshotRefNamespace(ref); ok {
			t.Errorf("%q parsed as a snapshot registry ref", ref)
		}
	}
}
