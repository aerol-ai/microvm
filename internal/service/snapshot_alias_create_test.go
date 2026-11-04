package service

import (
	"errors"
	"testing"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// CreateSnapshotWithAlias commits a snapshot and its facade alias in one call
// (D8): on success both rows exist; if the alias write fails, the just-created
// snapshot is rolled back so no aliasless snapshot is left behind.
func TestCreateSnapshotWithAlias(t *testing.T) {
	svc, _, _ := newSnapshotOwnerService(t)
	acme := userCtx("acme")

	t.Run("commits snapshot and alias together", func(t *testing.T) {
		snap, created, err := svc.CreateSnapshotWithAlias(acme, "sb-acme",
			models.CreateSandboxSnapshotRequest{Name: "acme-new"},
			models.SnapshotAlias{Alias: "acme-new-alias", Facade: models.FacadeRunloop, StateJSON: `{"k":"v"}`})
		if err != nil || !created {
			t.Fatalf("CreateSnapshotWithAlias = created %v err %v", created, err)
		}
		if snap.Name != "acme-new" {
			t.Fatalf("snapshot name = %q", snap.Name)
		}
		alias, err := svc.GetSnapshotAlias(acme, "acme-new-alias")
		if err != nil {
			t.Fatalf("GetSnapshotAlias: %v", err)
		}
		if alias.SnapshotName != "acme-new" || alias.StateJSON != `{"k":"v"}` {
			t.Fatalf("alias = %+v", alias)
		}
		if _, err := svc.GetSnapshot(acme, "acme-new"); err != nil {
			t.Fatalf("snapshot not found after create: %v", err)
		}
	})

	t.Run("rolls the snapshot back when the alias write fails", func(t *testing.T) {
		// globex cannot retarget "alias-acme" (it points at acme's snapshot,
		// which globex may not see), so the alias write fails and the snapshot
		// just created for globex must be removed.
		globex := userCtx("globex")
		_, _, err := svc.CreateSnapshotWithAlias(globex, "sb-globex",
			models.CreateSandboxSnapshotRequest{Name: "globex-doomed"},
			models.SnapshotAlias{Alias: "alias-acme", Facade: models.FacadeRunloop})
		if err == nil {
			t.Fatal("expected the alias retarget to be refused")
		}
		if _, err := svc.GetSnapshot(globex, "globex-doomed"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("snapshot survived a failed alias write: %v", err)
		}
	})

	t.Run("propagates a create error without writing an alias", func(t *testing.T) {
		if _, _, err := svc.CreateSnapshotWithAlias(acme, "sb-acme",
			models.CreateSandboxSnapshotRequest{Name: ""},
			models.SnapshotAlias{Alias: "never", Facade: models.FacadeRunloop}); err == nil {
			t.Fatal("empty snapshot name accepted")
		}
		if _, err := svc.GetSnapshotAlias(acme, "never"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("alias written despite create error: %v", err)
		}
	})
}
