package service

import (
	"context"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// A deleted template's pushed copy is retired like a deleted snapshot's: the
// delete records the obligation, and the snapshot push worker removes the
// manifest by digest. Before, the copy stayed in the registry for good.
func TestDeleteTemplateRetiresItsRegistryCopy(t *testing.T) {
	ctx := context.Background()
	h := newRetirementHarness(t, true)
	const id = "tpl-gone"
	ref := templateAOCRRef("aocr.test", "cluster-1", id)
	now := time.Now().UTC()
	if err := h.st.CreateTemplate(ctx, &models.Template{ID: id, Image: "img", Status: models.TemplateStatusReady, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.st.MarkTemplatePushPending(ctx, id); err != nil {
		t.Fatal(err)
	}
	_, stamp, ok, err := h.st.ClaimTemplatePush(ctx, id)
	if err != nil || !ok {
		t.Fatalf("claim = %v, %v", ok, err)
	}
	if _, err := h.st.CompleteTemplatePush(ctx, id, stamp, ref, retireDigestOld); err != nil {
		t.Fatal(err)
	}

	if err := h.svc.DeleteTemplate(ctx, id); err != nil {
		t.Fatalf("DeleteTemplate: %v", err)
	}
	ledger := h.ledger(t)
	if len(ledger) != 1 || ledger[0].RegistryRef != ref || ledger[0].Digest != retireDigestOld || ledger[0].Name != id {
		t.Fatalf("ledger = %+v", ledger)
	}
	var stats SnapshotPushReconcileStats
	h.rec.retireRegistryCopies(ctx, &stats)
	if stats.Retired != 1 {
		t.Fatalf("retire sweep = %+v", stats)
	}
	if got := h.del.refs(); len(got) != 1 || got[0] != repoOf(ref)+"@"+retireDigestOld {
		t.Fatalf("deleted %v, want %s pinned by digest", got, repoOf(ref))
	}
	if ledger := h.ledger(t); len(ledger) != 0 {
		t.Fatalf("ledger after retirement = %+v", ledger)
	}
}

// A template push that lands after its claim was lost (a newer claim, or
// the row deleted meanwhile) records the copy it made for retirement.
func TestLateTemplatePushIsRecordedForRetirement(t *testing.T) {
	inner := newFakeTemplatePushStore()
	dk := &fakeTemplatePushDocker{digest: retireDigestNew}
	rec, templatesDir := newTestTemplateReconciler(t, fencedTemplatePushStore{inner}, dk)
	rootfs, mem, state := seedArtifactsOnDisk(t, templatesDir, "tpl-late")
	inner.seed(&models.Template{
		ID: "tpl-late", Image: "img:1", Status: models.TemplateStatusReady,
		PushState: models.TemplatePushStatePending, RootfsPath: rootfs,
		SnapshotMemoryPath: mem, SnapshotStatePath: state,
	})
	if got := rec.pushOne(context.Background(), inner.get("tpl-late")); got != templatePushSkipped {
		t.Fatalf("pushOne = %v, want a skip", got)
	}
	want := testHostAOCRRef("aocr.test/cluster/cluster-1/templates/tpl-late:latest")
	if len(inner.retirements) != 1 || inner.retirements[0].RegistryRef != want ||
		inner.retirements[0].Digest != retireDigestNew || inner.retirements[0].Name != "tpl-late" {
		t.Fatalf("retirements = %+v, want the late copy %s@%s", inner.retirements, want, retireDigestNew)
	}
}
