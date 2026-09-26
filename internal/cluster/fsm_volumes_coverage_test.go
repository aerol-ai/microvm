package cluster

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestNoopVolumeByIDAndDeleteBranches(t *testing.T) {
	n := NewNoop("n", "http://x", "")
	ctx := context.Background()
	if _, _, err := n.VolumeUpsert(ctx, models.Volume{ID: "v", Tenant: "t", Name: "n", Backend: "s3"}, 0); err != nil {
		t.Fatal(err)
	}
	if got, err := n.VolumeByID(ctx, "t", "v"); err != nil || got.ID != "v" {
		t.Fatalf("VolumeByID=%+v err=%v", got, err)
	}
	if _, err := n.VolumeByID(ctx, "t", "missing"); !errors.Is(err, ErrUnknownVolume) {
		t.Fatalf("missing by id=%v", err)
	}
	if _, err := n.VolumeByName(ctx, "t", "missing"); !errors.Is(err, ErrUnknownVolume) {
		t.Fatalf("missing by name=%v", err)
	}
	if exists, err := n.VolumeExistsForSource(ctx, "nope"); err != nil || exists {
		t.Fatalf("exists=%v err=%v", exists, err)
	}
	if err := n.VolumeDelete(ctx, "t", "v"); err != nil {
		t.Fatal(err)
	}
	if err := n.VolumeDelete(ctx, "t", "v"); !errors.Is(err, ErrUnknownVolume) {
		t.Fatalf("second delete=%v", err)
	}
}

func TestClusterVolumeUpsertQuotaAndApplyErrors(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	c, cleanup := newTestCluster(t, "ldr-vol-q", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	ctx := context.Background()

	if _, _, err := c.VolumeUpsert(ctx, models.Volume{ID: "v1", Tenant: "tq", Name: "a", Backend: "s3"}, 1); err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	if _, _, err := c.VolumeUpsert(ctx, models.Volume{ID: "v2", Tenant: "tq", Name: "b", Backend: "s3"}, 1); !errors.Is(err, ErrVolumeQuotaExceeded) {
		t.Fatalf("quota=%v", err)
	}
	if err := c.VolumeDelete(ctx, "tq", "missing"); !errors.Is(err, ErrUnknownVolume) {
		t.Fatalf("delete missing=%v", err)
	}
	if err := c.PutVolumeAttachments(ctx, []models.VolumeAttachment{{
		Tenant: "tq", VolumeID: "missing", SandboxID: "sb", IncarnationID: "inc-sb", Target: "/d", Source: "s",
	}}); !errors.Is(err, ErrUnknownVolume) {
		t.Fatalf("attach unknown=%v", err)
	}
}

func TestNoopVolumeValidationAndAttachmentOverwrite(t *testing.T) {
	n := NewNoop("n", "http://x", "")
	ctx := context.Background()
	if _, _, err := n.VolumeUpsert(ctx, models.Volume{}, 0); !errors.Is(err, ErrUnknownVolume) {
		t.Fatalf("validation=%v", err)
	}
	if _, _, err := n.VolumeUpsert(ctx, models.Volume{ID: "v1", Tenant: "t", Name: "n1", Backend: "s3"}, 0); err != nil {
		t.Fatal(err)
	}
	// Idempotent existing-name return (111-113).
	row, created, err := n.VolumeUpsert(ctx, models.Volume{ID: "other", Tenant: "t", Name: "n1", Backend: "s3"}, 0)
	if err != nil || created || row.ID != "v1" {
		t.Fatalf("existing name row=%+v created=%v err=%v", row, created, err)
	}
	if err := n.PutVolumeAttachments(ctx, []models.VolumeAttachment{{
		Tenant: "t", VolumeID: "v1", SandboxID: "", IncarnationID: "inc-sb", Target: "/d", Source: "s",
	}}); !errors.Is(err, ErrUnknownVolume) {
		t.Fatalf("incomplete attachment=%v", err)
	}
	a := models.VolumeAttachment{Tenant: "t", VolumeID: "v1", SandboxID: "sb", IncarnationID: "inc-sb", Target: "/d", Source: "s"}
	if err := n.PutVolumeAttachments(ctx, []models.VolumeAttachment{a}); err != nil {
		t.Fatal(err)
	}
	// Overwrite same key → release existing branch (255-257).
	a.Source = "s2"
	if err := n.PutVolumeAttachments(ctx, []models.VolumeAttachment{a}); err != nil {
		t.Fatal(err)
	}
}
