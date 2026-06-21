package cluster

import (
	"context"
	"errors"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestNoopVolumeAttachmentsRoundTrip(t *testing.T) {
	n := NewNoop("standalone", "http://self", "")
	ctx := context.Background()
	v := models.Volume{ID: "vol-1", Tenant: "t-a", Name: "data", Backend: "s3", Source: "bucket/t-a/data"}
	if _, _, err := n.VolumeUpsert(ctx, v, 0); err != nil {
		t.Fatalf("VolumeUpsert: %v", err)
	}
	attach := models.VolumeAttachment{
		Tenant: "t-a", VolumeID: "vol-1", SandboxID: "sb-1", Target: "/data", Source: "bucket/t-a/data",
	}
	if err := n.PutVolumeAttachments(ctx, []models.VolumeAttachment{attach}); err != nil {
		t.Fatalf("PutVolumeAttachments: %v", err)
	}
	count, err := n.VolumeAttachmentCount(ctx, "t-a", "vol-1")
	if err != nil || count != 1 {
		t.Fatalf("VolumeAttachmentCount = %d, %v", count, err)
	}
	if err := n.VolumeDelete(ctx, "t-a", "vol-1"); !errors.Is(err, ErrVolumeInUse) {
		t.Fatalf("VolumeDelete attached = %v, want ErrVolumeInUse", err)
	}
	if err := n.DeleteVolumeAttachmentsForSandbox(ctx, "sb-1"); err != nil {
		t.Fatalf("DeleteVolumeAttachmentsForSandbox: %v", err)
	}
	if err := n.VolumeDelete(ctx, "t-a", "vol-1"); err != nil {
		t.Fatalf("VolumeDelete after detach: %v", err)
	}
}

func TestNoopPutVolumeAttachmentsRequiresKnownVolume(t *testing.T) {
	n := NewNoop("standalone", "http://self", "")
	err := n.PutVolumeAttachments(context.Background(), []models.VolumeAttachment{{
		Tenant: "t-a", VolumeID: "missing", SandboxID: "sb-1", Target: "/data", Source: "s/x",
	}})
	if !errors.Is(err, ErrUnknownVolume) {
		t.Fatalf("PutVolumeAttachments unknown volume = %v, want ErrUnknownVolume", err)
	}
}

func TestNoopVolumeReadsAndSourceIndex(t *testing.T) {
	n := NewNoop("standalone", "http://self", "")
	ctx := context.Background()
	v := models.Volume{ID: "vol-2", Tenant: "t-a", Name: "logs", Backend: "s3", Source: "bucket/t-a/logs"}
	if _, _, err := n.VolumeUpsert(ctx, v, 0); err != nil {
		t.Fatalf("VolumeUpsert: %v", err)
	}
	if got, err := n.VolumeByName(ctx, "t-a", "logs"); err != nil || got.ID != "vol-2" {
		t.Fatalf("VolumeByName = %+v, %v", got, err)
	}
	if got, err := n.VolumeByID(ctx, "t-a", "vol-2"); err != nil || got.Name != "logs" {
		t.Fatalf("VolumeByID = %+v, %v", got, err)
	}
	list, err := n.VolumesForTenant(ctx, "t-a")
	if err != nil || len(list) != 1 {
		t.Fatalf("VolumesForTenant = %+v, %v", list, err)
	}
	exists, err := n.VolumeExistsForSource(ctx, "bucket/t-a/logs")
	if err != nil || !exists {
		t.Fatalf("VolumeExistsForSource = %v, %v", exists, err)
	}
	if err := n.PutVolumeAttachments(ctx, nil); err != nil {
		t.Fatalf("PutVolumeAttachments empty: %v", err)
	}
}
