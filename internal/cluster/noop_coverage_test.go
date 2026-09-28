package cluster

import (
	"context"
	"errors"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestNoopVolumeQuotaAndAttachmentHelpers(t *testing.T) {
	n := NewNoop("node-a", "http://127.0.0.1:9000", "")
	ctx := context.Background()

	if _, _, err := n.VolumeUpsert(ctx, models.Volume{ID: "v1", Tenant: "tq", Name: "n1", Backend: "s3"}, 1); err != nil {
		t.Fatalf("VolumeUpsert first err=%v", err)
	}
	if _, _, err := n.VolumeUpsert(ctx, models.Volume{ID: "v2", Tenant: "tq", Name: "n2", Backend: "s3"}, 1); !errors.Is(err, ErrVolumeQuotaExceeded) {
		t.Fatalf("VolumeUpsert quota err=%v", err)
	}

	n.volMu.Lock()
	n.ensureVolumeAttachmentMapsLocked()
	if got := n.volumeAttachmentCountLocked("", ""); got != 0 {
		n.volMu.Unlock()
		t.Fatalf("volumeAttachmentCountLocked empty=%d", got)
	}
	a := models.VolumeAttachment{Tenant: "tq", VolumeID: "v1", SandboxID: "sb-1", IncarnationID: "inc-sb-1", Target: "/data", Source: "s3://x"}
	n.putVolumeAttachmentLocked(a)
	if got := n.volumeAttachmentCountLocked("tq", "v1"); got != 1 {
		n.volMu.Unlock()
		t.Fatalf("volumeAttachmentCountLocked=%d", got)
	}
	key := volumeAttachmentKey(a.Tenant, a.VolumeID, a.SandboxID, a.Target)
	n.releaseVolumeAttachmentKeyLocked(key, a)
	if got := n.volumeAttachmentCountLocked("tq", "v1"); got != 0 {
		n.volMu.Unlock()
		t.Fatalf("volumeAttachmentCountLocked after release=%d", got)
	}
	n.releaseVolumeAttachmentsForSandboxLocked("")
	n.volMu.Unlock()
}
