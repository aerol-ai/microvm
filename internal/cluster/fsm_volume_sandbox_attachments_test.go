package cluster

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/hashicorp/raft"
)

// TestFSMVolumeAttachmentsForSandbox: a destroy can list the attachments
// one sandbox holds, sorted, and they are gone once its placement delete
// releases them. A volume's delete_with_sandbox rides the replicated row
// and survives a snapshot round trip. Read-only: no new FSM command.
func TestFSMVolumeAttachmentsForSandbox(t *testing.T) {
	f := newPlacementFSM()
	idx := uint64(0)
	apply := func(cmd command) {
		t.Helper()
		idx++
		if got := f.Apply(&raft.Log{Index: idx, Data: mustEncode(t, cmd)}); got != nil {
			t.Fatalf("apply %d: %v", cmd.Op, got)
		}
	}
	apply(volCmd(models.Volume{ID: "vol-a", Tenant: "t-a", Name: "a", Backend: "s3", Source: "b/a"}, 0))
	apply(volCmd(models.Volume{ID: "vol-b", Tenant: "t-a", Name: "b", Backend: "s3", Source: "b/b", DeleteWithSandbox: true}, 0))
	apply(command{Op: opPlace, SandboxID: "sb-1", OwnerNodeID: "node-a", IncarnationID: "inc-sb-1"})
	apply(command{Op: opPlace, SandboxID: "sb-2", OwnerNodeID: "node-a", IncarnationID: "inc-sb-2"})
	apply(command{Op: opPutVolumeAttach, VolumeAttachments: []models.VolumeAttachment{
		{Tenant: "t-a", VolumeID: "vol-b", SandboxID: "sb-1", IncarnationID: "inc-sb-1", Target: "/b", Source: "b/b"},
		{Tenant: "t-a", VolumeID: "vol-a", SandboxID: "sb-1", IncarnationID: "inc-sb-1", Target: "/a", Source: "b/a"},
		{Tenant: "t-a", VolumeID: "vol-b", SandboxID: "sb-2", IncarnationID: "inc-sb-2", Target: "/b", Source: "b/b"},
	}})

	got := f.VolumeAttachmentsForSandbox(" sb-1 ")
	if len(got) != 2 || got[0].VolumeID != "vol-a" || got[1].VolumeID != "vol-b" {
		t.Fatalf("attachments for sb-1 = %+v", got)
	}
	if none := f.VolumeAttachmentsForSandbox("sb-none"); none == nil || len(none) != 0 {
		t.Fatalf("unknown sandbox = %#v", none)
	}
	if row, err := f.VolumeByID("t-a", "vol-b"); err != nil || !row.DeleteWithSandbox {
		t.Fatalf("delete_with_sandbox lost on the replicated row: %+v %v", row, err)
	}

	snap, err := f.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	sink := &fakeSnapshotSink{Buffer: &bytes.Buffer{}}
	if err := snap.Persist(sink); err != nil {
		t.Fatal(err)
	}
	restored := newPlacementFSM()
	if err := restored.Restore(io.NopCloser(sink.Buffer)); err != nil {
		t.Fatal(err)
	}
	if row, err := restored.VolumeByID("t-a", "vol-b"); err != nil || !row.DeleteWithSandbox {
		t.Fatalf("delete_with_sandbox lost in the snapshot: %+v %v", row, err)
	}
	if got := restored.VolumeAttachmentsForSandbox("sb-1"); len(got) != 2 {
		t.Fatalf("restored attachments for sb-1 = %+v", got)
	}

	apply(command{Op: opDelete, SandboxID: "sb-1", ExpectedIncarnationID: "inc-sb-1"})
	if got := f.VolumeAttachmentsForSandbox("sb-1"); len(got) != 0 {
		t.Fatalf("attachments after the placement delete = %+v", got)
	}
	if n := f.VolumeAttachmentCount("t-a", "vol-b"); n != 1 {
		t.Fatalf("sb-2 still holds vol-b, count = %d", n)
	}
}

func TestNoopVolumeAttachmentsForSandbox(t *testing.T) {
	n := NewNoop("node-a", "", "")
	ctx := context.Background()
	if _, _, err := n.VolumeUpsert(ctx, models.Volume{ID: "vol-a", Tenant: "t-a", Name: "a", Backend: "s3", Source: "b/a"}, 0); err != nil {
		t.Fatal(err)
	}
	if err := n.PutVolumeAttachments(ctx, []models.VolumeAttachment{
		{Tenant: "t-a", VolumeID: "vol-a", SandboxID: "sb-1", IncarnationID: "inc-1", Target: "/z", Source: "b/a"},
		{Tenant: "t-a", VolumeID: "vol-a", SandboxID: "sb-1", IncarnationID: "inc-1", Target: "/a", Source: "b/a"},
	}); err != nil {
		t.Fatal(err)
	}
	got, err := n.VolumeAttachmentsForSandbox(ctx, "sb-1")
	if err != nil || len(got) != 2 || got[0].Target != "/a" {
		t.Fatalf("attachments = %+v, %v", got, err)
	}
	if err := n.DeleteVolumeAttachmentsForSandbox(ctx, "sb-1", "inc-1"); err != nil {
		t.Fatal(err)
	}
	if got, err := n.VolumeAttachmentsForSandbox(ctx, "sb-1"); err != nil || got == nil || len(got) != 0 {
		t.Fatalf("after release = %#v, %v", got, err)
	}
}
