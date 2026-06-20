package cluster

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/hashicorp/raft"
)

func volCmd(v models.Volume, max int) command {
	return command{Op: opUpsertVolume, Volume: &v, MaxPerTenant: max}
}

func TestFSMVolumeUpsertAndReads(t *testing.T) {
	fsm := newPlacementFSM()
	v := models.Volume{ID: "vol-1", Tenant: "t-a", Name: "data", Backend: "s3", Source: "bucket/t-a/data"}
	if got := fsm.Apply(&raft.Log{Index: 1, Data: mustEncode(t, volCmd(v, 0))}); got != nil {
		t.Fatalf("apply upsert returned %v", got)
	}
	byID, err := fsm.VolumeByID("t-a", "vol-1")
	if err != nil || byID.Name != "data" || byID.Source != "bucket/t-a/data" {
		t.Fatalf("VolumeByID = %+v, %v", byID, err)
	}
	byName, err := fsm.VolumeByName("t-a", "data")
	if err != nil || byName.ID != "vol-1" {
		t.Fatalf("VolumeByName = %+v, %v", byName, err)
	}
	if !fsm.LiveVolumeExistsForSource("bucket/t-a/data") {
		t.Fatal("LiveVolumeExistsForSource should be true")
	}
	if fsm.LiveVolumeExistsForSource("bucket/other") {
		t.Fatal("unexpected source match")
	}
	// Tenant isolation: another tenant can reuse the name without collision.
	if _, err := fsm.VolumeByID("t-b", "vol-1"); !errors.Is(err, ErrUnknownVolume) {
		t.Fatalf("cross-tenant id leak: %v", err)
	}
}

func TestFSMVolumeUpsertIdempotent(t *testing.T) {
	fsm := newPlacementFSM()
	first := models.Volume{ID: "vol-1", Tenant: "t-a", Name: "data", Backend: "s3", Source: "bucket/t-a/data"}
	fsm.Apply(&raft.Log{Index: 1, Data: mustEncode(t, volCmd(first, 0))})
	// A duplicate create with a DIFFERENT id keeps the original row.
	dup := models.Volume{ID: "vol-2", Tenant: "t-a", Name: "data", Backend: "s3", Source: "bucket/t-a/data"}
	if got := fsm.Apply(&raft.Log{Index: 2, Data: mustEncode(t, volCmd(dup, 0))}); got != nil {
		t.Fatalf("duplicate upsert returned %v", got)
	}
	row, _ := fsm.VolumeByName("t-a", "data")
	if row.ID != "vol-1" {
		t.Fatalf("idempotent create made a new row: %q", row.ID)
	}
	if n := fsm.VolumeCountForTenant("t-a"); n != 1 {
		t.Fatalf("tenant count = %d, want 1", n)
	}
}

func TestFSMVolumeQuota(t *testing.T) {
	fsm := newPlacementFSM()
	fsm.Apply(&raft.Log{Index: 1, Data: mustEncode(t, volCmd(models.Volume{ID: "vol-1", Tenant: "t-a", Name: "a", Backend: "s3", Source: "s/a"}, 2))})
	fsm.Apply(&raft.Log{Index: 2, Data: mustEncode(t, volCmd(models.Volume{ID: "vol-2", Tenant: "t-a", Name: "b", Backend: "s3", Source: "s/b"}, 2))})
	// Third distinct name exceeds the cap of 2.
	got := fsm.Apply(&raft.Log{Index: 3, Data: mustEncode(t, volCmd(models.Volume{ID: "vol-3", Tenant: "t-a", Name: "c", Backend: "s3", Source: "s/c"}, 2))})
	if err, _ := got.(error); !errors.Is(err, ErrVolumeQuotaExceeded) {
		t.Fatalf("expected quota error, got %v", got)
	}
	// An existing name still resolves idempotently even at the cap.
	if got := fsm.Apply(&raft.Log{Index: 4, Data: mustEncode(t, volCmd(models.Volume{ID: "vol-x", Tenant: "t-a", Name: "a", Backend: "s3", Source: "s/a"}, 2))}); got != nil {
		t.Fatalf("idempotent create at cap should succeed, got %v", got)
	}
}

func TestFSMVolumeDelete(t *testing.T) {
	fsm := newPlacementFSM()
	fsm.Apply(&raft.Log{Index: 1, Data: mustEncode(t, volCmd(models.Volume{ID: "vol-1", Tenant: "t-a", Name: "data", Backend: "s3", Source: "s/d"}, 0))})
	if got := fsm.Apply(&raft.Log{Index: 2, Data: mustEncode(t, command{Op: opDeleteVolume, VolumeTenant: "t-a", VolumeID: "vol-1"})}); got != nil {
		t.Fatalf("delete returned %v", got)
	}
	if _, err := fsm.VolumeByID("t-a", "vol-1"); !errors.Is(err, ErrUnknownVolume) {
		t.Fatalf("row still present after delete: %v", err)
	}
	// The name index must be cleared so the name is reusable.
	if _, err := fsm.VolumeByName("t-a", "data"); !errors.Is(err, ErrUnknownVolume) {
		t.Fatalf("name index not cleared: %v", err)
	}
	// Deleting an unknown row is surfaced.
	got := fsm.Apply(&raft.Log{Index: 3, Data: mustEncode(t, command{Op: opDeleteVolume, VolumeTenant: "t-a", VolumeID: "vol-1"})})
	if err, _ := got.(error); !errors.Is(err, ErrUnknownVolume) {
		t.Fatalf("expected ErrUnknownVolume, got %v", got)
	}
}

// The replicated volume table must survive a snapshot/restore cold start —
// otherwise a follower resync or leader restart would lose every Daytona volume.
func TestFSMVolumesSurviveSnapshotRoundtrip(t *testing.T) {
	src := newPlacementFSM()
	src.Apply(&raft.Log{Index: 1, Data: mustEncode(t, volCmd(models.Volume{ID: "vol-1", Tenant: "t-a", Name: "data", Backend: "s3", Source: "s/a", CreatedAt: time.Unix(100, 0).UTC()}, 0))})
	src.Apply(&raft.Log{Index: 2, Data: mustEncode(t, volCmd(models.Volume{ID: "vol-2", Tenant: "t-b", Name: "logs", Backend: "nfs", Source: "srv:/x", CreatedAt: time.Unix(200, 0).UTC()}, 0))})

	snap, err := src.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	sink := &fakeSnapshotSink{Buffer: &bytes.Buffer{}}
	if err := snap.Persist(sink); err != nil {
		t.Fatalf("persist: %v", err)
	}
	dst := newPlacementFSM()
	if err := dst.Restore(io.NopCloser(sink.Buffer)); err != nil {
		t.Fatalf("restore: %v", err)
	}

	got, err := dst.VolumeByID("t-a", "vol-1")
	if err != nil || got.Source != "s/a" {
		t.Fatalf("vol-1 lost across snapshot: %+v %v", got, err)
	}
	if byName, err := dst.VolumeByName("t-b", "logs"); err != nil || byName.ID != "vol-2" {
		t.Fatalf("name index not rebuilt: %+v %v", byName, err)
	}
	if n := dst.VolumeCountForTenant("t-a"); n != 1 {
		t.Fatalf("tenant count after restore = %d, want 1", n)
	}
}

func mustEncode(t *testing.T, c command) []byte {
	t.Helper()
	b, err := encodeCommand(c)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return b
}
