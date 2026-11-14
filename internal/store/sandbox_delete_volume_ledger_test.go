package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// Review 2 finding 7, single-node half: deleting a sandbox row cascades its
// volume attachments away, the last link to a delete_with_sandbox volume it
// alone held. The same transaction writes that volume's reclaim-ledger row,
// so the cleanup can never be lost to a failed lookup before it.
func TestDeleteSandboxRecordsItsDeleteWithSandboxVolumes(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	for _, v := range []*models.Volume{
		{ID: "v-alone", Tenant: "t-a", Name: "alone", Backend: "s3", Source: "b/t-a/alone", DeleteWithSandbox: true},
		{ID: "v-shared", Tenant: "t-a", Name: "shared", Backend: "s3", Source: "b/t-a/shared", DeleteWithSandbox: true},
		{ID: "v-keep", Tenant: "t-a", Name: "keep", Backend: "s3", Source: "b/t-a/keep"},
		{ID: "v-nosrc", Tenant: "t-a", Name: "nosrc", Backend: "s3", DeleteWithSandbox: true},
	} {
		if err := st.CreateVolume(ctx, v); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"sb-a", "sb-b"} {
		if err := st.Create(ctx, sampleVolumeSandbox(id)); err != nil {
			t.Fatal(err)
		}
	}
	att := func(sb, vol, target string) models.VolumeAttachment {
		return models.VolumeAttachment{Tenant: "t-a", VolumeID: vol, SandboxID: sb, IncarnationID: "inc-" + sb, Target: target, Source: "b/t-a/" + vol}
	}
	if err := st.PutVolumeAttachments(ctx, []models.VolumeAttachment{
		att("sb-a", "v-alone", "/a"), att("sb-a", "v-alone", "/a2"), att("sb-a", "v-shared", "/s"),
		att("sb-a", "v-keep", "/k"), att("sb-a", "v-nosrc", "/n"), att("sb-b", "v-shared", "/s"),
	}); err != nil {
		t.Fatal(err)
	}
	// An earlier best-effort record of the same volume is refreshed, not
	// duplicated.
	if err := st.SchedulePendingVolumeDeletion(ctx, models.Volume{ID: "v-alone", Tenant: "t-a", Name: "alone", Backend: "s3"}, "b/t-a/alone"); err != nil {
		t.Fatal(err)
	}
	before := time.Now().UTC().Add(-time.Second)

	steps := []struct {
		name    string
		sandbox string
		wantErr error
		want    []string
	}{
		{"last holder of one volume, co-holder of another", "sb-a", nil, []string{"v-alone"}},
		{"a sandbox that is gone records nothing", "sb-a", ErrNotFound, []string{"v-alone"}},
		{"the last co-holder", "sb-b", nil, []string{"v-alone", "v-shared"}},
	}
	for _, step := range steps {
		if err := st.Delete(ctx, step.sandbox); !errors.Is(err, step.wantErr) {
			t.Fatalf("%s: Delete = %v, want %v", step.name, err, step.wantErr)
		}
		pending, err := st.ListPendingVolumeDeletions(ctx)
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]models.PendingVolumeDeletion{}
		for _, p := range pending {
			got[p.VolumeID] = p
		}
		if len(got) != len(step.want) {
			t.Fatalf("%s: ledger = %+v, want %v", step.name, pending, step.want)
		}
		for _, id := range step.want {
			p, ok := got[id]
			if !ok || p.Source != "b/t-a/"+id[2:] || p.Tenant != "t-a" || p.Backend != "s3" || p.CreatedAt.Before(before) {
				t.Fatalf("%s: ledger row for %s = %+v", step.name, id, p)
			}
		}
	}
	// The volume rows stay for the reclaim sweep, which deletes them first.
	if _, err := st.GetVolumeByID(ctx, "t-a", "v-alone"); err != nil {
		t.Fatalf("volume row: %v", err)
	}
}

// A delete that cannot write the ledger row does not delete the sandbox
// either: the row stays the retry anchor.
func TestDeleteSandboxFailsWholeWhenLedgerWriteFails(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	if err := st.Create(ctx, sampleVolumeSandbox("sb-a")); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, `DROP TABLE pending_volume_deletions`); err != nil {
		t.Fatal(err)
	}
	if err := st.Delete(ctx, "sb-a"); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("Delete without a ledger = %v, want a store error", err)
	}
	if _, err := st.Get(ctx, "sb-a"); err != nil {
		t.Fatalf("the sandbox row must survive a failed delete: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if err := st.Delete(ctx, "sb-a"); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("Delete on a closed store = %v, want a store error", err)
	}
}
