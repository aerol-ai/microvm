package store

import (
	"context"
	"errors"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// TestVolumeDeleteWithSandboxRoundTrips: the flag is stored by every write
// path and read back by every read path; a row without it reads false.
func TestVolumeDeleteWithSandboxRoundTrips(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	if err := st.CreateVolume(ctx, &models.Volume{ID: "v-dws", Tenant: "t-a", Name: "scratch", Backend: "s3", DeleteWithSandbox: true}); err != nil {
		t.Fatal(err)
	}
	created, made, err := st.GetOrCreateVolume(ctx, &models.Volume{ID: "v-dws2", Tenant: "t-a", Name: "scratch2", Backend: "s3", DeleteWithSandbox: true}, 0)
	if err != nil || !made || !created.DeleteWithSandbox {
		t.Fatalf("GetOrCreateVolume = %+v made=%v err=%v", created, made, err)
	}
	// A repeat with another value returns the stored row unchanged: the
	// service, not the store, decides whether that is a conflict.
	again, made, err := st.GetOrCreateVolume(ctx, &models.Volume{ID: "v-other", Tenant: "t-a", Name: "scratch2", Backend: "s3"}, 0)
	if err != nil || made || !again.DeleteWithSandbox || again.ID != "v-dws2" {
		t.Fatalf("repeat GetOrCreateVolume = %+v made=%v err=%v", again, made, err)
	}
	if err := st.CreateVolume(ctx, &models.Volume{ID: "v-keep", Tenant: "t-a", Name: "keep", Backend: "s3"}); err != nil {
		t.Fatal(err)
	}

	byName, err := st.GetVolume(ctx, "t-a", "scratch")
	if err != nil || !byName.DeleteWithSandbox {
		t.Fatalf("GetVolume = %+v, %v", byName, err)
	}
	byID, err := st.GetVolumeByID(ctx, "t-a", "v-dws2")
	if err != nil || !byID.DeleteWithSandbox {
		t.Fatalf("GetVolumeByID = %+v, %v", byID, err)
	}
	list, err := st.ListVolumes(ctx, "t-a")
	if err != nil {
		t.Fatal(err)
	}
	flags := map[string]bool{}
	for _, v := range list {
		flags[v.Name] = v.DeleteWithSandbox
	}
	if !flags["scratch"] || !flags["scratch2"] || flags["keep"] {
		t.Fatalf("listed flags = %v", flags)
	}
}

// TestListVolumeAttachmentsForSandbox: a destroy can read a sandbox's
// attachments, and they go with the sandbox row.
func TestListVolumeAttachmentsForSandbox(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	for _, v := range []*models.Volume{
		{ID: "v1", Tenant: "t-a", Name: "one", Backend: "s3"},
		{ID: "v2", Tenant: "t-a", Name: "two", Backend: "s3", DeleteWithSandbox: true},
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
		return models.VolumeAttachment{Tenant: "t-a", VolumeID: vol, SandboxID: sb, IncarnationID: "inc-" + sb, Target: target, Source: "bucket/t-a/" + vol}
	}
	if err := st.PutVolumeAttachments(ctx, []models.VolumeAttachment{att("sb-a", "v2", "/b"), att("sb-a", "v1", "/a"), att("sb-b", "v2", "/x")}); err != nil {
		t.Fatal(err)
	}
	got, err := st.ListVolumeAttachmentsForSandbox(ctx, "sb-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].VolumeID != "v1" || got[1].VolumeID != "v2" || got[1].Target != "/b" || got[0].IncarnationID != "inc-sb-a" {
		t.Fatalf("attachments for sb-a = %+v", got)
	}
	if err := st.Delete(ctx, "sb-a"); err != nil {
		t.Fatal(err)
	}
	got, err = st.ListVolumeAttachmentsForSandbox(ctx, "sb-a")
	if err != nil || len(got) != 0 {
		t.Fatalf("after the sandbox row went: %+v, %v", got, err)
	}
	if n, _ := st.CountVolumeAttachments(ctx, "t-a", "v2"); n != 1 {
		t.Fatalf("sb-b's attachment must stay, count = %d", n)
	}
	none, err := st.ListVolumeAttachmentsForSandbox(ctx, "sb-none")
	if err != nil || none == nil || len(none) != 0 {
		t.Fatalf("unknown sandbox = %#v, %v", none, err)
	}
}

// TestDeleteVolumeIfNoAttachments: the delete is refused while any
// attachment holds the row, in the same statement, so a racing attach is
// never cascaded away with it.
func TestDeleteVolumeIfNoAttachments(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	if err := st.CreateVolume(ctx, &models.Volume{ID: "v1", Tenant: "t-a", Name: "one", Backend: "s3"}); err != nil {
		t.Fatal(err)
	}
	if err := st.Create(ctx, sampleVolumeSandbox("sb-hold")); err != nil {
		t.Fatal(err)
	}
	if err := st.PutVolumeAttachments(ctx, []models.VolumeAttachment{{Tenant: "t-a", VolumeID: "v1", SandboxID: "sb-hold", IncarnationID: "inc-sb-hold", Target: "/v", Source: "b/v1"}}); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteVolumeIfNoAttachments(ctx, "t-a", "v1"); !errors.Is(err, ErrVolumeInUse) {
		t.Fatalf("attached = %v, want ErrVolumeInUse", err)
	}
	if n, _ := st.CountVolumeAttachments(ctx, "t-a", "v1"); n != 1 {
		t.Fatal("the attachment must survive a refused delete")
	}
	if err := st.Delete(ctx, "sb-hold"); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteVolumeIfNoAttachments(ctx, "t-a", "v1"); err != nil {
		t.Fatalf("released = %v", err)
	}
	if err := st.DeleteVolumeIfNoAttachments(ctx, "t-a", "v1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("gone = %v, want ErrNotFound", err)
	}
}

// TestVolumeLifetimeQueriesSurfaceDBErrors: a store that cannot answer
// reports it, so a destroy keeps the volume rather than guess.
func TestVolumeLifetimeQueriesSurfaceDBErrors(t *testing.T) {
	st := newTestStore(t)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := st.ListVolumeAttachmentsForSandbox(ctx, "sb"); err == nil {
		t.Fatal("list on a closed store must fail")
	}
	if err := st.DeleteVolumeIfNoAttachments(ctx, "t", "v"); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("delete on a closed store = %v, want a store error", err)
	}
}
