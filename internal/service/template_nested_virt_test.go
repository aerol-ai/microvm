package service

import (
	"context"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// seedTemplateSavedWith is seedReadyTemplate with the snapshot's
// nested-virtualization record ("" leaves it unknown).
func seedTemplateSavedWith(t *testing.T, st *store.Store, templatesDir, id, saved string) {
	t.Helper()
	tpl := seedReadyTemplate(t, st, templatesDir, id)
	if saved == "" {
		return
	}
	if err := st.UpdateTemplateSnapshotReady(context.Background(), id, tpl.SnapshotMemoryPath, tpl.SnapshotStatePath,
		tpl.SnapshotSizeBytes, tpl.SnapshotChecksum, tpl.SnapshotVsockCID, true, saved); err != nil {
		t.Fatal(err)
	}
}

// At start, every ready template saved under another setting than this
// node's is saved again with this node's, and the rest are left alone: a
// snapshot saved with it matches, and a template with no ready snapshot has
// nothing to load.
func TestResaveTemplateSnapshotsForNestedVirtAtStart(t *testing.T) {
	for _, tc := range []struct {
		name        string
		nodeAllowed bool
		resaved     []string
		kept        []string
	}{
		{"node hides", false, []string{"tpl-unknown", "tpl-on"}, []string{"tpl-off"}},
		{"node allows", true, []string{"tpl-off"}, []string{"tpl-unknown", "tpl-on"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			svc, st, templatesDir := newHealthHarness(t)
			svc.cfg.FirecrackerNestedVirt = tc.nodeAllowed
			for id, saved := range map[string]string{"tpl-unknown": "", "tpl-on": "on", "tpl-off": "off"} {
				seedTemplateSavedWith(t, st, templatesDir, id, saved)
			}
			seedReadyTemplate(t, st, templatesDir, "tpl-unhealthy")
			if _, err := st.MarkTemplateUnhealthy(ctx, "tpl-unhealthy", "being rebuilt"); err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			if err := st.CreateTemplate(ctx, &models.Template{ID: "tpl-no-snapshot", Image: "docker://alpine:3.19",
				Status: models.TemplateStatusReadyNoSnapshot, RootfsPath: "/r", CreatedAt: now, UpdatedAt: now}); err != nil {
				t.Fatal(err)
			}
			want := "off"
			if tc.nodeAllowed {
				want = "on"
			}
			snapper := &fakeTemplateSnapshotter{done: make(chan struct{}, 8), nestedVirt: want}
			svc.SetTemplateSnapshotter(snapper)
			svc.SetTemplateCIDAllocator(&fakeCIDAllocator{cid: 42})

			svc.ResaveTemplateSnapshotsForNestedVirtAtStart(ctx)
			if !svc.WaitForTemplateRebuilds(10 * time.Second) {
				t.Fatal("rebuilds did not finish")
			}
			if snapper.calls != len(tc.resaved) {
				t.Fatalf("snapshotter ran %d times, want %d", snapper.calls, len(tc.resaved))
			}
			for _, id := range tc.resaved {
				got, err := st.GetTemplate(ctx, id)
				if err != nil || got.Status != models.TemplateStatusReady || !got.HasSnapshot || got.SnapshotNestedVirt != want {
					t.Fatalf("%s after the sweep = %+v, %v; want ready, saved again with %q", id, got, err, want)
				}
			}
			for _, id := range tc.kept {
				got, _ := st.GetTemplate(ctx, id)
				if got.Status != models.TemplateStatusReady || got.UpdatedAt.After(got.CreatedAt.Add(time.Minute)) {
					t.Fatalf("%s was touched: %+v", id, got)
				}
			}
			for id, status := range map[string]models.TemplateStatus{
				"tpl-unhealthy": models.TemplateStatusUnhealthy, "tpl-no-snapshot": models.TemplateStatusReadyNoSnapshot,
			} {
				if got, _ := st.GetTemplate(ctx, id); got.Status != status {
					t.Fatalf("%s moved to %s; the sweep moves only ready rows", id, got.Status)
				}
			}
		})
	}
}

// Without the snapshot pipeline there is nothing to rebuild with, so the
// sweep leaves every template as it is; a store it cannot list is logged.
func TestResaveTemplateSnapshotsForNestedVirtAtStartEdges(t *testing.T) {
	ctx := context.Background()
	svc, st, templatesDir := newHealthHarness(t)
	seedReadyTemplate(t, st, templatesDir, "tpl-unknown")
	svc.ResaveTemplateSnapshotsForNestedVirtAtStart(ctx)
	if got, _ := st.GetTemplate(ctx, "tpl-unknown"); got.Status != models.TemplateStatusReady || !got.HasSnapshot {
		t.Fatalf("an unwired sweep moved the template: %+v", got)
	}

	svc.SetTemplateSnapshotter(&fakeTemplateSnapshotter{done: make(chan struct{}, 1)})
	svc.SetTemplateCIDAllocator(&fakeCIDAllocator{cid: 42})
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	svc.ResaveTemplateSnapshotsForNestedVirtAtStart(ctx)
}
