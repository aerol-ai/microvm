package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// A template's row goes only once its files are gone, on both the API
// delete and the GC sweep. Nothing sweeps the templates directory by path,
// so the row is the only record of the files: dropping it after a failed
// remove left them for good. The kept row also keeps its CID, which its
// snapshot's clones still need.
func TestTemplateRowKeptUntilFilesAreGone(t *testing.T) {
	cases := []struct {
		name string
		// remove tries to delete the template once and reports the error
		// the caller sees (GC reports none: it retries on its own).
		remove  func(svc *Service, id string) error
		wantErr bool
	}{
		{name: "API delete", remove: func(svc *Service, id string) error { return svc.DeleteTemplate(context.Background(), id) }, wantErr: true},
		{name: "GC", remove: func(svc *Service, _ string) error {
			svc.runTemplateGC(context.Background(), time.Now().UTC())
			return nil
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			svc, st, templatesDir := newTemplateHarness(t)
			cids := &fakeCIDAllocator{}
			svc.templateCIDAllocator = cids
			const id = "tpl-files"
			hold := filepath.Join(templatesDir, "hold")
			dir := filepath.Join(hold, id)
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			rootfs := filepath.Join(dir, "rootfs.ext4")
			if err := os.WriteFile(rootfs, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			stale := time.Now().UTC().Add(-48 * time.Hour)
			if err := st.CreateTemplate(ctx, &models.Template{
				ID: id, Image: "img", Status: models.TemplateStatusReady, HasSnapshot: true,
				RootfsPath: rootfs, CreatedAt: stale, UpdatedAt: stale, ReadyAt: &stale,
			}); err != nil {
				t.Fatal(err)
			}
			// A read-only parent refuses the directory's removal.
			if err := os.Chmod(hold, 0o555); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(hold, 0o755) })
			if f, err := os.CreateTemp(hold, "probe"); err == nil {
				_ = f.Close()
				t.Skip("running as root: a read-only directory does not refuse changes")
			}

			err := tc.remove(svc, id)
			if (err != nil) != tc.wantErr {
				t.Fatalf("first remove error = %v, want error=%v", err, tc.wantErr)
			}
			if _, err := st.GetTemplate(ctx, id); err != nil {
				t.Fatalf("row after a failed file remove = %v, want it kept", err)
			}
			if len(cids.releaseIDs) != 0 {
				t.Fatalf("CID released while the row is kept: %v", cids.releaseIDs)
			}

			if err := os.Chmod(hold, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := tc.remove(svc, id); err != nil {
				t.Fatalf("second remove = %v", err)
			}
			if _, err := st.GetTemplate(ctx, id); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("row after the files went = %v, want it gone", err)
			}
			if _, err := os.Stat(dir); !os.IsNotExist(err) {
				t.Fatalf("template directory = %v, want it removed", err)
			}
			if len(cids.releaseIDs) != 1 || cids.releaseIDs[0] != id {
				t.Fatalf("CID releases = %v, want one for %s", cids.releaseIDs, id)
			}
		})
	}
}
