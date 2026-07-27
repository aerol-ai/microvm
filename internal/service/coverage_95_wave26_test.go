package service

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestCreateIsolateSandboxDirectDuplicateWave26(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableIsolate = true
	svc.admitter = nil
	driver := &recordingRuntime{
		createState: &models.SandboxRuntimeState{SandboxID: "sb-iso-d26", Status: models.SandboxStatusStarted},
	}
	svc.SetIsolateRuntime(driver)
	now := time.Now().UTC()
	_ = st.Create(ctx, &models.Sandbox{
		ID: "sb-iso-d26", Image: "bundle", Runtime: models.RuntimeIsolate, Status: models.SandboxStatusStarted,
		ModuleRef: "mybundle", CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	resp, err := svc.createIsolateSandbox(ctx, models.CreateSandboxRequest{
		Runtime: models.RuntimeIsolate, ModuleRef: "mybundle",
	}, "sb-iso-d26")
	if err != nil {
		t.Fatalf("duplicate isolate create: %v", err)
	}
	if resp == nil || resp.Sandbox.ID != "sb-iso-d26" {
		t.Fatalf("resp = %+v", resp)
	}
	if len(driver.destroyIDs) != 0 {
		t.Fatalf("must not destroy winner: %v", driver.destroyIDs)
	}
}

func TestAutoImportRetryFlagClearFailWave26(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(importResponse{
			Status: "imported", RegistryRef: "aocr.test/x:1",
		})
	}))
	t.Cleanup(srv.Close)

	fs := newFakeStore()
	fs.seed("sb-ai", true)
	fs.setErr = errors.New("flag clear boom")
	imp, err := NewAutoImporter(validImportCfg(srv.URL))
	if err != nil || imp == nil {
		t.Fatalf("importer: %v", err)
	}
	r := NewAutoImportReconciler(imp, fs, &fakeSpecResolver{specs: map[string]*models.CreateSandboxRequest{
		"sb-ai": eligibleSpec(),
	}}, slog.New(slog.NewTextHandler(io.Discard, nil)), 1)
	got := r.retryOne(context.Background(), "sb-ai")
	if got != retryFailed {
		t.Fatalf("got %v want retryFailed", got)
	}
}

func TestRebuildSnapshotReadyUpdateFailWave26(t *testing.T) {
	ctx := context.Background()
	svc, st, templatesDir := newHealthHarness(t)
	tpl := seedReadyTemplate(t, st, templatesDir, "tpl-rebuild26")
	_ = st.UpdateTemplateStatus(ctx, tpl.ID, models.TemplateStatusUnhealthy, tpl.RootfsPath, "corrupt", tpl.RootfsSizeBytes)
	snap := &closingSnapper{closeFn: func() { _ = st.Close() }, done: make(chan struct{}, 1)}
	svc.SetTemplateSnapshotter(snap)
	svc.SetTemplateCIDAllocator(&fakeCIDAllocator{cid: 42})
	_ = svc.RebuildTemplateSnapshot(ctx, tpl.ID)
}

type closingSnapper struct {
	closeFn func()
	done    chan struct{}
}

func (c *closingSnapper) SnapshotTemplate(_ context.Context, req TemplateSnapshotRequest) (*TemplateSnapshotResult, error) {
	_ = os.WriteFile(req.OutMemoryPath, []byte("m"), 0o644)
	_ = os.WriteFile(req.OutStatePath, []byte("s"), 0o644)
	if c.closeFn != nil {
		c.closeFn()
	}
	select {
	case c.done <- struct{}{}:
	default:
	}
	return &TemplateSnapshotResult{MemorySizeBytes: 1, StateSizeBytes: 1, Checksum: "sha256:x"}, nil
}
