package service

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// cov97BlockingBuilder pauses inside Build so the test can close the store
// before the goroutine records the snapshot outcome.
type cov97BlockingBuilder struct {
	started chan struct{}
	release chan struct{}
	staging string
}

func (b *cov97BlockingBuilder) Build(context.Context, TemplateBuildRequest) (*TemplateBuildResult, error) {
	close(b.started)
	<-b.release
	return &TemplateBuildResult{StagingDir: b.staging, SizeBytes: 4}, nil
}

func TestCoverage97TemplateCleanupFailures(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newTemplateHarness(t)
	now := time.Now().UTC()
	if err := st.CreateTemplate(ctx, &models.Template{
		ID: "tpl-clean", Image: "img", Status: models.TemplateStatusReady,
		HasSnapshot: true, RootfsPath: lockedRootfs(t),
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	svc.templateCIDAllocator = &fakeCIDAllocator{releaseErr: errors.New("cid busy")}
	if err := svc.DeleteTemplate(ctx, "tpl-clean"); err != nil {
		t.Fatalf("DeleteTemplate = %v", err)
	}
	if err := writeTemplateManifest(t.TempDir(), templateManifest{SourceImage: "img"}); err == nil {
		t.Fatal("manifest write onto a directory succeeded")
	}

	locked := lockedDir(t)
	for _, id := range []string{"tpl-alloc", "tpl-snap"} {
		if err := st.CreateTemplate(ctx, &models.Template{
			ID: id, Image: "img", Status: models.TemplateStatusPending,
			CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}
	svc.cfg.FirecrackerSnapshotEnabled = true
	svc.templateSnapshotter = &fakeTemplateSnapshotter{err: errors.New("snapshot failed")}
	alloc := &fakeCIDAllocator{cid: 7, releaseErr: errors.New("release failed")}
	svc.templateCIDAllocator = alloc

	runBuild := func(id string, allocateErr error) {
		alloc.allocateErr = allocateErr
		builder := &cov97BlockingBuilder{
			started: make(chan struct{}),
			release: make(chan struct{}),
			staging: locked,
		}
		svc.templateBuilder = builder
		svc.kickTemplateBuild(&models.Template{ID: id, Image: "img"})
		select {
		case <-builder.started:
		case <-time.After(2 * time.Second):
			t.Fatal("build did not start")
		}
		st.Close()
		close(builder.release)
		time.Sleep(150 * time.Millisecond)
	}
	runBuild("tpl-alloc", errors.New("no cid"))

	svc2, st2, _ := newTemplateHarness(t)
	if err := st2.CreateTemplate(ctx, &models.Template{
		ID: "tpl-snap", Image: "img", Status: models.TemplateStatusPending,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	svc2.cfg.FirecrackerSnapshotEnabled = true
	svc2.templateSnapshotter = &fakeTemplateSnapshotter{err: errors.New("snapshot failed")}
	svc2.templateCIDAllocator = &fakeCIDAllocator{cid: 9, releaseErr: errors.New("release failed")}
	builder := &cov97BlockingBuilder{
		started: make(chan struct{}),
		release: make(chan struct{}),
		staging: lockedDir(t),
	}
	svc2.templateBuilder = builder
	svc2.kickTemplateBuild(&models.Template{ID: "tpl-snap", Image: "img"})
	select {
	case <-builder.started:
	case <-time.After(2 * time.Second):
		t.Fatal("snapshot build did not start")
	}
	st2.Close()
	close(builder.release)
	time.Sleep(150 * time.Millisecond)
}

func TestCoverage97SyncAllowedPortsWithoutRuntime(t *testing.T) {
	s := &Service{logger: slog.New(slog.DiscardHandler)}
	s.syncAllowedPorts(context.Background(), &models.Sandbox{
		ID: "sb", Status: models.SandboxStatusStarted, ContainerIP: "10.0.0.2",
		Runtime:      models.RuntimeDocker,
		ExposedPorts: []models.ExposedPort{{Port: 80}},
	})
}

func lockedRootfs(t *testing.T) string {
	t.Helper()
	return filepath.Join(lockedDir(t), "rootfs.ext4")
}

func lockedDir(t *testing.T) string {
	t.Helper()
	parent := t.TempDir()
	hold := filepath.Join(parent, "hold")
	dir := filepath.Join(hold, "tpl")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "rootfs.ext4"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(hold, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(hold, 0o755) })
	return dir
}
