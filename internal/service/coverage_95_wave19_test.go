package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestTemplatePullOnceErrorArmsWave19(t *testing.T) {
	ctx := context.Background()
	templatesDir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Pull fail.
	p, err := NewTemplateArtifactPuller(&fakeTemplatePullDocker{pullErr: errors.New("pull boom")}, templatesDir, logger)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &models.Template{ID: "tpl-p1", RegistryRef: "aocr.test/t:latest", SnapshotChecksum: "sha256:x"}
	if err := p.PullOnce(ctx, tpl); err == nil {
		t.Fatal("expected pull fail")
	}

	// Export fail after pull ok.
	p2, _ := NewTemplateArtifactPuller(&fakeTemplatePullDocker{exportErr: errors.New("save boom")}, templatesDir, logger)
	if err := p2.PullOnce(ctx, tpl); err == nil {
		t.Fatal("expected export fail")
	}

	// Bad extract (garbage tar).
	p3, _ := NewTemplateArtifactPuller(&fakeTemplatePullDocker{exportBody: []byte("not-tar")}, templatesDir, logger)
	if err := p3.PullOnce(ctx, tpl); err == nil {
		t.Fatal("expected extract fail")
	}

	// Local files present → early success.
	tplDir := filepath.Join(templatesDir, "tpl-local")
	_ = os.MkdirAll(tplDir, 0o755)
	for _, name := range []string{templateRootfsFilename, snapshotMemoryFilename, snapshotStateFilename, templateManifestFilename} {
		_ = os.WriteFile(filepath.Join(tplDir, name), []byte("x"), 0o644)
	}
	local := &models.Template{ID: "tpl-local", RegistryRef: "aocr.test/t:latest"}
	p4, _ := NewTemplateArtifactPuller(&fakeTemplatePullDocker{pullErr: errors.New("should not pull")}, templatesDir, logger)
	if err := p4.PullOnce(ctx, local); err != nil {
		t.Fatalf("local present: %v", err)
	}
}

func TestReconcileDockerGoneDestroyFailWave19(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	rt := &recordingRuntime{
		destroyErr: errors.New("destroy boom"),
		inspect:    map[string]*models.SandboxRuntimeState{}, // miss → gone confirmed
	}
	svc, st, _ := newServiceRuntimeHarnessAtPath(t, t.TempDir()+"/gone19.db", rt)
	svc.cfg.EnableCaddy = false
	_ = st.Create(ctx, &models.Sandbox{
		ID: "sb-gone19", Image: "alpine:3.20", Status: models.SandboxStatusStarted, ContainerID: "ctr-gone",
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	err := svc.Reconcile(ctx)
	t.Logf("Reconcile: %v", err)
}

func TestReconcileFirecrackerGoneWave19(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	fc := &recordingRuntime{
		destroyErr: errors.New("destroy boom"),
		inspect:    map[string]*models.SandboxRuntimeState{},
	}
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableFirecracker = true
	svc.SetFirecrackerRuntime(fc)
	svc.testForceUnmountErr = errors.New("umount")
	_ = st.Create(ctx, &models.Sandbox{
		ID: "sb-fc-gone", Image: "alpine", Runtime: models.RuntimeFirecracker,
		Status: models.SandboxStatusStarted, ContainerID: "vm-1",
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	if err := svc.Reconcile(ctx); err == nil {
		t.Fatal("expected destroy failure")
	}
}

func TestReconcileFirecrackerGoneUnmountWave19(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	fc := &recordingRuntime{inspect: map[string]*models.SandboxRuntimeState{}}
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableFirecracker = true
	svc.SetFirecrackerRuntime(fc)
	svc.testForceUnmountErr = errors.New("umount")
	_ = st.Create(ctx, &models.Sandbox{
		ID: "sb-fc-um", Image: "alpine", Runtime: models.RuntimeFirecracker,
		Status: models.SandboxStatusStarted, ContainerID: "vm-2",
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
}

func TestCreateSnapshotOwnershipConflictWave19(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	now := time.Now().UTC()
	_ = st.Create(ctx, &models.Sandbox{
		ID: "sb-snap", Image: "a", Status: models.SandboxStatusStarted, ContainerID: "c1",
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	_ = st.CreateSnapshot(ctx, &models.SandboxSnapshot{
		Name: "n1", SourceSandboxID: "other", Image: "img:other", CreatedAt: now,
	})
	_, _, err := svc.CreateSnapshotWithOwnership(ctx, "sb-snap", models.CreateSandboxSnapshotRequest{Name: "n1"})
	if err == nil {
		t.Fatal("expected name conflict")
	}
}

func TestUnexposeAndFindExposureWave19(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	now := time.Now().UTC()
	_ = st.Create(ctx, &models.Sandbox{
		ID: "sb-unx", Image: "a", Status: models.SandboxStatusStarted, ContainerIP: "10.0.0.1",
		ExposedPorts: []models.ExposedPort{{Port: 80, Protocol: models.ExposedPortProtocolHTTP, PublicURL: "https://x"}},
		CreatedAt:    now, UpdatedAt: now, LastActiveAt: now,
	})
	_ = st.UpsertPort(ctx, models.ExposedPort{
		SandboxID: "sb-unx", Port: 80, Protocol: models.ExposedPortProtocolHTTP, PublicURL: "https://x", CreatedAt: now,
	})
	_ = svc.UnexposePort(ctx, "sb-unx", 80)
	_ = svc.UnexposePort(ctx, "sb-unx", 999)
	_ = findExposure(&models.Sandbox{ExposedPorts: []models.ExposedPort{{Port: 1}}}, 2)
}
