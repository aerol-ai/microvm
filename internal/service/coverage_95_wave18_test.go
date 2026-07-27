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

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/models"
)

func seedTemplateArtifacts(t *testing.T, dir, id string) *models.Template {
	t.Helper()
	tplDir := filepath.Join(dir, id)
	_ = os.MkdirAll(tplDir, 0o755)
	rootfs := filepath.Join(tplDir, templateRootfsFilename)
	mem := filepath.Join(tplDir, snapshotMemoryFilename)
	state := filepath.Join(tplDir, snapshotStateFilename)
	_ = os.WriteFile(rootfs, []byte("rootfs"), 0o644)
	_ = os.WriteFile(mem, []byte("mem"), 0o644)
	_ = os.WriteFile(state, []byte("state"), 0o644)
	now := time.Now().UTC()
	return &models.Template{
		ID: id, Image: "docker://alpine", Status: models.TemplateStatusReady,
		RootfsPath: rootfs, SnapshotMemoryPath: mem, SnapshotStatePath: state,
		RootfsSizeBytes: 6, SnapshotSizeBytes: 8, HasSnapshot: true,
		CreatedAt: now, UpdatedAt: now,
	}
}

type removeFailTemplateDocker struct {
	fakeTemplatePushDocker
	removeErr error
}

func (f *removeFailTemplateDocker) RemoveImage(ctx context.Context, ref string) error {
	_ = f.fakeTemplatePushDocker.RemoveImage(ctx, ref)
	return f.removeErr
}

func TestTemplateArtifactPushOnceBranchesWave18(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	templatesDir := t.TempDir()
	pat := filepath.Join(t.TempDir(), "pat")
	_ = os.WriteFile(pat, []byte("tok"), 0o600)
	cfg := SnapshotPushConfig{Enabled: true, Host: "aocr.test", ClusterID: "cl1", PATPath: pat}

	tpl := seedTemplateArtifacts(t, templatesDir, "tpl-push18")

	dockerFail := &removeFailTemplateDocker{
		fakeTemplatePushDocker: fakeTemplatePushDocker{importErr: errors.New("import boom")},
		removeErr:              errors.New("rm boom"),
	}
	p, err := NewTemplateArtifactPusher(cfg, dockerFail, templatesDir, logger)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.PushOnce(ctx, tpl); err == nil {
		t.Fatal("expected import fail")
	}

	tpl2 := seedTemplateArtifacts(t, templatesDir, "tpl-nomem")
	_ = os.Remove(tpl2.SnapshotMemoryPath)
	p2, _ := NewTemplateArtifactPusher(cfg, &fakeTemplatePushDocker{}, templatesDir, logger)
	if _, err := p2.PushOnce(ctx, tpl2); err == nil {
		t.Fatal("expected mem missing")
	}

	tpl3 := seedTemplateArtifacts(t, templatesDir, "tpl-nostate")
	_ = os.Remove(tpl3.SnapshotStatePath)
	if _, err := p2.PushOnce(ctx, tpl3); err == nil {
		t.Fatal("expected state missing")
	}

	badPAT := SnapshotPushConfig{Enabled: true, Host: "aocr.test", ClusterID: "cl1", PATPath: filepath.Join(t.TempDir(), "missing")}
	pBad, _ := NewTemplateArtifactPusher(badPAT, &fakeTemplatePushDocker{}, templatesDir, logger)
	if _, err := pBad.PushOnce(ctx, tpl); err == nil {
		t.Fatal("expected pat fail")
	}

	pushFail := &fakeTemplatePushDocker{pushErr: errors.New("push boom")}
	p3, _ := NewTemplateArtifactPusher(cfg, pushFail, templatesDir, logger)
	if _, err := p3.PushOnce(ctx, tpl); err == nil {
		t.Fatal("expected push fail")
	}

	okDocker := &fakeTemplatePushDocker{pushTag: "", digest: "sha256:abc"}
	p4, _ := NewTemplateArtifactPusher(cfg, okDocker, templatesDir, logger)
	res, err := p4.PushOnce(ctx, tpl)
	if err != nil {
		t.Fatalf("success: %v", err)
	}
	if res.Digest != "sha256:abc" {
		t.Fatalf("digest = %q", res.Digest)
	}
	_ = p4.DestRefFor("tpl-push18")
}

func TestExposePortCustomDomainConflictWave18(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCaddy = true
	svc.cfg.Domain = "sandbox.example.com"
	now := time.Now().UTC()
	_ = st.Create(ctx, &models.Sandbox{
		ID: "sb-cd-proto", Image: "a", Status: models.SandboxStatusStarted, ContainerIP: "10.0.0.1",
		CustomDomains: []models.CustomDomain{{Hostname: "api.customer.dev"}},
		CreatedAt:     now, UpdatedAt: now, LastActiveAt: now,
	})
	if _, err := svc.ExposePort(ctx, "sb-cd-proto", 5432, "tcp"); !errors.Is(err, ErrCustomDomainProtocolConflict) && err == nil {
		t.Fatalf("err=%v", err)
	}
	if _, err := svc.ExposePort(ctx, "sb-cd-proto", 443, "tls"); err == nil {
		t.Fatal("expected tls conflict")
	}
	if _, err := svc.ExposePort(ctx, "sb-cd-proto", 0, "http"); err == nil {
		t.Fatal("expected invalid port")
	}
	if _, err := svc.ExposePort(ctx, "missing", 80, "http"); err == nil {
		t.Fatal("expected missing")
	}
}

func TestAllocateHostPortPreferredUnavailableWave18(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCaddy = true
	svc.cfg.Domain = "sandbox.example.com"
	svc.cfg.L4PortRangeStart = 43000
	svc.cfg.L4PortRangeEnd = 43002
	svc.l4Ready.Store(true)
	now := time.Now().UTC()
	_ = st.Create(ctx, &models.Sandbox{
		ID: "sb-pref", Image: "a", Status: models.SandboxStatusStarted, ContainerIP: "10.0.0.2",
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	_ = st.Create(ctx, &models.Sandbox{
		ID: "sb-other", Image: "a", Status: models.SandboxStatusStarted, ContainerIP: "10.0.0.3",
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	_ = st.UpsertPort(ctx, models.ExposedPort{
		SandboxID: "sb-other", Port: 1, Protocol: models.ExposedPortProtocolTCP,
		HostPort: 43001, PublicURL: "tcp://x:43001", CreatedAt: now,
	})
	_, _, _, err := svc.allocateHostPort(ctx, "sb-pref", 99, now, 43001)
	if err == nil {
		t.Fatal("expected preferred unavailable")
	}
}

func TestReconcileMissingSelfOwnedWave18(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCluster = true
	cl := &recordingOwnershipCluster{
		Noop: cluster.NewNoop("self", "http://self", ""),
		placements: map[string]cluster.Placement{
			"sb-orphan-place": {
				SandboxID: "sb-orphan-place", OwnerNodeID: "self",
				Spec: &models.CreateSandboxRequest{Image: "alpine"},
			},
		},
	}
	svc.AttachCluster(cl)
	now := time.Now().UTC()
	_ = st.Create(ctx, &models.Sandbox{
		ID: "sb-local", Image: "a", Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	known := map[string]struct{}{"sb-local": {}}
	svc.reconcileMissingSelfOwnedPlacements(ctx, known)
}

func TestRegisterSnapshotConflictWave18(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	now := time.Now().UTC()
	_ = st.CreateSnapshot(ctx, &models.SandboxSnapshot{
		Name: "snap-c", SourceSandboxID: "sb-a", Image: "img:a", CreatedAt: now,
	})
	_, err := svc.RegisterSnapshot(ctx, &models.SandboxSnapshot{
		Name: "snap-c", SourceSandboxID: "sb-b", Image: "img:b", CreatedAt: now,
	})
	if err == nil {
		t.Fatal("expected conflict")
	}
	_, err = svc.RegisterSnapshot(ctx, &models.SandboxSnapshot{
		Name: "snap-c", SourceSandboxID: "sb-a", Image: "img:a", CreatedAt: now,
	})
	if err != nil {
		t.Fatalf("idempotent: %v", err)
	}
}
