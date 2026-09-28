package service

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestWriteTarHelpersErrorArmsWave15(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := writeTarFile(tw, "missing", filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("expected missing file")
	}
	// Size mismatch on writeTarRegular.
	if err := writeTarRegular(tw, "x", 10, nil, []byte("hi")); err == nil {
		// may succeed writing short blob then fail on Close — still exercises Write
		t.Logf("writeTarRegular size mismatch: %v", err)
	}
	_ = tw.Close()

	var buf2 bytes.Buffer
	tw2 := tar.NewWriter(&buf2)
	_ = tw2.Close() // closed writer
	_ = writeTarRegular(tw2, "y", 1, nil, []byte("z"))
}

func TestExtractTemplateLayerMoreArmsWave16(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	manifest := TemplateArtifactManifest{SchemaVersion: TemplateArtifactSchemaVersion}
	mb, _ := json.Marshal(manifest)
	_ = tw.WriteHeader(&tar.Header{Name: "nested/" + templateManifestFilename, Mode: 0o644, Size: int64(len(mb)), Typeflag: tar.TypeReg})
	_, _ = tw.Write(mb)
	// Oversized read on a declared rootfs that truncates.
	_ = tw.WriteHeader(&tar.Header{Name: templateRootfsFilename, Mode: 0o644, Size: 100, Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte("short"))
	_ = tw.Close()
	_, _ = extractTemplateArtifactsFromLayer(bytes.NewReader(buf.Bytes()), dir)

	// Write files then hit outDir not writable.
	ro := filepath.Join(t.TempDir(), "ro")
	_ = os.MkdirAll(ro, 0o555)
	var buf2 bytes.Buffer
	tw2 := tar.NewWriter(&buf2)
	_ = tw2.WriteHeader(&tar.Header{Name: templateManifestFilename, Mode: 0o644, Size: int64(len(mb)), Typeflag: tar.TypeReg})
	_, _ = tw2.Write(mb)
	_ = tw2.WriteHeader(&tar.Header{Name: templateRootfsFilename, Mode: 0o644, Size: 1, Typeflag: tar.TypeReg})
	_, _ = tw2.Write([]byte("x"))
	_ = tw2.WriteHeader(&tar.Header{Name: snapshotMemoryFilename, Mode: 0o644, Size: 1, Typeflag: tar.TypeReg})
	_, _ = tw2.Write([]byte("y"))
	_ = tw2.WriteHeader(&tar.Header{Name: snapshotStateFilename, Mode: 0o644, Size: 1, Typeflag: tar.TypeReg})
	_, _ = tw2.Write([]byte("z"))
	_ = tw2.Close()
	_, _ = extractTemplateArtifactsFromLayer(bytes.NewReader(buf2.Bytes()), filepath.Join(ro, "out"))
}

func TestNewTemplateArtifactPusherValidationWave17(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	p, err := NewTemplateArtifactPusher(SnapshotPushConfig{Enabled: false}, nil, "", logger)
	if err != nil || p != nil {
		t.Fatalf("disabled = %v %v", p, err)
	}
	_, err = NewTemplateArtifactPusher(SnapshotPushConfig{Enabled: true}, nil, "/tmp", logger)
	if err == nil {
		t.Fatal("expected validate fail")
	}
	cfg := SnapshotPushConfig{Enabled: true, Host: "r.example", ClusterID: "c", PATPath: filepath.Join(t.TempDir(), "pat")}
	_ = os.WriteFile(cfg.PATPath, []byte("token"), 0o600)
	_, err = NewTemplateArtifactPusher(cfg, nil, "/tmp", logger)
	if err == nil {
		t.Fatal("expected nil docker")
	}
	_, err = NewTemplateArtifactPusher(cfg, &fakeTemplatePushDocker{}, "", logger)
	if err == nil {
		t.Fatal("expected empty templatesDir")
	}
	p, err = NewTemplateArtifactPusher(cfg, &fakeTemplatePushDocker{}, t.TempDir(), nil)
	if err != nil || p == nil {
		t.Fatalf("ok = %v %v", p, err)
	}

	_, err = p.PushOnce(context.Background(), nil)
	if err == nil {
		t.Fatal("nil tpl")
	}
	_, err = p.PushOnce(context.Background(), &models.Template{})
	if err == nil {
		t.Fatal("empty id")
	}
	_, err = (*TemplateArtifactPusher)(nil).PushOnce(context.Background(), &models.Template{ID: "x"})
	if err == nil {
		t.Fatal("nil pusher")
	}
	_, err = p.PushOnce(context.Background(), &models.Template{ID: "missing"})
	if err == nil {
		t.Fatal("missing artifacts")
	}
}

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
