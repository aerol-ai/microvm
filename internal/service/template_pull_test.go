package service

// template_pull_test.go pins the Phase 6 PR 6-B.2 consumer-side puller.
// Tests run against fakeTemplatePullDocker (an in-memory pair to
// fakeTemplatePushDocker in template_push_test.go) — no real docker
// daemon, no real network. The producer side is round-tripped: we run
// the writeTemplateArtifactTar helper (template_push.go) to build the
// exact bytes the consumer would see post-import/push/pull, then hand
// those bytes to the puller wrapped in a docker-save outer tar.

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// fakeTemplatePullDocker satisfies TemplateArtifactPullDocker. Tests
// can pre-load the export body (the docker-save outer tar) and assert
// that pull/export/remove were called the expected number of times.
type fakeTemplatePullDocker struct {
	mu sync.Mutex

	pullCalls   atomic.Int32
	exportCalls atomic.Int32
	removeCalls atomic.Int32

	pullErr   error
	exportErr error

	exportBody []byte
}

func (f *fakeTemplatePullDocker) PullImage(_ context.Context, _ string, _ *models.RegistryAuth) error {
	f.pullCalls.Add(1)
	return f.pullErr
}

func (f *fakeTemplatePullDocker) ExportImageTar(_ context.Context, _ string) (io.ReadCloser, error) {
	f.exportCalls.Add(1)
	if f.exportErr != nil {
		return nil, f.exportErr
	}
	f.mu.Lock()
	body := append([]byte(nil), f.exportBody...)
	f.mu.Unlock()
	return io.NopCloser(bytes.NewReader(body)), nil
}

func (f *fakeTemplatePullDocker) RemoveImage(_ context.Context, _ string) error {
	f.removeCalls.Add(1)
	return nil
}

// buildArtifactSaveBytes builds the bytes the puller will see: an outer
// docker-save tar whose single layer.tar entry holds the producer's
// artifact tar. The artifact tar itself is exactly what
// writeTemplateArtifactTar produces, so any drift between push and pull
// surfaces here.
func buildArtifactSaveBytes(t *testing.T, manifest TemplateArtifactManifest, rootfs, mem, state []byte) []byte {
	t.Helper()

	// Build the producer-side artifact tar in-memory by writing the
	// three files into a tempdir and feeding them through the same
	// writer the pusher uses. The tempdir avoids special-casing the
	// pusher's stream API for tests.
	dir := t.TempDir()
	rootfsPath := filepath.Join(dir, templateRootfsFilename)
	memPath := filepath.Join(dir, snapshotMemoryFilename)
	statePath := filepath.Join(dir, snapshotStateFilename)
	if err := os.WriteFile(rootfsPath, rootfs, 0o644); err != nil {
		t.Fatalf("write rootfs: %v", err)
	}
	if err := os.WriteFile(memPath, mem, 0o644); err != nil {
		t.Fatalf("write mem: %v", err)
	}
	if err := os.WriteFile(statePath, state, 0o644); err != nil {
		t.Fatalf("write state: %v", err)
	}
	pr, pw := io.Pipe()
	errCh := make(chan error, 1)
	go func() {
		errCh <- writeTemplateArtifactTar(pw, manifest, rootfsPath, memPath, statePath)
	}()
	artifactBytes, readErr := io.ReadAll(pr)
	if werr := <-errCh; werr != nil {
		t.Fatalf("writeTemplateArtifactTar: %v", werr)
	}
	if readErr != nil {
		t.Fatalf("read artifact: %v", readErr)
	}

	// Now wrap that artifact tar in a docker-save outer tar with a
	// minimal layout (one layer dir containing layer.tar). docker also
	// emits manifest.json/repositories metadata at the outer level; the
	// puller ignores anything that isn't named layer.tar so we omit them
	// for brevity.
	var out bytes.Buffer
	tw := tar.NewWriter(&out)
	hdr := &tar.Header{
		Name:     "abc123/layer.tar",
		Mode:     0o644,
		Size:     int64(len(artifactBytes)),
		Typeflag: tar.TypeReg,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatalf("write outer hdr: %v", err)
	}
	if _, err := tw.Write(artifactBytes); err != nil {
		t.Fatalf("write outer body: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close outer: %v", err)
	}
	return out.Bytes()
}

func sha256hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func newTestPuller(t *testing.T, dk TemplateArtifactPullDocker, templatesDir string) *TemplateArtifactPuller {
	t.Helper()
	p, err := NewTemplateArtifactPuller(dk, templatesDir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewTemplateArtifactPuller: %v", err)
	}
	return p
}

// TestPullOnce_HappyPath proves the round-trip: producer-built artifact
// tar wrapped in a docker-save outer tar lands as the four canonical
// files under <templatesDir>/<id>/ with correct contents. This is the
// contract test for cluster-wide template replication.
func TestPullOnce_HappyPath(t *testing.T) {
	const id = "tpl-happy"
	rootfs := []byte("rootfs-bytes-for-pull-test")
	mem := []byte("mem-bytes-pull")
	state := []byte("state-bytes-pull")
	checksum := "sha256:" + sha256hex(mem) + "|sha256:" + sha256hex(state)

	manifest := TemplateArtifactManifest{
		SchemaVersion:     TemplateArtifactSchemaVersion,
		TemplateID:        id,
		Image:             "docker://alpine:3.19",
		RootfsSizeBytes:   int64(len(rootfs)),
		SnapshotSizeBytes: int64(len(mem) + len(state)),
		SnapshotChecksum:  checksum,
		SnapshotVsockCID:  77,
		HasOverlay:        true,
		MinSizeMiB:        512,
	}
	dk := &fakeTemplatePullDocker{
		exportBody: buildArtifactSaveBytes(t, manifest, rootfs, mem, state),
	}
	tplDir := t.TempDir()
	puller := newTestPuller(t, dk, tplDir)

	tpl := &models.Template{
		ID:               id,
		RegistryRef:      "aocr.test/cluster/c1/templates/tpl-happy:latest",
		SnapshotChecksum: checksum,
	}
	if err := puller.PullOnce(context.Background(), tpl); err != nil {
		t.Fatalf("PullOnce: %v", err)
	}

	// All three files should exist with the bytes we fed in. The
	// directory was atomically renamed from <id>.partial to <id>;
	// .partial must NOT exist post-success.
	for _, want := range []struct {
		name string
		body []byte
	}{
		{templateRootfsFilename, rootfs},
		{snapshotMemoryFilename, mem},
		{snapshotStateFilename, state},
	} {
		got, err := os.ReadFile(filepath.Join(tplDir, id, want.name))
		if err != nil {
			t.Errorf("read %s: %v", want.name, err)
			continue
		}
		if !bytes.Equal(got, want.body) {
			t.Errorf("%s = %q, want %q", want.name, got, want.body)
		}
	}
	if _, err := os.Stat(filepath.Join(tplDir, id+".partial")); !os.IsNotExist(err) {
		t.Errorf(".partial dir still exists after success: %v", err)
	}
	if dk.pullCalls.Load() != 1 {
		t.Errorf("PullImage calls = %d, want 1", dk.pullCalls.Load())
	}
	if dk.exportCalls.Load() != 1 {
		t.Errorf("ExportImageTar calls = %d, want 1", dk.exportCalls.Load())
	}
}

// TestPullOnce_FilesAlreadyPresent proves the fast-path skip: a row
// whose local files already exist must not pay docker pull/save. This
// is the steady-state behaviour on the producer node — files are local
// from the build, registry_ref is non-empty from the push, and we
// should not re-fetch our own output.
func TestPullOnce_FilesAlreadyPresent(t *testing.T) {
	const id = "tpl-local"
	tplDir := t.TempDir()
	dir := filepath.Join(tplDir, id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	for _, name := range []string{templateRootfsFilename, snapshotMemoryFilename, snapshotStateFilename} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	dk := &fakeTemplatePullDocker{} // no body — would error if pull triggered
	puller := newTestPuller(t, dk, tplDir)
	tpl := &models.Template{ID: id, RegistryRef: "any/ref:latest"}
	if err := puller.PullOnce(context.Background(), tpl); err != nil {
		t.Fatalf("PullOnce: %v", err)
	}
	if dk.pullCalls.Load() != 0 {
		t.Errorf("PullImage calls = %d, want 0 (files present)", dk.pullCalls.Load())
	}
	if dk.exportCalls.Load() != 0 {
		t.Errorf("ExportImageTar calls = %d, want 0 (files present)", dk.exportCalls.Load())
	}
}

// TestPullOnce_PartialCleanupOnExtractError proves the failure-path
// invariant: an extract that fails mid-way leaves no <id>.partial dir
// behind (and crucially no <id>/ either — the resolver would happily
// hand a half-populated dir to the runtime driver, which would boot a
// truncated snapshot and crash). The row state is untouched; the next
// call retries cleanly.
func TestPullOnce_PartialCleanupOnExtractError(t *testing.T) {
	const id = "tpl-broken"
	// Hand the puller a non-tar body so the extract step fails after
	// the .partial dir is created.
	dk := &fakeTemplatePullDocker{exportBody: []byte("not a tar")}
	tplDir := t.TempDir()
	puller := newTestPuller(t, dk, tplDir)
	tpl := &models.Template{ID: id, RegistryRef: "aocr.test/cluster/c1/templates/tpl-broken:latest"}

	err := puller.PullOnce(context.Background(), tpl)
	if err == nil {
		t.Fatal("PullOnce returned nil despite malformed tar")
	}
	if _, statErr := os.Stat(filepath.Join(tplDir, id+".partial")); !os.IsNotExist(statErr) {
		t.Errorf(".partial dir survived failure: %v", statErr)
	}
	if _, statErr := os.Stat(filepath.Join(tplDir, id)); !os.IsNotExist(statErr) {
		t.Errorf("final dir created despite failure: %v", statErr)
	}
}

// TestPullOnce_SchemaVersionMismatchIsRefused proves the forward-compat
// guard. A future producer bumping TemplateArtifactSchemaVersion would
// otherwise silently feed an older consumer a layout it can't read,
// surfacing as a hard-to-diagnose boot-time crash. Better to refuse the
// pull and surface a clear "producer/consumer mismatch" error.
func TestPullOnce_SchemaVersionMismatchIsRefused(t *testing.T) {
	const id = "tpl-future"
	rootfs := []byte("r")
	mem := []byte("m")
	state := []byte("s")
	manifest := TemplateArtifactManifest{
		SchemaVersion:    TemplateArtifactSchemaVersion + 1,
		TemplateID:       id,
		SnapshotChecksum: "sha256:" + sha256hex(mem) + "|sha256:" + sha256hex(state),
	}
	dk := &fakeTemplatePullDocker{
		exportBody: buildArtifactSaveBytes(t, manifest, rootfs, mem, state),
	}
	tplDir := t.TempDir()
	puller := newTestPuller(t, dk, tplDir)
	tpl := &models.Template{ID: id, RegistryRef: "any/ref:latest"}

	err := puller.PullOnce(context.Background(), tpl)
	if err == nil {
		t.Fatal("PullOnce accepted unknown schema version")
	}
	if _, statErr := os.Stat(filepath.Join(tplDir, id)); !os.IsNotExist(statErr) {
		t.Errorf("final dir created despite schema mismatch: %v", statErr)
	}
}

// TestPullOnce_ChecksumMismatchIsRefused proves the integrity guard. If
// the bytes that came out of AOCR don't hash to the row's recorded
// checksum, either the registry corrupted them or someone is feeding us
// a different template's artifacts under this ID. Refuse rather than
// risk booting a clone against bytes that don't match what the producer
// captured.
func TestPullOnce_ChecksumMismatchIsRefused(t *testing.T) {
	const id = "tpl-tampered"
	rootfs := []byte("r")
	mem := []byte("m")
	state := []byte("s")
	// Manifest carries the truthful checksum, but the row has the
	// expected checksum for DIFFERENT bytes. computeSnapshotChecksum
	// will hash the on-disk files (which match the manifest), so the
	// row check is what fails.
	manifest := TemplateArtifactManifest{
		SchemaVersion:    TemplateArtifactSchemaVersion,
		TemplateID:       id,
		SnapshotChecksum: "sha256:" + sha256hex(mem) + "|sha256:" + sha256hex(state),
	}
	dk := &fakeTemplatePullDocker{
		exportBody: buildArtifactSaveBytes(t, manifest, rootfs, mem, state),
	}
	tplDir := t.TempDir()
	puller := newTestPuller(t, dk, tplDir)
	tpl := &models.Template{
		ID:               id,
		RegistryRef:      "aocr.test/cluster/c1/templates/tpl-tampered:latest",
		SnapshotChecksum: "sha256:deadbeef|sha256:deadbeef",
	}

	err := puller.PullOnce(context.Background(), tpl)
	if err == nil {
		t.Fatal("PullOnce accepted mismatched checksum")
	}
	if _, statErr := os.Stat(filepath.Join(tplDir, id)); !os.IsNotExist(statErr) {
		t.Errorf("final dir created despite checksum mismatch: %v", statErr)
	}
}

// TestPullOnce_PullFailureSurfacedClean proves a failing docker pull
// does not leave .partial state. We never create .partial before the
// pull succeeds (the staging dir lives between pull and export); a
// quick docker-pull failure must surface clean.
func TestPullOnce_PullFailureSurfacedClean(t *testing.T) {
	const id = "tpl-pullfail"
	dk := &fakeTemplatePullDocker{pullErr: errors.New("registry unreachable")}
	tplDir := t.TempDir()
	puller := newTestPuller(t, dk, tplDir)
	tpl := &models.Template{ID: id, RegistryRef: "any/ref:latest"}

	if err := puller.PullOnce(context.Background(), tpl); err == nil {
		t.Fatal("PullOnce returned nil despite pull failure")
	}
	if _, statErr := os.Stat(filepath.Join(tplDir, id+".partial")); !os.IsNotExist(statErr) {
		t.Errorf(".partial dir created before pull succeeded: %v", statErr)
	}
	if dk.exportCalls.Load() != 0 {
		t.Errorf("ExportImageTar called despite pull failure (calls=%d)", dk.exportCalls.Load())
	}
}

// TestEnsureTemplateLocal_SingleFlight proves the §3 invariant: N
// concurrent first-callers against the same not-yet-local template
// collapse to one pull. Without this, a startup spike of clones against
// a freshly-replicated template would issue N docker pulls of the same
// hundred-MB image in parallel — the daemon would dedupe internally,
// but we'd still pay N extract+rename round-trips, racing the rename
// step.
func TestEnsureTemplateLocal_SingleFlight(t *testing.T) {
	const id = "tpl-collapse"
	rootfs := []byte("r")
	mem := []byte("m")
	state := []byte("s")
	checksum := "sha256:" + sha256hex(mem) + "|sha256:" + sha256hex(state)
	manifest := TemplateArtifactManifest{
		SchemaVersion:    TemplateArtifactSchemaVersion,
		TemplateID:       id,
		SnapshotChecksum: checksum,
	}
	dk := &fakeTemplatePullDocker{
		exportBody: buildArtifactSaveBytes(t, manifest, rootfs, mem, state),
	}
	tplDir := t.TempDir()
	puller := newTestPuller(t, dk, tplDir)
	svc := &Service{}
	svc.AttachTemplateArtifactPuller(puller)
	tpl := &models.Template{
		ID:               id,
		RegistryRef:      "aocr.test/cluster/c1/templates/tpl-collapse:latest",
		SnapshotChecksum: checksum,
	}

	const N = 16
	var wg sync.WaitGroup
	errs := make(chan error, N)
	start := make(chan struct{})
	for range N {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- svc.EnsureTemplateLocal(context.Background(), tpl)
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("EnsureTemplateLocal: %v", err)
		}
	}
	if got := dk.pullCalls.Load(); got != 1 {
		t.Errorf("PullImage calls = %d, want 1 (single-flight collapse)", got)
	}
	if got := dk.exportCalls.Load(); got != 1 {
		t.Errorf("ExportImageTar calls = %d, want 1 (single-flight collapse)", got)
	}
}

// TestEnsureTemplateLocal_DegradesWhenPullerNotAttached proves the
// single-node / pull-disabled invariant: with no puller, the function
// is a fast no-op so the resolver can call it unconditionally. This
// matches the EnsureLayer4Ready pattern (atomic.Bool fast-path) and
// the AttachX(nil) no-op convention used elsewhere in Service.
func TestEnsureTemplateLocal_DegradesWhenPullerNotAttached(t *testing.T) {
	svc := &Service{} // no puller attached
	tpl := &models.Template{ID: "tpl-x", RegistryRef: "any/ref:latest"}
	if err := svc.EnsureTemplateLocal(context.Background(), tpl); err != nil {
		t.Fatalf("EnsureTemplateLocal: %v", err)
	}
}

// TestEnsureTemplateLocal_NoRegistryRefIsNoop proves the producer-node
// invariant: a row that was never pushed (this node is the producer, or
// push is disabled) has no registry_ref and therefore nothing to fetch.
// Returning early avoids exposing producer nodes to docker-pull errors
// for a ref the registry never saw.
func TestEnsureTemplateLocal_NoRegistryRefIsNoop(t *testing.T) {
	dk := &fakeTemplatePullDocker{}
	puller := newTestPuller(t, dk, t.TempDir())
	svc := &Service{}
	svc.AttachTemplateArtifactPuller(puller)
	tpl := &models.Template{ID: "tpl-local-only", RegistryRef: ""}
	if err := svc.EnsureTemplateLocal(context.Background(), tpl); err != nil {
		t.Fatalf("EnsureTemplateLocal: %v", err)
	}
	if dk.pullCalls.Load() != 0 {
		t.Errorf("PullImage calls = %d, want 0 (no registry_ref)", dk.pullCalls.Load())
	}
}

func TestTemplateArtifactPullerEdgeBranches(t *testing.T) {
	ctx := context.Background()
	if _, err := NewTemplateArtifactPuller(nil, t.TempDir(), nil); err == nil {
		t.Fatal("nil docker should be rejected")
	}
	if _, err := NewTemplateArtifactPuller(&fakeTemplatePullDocker{}, " ", nil); err == nil {
		t.Fatal("blank templatesDir should be rejected")
	}
	if puller, err := NewTemplateArtifactPuller(&fakeTemplatePullDocker{}, t.TempDir(), nil); err != nil || puller == nil {
		t.Fatalf("NewTemplateArtifactPuller with nil logger = (%v, %v)", puller, err)
	}
	if got := NewTemplateArtifactPullDockerAdapter(nil); got != nil {
		t.Fatalf("nil docker client adapter = %v, want nil", got)
	}

	var nilPuller *TemplateArtifactPuller
	if err := nilPuller.PullOnce(ctx, &models.Template{ID: "tpl", RegistryRef: "ref"}); err == nil {
		t.Fatal("nil puller should reject PullOnce")
	}
	if err := nilPuller.PullOnce(ctx, nil); err == nil {
		t.Fatal("nil template should reject PullOnce")
	}
	if err := nilPuller.PullOnce(ctx, &models.Template{ID: " ", RegistryRef: "ref"}); err == nil {
		t.Fatal("blank template ID should reject PullOnce")
	}
	if err := nilPuller.PullOnce(ctx, &models.Template{ID: "tpl", RegistryRef: " "}); err == nil {
		t.Fatal("blank registry ref should reject PullOnce")
	}

	adapter := &templateArtifactPullDockerAdapter{}
	for _, tc := range []struct {
		name string
		call func()
	}{
		{
			name: "pull",
			call: func() { _ = adapter.PullImage(ctx, "ref", &models.RegistryAuth{Server: "s"}) },
		},
		{
			name: "export",
			call: func() {
				body, _ := adapter.ExportImageTar(ctx, "ref")
				if body != nil {
					_ = body.Close()
				}
			},
		},
		{
			name: "remove",
			call: func() { _ = adapter.RemoveImage(ctx, "ref") },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					t.Fatal("expected nil client panic")
				}
			}()
			tc.call()
		})
	}

	memFile := filepath.Join(t.TempDir(), "mem.snap")
	stateFile := filepath.Join(t.TempDir(), "state.snap")
	if err := os.WriteFile(memFile, []byte("mem"), 0o644); err != nil {
		t.Fatalf("write mem: %v", err)
	}
	if err := os.WriteFile(stateFile, []byte("state"), 0o644); err != nil {
		t.Fatalf("write state: %v", err)
	}
	if got, err := computeSnapshotChecksum(memFile, stateFile); err != nil || !strings.HasPrefix(got, "sha256:") {
		t.Fatalf("computeSnapshotChecksum success = (%q, %v)", got, err)
	}
	if got, err := hashFileSHA256(memFile); err != nil || got == "" {
		t.Fatalf("hashFileSHA256 success = (%q, %v)", got, err)
	}

	dk := &fakeTemplatePullDocker{exportErr: errors.New("save failed")}
	puller := newTestPuller(t, dk, t.TempDir())
	err := puller.PullOnce(ctx, &models.Template{
		ID:          "tpl-export-fail",
		RegistryRef: "aocr.test/cluster/c1/templates/tpl-export-fail:latest",
	})
	if err == nil || !strings.Contains(err.Error(), "save failed") {
		t.Fatalf("PullOnce export failure = %v, want save failed", err)
	}
	if _, statErr := os.Stat(filepath.Join(puller.templatesDir, "tpl-export-fail.partial")); !os.IsNotExist(statErr) {
		t.Fatalf("partial dir survived export failure: %v", statErr)
	}

	memPath := filepath.Join(t.TempDir(), "mem.snap")
	statePath := filepath.Join(t.TempDir(), "state.snap")
	if _, err := computeSnapshotChecksum(memPath, statePath); err == nil {
		t.Fatal("computeSnapshotChecksum should fail when files are missing")
	}
	if _, err := hashFileSHA256(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("hashFileSHA256 should fail on missing file")
	}

	fallbackManifest := TemplateArtifactManifest{
		SchemaVersion:    TemplateArtifactSchemaVersion,
		TemplateID:       "tpl-fallback",
		SnapshotChecksum: "sha256:" + sha256hex([]byte("m")) + "|sha256:" + sha256hex([]byte("s")),
	}
	fallbackDK := &fakeTemplatePullDocker{
		exportBody: buildArtifactSaveBytes(t, fallbackManifest, []byte("r"), []byte("m"), []byte("s")),
	}
	fallbackPuller := newTestPuller(t, fallbackDK, t.TempDir())
	if err := fallbackPuller.PullOnce(ctx, &models.Template{
		ID:          "tpl-fallback",
		RegistryRef: "aocr.test/cluster/c1/templates/tpl-fallback:latest",
	}); err != nil {
		t.Fatalf("PullOnce fallback checksum: %v", err)
	}
}

func TestEnsureTemplateLocalEdgeBranches(t *testing.T) {
	ctx := context.Background()

	var nilSvc *Service
	if err := nilSvc.EnsureTemplateLocal(ctx, &models.Template{ID: "tpl", RegistryRef: "ref"}); err != nil {
		t.Fatalf("nil service should return nil, got %v", err)
	}

	svc := &Service{}
	if err := svc.EnsureTemplateLocal(ctx, nil); err != nil {
		t.Fatalf("nil template should return nil, got %v", err)
	}
	svc.AttachTemplateArtifactPuller(nil)
	if err := svc.EnsureTemplateLocal(ctx, &models.Template{ID: "tpl", RegistryRef: "ref"}); err != nil {
		t.Fatalf("nil puller should return nil, got %v", err)
	}

	rootfs := []byte("rootfs")
	mem := []byte("mem")
	state := []byte("state")
	checksum := "sha256:" + sha256hex(mem) + "|sha256:" + sha256hex(state)
	manifest := TemplateArtifactManifest{
		SchemaVersion:    TemplateArtifactSchemaVersion,
		TemplateID:       "tpl-retry",
		SnapshotChecksum: checksum,
	}
	dk := &fakeTemplatePullDocker{
		pullErr:    errors.New("pull failed"),
		exportBody: buildArtifactSaveBytes(t, manifest, rootfs, mem, state),
	}
	puller := newTestPuller(t, dk, t.TempDir())
	svc.AttachTemplateArtifactPuller(puller)

	tpl := &models.Template{
		ID:               "tpl-retry",
		RegistryRef:      "aocr.test/cluster/c1/templates/tpl-retry:latest",
		SnapshotChecksum: checksum,
	}
	if err := svc.EnsureTemplateLocal(ctx, tpl); err == nil || !strings.Contains(err.Error(), "pull failed") {
		t.Fatalf("EnsureTemplateLocal first call = %v, want pull failed", err)
	}
	if dk.pullCalls.Load() != 1 {
		t.Fatalf("PullImage calls after failure = %d, want 1", dk.pullCalls.Load())
	}

	dk.pullErr = nil
	if err := svc.EnsureTemplateLocal(ctx, tpl); err != nil {
		t.Fatalf("EnsureTemplateLocal second call: %v", err)
	}
	if dk.pullCalls.Load() != 2 {
		t.Fatalf("PullImage calls after retry = %d, want 2", dk.pullCalls.Load())
	}
	if !templateLocalFilesPresent(filepath.Join(puller.templatesDir, tpl.ID), tpl) {
		t.Fatalf("template files not present after successful retry")
	}
}
