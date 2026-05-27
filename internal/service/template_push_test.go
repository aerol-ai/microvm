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
	"strings"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// fakeTemplatePushDocker captures both Import and Push calls so tests
// can assert tar contents (manifest, file ordering) and the registry
// ref the pusher built. Mirrors fakeSnapshotPushDocker in shape.
type fakeTemplatePushDocker struct {
	mu sync.Mutex

	importCalls []importCall
	pushCalls   []docker.PushImageRequest
	removeCalls []string

	importErr error
	pushErr   error
	pushTag   string
	digest    string
}

type importCall struct {
	DestTag string
	TarRaw  []byte
}

func (f *fakeTemplatePushDocker) ImportImage(_ context.Context, req docker.ImportImageRequest) error {
	body, _ := io.ReadAll(req.Tar)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.importCalls = append(f.importCalls, importCall{DestTag: req.DestTag, TarRaw: body})
	return f.importErr
}

func (f *fakeTemplatePushDocker) PushImage(_ context.Context, req docker.PushImageRequest) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pushCalls = append(f.pushCalls, req)
	if f.pushErr != nil {
		return "", f.pushErr
	}
	if f.digest != "" && req.OnDigest != nil {
		req.OnDigest(f.digest)
	}
	if f.pushTag != "" {
		return f.pushTag, nil
	}
	return req.DestRef, nil
}

func (f *fakeTemplatePushDocker) RemoveImage(_ context.Context, ref string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removeCalls = append(f.removeCalls, ref)
	return nil
}

func newTestTemplatePusher(t *testing.T, patPath, templatesDir string, dk TemplateArtifactPushDocker) *TemplateArtifactPusher {
	t.Helper()
	pusher, err := NewTemplateArtifactPusher(SnapshotPushConfig{
		Enabled:   true,
		Host:      "aocr.test",
		ClusterID: "cluster-42",
		PATPath:   patPath,
	}, dk, templatesDir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewTemplateArtifactPusher: %v", err)
	}
	return pusher
}

// TestTemplateArtifactPusher_HappyPath pins the end-to-end happy path:
// the tar carries all four files in the documented order, the import
// lands under the local BuiltImageNamespace tag, the push targets the
// AOCR ref, and the local intermediate tag is cleaned up after the
// push succeeds. PR 6-B.2's puller depends on the in-tar file layout,
// so this test is the contract between the two PRs.
func TestTemplateArtifactPusher_HappyPath(t *testing.T) {
	patPath := writePATFile(t, "secret-token\n")
	dk := &fakeTemplatePushDocker{digest: "sha256:abc123"}

	templatesDir := t.TempDir()
	templateID := "tpl-happy"
	dir := filepath.Join(templatesDir, templateID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	rootfsPath := filepath.Join(dir, templateRootfsFilename)
	memPath := filepath.Join(dir, snapshotMemoryFilename)
	statePath := filepath.Join(dir, snapshotStateFilename)
	if err := os.WriteFile(rootfsPath, []byte("rootfs-bytes"), 0o644); err != nil {
		t.Fatalf("write rootfs: %v", err)
	}
	if err := os.WriteFile(memPath, []byte("mem-bytes"), 0o644); err != nil {
		t.Fatalf("write mem: %v", err)
	}
	if err := os.WriteFile(statePath, []byte("state-bytes"), 0o644); err != nil {
		t.Fatalf("write state: %v", err)
	}

	pusher := newTestTemplatePusher(t, patPath, templatesDir, dk)
	tpl := &models.Template{
		ID:                 templateID,
		Image:              "docker://alpine:3.19",
		Status:             models.TemplateStatusReady,
		RootfsPath:         rootfsPath,
		RootfsSizeBytes:    int64(len("rootfs-bytes")),
		SnapshotMemoryPath: memPath,
		SnapshotStatePath:  statePath,
		SnapshotSizeBytes:  int64(len("mem-bytes") + len("state-bytes")),
		SnapshotChecksum:   "sha256:mem|sha256:state",
		SnapshotVsockCID:   77,
		HasOverlay:         true,
		HasSnapshot:        true,
		MinSizeMiB:         512,
	}

	res, err := pusher.PushOnce(context.Background(), tpl)
	if err != nil {
		t.Fatalf("PushOnce: %v", err)
	}
	wantRef := "aocr.test/cluster/cluster-42/templates/tpl-happy:latest"
	if res.RegistryRef != wantRef {
		t.Errorf("RegistryRef = %q, want %q", res.RegistryRef, wantRef)
	}
	if res.Digest != "sha256:abc123" {
		t.Errorf("Digest = %q, want sha256:abc123", res.Digest)
	}

	// Import side.
	if len(dk.importCalls) != 1 {
		t.Fatalf("ImportImage calls = %d, want 1", len(dk.importCalls))
	}
	wantLocalTag := docker.BuiltImageNamespace + "/tpl-tpl-happy:latest"
	if dk.importCalls[0].DestTag != wantLocalTag {
		t.Errorf("import DestTag = %q, want %q", dk.importCalls[0].DestTag, wantLocalTag)
	}
	entries := readTarEntries(t, dk.importCalls[0].TarRaw)
	wantNames := []string{templateManifestFilename, templateRootfsFilename, snapshotMemoryFilename, snapshotStateFilename}
	if len(entries) != len(wantNames) {
		t.Fatalf("tar entries = %d (%v), want %d (%v)", len(entries), entryNames(entries), len(wantNames), wantNames)
	}
	for i, want := range wantNames {
		if entries[i].name != want {
			t.Errorf("tar[%d] name = %q, want %q (order matters — puller reads manifest first)", i, entries[i].name, want)
		}
	}
	if string(entries[1].body) != "rootfs-bytes" {
		t.Errorf("rootfs body = %q, want rootfs-bytes", string(entries[1].body))
	}
	if string(entries[2].body) != "mem-bytes" {
		t.Errorf("mem body = %q", string(entries[2].body))
	}
	if string(entries[3].body) != "state-bytes" {
		t.Errorf("state body = %q", string(entries[3].body))
	}

	var manifest TemplateArtifactManifest
	if err := json.Unmarshal(entries[0].body, &manifest); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}
	if manifest.SchemaVersion != TemplateArtifactSchemaVersion {
		t.Errorf("manifest.SchemaVersion = %d, want %d", manifest.SchemaVersion, TemplateArtifactSchemaVersion)
	}
	if manifest.TemplateID != templateID {
		t.Errorf("manifest.TemplateID = %q, want %q", manifest.TemplateID, templateID)
	}
	if manifest.Image != "docker://alpine:3.19" {
		t.Errorf("manifest.Image = %q", manifest.Image)
	}
	if manifest.SnapshotChecksum != "sha256:mem|sha256:state" {
		t.Errorf("manifest.SnapshotChecksum = %q", manifest.SnapshotChecksum)
	}
	if manifest.SnapshotVsockCID != 77 {
		t.Errorf("manifest.SnapshotVsockCID = %d, want 77", manifest.SnapshotVsockCID)
	}
	if !manifest.HasOverlay {
		t.Error("manifest.HasOverlay = false, want true")
	}
	if manifest.MinSizeMiB != 512 {
		t.Errorf("manifest.MinSizeMiB = %d, want 512", manifest.MinSizeMiB)
	}

	// Push side.
	if len(dk.pushCalls) != 1 {
		t.Fatalf("PushImage calls = %d, want 1", len(dk.pushCalls))
	}
	push := dk.pushCalls[0]
	if push.SourceTag != wantLocalTag {
		t.Errorf("push.SourceTag = %q, want %q", push.SourceTag, wantLocalTag)
	}
	if push.DestRef != wantRef {
		t.Errorf("push.DestRef = %q, want %q", push.DestRef, wantRef)
	}
	if push.Auth.Username != "cluster-42" {
		t.Errorf("push.Auth.Username = %q, want cluster-42", push.Auth.Username)
	}
	if push.Auth.Password != "secret-token" {
		t.Errorf("push.Auth.Password = %q, want secret-token (PAT must be trimmed)", push.Auth.Password)
	}
	if push.Auth.Server != "aocr.test" {
		t.Errorf("push.Auth.Server = %q, want aocr.test", push.Auth.Server)
	}

	// Cleanup side — local intermediate tag removed after a successful push.
	if len(dk.removeCalls) != 1 || dk.removeCalls[0] != wantLocalTag {
		t.Errorf("RemoveImage calls = %v, want exactly [%q]", dk.removeCalls, wantLocalTag)
	}
}

// TestTemplateArtifactPusher_MissingArtifactFile pins the early-fail
// arm. If one of the three files is absent, the pusher must NOT call
// ImportImage at all — half-streaming a tar to the daemon for the
// caller to then learn "rootfs missing" wastes the daemon's IO and
// produces a confusing error.
func TestTemplateArtifactPusher_MissingArtifactFile(t *testing.T) {
	patPath := writePATFile(t, "tok")
	dk := &fakeTemplatePushDocker{}
	templatesDir := t.TempDir()
	pusher := newTestTemplatePusher(t, patPath, templatesDir, dk)

	// Only mem + state on disk; rootfs is missing.
	dir := filepath.Join(templatesDir, "tpl-missing")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	memPath := filepath.Join(dir, snapshotMemoryFilename)
	statePath := filepath.Join(dir, snapshotStateFilename)
	_ = os.WriteFile(memPath, []byte("m"), 0o644)
	_ = os.WriteFile(statePath, []byte("s"), 0o644)

	tpl := &models.Template{
		ID: "tpl-missing", Image: "x", Status: models.TemplateStatusReady,
		SnapshotMemoryPath: memPath, SnapshotStatePath: statePath,
	}
	_, err := pusher.PushOnce(context.Background(), tpl)
	if err == nil {
		t.Fatal("PushOnce returned nil despite missing rootfs")
	}
	if !strings.Contains(err.Error(), "rootfs") {
		t.Errorf("err = %v, want it to mention rootfs", err)
	}
	if len(dk.importCalls) != 0 {
		t.Errorf("ImportImage called %d times despite missing artifact", len(dk.importCalls))
	}
	if len(dk.pushCalls) != 0 {
		t.Errorf("PushImage called %d times despite missing artifact", len(dk.pushCalls))
	}
}

// TestTemplateArtifactPusher_PushFailureCleansUpLocalTag pins the
// failure-path post-condition: even when the push to AOCR fails, the
// local intermediate tag must be removed so the next reconciler tick
// imports a fresh tar (vs. silently re-pushing whatever old bytes
// happened to be tagged locally).
func TestTemplateArtifactPusher_PushFailureCleansUpLocalTag(t *testing.T) {
	patPath := writePATFile(t, "tok")
	dk := &fakeTemplatePushDocker{pushErr: errors.New("registry 502 bad gateway")}
	templatesDir := t.TempDir()
	pusher := newTestTemplatePusher(t, patPath, templatesDir, dk)

	id := "tpl-pushfail"
	dir := filepath.Join(templatesDir, id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	rootfsPath := filepath.Join(dir, templateRootfsFilename)
	memPath := filepath.Join(dir, snapshotMemoryFilename)
	statePath := filepath.Join(dir, snapshotStateFilename)
	_ = os.WriteFile(rootfsPath, []byte("r"), 0o644)
	_ = os.WriteFile(memPath, []byte("m"), 0o644)
	_ = os.WriteFile(statePath, []byte("s"), 0o644)

	tpl := &models.Template{
		ID: id, Image: "x", Status: models.TemplateStatusReady,
		RootfsPath: rootfsPath, SnapshotMemoryPath: memPath, SnapshotStatePath: statePath,
	}
	_, err := pusher.PushOnce(context.Background(), tpl)
	if err == nil {
		t.Fatal("PushOnce returned nil despite push error")
	}
	if !strings.Contains(err.Error(), "registry 502") {
		t.Errorf("err = %v, want registry error surfaced", err)
	}
	wantLocalTag := docker.BuiltImageNamespace + "/tpl-tpl-pushfail:latest"
	if len(dk.removeCalls) != 1 || dk.removeCalls[0] != wantLocalTag {
		t.Errorf("RemoveImage calls = %v, want exactly [%q] (cleanup must run on push failure)", dk.removeCalls, wantLocalTag)
	}
}

// TestTemplateArtifactPusher_ImportFailureCleansUpAndSkipsPush pins
// the other failure arm: when the daemon refuses the import (malformed
// tar, daemon down), the pusher must NOT proceed to PushImage —
// pushing whatever stale tag happens to exist would publish the wrong
// bytes to AOCR.
func TestTemplateArtifactPusher_ImportFailureCleansUpAndSkipsPush(t *testing.T) {
	patPath := writePATFile(t, "tok")
	dk := &fakeTemplatePushDocker{importErr: errors.New("daemon unreachable")}
	templatesDir := t.TempDir()
	pusher := newTestTemplatePusher(t, patPath, templatesDir, dk)

	id := "tpl-importfail"
	dir := filepath.Join(templatesDir, id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	rootfsPath := filepath.Join(dir, templateRootfsFilename)
	memPath := filepath.Join(dir, snapshotMemoryFilename)
	statePath := filepath.Join(dir, snapshotStateFilename)
	_ = os.WriteFile(rootfsPath, []byte("r"), 0o644)
	_ = os.WriteFile(memPath, []byte("m"), 0o644)
	_ = os.WriteFile(statePath, []byte("s"), 0o644)

	tpl := &models.Template{
		ID: id, Image: "x", Status: models.TemplateStatusReady,
		RootfsPath: rootfsPath, SnapshotMemoryPath: memPath, SnapshotStatePath: statePath,
	}
	_, err := pusher.PushOnce(context.Background(), tpl)
	if err == nil {
		t.Fatal("PushOnce returned nil despite import error")
	}
	if !strings.Contains(err.Error(), "daemon unreachable") {
		t.Errorf("err = %v, want daemon error surfaced", err)
	}
	if len(dk.pushCalls) != 0 {
		t.Errorf("PushImage called %d times despite import failure", len(dk.pushCalls))
	}
	if len(dk.removeCalls) != 1 {
		t.Errorf("RemoveImage calls = %d, want 1 (cleanup must run on import failure too)", len(dk.removeCalls))
	}
}

// TestTemplateArtifactPusher_PATRotation pins the
// rotation-on-every-call semantics shared with the snapshot pusher.
// Mutating the PAT file between two PushOnce calls must be picked up
// by the second call — operators rely on this to rotate without a
// daemon restart.
func TestTemplateArtifactPusher_PATRotation(t *testing.T) {
	patPath := writePATFile(t, "first")
	dk := &fakeTemplatePushDocker{}
	templatesDir := t.TempDir()
	pusher := newTestTemplatePusher(t, patPath, templatesDir, dk)

	id := "tpl-rot"
	dir := filepath.Join(templatesDir, id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	for _, n := range []string{templateRootfsFilename, snapshotMemoryFilename, snapshotStateFilename} {
		_ = os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o644)
	}
	tpl := &models.Template{
		ID: id, Image: "x", Status: models.TemplateStatusReady,
		RootfsPath:         filepath.Join(dir, templateRootfsFilename),
		SnapshotMemoryPath: filepath.Join(dir, snapshotMemoryFilename),
		SnapshotStatePath:  filepath.Join(dir, snapshotStateFilename),
	}

	if _, err := pusher.PushOnce(context.Background(), tpl); err != nil {
		t.Fatalf("first push: %v", err)
	}
	if dk.pushCalls[0].Auth.Password != "first" {
		t.Fatalf("first push password = %q, want first", dk.pushCalls[0].Auth.Password)
	}

	if err := os.WriteFile(patPath, []byte("rotated\n"), 0o600); err != nil {
		t.Fatalf("rotate PAT: %v", err)
	}
	if _, err := pusher.PushOnce(context.Background(), tpl); err != nil {
		t.Fatalf("second push: %v", err)
	}
	if dk.pushCalls[1].Auth.Password != "rotated" {
		t.Errorf("second push password = %q, want rotated (PAT rotation broken)", dk.pushCalls[1].Auth.Password)
	}
}

// TestTemplateArtifactPusher_DisabledReturnsNil documents the config
// gate: when Enabled=false, NewTemplateArtifactPusher returns
// (nil, nil) so callers can use the `if pusher == nil` short-circuit
// the snapshot pipeline already established.
func TestTemplateArtifactPusher_DisabledReturnsNil(t *testing.T) {
	p, err := NewTemplateArtifactPusher(SnapshotPushConfig{Enabled: false}, &fakeTemplatePushDocker{}, "/tmp", nil)
	if err != nil {
		t.Fatalf("NewTemplateArtifactPusher(disabled): %v", err)
	}
	if p != nil {
		t.Errorf("pusher = %+v, want nil when disabled", p)
	}
}

// TestTemplateArtifactPusher_DestRefFor pins the exact ref convention
// the consumer pull in PR 6-B.2 will use. If this drifts, the puller
// looks under the wrong AOCR path and never finds the artifact.
func TestTemplateArtifactPusher_DestRefFor(t *testing.T) {
	patPath := writePATFile(t, "tok")
	p := newTestTemplatePusher(t, patPath, t.TempDir(), &fakeTemplatePushDocker{})
	want := "aocr.test/cluster/cluster-42/templates/tpl-abc:latest"
	if got := p.DestRefFor("tpl-abc"); got != want {
		t.Errorf("DestRefFor = %q, want %q", got, want)
	}
	// Uppercase is folded so an operator-chosen id with mixed case
	// doesn't produce a registry-rejected ref.
	if got := p.DestRefFor("Tpl-ABC"); got != want {
		t.Errorf("DestRefFor(mixed-case) = %q, want %q (lowercase)", got, want)
	}
	// Nil pusher and empty id return "" — exercised by callers that
	// can't easily check both upfront.
	if got := (*TemplateArtifactPusher)(nil).DestRefFor("x"); got != "" {
		t.Errorf("nil pusher DestRefFor = %q, want empty", got)
	}
	if got := p.DestRefFor(""); got != "" {
		t.Errorf("empty id DestRefFor = %q, want empty", got)
	}
}

// TestTemplateNeedsPush pins the "only ready rows" guard the
// reconciler uses. Unhealthy templates (Phase 6 PR-A's corrupt-at-
// load-time state) must NOT be pushed — propagating known-corrupt
// bytes to peers turns one host's failure into a cluster-wide
// failure.
func TestTemplateNeedsPush(t *testing.T) {
	cases := []struct {
		state models.TemplateStatus
		want  bool
	}{
		{models.TemplateStatusReady, true},
		{models.TemplateStatusReadyNoSnapshot, false},
		{models.TemplateStatusPending, false},
		{models.TemplateStatusBuildingRootfs, false},
		{models.TemplateStatusSnapshotting, false},
		{models.TemplateStatusFailed, false},
		{models.TemplateStatusUnhealthy, false},
	}
	for _, c := range cases {
		t.Run(string(c.state), func(t *testing.T) {
			got := TemplateNeedsPush(&models.Template{Status: c.state})
			if got != c.want {
				t.Errorf("TemplateNeedsPush(%s) = %v, want %v", c.state, got, c.want)
			}
		})
	}
	if TemplateNeedsPush(nil) {
		t.Error("TemplateNeedsPush(nil) = true, want false")
	}
}

type tarEntry struct {
	name string
	body []byte
}

func readTarEntries(t *testing.T, raw []byte) []tarEntry {
	t.Helper()
	tr := tar.NewReader(bytes.NewReader(raw))
	var out []tarEntry
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar next: %v", err)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("tar read: %v", err)
		}
		out = append(out, tarEntry{name: hdr.Name, body: body})
	}
	return out
}

func entryNames(es []tarEntry) []string {
	out := make([]string, len(es))
	for i, e := range es {
		out[i] = e.name
	}
	return out
}
