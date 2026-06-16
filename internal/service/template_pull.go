package service

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// TemplateArtifactPullDocker is the narrow Docker surface the puller
// needs. Mirrors TemplateArtifactPushDocker so test fakes look the same;
// pulled out so unit tests don't need a real *docker.Client.
type TemplateArtifactPullDocker interface {
	PullImage(ctx context.Context, ref string, auth *models.RegistryAuth) error
	ExportImageTar(ctx context.Context, ref string) (io.ReadCloser, error)
	RemoveImage(ctx context.Context, ref string) error
}

// TemplateArtifactPuller is the consumer-side counterpart to
// TemplateArtifactPusher (template_push.go:60). It fetches a template's
// AOCR-pushed OCI image, walks the docker-save outer tar to find the
// single layer, walks that layer (which is the producer's original
// artifact tar) to extract manifest.json + rootfs.ext4 +
// snapshot.{memory,state}, validates the schema version + checksums,
// and atomically renames the staging dir into place under templatesDir.
//
// Holds no per-template state; instantiate once at boot and reuse. The
// per-template single-flight latch lives on Service so the lazy
// EnsureTemplateLocal pattern (§3 of pr-review.md) can collapse
// concurrent first-creates against a missing-local template into one
// pull. Mirrors the EnsureLayer4Ready shape exactly.
type TemplateArtifactPuller struct {
	docker       TemplateArtifactPullDocker
	templatesDir string
	logger       *slog.Logger
}

// NewTemplateArtifactPuller mirrors NewTemplateArtifactPusher: returns
// nil when puller is disabled (templatesDir blank). Caller can then do
// `if puller == nil { return }` to keep the wire-up path tidy.
func NewTemplateArtifactPuller(d TemplateArtifactPullDocker, templatesDir string, logger *slog.Logger) (*TemplateArtifactPuller, error) {
	if d == nil {
		return nil, errors.New("TemplateArtifactPuller: docker is required")
	}
	if strings.TrimSpace(templatesDir) == "" {
		return nil, errors.New("TemplateArtifactPuller: templatesDir is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &TemplateArtifactPuller{
		docker:       d,
		templatesDir: templatesDir,
		logger:       logger,
	}, nil
}

// PullOnce fetches+extracts the template's artifacts. Idempotent: a row
// whose local files already exist is a fast no-op (no network call).
// Failure modes — all surface to the caller, none are silently swallowed:
//   - registry_ref blank: nothing to pull, return descriptive error
//   - docker pull failure (registry unreachable, auth, manifest unknown)
//   - docker save failure (image went missing between pull and save)
//   - tar walk failure / unexpected layout (missing manifest, missing files)
//   - schema-version mismatch (refuse: a future producer can't roll back)
//   - filesystem error mid-extract (out of space, permission denied)
//
// On any failure, the .partial directory is removed before return so the
// next call starts clean. Row state is untouched — the puller is purely
// "make local files match registry_ref", not a state-machine driver.
func (p *TemplateArtifactPuller) PullOnce(ctx context.Context, tpl *models.Template) error {
	if p == nil {
		return errors.New("template pull disabled (puller is nil)")
	}
	if tpl == nil {
		return errors.New("template pull: template is required")
	}
	id := strings.TrimSpace(tpl.ID)
	if id == "" {
		return errors.New("template pull: template ID is required")
	}
	ref := strings.TrimSpace(tpl.RegistryRef)
	if ref == "" {
		return fmt.Errorf("template pull %s: registry_ref is empty (template was never pushed)", id)
	}

	dir := filepath.Join(p.templatesDir, id)
	if templateLocalFilesPresent(dir, tpl) {
		// Files already on disk — common after a daemon restart on the
		// node that originally built the template. The latch path treats
		// this as success without paying the docker pull/save cost.
		return nil
	}

	if err := p.docker.PullImage(ctx, ref, nil); err != nil {
		return fmt.Errorf("template pull %s: docker pull %s: %w", id, ref, err)
	}

	// Stage extraction under <dir>.partial so a crash mid-extract leaves
	// no half-populated <dir> the resolver would happily hand to a clone.
	// Mirrors the snapshot-load atomic-rename pattern from
	// cluster/recovery_store.go.
	partial := dir + ".partial"
	if err := os.RemoveAll(partial); err != nil {
		return fmt.Errorf("template pull %s: clear stale partial dir: %w", id, err)
	}
	if err := os.MkdirAll(partial, 0o755); err != nil {
		return fmt.Errorf("template pull %s: mkdir partial: %w", id, err)
	}
	// Best-effort cleanup on any error path. A successful extract renames
	// the partial dir away so this no-ops; a failure leaves it in place
	// until we explicitly remove it.
	cleanup := true
	defer func() {
		if cleanup {
			if rmErr := os.RemoveAll(partial); rmErr != nil && p.logger != nil {
				p.logger.Warn("template pull: remove partial dir failed",
					"template", id, "path", partial, "error", rmErr)
			}
		}
	}()

	body, err := p.docker.ExportImageTar(ctx, ref)
	if err != nil {
		return fmt.Errorf("template pull %s: docker save %s: %w", id, ref, err)
	}
	defer body.Close()

	manifest, err := extractTemplateArtifactsFromSave(body, partial)
	if err != nil {
		return fmt.Errorf("template pull %s: extract: %w", id, err)
	}
	if manifest.SchemaVersion != TemplateArtifactSchemaVersion {
		return fmt.Errorf("template pull %s: manifest schema_version=%d, want %d (producer/consumer mismatch)",
			id, manifest.SchemaVersion, TemplateArtifactSchemaVersion)
	}

	// Validate the extracted snapshot checksum against the row's recorded
	// digest. The row checksum was written by the producer's snapshot
	// phase; if it doesn't match the bytes we just pulled, either the
	// registry corrupted them or someone is feeding us a different
	// template's artifacts under this ID. Either way: refuse.
	wantChecksum := strings.TrimSpace(tpl.SnapshotChecksum)
	if wantChecksum == "" {
		// Producer-side row may not have populated checksum yet (e.g.
		// ready_no_snapshot row whose snapshot phase later succeeded but
		// the column update raced the push). Fall back to the manifest's
		// own checksum so we still catch in-flight corruption between
		// producer disk and registry.
		wantChecksum = strings.TrimSpace(manifest.SnapshotChecksum)
	}
	gotChecksum, err := computeSnapshotChecksum(
		filepath.Join(partial, snapshotMemoryFilename),
		filepath.Join(partial, snapshotStateFilename),
	)
	if err != nil {
		return fmt.Errorf("template pull %s: checksum: %w", id, err)
	}
	if wantChecksum != "" && gotChecksum != wantChecksum {
		return fmt.Errorf("template pull %s: snapshot checksum mismatch (got %s, want %s) — registry or row state is corrupt",
			id, gotChecksum, wantChecksum)
	}

	// All checks passed. Rename the staging dir into place. os.Rename
	// across the same filesystem is atomic; we MkdirAll the parent
	// first in case templatesDir itself is fresh on this node.
	if err := os.MkdirAll(p.templatesDir, 0o755); err != nil {
		return fmt.Errorf("template pull %s: mkdir templatesDir: %w", id, err)
	}
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("template pull %s: clear stale dir before rename: %w", id, err)
	}
	if err := os.Rename(partial, dir); err != nil {
		return fmt.Errorf("template pull %s: rename %s -> %s: %w", id, partial, dir, err)
	}
	cleanup = false // success — keep <dir>
	if p.logger != nil {
		p.logger.Info("template pull: succeeded",
			"template", id, "registry_ref", ref)
	}
	return nil
}

// templateLocalFilesPresent is the fast-path skip: a node that built or
// already-pulled this template has all four files on disk; no point in
// paying docker pull/save again. Only checks the snapshot triple plus
// rootfs because that's exactly what the resolver hands to the runtime
// driver.
func templateLocalFilesPresent(dir string, tpl *models.Template) bool {
	rootfs := strings.TrimSpace(tpl.RootfsPath)
	if rootfs == "" {
		rootfs = filepath.Join(dir, templateRootfsFilename)
	}
	mem := strings.TrimSpace(tpl.SnapshotMemoryPath)
	if mem == "" {
		mem = filepath.Join(dir, snapshotMemoryFilename)
	}
	state := strings.TrimSpace(tpl.SnapshotStatePath)
	if state == "" {
		state = filepath.Join(dir, snapshotStateFilename)
	}
	for _, p := range []string{rootfs, mem, state} {
		if assertRegularFile(p) != nil {
			return false
		}
	}
	return true
}

// extractTemplateArtifactsFromSave walks the docker-save outer tar
// looking for the single layer.tar entry, then walks that nested tar to
// extract manifest.json + rootfs.ext4 + snapshot.memory + snapshot.state
// by exact basename into outDir.
//
// docker save's outer layout (per the v1.2 image spec):
//
//	manifest.json                        (image manifest, lists layers)
//	repositories                         (legacy tag map, ignored)
//	<sha256>/layer.tar                   (one per layer)
//	<sha256>/json                        (legacy v1 layer meta)
//	<sha256>/VERSION                     (legacy)
//
// The producer's ImportImage always lands a single-layer image, so we
// expect exactly one layer.tar. We extract from the first layer.tar we
// hit and ignore the rest — defence in depth in case docker ever returns
// extra layers (it doesn't today).
func extractTemplateArtifactsFromSave(body io.Reader, outDir string) (TemplateArtifactManifest, error) {
	var manifest TemplateArtifactManifest
	tr := tar.NewReader(body)
	foundLayer := false
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return manifest, fmt.Errorf("outer tar: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		// Match `<sha>/layer.tar` (canonical) and bare `layer.tar`
		// (defensive — some docker daemons emit it that way for single-
		// layer images). Anything else in the outer tar is metadata we
		// don't care about.
		base := filepath.Base(hdr.Name)
		if base != "layer.tar" {
			continue
		}
		// Bound the nested read at hdr.Size — the outer tar reader will
		// otherwise leak into the next outer entry.
		m, err := extractTemplateArtifactsFromLayer(io.LimitReader(tr, hdr.Size), outDir)
		if err != nil {
			return manifest, fmt.Errorf("layer tar: %w", err)
		}
		manifest = m
		foundLayer = true
		break
	}
	if !foundLayer {
		return manifest, errors.New("no layer.tar in docker-save output")
	}
	return manifest, nil
}

// extractTemplateArtifactsFromLayer reads the producer's artifact tar
// (the single layer the importer wrapped on the push side) and extracts
// the four canonical files. manifest.json is held in memory and parsed
// for schema validation; the three large files stream to disk so a
// hundreds-of-MB rootfs never lives in RAM.
//
// The producer writes manifest.json FIRST (template_push.go:335), so a
// well-formed tar lets us parse the manifest before we touch disk.
// Tolerating a different order would require a two-pass scan; we don't.
func extractTemplateArtifactsFromLayer(body io.Reader, outDir string) (TemplateArtifactManifest, error) {
	var manifest TemplateArtifactManifest
	manifestParsed := false
	extracted := map[string]bool{
		templateRootfsFilename: false,
		snapshotMemoryFilename: false,
		snapshotStateFilename:  false,
	}
	tr := tar.NewReader(body)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return manifest, fmt.Errorf("read header: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		name := filepath.Base(hdr.Name)
		switch name {
		case templateManifestFilename:
			data, err := io.ReadAll(io.LimitReader(tr, hdr.Size))
			if err != nil {
				return manifest, fmt.Errorf("read manifest: %w", err)
			}
			if err := json.Unmarshal(data, &manifest); err != nil {
				return manifest, fmt.Errorf("decode manifest: %w", err)
			}
			manifestParsed = true
		case templateRootfsFilename, snapshotMemoryFilename, snapshotStateFilename:
			if err := writeFileFromTar(tr, hdr.Size, filepath.Join(outDir, name)); err != nil {
				return manifest, fmt.Errorf("write %s: %w", name, err)
			}
			extracted[name] = true
		default:
			// Ignore anything else (future-compat: producer may add files).
		}
	}
	if !manifestParsed {
		return manifest, fmt.Errorf("missing %s in artifact tar", templateManifestFilename)
	}
	for name, ok := range extracted {
		if !ok {
			return manifest, fmt.Errorf("missing %s in artifact tar", name)
		}
	}
	return manifest, nil
}

// writeFileFromTar streams a tar entry to a file with 0o644 perms. The
// caller already knows the size from the header; we use it to bound the
// io.Copy so a malformed tar can't overrun into the next entry.
func writeFileFromTar(tr io.Reader, size int64, path string) (rerr error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); rerr == nil {
			rerr = cerr
		}
	}()
	if _, err := io.Copy(f, io.LimitReader(tr, size)); err != nil {
		return err
	}
	return nil
}

// computeSnapshotChecksum recomputes "sha256:<hex>|sha256:<hex>" over
// (memory, state) — the same shape the producer's snapshot phase wrote
// to the row. Used by the puller to verify the bytes survived the
// registry round-trip.
func computeSnapshotChecksum(memPath, statePath string) (string, error) {
	memHash, err := hashFileSHA256(memPath)
	if err != nil {
		return "", fmt.Errorf("hash %s: %w", filepath.Base(memPath), err)
	}
	stateHash, err := hashFileSHA256(statePath)
	if err != nil {
		return "", fmt.Errorf("hash %s: %w", filepath.Base(statePath), err)
	}
	return "sha256:" + memHash + "|sha256:" + stateHash, nil
}

// hashFileSHA256 streams a file through sha256 and returns the lower-
// case hex digest. Local helper rather than reaching into the firecracker
// runtime package (which would be a layering inversion from service).
func hashFileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// templateLocalReadyEntry is the per-template single-flight slot that
// EnsureTemplateLocal allocates lazily. Same layout as the wakeFlights
// map on Service: an atomic.Bool latch for the lock-free fast path
// after the first successful pull, and a sync.Mutex that funnels
// concurrent first-callers into a single PullOnce.
type templateLocalReadyEntry struct {
	mu    sync.Mutex
	ready atomic.Bool
}

// EnsureTemplateLocal guarantees that <templatesDir>/<id>/ exists with
// rootfs.ext4 + snapshot.{memory,state} on this node, fetching from
// AOCR via the attached puller when missing. Idempotent: callers that
// hit the latch fast-path pay one atomic load.
//
// Mirrors EnsureLayer4Ready exactly:
//   - atomic.Bool per-template latch for the lock-free steady-state path
//   - sync.Mutex per-template single-flight collapses concurrent first
//     callers into one pull
//   - failure leaves the latch unset so the next call retries
//
// Returns nil immediately when:
//   - puller is not attached (single-node mode, or push/pull disabled)
//   - the template has no registry_ref (never pushed; this node must be
//     the producer and the files are presumed local already)
//   - the files are already on disk (cold-start on the producer node)
func (s *Service) EnsureTemplateLocal(ctx context.Context, tpl *models.Template) error {
	if s == nil || tpl == nil {
		return nil
	}
	if s.templateArtifactPuller == nil {
		return nil
	}
	id := strings.TrimSpace(tpl.ID)
	if id == "" {
		return nil
	}
	if strings.TrimSpace(tpl.RegistryRef) == "" {
		// Producer node, or pre-Phase-6 row that predates the push
		// pipeline. Either way, nothing to fetch — let the resolver
		// proceed against whatever local files exist.
		return nil
	}
	if err := validateClusterArtifactRefArch(tpl.RegistryRef, hostSnapshotArch()); err != nil {
		return fmt.Errorf("template pull %s: %w", id, err)
	}

	entry := s.templateLocalReadyEntry(id)
	if entry.ready.Load() {
		return nil
	}
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.ready.Load() {
		return nil
	}
	if err := s.templateArtifactPuller.PullOnce(ctx, tpl); err != nil {
		templatePullFailedTotal.Add(1)
		return err
	}
	templatePullSucceededTotal.Add(1)
	entry.ready.Store(true)
	return nil
}

// templateLocalReadyEntry lazily allocates the per-template latch slot.
// The outer map lock is only held for the slot creation; once an entry
// exists, callers contend on its per-template mutex instead. Same shape
// as wakeFlights.
func (s *Service) templateLocalReadyEntry(id string) *templateLocalReadyEntry {
	s.templateLocalReadyMu.Lock()
	defer s.templateLocalReadyMu.Unlock()
	if s.templateLocalReady == nil {
		s.templateLocalReady = make(map[string]*templateLocalReadyEntry)
	}
	if entry, ok := s.templateLocalReady[id]; ok {
		return entry
	}
	entry := &templateLocalReadyEntry{}
	s.templateLocalReady[id] = entry
	return entry
}

// AttachTemplateArtifactPuller wires in the consumer-side puller. nil
// puller leaves the feature off and EnsureTemplateLocal becomes a fast
// no-op — the right behaviour for single-node deployments and for
// nodes where SnapshotPushEnabled=false (no AOCR configured). Called
// once from main() after the docker client is up.
func (s *Service) AttachTemplateArtifactPuller(p *TemplateArtifactPuller) {
	if p == nil {
		return
	}
	s.templateArtifactPuller = p
}

// templateArtifactPullDockerAdapter bridges the *docker.Client surface
// into the narrow TemplateArtifactPullDocker interface the puller
// consumes. Lives here (not in cmd/) because the puller is the only
// caller and the adapter is trivial; mirrors the snapshot-push wiring
// in this package.
type templateArtifactPullDockerAdapter struct {
	client *docker.Client
}

// NewTemplateArtifactPullDockerAdapter is the constructor used by
// cmd/sandboxd to satisfy the puller's docker dependency without
// exposing the full *docker.Client API.
func NewTemplateArtifactPullDockerAdapter(c *docker.Client) TemplateArtifactPullDocker {
	if c == nil {
		return nil
	}
	return &templateArtifactPullDockerAdapter{client: c}
}

func (a *templateArtifactPullDockerAdapter) PullImage(ctx context.Context, ref string, auth *models.RegistryAuth) error {
	return a.client.PullImage(ctx, ref, auth)
}

func (a *templateArtifactPullDockerAdapter) ExportImageTar(ctx context.Context, ref string) (io.ReadCloser, error) {
	return a.client.ExportImageTar(ctx, ref)
}

func (a *templateArtifactPullDockerAdapter) RemoveImage(ctx context.Context, ref string) error {
	return a.client.RemoveImage(ctx, ref)
}
