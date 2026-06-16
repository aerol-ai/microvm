package service

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// TemplateArtifactSchemaVersion is the wire/storage schema of the
// manifest.json that travels inside the OCI image alongside the three
// artifact files. PR 6-B.2 (consumer side) reads this and refuses
// unknown versions; bumping it means a coordinated push/pull rollout.
const TemplateArtifactSchemaVersion = 1

// templateRootfsFilename / templateManifestFilename are the canonical
// file names that land inside the tar layer. The puller in PR 6-B.2
// extracts by exact basename — keep these stable.
const templateRootfsFilename = "rootfs.ext4"

// TemplateArtifactPushDocker is the narrow Docker surface the
// TemplateArtifactPusher needs. Mirrors SnapshotPushDocker so test
// fakes look the same; pulled out for the same reason — to avoid
// instantiating a real *docker.Client inside unit tests.
type TemplateArtifactPushDocker interface {
	ImportImage(ctx context.Context, req docker.ImportImageRequest) error
	PushImage(ctx context.Context, req docker.PushImageRequest) (string, error)
	RemoveImage(ctx context.Context, ref string) error
}

// TemplateArtifactPushResult mirrors SnapshotPushResult. RegistryRef is
// what the reconciler writes to firecracker_templates.registry_ref;
// Digest is the OCI manifest digest reported by the daemon's push
// stream `aux` payload (may be empty for older daemons / registries).
type TemplateArtifactPushResult struct {
	RegistryRef string
	Digest      string
}

// TemplateArtifactPusher pushes the three artifact files (rootfs.ext4 +
// snapshot.memory + snapshot.state) plus a manifest.json to AOCR by
// (a) wrapping them in a tar, (b) docker-importing the tar as a local
// image under BuiltImageNamespace, and (c) pushing that image to
// `<host>/cluster/<id>/templates/<tid>:latest`. The local intermediate
// tag is removed on best-effort after the push so the built-image GC
// doesn't have to sweep it later.
//
// Holds no per-template state; instantiate once at boot and reuse.
// Safe for concurrent use; the reconciler invokes PushOnce from
// goroutines under the bounded fanout semaphore.
type TemplateArtifactPusher struct {
	cfg          SnapshotPushConfig
	docker       TemplateArtifactPushDocker
	templatesDir string
	logger       *slog.Logger
}

// NewTemplateArtifactPusher mirrors NewSnapshotPusher: returns nil if
// cfg.Enabled is false so callers can do `if pusher == nil { return }`.
// templatesDir is the absolute path that templateDir(id) was computed
// against in template.go so the pusher can re-derive the artifact paths
// from a Template row alone (the row's path columns are also checked
// for safety).
func NewTemplateArtifactPusher(cfg SnapshotPushConfig, docker TemplateArtifactPushDocker, templatesDir string, logger *slog.Logger) (*TemplateArtifactPusher, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if docker == nil {
		return nil, errors.New("TemplateArtifactPusher: docker is required when SnapshotPushConfig.Enabled=true")
	}
	if strings.TrimSpace(templatesDir) == "" {
		return nil, errors.New("TemplateArtifactPusher: templatesDir is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &TemplateArtifactPusher{
		cfg:          cfg,
		docker:       docker,
		templatesDir: templatesDir,
		logger:       logger,
	}, nil
}

// TemplateArtifactManifest is the JSON the puller in PR 6-B.2 reads to
// reconstruct the Template row on a fresh node. SchemaVersion is the
// forward-compat guard; everything else mirrors what the consumer
// needs to insert the row in status=ready without a second round-trip
// to the origin node.
type TemplateArtifactManifest struct {
	SchemaVersion     int    `json:"schema_version"`
	TemplateID        string `json:"template_id"`
	Image             string `json:"image"`
	RootfsSizeBytes   int64  `json:"rootfs_size_bytes"`
	SnapshotSizeBytes int64  `json:"snapshot_size_bytes"`
	SnapshotChecksum  string `json:"snapshot_checksum"`
	SnapshotVsockCID  uint32 `json:"snapshot_vsock_cid"`
	HasOverlay        bool   `json:"has_overlay"`
	MinSizeMiB        int    `json:"min_size_mib,omitempty"`
}

// PushOnce builds the artifact tar, imports it as a local image, and
// pushes it to AOCR. Returns the canonical ref + manifest digest on
// success. The PAT is read fresh on every call so an operator can
// rotate it without restarting sandboxd — same contract as the
// snapshot pusher.
//
// Failure modes (caller maps each to push_state=error + push_error):
//   - missing artifact file (rootfs.ext4 or snapshot.{memory,state})
//   - read error mid-tar (e.g. disk fault)
//   - docker import failure (daemon down, malformed tar)
//   - docker push failure (registry down, auth rejected)
//
// On any failure the local intermediate tag may or may not exist;
// RemoveImage is benign on 404/409 so the cleanup runs unconditionally.
func (p *TemplateArtifactPusher) PushOnce(ctx context.Context, tpl *models.Template) (TemplateArtifactPushResult, error) {
	if p == nil {
		return TemplateArtifactPushResult{}, errors.New("template push disabled (pusher is nil)")
	}
	if tpl == nil {
		return TemplateArtifactPushResult{}, errors.New("template push: template is required")
	}
	id := strings.TrimSpace(tpl.ID)
	if id == "" {
		return TemplateArtifactPushResult{}, errors.New("template push: template ID is required")
	}

	// Resolve the three artifact paths. Prefer the row's path columns
	// (they survive a FirecrackerTemplatesDir rename), but fall back to
	// the conventional layout under templatesDir when the columns are
	// blank — e.g. a freshly-built row whose snapshot columns the build
	// goroutine just wrote.
	dir := filepath.Join(p.templatesDir, id)
	rootfs := filepath.Join(dir, templateRootfsFilename)
	memPath := strings.TrimSpace(tpl.SnapshotMemoryPath)
	if memPath == "" {
		memPath = filepath.Join(dir, snapshotMemoryFilename)
	}
	statePath := strings.TrimSpace(tpl.SnapshotStatePath)
	if statePath == "" {
		statePath = filepath.Join(dir, snapshotStateFilename)
	}
	rootfsPath := strings.TrimSpace(tpl.RootfsPath)
	if rootfsPath == "" {
		rootfsPath = rootfs
	}

	if err := assertRegularFile(rootfsPath); err != nil {
		return TemplateArtifactPushResult{}, fmt.Errorf("template push: rootfs: %w", err)
	}
	if err := assertRegularFile(memPath); err != nil {
		return TemplateArtifactPushResult{}, fmt.Errorf("template push: snapshot.memory: %w", err)
	}
	if err := assertRegularFile(statePath); err != nil {
		return TemplateArtifactPushResult{}, fmt.Errorf("template push: snapshot.state: %w", err)
	}

	manifest := TemplateArtifactManifest{
		SchemaVersion:     TemplateArtifactSchemaVersion,
		TemplateID:        id,
		Image:             strings.TrimSpace(tpl.Image),
		RootfsSizeBytes:   tpl.RootfsSizeBytes,
		SnapshotSizeBytes: tpl.SnapshotSizeBytes,
		SnapshotChecksum:  tpl.SnapshotChecksum,
		SnapshotVsockCID:  tpl.SnapshotVsockCID,
		HasOverlay:        tpl.HasOverlay,
		MinSizeMiB:        tpl.MinSizeMiB,
	}

	pat, err := readPATFile(p.cfg.PATPath)
	if err != nil {
		return TemplateArtifactPushResult{}, fmt.Errorf("template push: read PAT: %w", err)
	}

	localTag := localTemplateImageTag(id)
	dest := templateAOCRRef(p.cfg.Host, p.cfg.ClusterID, id)

	// Stream the tar through io.Pipe so the rootfs.ext4 (which can be
	// hundreds of MB) never lives in memory all at once. The writer
	// goroutine fans data into the daemon's HTTP body; ImportImage
	// blocks until the daemon finishes reading. If the writer fails
	// (e.g. disk fault mid-rootfs), the pipe closes with an error and
	// ImportImage surfaces it.
	pr, pw := io.Pipe()
	writeErrCh := make(chan error, 1)
	go func() {
		writeErrCh <- writeTemplateArtifactTar(pw, manifest, rootfsPath, memPath, statePath)
	}()

	importErr := p.docker.ImportImage(ctx, docker.ImportImageRequest{
		DestTag: localTag,
		Tar:     pr,
	})
	// Drain the writer goroutine before deciding the outcome — a nil
	// import error with a non-nil writer error means the daemon ate the
	// partial tar but the source is broken; surface the writer error so
	// the operator sees the real cause.
	writeErr := <-writeErrCh

	// Whatever happens next, free the intermediate tag so the
	// built-image GC doesn't have to deal with it. RemoveImage is
	// benign on 404/409.
	cleanupTag := func() {
		// Use a detached context — the parent may already be cancelled
		// from a failure path, but the local-tag removal is a daemon
		// call that should still happen.
		rmCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if rmErr := p.docker.RemoveImage(rmCtx, localTag); rmErr != nil && p.logger != nil {
			p.logger.Warn("template push: cleanup local tag failed",
				"template", id, "tag", localTag, "error", rmErr)
		}
	}

	if importErr != nil {
		cleanupTag()
		return TemplateArtifactPushResult{}, fmt.Errorf("template push: import %s: %w", localTag, importErr)
	}
	if writeErr != nil {
		cleanupTag()
		return TemplateArtifactPushResult{}, fmt.Errorf("template push: build tar: %w", writeErr)
	}

	var digest string
	pushed, err := p.docker.PushImage(ctx, docker.PushImageRequest{
		SourceTag: localTag,
		DestRef:   dest,
		Auth: models.RegistryAuth{
			Server:   p.cfg.Host,
			Username: p.cfg.ClusterID,
			Password: pat,
		},
		OnLog: func(line string) {
			if p.logger != nil {
				p.logger.Debug("template push", "template", id, "dest", dest, "line", line)
			}
		},
		OnDigest: func(d string) {
			digest = d
		},
	})
	cleanupTag()
	if err != nil {
		return TemplateArtifactPushResult{}, fmt.Errorf("template push %s -> %s: %w", localTag, dest, err)
	}
	if strings.TrimSpace(pushed) == "" {
		pushed = dest
	}
	return TemplateArtifactPushResult{RegistryRef: pushed, Digest: digest}, nil
}

// DestRefFor returns the AOCR destination ref this pusher would write
// for the given template ID. Used by the future consumer-side pull
// (PR 6-B.2) to compute the lookup ref without involving the pusher
// instance directly.
func (p *TemplateArtifactPusher) DestRefFor(templateID string) string {
	if p == nil {
		return ""
	}
	id := strings.TrimSpace(templateID)
	if id == "" {
		return ""
	}
	return templateAOCRRef(p.cfg.Host, p.cfg.ClusterID, id)
}

// templateAOCRRef is the AOCR destination convention for cluster-local
// template artifacts: `<host>/cluster/<id>/templates/<tid>:latest`.
// Mirrors snapshotAOCRRef's shape — operators see one ref convention
// across snapshots and templates.
func templateAOCRRef(host, clusterID, templateID string) string {
	host = strings.TrimRight(strings.TrimSpace(host), "/")
	clusterID = strings.TrimSpace(clusterID)
	templateID = strings.ToLower(strings.TrimSpace(templateID))
	archSfx := archTagSuffix(hostSnapshotArch())
	return fmt.Sprintf("%s/cluster/%s/templates/%s:latest%s", host, clusterID, templateID, archSfx)
}

// localTemplateImageTag is the intermediate local tag the imported
// tar lands under. Living inside BuiltImageNamespace means the
// existing built-image GC sweeps it naturally if PushOnce dies between
// import and cleanup — no separate janitor needed.
func localTemplateImageTag(templateID string) string {
	return docker.BuiltImageNamespace + "/tpl-" + strings.ToLower(strings.TrimSpace(templateID)) + ":latest"
}

// TemplateNeedsPush reports whether a template row is a candidate for
// background AOCR push. Only `ready` rows qualify — `unhealthy` is the
// Phase 6 PR-A "snapshot was corrupt at load time" terminal state, and
// pushing a known-corrupt snapshot would just propagate the corruption
// to every peer. The reconciler enforces this defensively too.
func TemplateNeedsPush(tpl *models.Template) bool {
	if tpl == nil {
		return false
	}
	return tpl.Status == models.TemplateStatusReady
}

// writeTemplateArtifactTar streams the four files into a tar. Order is
// (manifest.json, rootfs.ext4, snapshot.memory, snapshot.state); the
// puller in PR 6-B.2 reads manifest.json first to learn schema/sizes,
// then extracts the rest by basename. The tar format is USTAR with
// default mode 0o644 — Docker's import endpoint accepts uncompressed
// tarballs as a single layer.
func writeTemplateArtifactTar(w *io.PipeWriter, manifest TemplateArtifactManifest, rootfs, mem, state string) (rerr error) {
	defer func() {
		// CloseWithError(nil) is the same as Close — the daemon-side
		// reader sees clean EOF. CloseWithError(err) lets the daemon
		// surface the writer's error in its response.
		_ = w.CloseWithError(rerr)
	}()
	tw := tar.NewWriter(w)
	defer func() {
		if cerr := tw.Close(); rerr == nil {
			rerr = cerr
		}
	}()

	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}
	if err := writeTarRegular(tw, templateManifestFilename, int64(len(manifestBytes)), nil, manifestBytes); err != nil {
		return err
	}

	for _, entry := range []struct {
		name string
		path string
	}{
		{templateRootfsFilename, rootfs},
		{snapshotMemoryFilename, mem},
		{snapshotStateFilename, state},
	} {
		if err := writeTarFile(tw, entry.name, entry.path); err != nil {
			return fmt.Errorf("tar %s: %w", entry.name, err)
		}
	}
	return nil
}

// writeTarRegular writes a single in-memory blob as a tar entry. Used
// for manifest.json; large artifacts use writeTarFile so they stream
// from disk.
func writeTarRegular(tw *tar.Writer, name string, size int64, _ io.Reader, blob []byte) error {
	hdr := &tar.Header{
		Name:    name,
		Mode:    0o644,
		Size:    size,
		ModTime: time.Now().UTC(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	if _, err := tw.Write(blob); err != nil {
		return err
	}
	return nil
}

// writeTarFile streams a file from disk into the tar without buffering
// the whole thing in memory — critical for rootfs.ext4 which can be
// hundreds of MB. Stat tells the tar header the exact size up front;
// io.Copy then streams the bytes.
func writeTarFile(tw *tar.Writer, name, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	hdr := &tar.Header{
		Name:    name,
		Mode:    0o644,
		Size:    info.Size(),
		ModTime: info.ModTime().UTC(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	if _, err := io.Copy(tw, f); err != nil {
		return err
	}
	return nil
}

// assertRegularFile is the precondition the pusher checks before
// opening the tar pipe — we'd rather fail with a clear "missing
// artifact" error than half-stream the import and surface a
// confusing daemon-side tar parse error.
func assertRegularFile(path string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("path is empty")
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	return nil
}
