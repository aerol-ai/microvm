// Package wasmmod — AOCR push for §4.8.1 WASM snapshot artifacts (D2).
package wasmmod

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/file"
)

var snapshotLayerMediaTypes = map[string]string{
	"config.json":     "application/vnd.aerolvm.wasm-snapshot.v1+json",
	"memory.zstd":     "application/vnd.aerolvm.wasm-snapshot.v1.memory.zstd",
	"globals.cbor":    "application/vnd.aerolvm.wasm-snapshot.v1.globals.cbor",
	"wasi-state.cbor": "application/vnd.aerolvm.wasm-snapshot.v1.wasi-state.cbor",
}

const wasmSnapshotArtifactType = "application/vnd.aerolvm.wasm-snapshot.v1"

// ORASPushConfig wires AOCR auth for WASM checkpoint push. Mirrors the
// snapshot-push PAT file semantics: token is re-read on every call.
type ORASPushConfig struct {
	Host      string
	ClusterID string
	PATPath   string
}

// Validate enforces required fields when push is requested.
func (c ORASPushConfig) Validate() error {
	if strings.TrimSpace(c.Host) == "" {
		return fmt.Errorf("oras push: Host required")
	}
	if strings.TrimSpace(c.ClusterID) == "" {
		return fmt.Errorf("oras push: ClusterID required")
	}
	if strings.TrimSpace(c.PATPath) == "" {
		return fmt.Errorf("oras push: PATPath required")
	}
	return nil
}

// WasmCheckpointRef is the AOCR destination for a durable WASM checkpoint (:latest).
func WasmCheckpointRef(host, clusterID, sandboxID string) string {
	return WasmCheckpointRefTagged(host, clusterID, sandboxID, "latest")
}

// WasmCheckpointRefTagged builds an AOCR ref with an explicit tag (digest or latest).
func WasmCheckpointRefTagged(host, clusterID, sandboxID, tag string) string {
	host = strings.TrimRight(strings.TrimSpace(host), "/")
	clusterID = strings.TrimSpace(clusterID)
	sandboxID = strings.ToLower(strings.TrimSpace(sandboxID))
	tag = strings.TrimSpace(tag)
	if tag == "" {
		tag = "latest"
	}
	return fmt.Sprintf("%s/cluster/%s/wasm-checkpoints/%s:%s", host, clusterID, sandboxID, tag)
}

// WasmCheckpointIncarnationAnnotation carries, on every checkpoint manifest,
// the sandbox LIFETIME that published it. It is the artifact's identity: a pull
// verifies it against the lifetime it expects, and because it differs per
// lifetime it also makes every lifetime's manifests distinct, so deleting one
// lifetime's manifest can never take another lifetime's tag with it.
const WasmCheckpointIncarnationAnnotation = "com.aerol.wasm-checkpoint.incarnation"

// ErrCheckpointLifetimeMismatch reports a checkpoint published by a different
// sandbox lifetime than the one restoring it. Restoring it would hand the
// current sandbox another lifetime's memory.
var ErrCheckpointLifetimeMismatch = errors.New("wasm checkpoint belongs to a different sandbox lifetime")

// WasmCheckpointLifetimeKey is the tag-safe name for one sandbox lifetime.
//
// Checkpoint tags used to be keyed by sandbox ID alone, and every push wrote the
// shared :latest. A sandbox ID outlives its lifetimes — destroy and re-create
// keeps it — while a checkpoint push runs detached for minutes, so a dead
// lifetime's late push re-pointed the tag the live one depended on. A fenced
// metadata write afterwards cannot undo a registry write. Scoping every tag to
// the lifetime means no other lifetime can ever move a tag this one resolves.
//
// A hash rather than the raw id: incarnation ids are 64 hex characters, and an
// OCI tag allows 128, which a digest suffix alone nearly fills. 128 bits of
// sha256 cannot collide between lifetimes of one sandbox.
func WasmCheckpointLifetimeKey(incarnationID string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(incarnationID)))
	return hex.EncodeToString(sum[:16])
}

// WasmCheckpointLatestTag is one lifetime's rolling pointer to its most recent
// checkpoint. Only that lifetime's pushes ever write it.
func WasmCheckpointLatestTag(incarnationID string) string {
	return WasmCheckpointLifetimeKey(incarnationID) + "-latest"
}

// WasmCheckpointLifetimeDigestTag is one lifetime's immutable, content-addressed
// tag for a single checkpoint.
func WasmCheckpointLifetimeDigestTag(incarnationID, digest string) string {
	return WasmCheckpointLifetimeKey(incarnationID) + "-" + WasmCheckpointDigestTag(digest)
}

// WasmCheckpointDigestTag normalizes a manifest digest for use as an OCI tag.
func WasmCheckpointDigestTag(digest string) string {
	digest = strings.TrimSpace(digest)
	digest = strings.TrimPrefix(digest, "sha256:")
	if digest == "" {
		return "latest"
	}
	if len(digest) > 64 {
		return digest[:64]
	}
	return digest
}

// PushSnapshotArtifact uploads a local mem.snap directory to an OCI registry,
// as a manifest bound to the sandbox lifetime that produced it.
func PushSnapshotArtifact(ctx context.Context, cfg ORASPushConfig, memSnapDir, registryRef, incarnationID string) (digest string, err error) {
	memSnapDir = strings.TrimSpace(memSnapDir)
	registryRef = strings.TrimSpace(registryRef)
	incarnationID = strings.TrimSpace(incarnationID)
	if memSnapDir == "" || registryRef == "" {
		return "", fmt.Errorf("oras push: mem.snap dir and registry ref required")
	}
	if incarnationID == "" {
		// An unbound checkpoint could be restored into any lifetime of this
		// sandbox id, which is exactly what the binding exists to prevent.
		return "", fmt.Errorf("oras push: sandbox lifetime (incarnation) required")
	}
	if err := cfg.Validate(); err != nil {
		return "", err
	}
	if !snapshotDirExists(memSnapDir) {
		return "", fmt.Errorf("oras push: mem.snap directory missing config.json")
	}

	pat, err := readPATFile(cfg.PATPath)
	if err != nil {
		return "", fmt.Errorf("oras push: read PAT: %w", err)
	}

	staging, err := os.MkdirTemp("", "aerol-wasm-oras-push-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(staging)

	fs, err := file.New(staging)
	if err != nil {
		return "", fmt.Errorf("oras push: file store: %w", err)
	}
	defer fs.Close()

	configPath := filepath.Join(memSnapDir, "config.json")
	configDesc, err := fs.Add(ctx, "config.json", snapshotLayerMediaTypes["config.json"], configPath)
	if err != nil {
		return "", fmt.Errorf("oras push: add config: %w", err)
	}

	layerNames := []string{"memory.zstd", "globals.cbor", "wasi-state.cbor"}
	layers := make([]ocispec.Descriptor, 0, len(layerNames))
	for _, name := range layerNames {
		desc, err := fs.Add(ctx, name, snapshotLayerMediaTypes[name], filepath.Join(memSnapDir, name))
		if err != nil {
			return "", fmt.Errorf("oras push: add layer %s: %w", name, err)
		}
		layers = append(layers, desc)
	}

	manifestDesc, err := oras.PackManifest(ctx, fs, oras.PackManifestVersion1_1, wasmSnapshotArtifactType, oras.PackManifestOptions{
		ConfigDescriptor: &configDesc,
		Layers:           layers,
		ManifestAnnotations: map[string]string{
			WasmCheckpointIncarnationAnnotation: incarnationID,
			// Nanosecond creation stamp: oras would stamp whole seconds, and two
			// identical snapshots pushed in the same second would then share a
			// manifest — deleting one push's tag would delete the other's.
			// Every push gets a manifest of its own.
			ocispec.AnnotationCreated: time.Now().UTC().Format(time.RFC3339Nano),
		},
	})
	if err != nil {
		return "", fmt.Errorf("oras push: pack manifest: %w", err)
	}

	repo, err := newAuthedRepo(registryRef, cfg.ClusterID, pat)
	if err != nil {
		return "", err
	}

	tag := registryTag(registryRef)
	if err := fs.Tag(ctx, manifestDesc, tag); err != nil {
		return "", fmt.Errorf("oras push tag manifest: %w", err)
	}
	if _, err := oras.Copy(ctx, fs, tag, repo, tag, oras.DefaultCopyOptions); err != nil {
		return "", fmt.Errorf("oras push copy to %s: %w", registryRef, err)
	}
	return manifestDesc.Digest.String(), nil
}

func registryHost(ref string) string {
	ref = strings.TrimSpace(ref)
	if i := strings.Index(ref, "/"); i > 0 {
		return ref[:i]
	}
	return ref
}

// registryTag returns the tag or digest portion of a registry ref. The host
// (and any :port on it) is stripped first so "host:port/repo" no longer parses
// the port colon as a tag, and a "host/repo@sha256:<digest>" pin resolves to
// the digest reference rather than treating the last colon as a tag delimiter
// (codex P2). Used by push (always a tag) and pull/resolve (tag OR digest).
func registryTag(ref string) string {
	ref = strings.TrimSpace(ref)
	rest := ref
	if i := strings.Index(ref, "/"); i >= 0 {
		rest = ref[i+1:]
	}
	// A digest pin (repo@sha256:<hex>) wins over tag parsing.
	if i := strings.Index(rest, "@"); i >= 0 && i < len(rest)-1 {
		return rest[i+1:]
	}
	if i := strings.LastIndex(rest, ":"); i >= 0 && i < len(rest)-1 {
		return rest[i+1:]
	}
	return "latest"
}

func snapshotDirExists(dir string) bool {
	st, err := os.Stat(filepath.Join(dir, "config.json"))
	return err == nil && !st.IsDir()
}

func readPATFile(path string) (string, error) {
	raw, err := os.ReadFile(strings.TrimSpace(path))
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", fmt.Errorf("PAT file is empty")
	}
	return token, nil
}
