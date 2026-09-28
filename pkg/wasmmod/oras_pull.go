package wasmmod

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/file"
)

// ORASPullConfig wires AOCR auth for WASM checkpoint pull (failover-from-snapshot).
type ORASPullConfig struct {
	Host      string
	ClusterID string
	PATPath   string
}

// Validate enforces required fields when pull is requested.
func (c ORASPullConfig) Validate() error {
	if strings.TrimSpace(c.Host) == "" {
		return fmt.Errorf("oras pull: Host required")
	}
	if strings.TrimSpace(c.ClusterID) == "" {
		return fmt.Errorf("oras pull: ClusterID required")
	}
	if strings.TrimSpace(c.PATPath) == "" {
		return fmt.Errorf("oras pull: PATPath required")
	}
	return nil
}

// PullSnapshotArtifact downloads a §4.8.1 mem.snap directory from AOCR into
// dstDir, refusing a checkpoint that another sandbox lifetime published.
//
// incarnationID is the lifetime the caller is restoring. A manifest that names
// a different lifetime is rejected with ErrCheckpointLifetimeMismatch. One that
// names none predates the binding and is accepted: it can only be reached
// through a ref the lifetime's own row recorded, because every fallback now
// resolves a lifetime-scoped tag that only annotated pushes write.
func PullSnapshotArtifact(ctx context.Context, cfg ORASPullConfig, registryRef, incarnationID, dstDir string) error {
	registryRef = strings.TrimSpace(registryRef)
	incarnationID = strings.TrimSpace(incarnationID)
	dstDir = strings.TrimSpace(dstDir)
	if registryRef == "" || dstDir == "" {
		return fmt.Errorf("oras pull: registry ref and destination dir required")
	}
	if err := cfg.Validate(); err != nil {
		return err
	}

	pat, err := readPATFile(cfg.PATPath)
	if err != nil {
		return fmt.Errorf("oras pull: read PAT: %w", err)
	}

	if err := os.MkdirAll(dstDir, 0o700); err != nil {
		return err
	}

	fs, err := file.New(dstDir)
	if err != nil {
		return fmt.Errorf("oras pull: file store: %w", err)
	}
	defer fs.Close()

	repo, err := newAuthedRepo(registryRef, cfg.ClusterID, pat)
	if err != nil {
		return err
	}

	tag := registryTag(registryRef)
	desc, manifestBytes, err := oras.FetchBytes(ctx, repo, tag, oras.DefaultFetchBytesOptions)
	if err != nil {
		return fmt.Errorf("oras pull resolve %s: %w", registryRef, err)
	}
	var manifest ocispec.Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return fmt.Errorf("oras pull decode manifest %s: %w", registryRef, err)
	}
	if owner := strings.TrimSpace(manifest.Annotations[WasmCheckpointIncarnationAnnotation]); owner != "" && owner != incarnationID {
		return fmt.Errorf("%w: %s was published by lifetime %s, restoring %s",
			ErrCheckpointLifetimeMismatch, registryRef, owner, incarnationID)
	}

	// Copy the manifest that was just VERIFIED, by digest. Copying by tag would
	// resolve it a second time, and a tag that moved in between would restore
	// a checkpoint nobody checked.
	if _, err := oras.Copy(ctx, repo, desc.Digest.String(), fs, tag, oras.DefaultCopyOptions); err != nil {
		return fmt.Errorf("oras pull copy from %s: %w", registryRef, err)
	}

	// file.Store unpacks named layers into dstDir; verify the artifact shape.
	if !snapshotDirExists(dstDir) {
		return fmt.Errorf("oras pull: unpacked artifact missing config.json in %s", dstDir)
	}
	return nil
}
