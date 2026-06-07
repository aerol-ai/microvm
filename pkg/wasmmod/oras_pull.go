package wasmmod

import (
	"context"
	"fmt"
	"os"
	"strings"

	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/file"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
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

// PullSnapshotArtifact downloads a §4.8.1 mem.snap directory from AOCR into dstDir.
func PullSnapshotArtifact(ctx context.Context, cfg ORASPullConfig, registryRef, dstDir string) error {
	registryRef = strings.TrimSpace(registryRef)
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

	repo, err := remote.NewRepository(registryRef)
	if err != nil {
		return fmt.Errorf("oras pull: repository: %w", err)
	}
	repoHost := registryHost(registryRef)
	repo.Client = &auth.Client{
		Client:     auth.DefaultClient.Client,
		Cache:      auth.DefaultCache,
		Credential: auth.StaticCredential(repoHost, auth.Credential{Username: cfg.ClusterID, Password: pat}),
	}

	tag := registryTag(registryRef)
	if _, err := repo.Resolve(ctx, tag); err != nil {
		return fmt.Errorf("oras pull resolve %s: %w", registryRef, err)
	}

	if _, err := oras.Copy(ctx, repo, tag, fs, tag, oras.DefaultCopyOptions); err != nil {
		return fmt.Errorf("oras pull copy from %s: %w", registryRef, err)
	}

	// file.Store unpacks named layers into dstDir; verify the artifact shape.
	if !snapshotDirExists(dstDir) {
		return fmt.Errorf("oras pull: unpacked artifact missing config.json in %s", dstDir)
	}
	return nil
}
