package wasmmod

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
)

// DeleteSnapshotRef removes a tagged WASM checkpoint manifest from AOCR.
// Missing refs are treated as success so SQLite prune can proceed after manual cleanup.
func DeleteSnapshotRef(ctx context.Context, cfg ORASPushConfig, registryRef string) error {
	registryRef = strings.TrimSpace(registryRef)
	if registryRef == "" {
		return fmt.Errorf("oras delete: registry ref required")
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	pat, err := readPATFile(cfg.PATPath)
	if err != nil {
		return fmt.Errorf("oras delete: read PAT: %w", err)
	}
	repo, err := remote.NewRepository(registryRef)
	if err != nil {
		return fmt.Errorf("oras delete: repository: %w", err)
	}
	repoHost := registryHost(registryRef)
	repo.PlainHTTP = registryPlainHTTP(repoHost)
	repo.Client = &auth.Client{
		Client:     auth.DefaultClient.Client,
		Cache:      auth.DefaultCache,
		Credential: auth.StaticCredential(repoHost, auth.Credential{Username: cfg.ClusterID, Password: pat}),
	}
	tag := registryTag(registryRef)
	desc, err := repo.Resolve(ctx, tag)
	if err != nil {
		// A ref that is already gone is the success state for a delete: the
		// caller (checkpoint cleanup / orphan-ref GC) only wants the manifest
		// absent, and it may have been removed by a prior partial run or manual
		// cleanup. Swallowing not-found here is what lets the caller safely drop
		// its tracking row — otherwise an already-deleted ref would look like a
		// permanent failure and the row would leak forever.
		if errors.Is(err, errdef.ErrNotFound) {
			return nil
		}
		return fmt.Errorf("oras delete resolve %s: %w", registryRef, err)
	}
	if err := repo.Delete(ctx, desc); err != nil {
		if errors.Is(err, errdef.ErrNotFound) {
			return nil
		}
		return fmt.Errorf("oras delete %s: %w", registryRef, err)
	}
	return nil
}
