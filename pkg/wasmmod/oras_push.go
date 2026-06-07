// Package wasmmod — AOCR push for §4.8.1 WASM snapshot artifacts (D2).
package wasmmod

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/file"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
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

// WasmCheckpointRef is the AOCR destination for a durable WASM checkpoint.
func WasmCheckpointRef(host, clusterID, sandboxID string) string {
	host = strings.TrimRight(strings.TrimSpace(host), "/")
	clusterID = strings.TrimSpace(clusterID)
	sandboxID = strings.ToLower(strings.TrimSpace(sandboxID))
	return fmt.Sprintf("%s/cluster/%s/wasm-checkpoints/%s:latest", host, clusterID, sandboxID)
}

// PushSnapshotArtifact uploads a local mem.snap directory to an OCI registry.
func PushSnapshotArtifact(ctx context.Context, cfg ORASPushConfig, memSnapDir, registryRef string) (digest string, err error) {
	memSnapDir = strings.TrimSpace(memSnapDir)
	registryRef = strings.TrimSpace(registryRef)
	if memSnapDir == "" || registryRef == "" {
		return "", fmt.Errorf("oras push: mem.snap dir and registry ref required")
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
	})
	if err != nil {
		return "", fmt.Errorf("oras push: pack manifest: %w", err)
	}

	repo, err := remote.NewRepository(registryRef)
	if err != nil {
		return "", fmt.Errorf("oras push: repository: %w", err)
	}
	repoHost := registryHost(registryRef)
	repo.Client = &auth.Client{
		Client:     auth.DefaultClient.Client,
		Cache:      auth.DefaultCache,
		Credential: auth.StaticCredential(repoHost, auth.Credential{Username: cfg.ClusterID, Password: pat}),
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

func registryTag(ref string) string {
	if i := strings.LastIndex(ref, ":"); i >= 0 && i < len(ref)-1 {
		return ref[i+1:]
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
