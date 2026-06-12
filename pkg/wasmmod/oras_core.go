package wasmmod

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/file"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
)

// Shared ORAS transport. Both the checkpoint artifacts (oras_push.go /
// oras_pull.go) and the BYO module artifacts (below) ride this one auth +
// remote-repository setup so there is a single place to maintain AOCR
// credential handling, host parsing, and error classification.

// moduleArtifactType / moduleLayerMediaType describe a single-layer .wasm
// artifact. Distinct from the snapshot artifact type so AOCR + tooling can
// tell a module from a checkpoint.
const (
	moduleArtifactType   = "application/vnd.aerolvm.wasm-module.v1"
	moduleLayerMediaType = "application/wasm"
	// moduleLayerName is the file name the layer unpacks to on pull.
	moduleLayerName = "module.wasm"
)

// newAuthedRepo builds an AOCR-authenticated remote repository for registryRef.
// username is the registry login (cluster id for checkpoints, tenant id for
// modules); pat is the already-read token. Single source of truth for the
// auth.Client wiring.
func newAuthedRepo(registryRef, username, pat string) (*remote.Repository, error) {
	repo, err := remote.NewRepository(registryRef)
	if err != nil {
		return nil, fmt.Errorf("oras: repository %q: %w", registryRef, err)
	}
	host := registryHost(registryRef)
	repo.Client = &auth.Client{
		Client:     auth.DefaultClient.Client,
		Cache:      auth.DefaultCache,
		Credential: auth.StaticCredential(host, auth.Credential{Username: username, Password: pat}),
	}
	return repo, nil
}

// ModuleAuth carries the registry credentials for a BYO module pull/push.
// Username is the AOCR login.
//
// Two credential sources, by design:
//   - PAT: an inline token. This is the PER-TENANT path — the token rides the
//     create/push request (req.Registry.Password) and is never persisted in
//     plaintext. Thousands of tenants each supply their own; nothing is
//     configured globally.
//   - PATPath: a token file. This is the SYSTEM path — the operator's identity
//     for pulling the curated standard modules. Set once, re-read each call so
//     rotation needs no restart.
//
// PAT wins when both are set.
type ModuleAuth struct {
	Username string
	PAT      string
	PATPath  string
}

// token resolves the effective credential: the inline per-tenant PAT if
// present, else the system token file.
func (a ModuleAuth) token() (string, error) {
	if strings.TrimSpace(a.PAT) != "" {
		return strings.TrimSpace(a.PAT), nil
	}
	if strings.TrimSpace(a.PATPath) == "" {
		return "", fmt.Errorf("no registry credential: neither inline token nor PAT file set")
	}
	return readPATFile(a.PATPath)
}

// PushModuleArtifact uploads a single local .wasm file to registryRef as a
// one-layer OCI artifact. Returns the manifest digest. wasmPath must already
// be a validated core module (caller runs ValidateFile).
func PushModuleArtifact(ctx context.Context, a ModuleAuth, wasmPath, registryRef string) (digest string, err error) {
	wasmPath = strings.TrimSpace(wasmPath)
	registryRef = strings.TrimSpace(registryRef)
	if wasmPath == "" || registryRef == "" {
		return "", fmt.Errorf("oras push module: wasm path and registry ref required")
	}
	pat, err := a.token()
	if err != nil {
		return "", fmt.Errorf("oras push module: %w", err)
	}

	staging, err := os.MkdirTemp("", "aerol-wasm-module-push-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(staging)

	fs, err := file.New(staging)
	if err != nil {
		return "", fmt.Errorf("oras push module: file store: %w", err)
	}
	defer fs.Close()

	layerDesc, err := fs.Add(ctx, moduleLayerName, moduleLayerMediaType, wasmPath)
	if err != nil {
		return "", fmt.Errorf("oras push module: add layer: %w", err)
	}
	manifestDesc, err := oras.PackManifest(ctx, fs, oras.PackManifestVersion1_1, moduleArtifactType, oras.PackManifestOptions{
		Layers: []ocispec.Descriptor{layerDesc},
	})
	if err != nil {
		return "", fmt.Errorf("oras push module: pack manifest: %w", err)
	}

	repo, err := newAuthedRepo(registryRef, a.Username, pat)
	if err != nil {
		return "", err
	}
	tag := registryTag(registryRef)
	if err := fs.Tag(ctx, manifestDesc, tag); err != nil {
		return "", fmt.Errorf("oras push module: tag: %w", err)
	}
	if _, err := oras.Copy(ctx, fs, tag, repo, tag, oras.DefaultCopyOptions); err != nil {
		return "", fmt.Errorf("oras push module: copy to %s: %w", registryRef, classifyRegistryErr(err))
	}
	return manifestDesc.Digest.String(), nil
}

// PullModuleArtifact downloads a single-layer .wasm artifact from registryRef
// into dstDir and returns the unpacked file path. The caller is responsible
// for validation (ValidateFile) and content-addressed publishing — this
// function only does the transport. dstDir should be a caller-owned temp dir.
//
// maxBytes (>0) bounds the download: the manifest is resolved and its layer
// sizes summed BEFORE any layer blob is fetched, so an oversized artifact is
// rejected without buffering it. This is the DoS/SSRF size guard — a malicious
// registry cannot make us pull an unbounded body.
func PullModuleArtifact(ctx context.Context, a ModuleAuth, registryRef, dstDir string, maxBytes int64) (wasmPath string, err error) {
	registryRef = strings.TrimSpace(registryRef)
	dstDir = strings.TrimSpace(dstDir)
	if registryRef == "" || dstDir == "" {
		return "", fmt.Errorf("oras pull module: registry ref and dst dir required")
	}
	pat, err := a.token()
	if err != nil {
		return "", fmt.Errorf("oras pull module: %w", err)
	}
	if err := os.MkdirAll(dstDir, 0o700); err != nil {
		return "", err
	}

	fs, err := file.New(dstDir)
	if err != nil {
		return "", fmt.Errorf("oras pull module: file store: %w", err)
	}
	defer fs.Close()

	repo, err := newAuthedRepo(registryRef, a.Username, pat)
	if err != nil {
		return "", err
	}
	tag := registryTag(registryRef)

	// Size preflight: resolve + fetch the manifest, sum layer sizes, reject
	// before downloading blobs.
	if maxBytes > 0 {
		manifestDesc, rErr := repo.Resolve(ctx, tag)
		if rErr != nil {
			return "", fmt.Errorf("oras pull module: resolve %s: %w", registryRef, classifyRegistryErr(rErr))
		}
		manifestBytes, fErr := content.FetchAll(ctx, repo, manifestDesc)
		if fErr != nil {
			return "", fmt.Errorf("oras pull module: fetch manifest: %w", classifyRegistryErr(fErr))
		}
		var man ocispec.Manifest
		if jErr := json.Unmarshal(manifestBytes, &man); jErr != nil {
			return "", fmt.Errorf("oras pull module: parse manifest: %w", jErr)
		}
		var total int64
		for _, l := range man.Layers {
			total += l.Size
		}
		if total > maxBytes {
			return "", fmt.Errorf("%w: artifact layers %d bytes > cap %d", ErrModuleTooLarge, total, maxBytes)
		}
	}

	if _, err := oras.Copy(ctx, repo, tag, fs, tag, oras.DefaultCopyOptions); err != nil {
		return "", fmt.Errorf("oras pull module: copy from %s: %w", registryRef, classifyRegistryErr(err))
	}
	out := filepath.Join(dstDir, moduleLayerName)
	if st, statErr := os.Stat(out); statErr != nil || st.IsDir() {
		return "", fmt.Errorf("oras pull module: unpacked artifact missing %s in %s", moduleLayerName, dstDir)
	}
	return out, nil
}

// classifyRegistryErr maps an ORAS/registry transport error onto the typed
// taxonomy so the service can pick the right HTTP status. Auth failures are
// terminal; everything else network-ish is retryable.
func classifyRegistryErr(err error) error {
	if err == nil {
		return nil
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "unauthorized") || strings.Contains(msg, "401") ||
		strings.Contains(msg, "forbidden") || strings.Contains(msg, "403") ||
		strings.Contains(msg, "credential") || strings.Contains(msg, "denied"):
		return fmt.Errorf("%w: %v", ErrRegistryAuth, err)
	default:
		return fmt.Errorf("%w: %v", ErrRegistryUnavailable, err)
	}
}
