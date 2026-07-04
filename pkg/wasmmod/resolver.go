package wasmmod

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
)

// Resolver maps a module reference to a local .wasm path under modulesDir.
type Resolver struct {
	ModulesDir string
	// DigestMode controls per-resolve hashing: once (default) or always.
	DigestMode string
	cache      *digestCache
}

// NewResolver constructs a resolver. modulesDir is the host cache root
// (SB_WASM_MODULES_DIR).
func NewResolver(modulesDir string) *Resolver {
	return &Resolver{
		ModulesDir: modulesDir,
		DigestMode: moduleDigestModeOnce,
		cache:      newDigestCache(moduleDigestModeOnce),
	}
}

// SetDigestMode switches verify-once vs always-hash behavior (SB_WASM_MODULE_DIGEST_MODE).
func (r *Resolver) SetDigestMode(mode string) {
	if r == nil {
		return
	}
	r.DigestMode = mode
	r.cache = newDigestCache(mode)
}

// Resolve turns ref into a local file path. Phase 2 accepts:
//   - absolute paths to .wasm files
//   - file:// URLs
//   - bare filenames or relative paths under modulesDir
func (r *Resolver) Resolve(_ context.Context, ref string) (*ResolvedModule, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, fmt.Errorf("module ref is required")
	}
	path, err := r.resolvePath(ref)
	if err != nil {
		return nil, err
	}
	if err := ValidateFile(path); err != nil {
		return nil, err
	}
	digest, size, err := r.digestFor(path)
	if err != nil {
		return nil, err
	}
	return &ResolvedModule{
		Ref:       ref,
		Path:      path,
		Digest:    digest,
		SizeBytes: size,
	}, nil
}

func (r *Resolver) resolvePath(ref string) (string, error) {
	if strings.HasPrefix(ref, "file://") {
		ref = strings.TrimPrefix(ref, "file://")
	}
	if filepath.IsAbs(ref) {
		return ref, nil
	}
	if r.ModulesDir == "" {
		return "", fmt.Errorf("relative module ref %q requires modules dir", ref)
	}
	return filepath.Join(r.ModulesDir, ref), nil
}

func (r *Resolver) digestFor(path string) (hexDigest string, size int64, err error) {
	if r != nil && r.cache != nil {
		return r.cache.digestFor(path)
	}
	return fileDigest(path)
}

// InvalidateDigestCache drops verify-once entries for path after module delete/replace.
func (r *Resolver) InvalidateDigestCache(path string) {
	if r != nil && r.cache != nil {
		r.cache.dropPath(path)
	}
}
