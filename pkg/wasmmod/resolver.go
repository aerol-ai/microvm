package wasmmod

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Resolver maps a module reference to a local .wasm path under modulesDir.
type Resolver struct {
	ModulesDir string
}

// NewResolver constructs a resolver. modulesDir is the host cache root
// (SB_WASM_MODULES_DIR).
func NewResolver(modulesDir string) *Resolver {
	return &Resolver{ModulesDir: modulesDir}
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
	digest, size, err := fileDigest(path)
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

func fileDigest(path string) (hexDigest string, size int64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}
