package wasm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aerol-ai/microvm/pkg/models"
)

// RemoveImage deletes a module artifact from the host cache. imageRef may be a
// module ref (file://, relative under ModulesDir, or absolute path) or a bare
// digest hex string. Missing paths are treated as success (idempotent GC).
func (d *Driver) RemoveImage(ctx context.Context, imageRef string) error {
	if d == nil {
		return fmt.Errorf("wasm runtime: driver is nil")
	}
	if d.resolver == nil {
		return fmt.Errorf("wasm runtime: module resolver not configured: %w", models.ErrRuntimeNotImplemented)
	}
	ref := strings.TrimSpace(imageRef)
	if ref == "" {
		return fmt.Errorf("wasm runtime: module ref is required")
	}

	var paths []string
	if looksLikeDigest(ref) {
		if d.cfg.ModulesDir != "" {
			paths = append(paths, filepath.Join(d.cfg.ModulesDir, ref))
		}
		if d.warmPool != nil {
			if dropper, ok := d.warmPool.(warmPoolDropper); ok {
				dropper.DropModule(ref)
			}
		}
	} else {
		resolved, err := d.resolver.Resolve(ctx, ref)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return fmt.Errorf("resolve module %q: %w", ref, err)
		}
		paths = append(paths, resolved.Path)
		if resolved.Digest != "" && d.warmPool != nil {
			if dropper, ok := d.warmPool.(warmPoolDropper); ok {
				dropper.DropModule(resolved.Digest)
			}
		}
		if !pathUnderDir(d.cfg.ModulesDir, resolved.Path) {
			paths = paths[:len(paths)-1]
		}
	}

	for _, path := range paths {
		if path == "" {
			continue
		}
		if !pathUnderDir(d.cfg.ModulesDir, path) {
			continue
		}
		if err := os.RemoveAll(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove module artifact %q: %w", path, err)
		}
	}
	return nil
}

func looksLikeDigest(ref string) bool {
	if len(ref) != 64 {
		return false
	}
	for _, c := range ref {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

func pathUnderDir(root, path string) bool {
	root = strings.TrimSpace(root)
	path = strings.TrimSpace(path)
	if root == "" || path == "" {
		return false
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	pathAbs, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(rootAbs, pathAbs)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && !filepath.IsAbs(rel))
}

type warmPoolDropper interface {
	DropModule(digest string)
}
