package jsbundle

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// jsSourceExtensions are the entrypoint extensions BuildFromFile accepts.
var jsSourceExtensions = map[string]bool{
	".js": true, ".mjs": true, ".ts": true,
}

// BuildFromFile turns a single JS/TS entrypoint file into a one-module bundle.
// This is the Phase-2 hot-path default: operators point module_ref at a .js
// file and it becomes the bundle verbatim (no transpile step — workerd runs
// modern JS and TS type-strips at load with the right compatibility flags).
// Multi-module / import-following builds (esbuild, §13 Q2) are a later seam;
// the single-file path covers the "AI-generated JS tool" and "webhook
// transform" use cases that motivate the tier without a build toolchain on the
// host.
func BuildFromFile(path string) (*Bundle, error) {
	ext := strings.ToLower(filepath.Ext(path))
	if !jsSourceExtensions[ext] {
		return nil, fmt.Errorf("%w: %q is not a .js/.mjs/.ts entrypoint", ErrUnsupportedRef, path)
	}
	src, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", ErrBundleNotFound, path)
		}
		return nil, fmt.Errorf("jsbundle: read entrypoint: %w", err)
	}
	name := filepath.Base(path)
	b := &Bundle{
		MainModule:        name,
		Modules:           map[string]string{name: string(src)},
		CompatibilityDate: DefaultCompatibilityDate,
	}
	if err := b.Validate(); err != nil {
		return nil, err
	}
	if _, err := b.ComputeDigest(); err != nil {
		return nil, err
	}
	return b, nil
}

// BuildFromSource turns inline entry-module source into a one-module bundle
// (the /v1/js-bundles push path and tests). name defaults to DefaultMainModule
// when empty; compatDate defaults to DefaultCompatibilityDate.
func BuildFromSource(name, source, compatDate string) (*Bundle, error) {
	if name == "" {
		name = DefaultMainModule
	}
	if compatDate == "" {
		compatDate = DefaultCompatibilityDate
	}
	b := &Bundle{
		MainModule:        name,
		Modules:           map[string]string{name: source},
		CompatibilityDate: compatDate,
	}
	if err := b.Validate(); err != nil {
		return nil, err
	}
	if _, err := b.ComputeDigest(); err != nil {
		return nil, err
	}
	return b, nil
}
