package facadeutil

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestTranslateWasmCreateLabelKeyFallbacks(t *testing.T) {
	req, ok, err := TranslateWasmCreate(context.Background(), nil, "", map[string]string{
		"aerol.runtime":    models.RuntimeWasm,
		"aerol.module_ref": "file:///tmp/aerol-label.wasm",
	})
	if err != nil || !ok || req.ModuleRef != "file:///tmp/aerol-label.wasm" {
		t.Fatalf("aerol labels: req=%+v ok=%v err=%v", req, ok, err)
	}

	req, ok, err = TranslateWasmCreate(context.Background(), nil, "", map[string]string{
		"runtime": models.RuntimeWasm,
		"image":   "file:///tmp/image-label.wasm",
	})
	if err != nil || !ok || req.ModuleRef != "file:///tmp/image-label.wasm" {
		t.Fatalf("image label: req=%+v ok=%v err=%v", req, ok, err)
	}
}

func TestTranslateWasmCreateMissingModuleRefCoverage95(t *testing.T) {
	_, _, err := TranslateWasmCreate(context.Background(), nil, "", map[string]string{
		"runtime": models.RuntimeWasm,
	})
	if err == nil || !strings.Contains(err.Error(), "module_ref") {
		t.Fatalf("err = %v, want module_ref requirement", err)
	}
}

func TestTranslateWasmCreateRuntimeNotImplementedFallsThrough(t *testing.T) {
	get := fakeWasmModuleGetter{err: models.ErrRuntimeNotImplemented}
	req, ok, err := TranslateWasmCreate(context.Background(), get, "mod-1", map[string]string{
		"runtime":    models.RuntimeWasm,
		"module_ref": "file:///tmp/fallback.wasm",
	})
	if err != nil || !ok || req.ModuleRef != "file:///tmp/fallback.wasm" {
		t.Fatalf("fallback after ErrRuntimeNotImplemented: req=%+v ok=%v err=%v", req, ok, err)
	}
}

func TestTranslateWasmCreateEmptyCatalogueIDSkipsGetter(t *testing.T) {
	get := fakeWasmModuleGetter{err: errors.New("should not be called")}
	_, ok, err := TranslateWasmCreate(context.Background(), get, "   ", map[string]string{
		"runtime": "docker",
	})
	if err != nil || ok {
		t.Fatalf("docker runtime: ok=%v err=%v", ok, err)
	}
}

// Ensure store.ErrNotFound still falls through to labels (regression guard).
func TestTranslateWasmCreateGetterNotFoundUsesLabels(t *testing.T) {
	get := fakeWasmModuleGetter{err: store.ErrNotFound}
	req, ok, err := TranslateWasmCreate(context.Background(), get, "missing-id", map[string]string{
		"aerol.runtime":    models.RuntimeWasm,
		"aerol.module_ref": "file:///tmp/not-found-fallback.wasm",
	})
	if err != nil || !ok || req.ModuleRef != "file:///tmp/not-found-fallback.wasm" {
		t.Fatalf("req=%+v ok=%v err=%v", req, ok, err)
	}
}
