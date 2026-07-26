package facadeutil

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

type fakeWasmModuleGetter struct {
	mod *models.WasmModule
	err error
}

func (f fakeWasmModuleGetter) GetWasmModule(_ context.Context, _ string) (*models.WasmModule, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.mod, nil
}

func TestTranslateWasmCreateFromCatalogue(t *testing.T) {
	get := fakeWasmModuleGetter{
		mod: &models.WasmModule{
			ID:        "mod-1",
			ModuleRef: "file:///tmp/demo.wasm",
			Status:    models.WasmModuleStatusReady,
		},
	}
	req, ok, err := TranslateWasmCreate(context.Background(), get, "mod-1", nil)
	if err != nil {
		t.Fatalf("TranslateWasmCreate: %v", err)
	}
	if !ok {
		t.Fatal("expected ok")
	}
	if req.Runtime != models.RuntimeWasm || req.ModuleRef != "file:///tmp/demo.wasm" {
		t.Fatalf("req = %+v", req)
	}
}

func TestTranslateWasmCreateFromLabels(t *testing.T) {
	req, ok, err := TranslateWasmCreate(context.Background(), nil, "", map[string]string{
		"runtime":    models.RuntimeWasm,
		"module_ref": "file:///tmp/from-label.wasm",
	})
	if err != nil {
		t.Fatalf("TranslateWasmCreate: %v", err)
	}
	if !ok {
		t.Fatal("expected ok")
	}
	if req.ModuleRef != "file:///tmp/from-label.wasm" {
		t.Fatalf("module_ref = %q", req.ModuleRef)
	}
}

func TestTranslateWasmCreateNotWasm(t *testing.T) {
	_, ok, err := TranslateWasmCreate(context.Background(), nil, "", map[string]string{
		"runtime": "docker",
	})
	if err != nil {
		t.Fatalf("TranslateWasmCreate: %v", err)
	}
	if ok {
		t.Fatal("expected not ok for docker runtime")
	}
}

func TestTranslateWasmCreateModuleNotReady(t *testing.T) {
	get := fakeWasmModuleGetter{
		mod: &models.WasmModule{
			ID:        "mod-1",
			ModuleRef: "file:///tmp/demo.wasm",
			Status:    "building",
		},
	}
	_, _, err := TranslateWasmCreate(context.Background(), get, "mod-1", nil)
	if err == nil {
		t.Fatal("expected error for non-ready module")
	}
}

func TestTranslateWasmCreateGetterNotFoundFallsThrough(t *testing.T) {
	get := fakeWasmModuleGetter{err: store.ErrNotFound}
	req, ok, err := TranslateWasmCreate(context.Background(), get, "missing", map[string]string{
		"runtime":    models.RuntimeWasm,
		"module_ref": "file:///tmp/fallback.wasm",
	})
	if err != nil {
		t.Fatalf("TranslateWasmCreate: %v", err)
	}
	if !ok || req.ModuleRef != "file:///tmp/fallback.wasm" {
		t.Fatalf("req = %+v ok=%v", req, ok)
	}
}

func TestTranslateWasmCreatePropagatesGetterError(t *testing.T) {
	get := fakeWasmModuleGetter{err: errors.New("db down")}
	_, _, err := TranslateWasmCreate(context.Background(), get, "mod-1", nil)
	if err == nil || err.Error() != "db down" {
		t.Fatalf("err = %v", err)
	}
}

func TestTranslateWasmCreateMissingModuleRef(t *testing.T) {
	_, _, err := TranslateWasmCreate(context.Background(), nil, "", map[string]string{
		"runtime": models.RuntimeWasm,
		// module_ref intentionally omitted
	})
	if err == nil || !strings.Contains(err.Error(), "module_ref") {
		t.Fatalf("err = %v, want module_ref required", err)
	}
}

func TestLabelValueEmpty(t *testing.T) {
	if got := labelValue(map[string]string{"runtime": "  "}, "runtime", "aerol.runtime"); got != "" {
		t.Fatalf("labelValue = %q, want empty", got)
	}
	if got := labelValue(nil, "runtime"); got != "" {
		t.Fatalf("labelValue(nil) = %q", got)
	}
}
