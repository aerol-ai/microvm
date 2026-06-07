package facadeutil

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// WasmModuleGetter resolves wasm_modules catalogue rows.
type WasmModuleGetter interface {
	GetWasmModule(ctx context.Context, id string) (*models.WasmModule, error)
}

// TranslateWasmCreate maps a facade template/snapshot id or runtime labels into a
// native wasm CreateSandboxRequest (plans/wasm-runtime.md UC-48).
func TranslateWasmCreate(ctx context.Context, get WasmModuleGetter, catalogueID string, labels map[string]string) (models.CreateSandboxRequest, bool, error) {
	if get != nil {
		if id := strings.TrimSpace(catalogueID); id != "" {
			mod, err := get.GetWasmModule(ctx, id)
			if err == nil {
				if mod.Status != models.WasmModuleStatusReady {
					return models.CreateSandboxRequest{}, false, fmt.Errorf("wasm module %q is not ready", id)
				}
				return wasmCreateFromRef(mod.ModuleRef), true, nil
			}
			if err != nil && !errors.Is(err, store.ErrNotFound) && !errors.Is(err, models.ErrRuntimeNotImplemented) {
				return models.CreateSandboxRequest{}, false, err
			}
		}
	}
	runtime := labelValue(labels, "runtime", "aerol.runtime")
	if runtime != models.RuntimeWasm {
		return models.CreateSandboxRequest{}, false, nil
	}
	ref := labelValue(labels, "module_ref", "aerol.module_ref", "image")
	if ref == "" {
		return models.CreateSandboxRequest{}, false, fmt.Errorf("wasm runtime requires module_ref label")
	}
	return wasmCreateFromRef(ref), true, nil
}

func wasmCreateFromRef(moduleRef string) models.CreateSandboxRequest {
	moduleRef = strings.TrimSpace(moduleRef)
	return models.CreateSandboxRequest{
		Runtime:   models.RuntimeWasm,
		ModuleRef: moduleRef,
		Image:     moduleRef,
	}
}

func labelValue(labels map[string]string, keys ...string) string {
	for _, key := range keys {
		if v := strings.TrimSpace(labels[key]); v != "" {
			return v
		}
	}
	return ""
}
