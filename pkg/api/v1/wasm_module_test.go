package v1

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

type stubWasmModuleResolver struct {
	path   string
	digest string
}

func (s stubWasmModuleResolver) Resolve(_ context.Context, ref string) (*wasmmod.ResolvedModule, error) {
	return &wasmmod.ResolvedModule{
		Path:      s.path,
		Digest:    s.digest,
		SizeBytes: 4,
	}, nil
}

type wasmModuleV1Env struct {
	svc     *service.Service
	store   *store.Store
	handler http.Handler
}

func newWasmModuleV1TestEnv(t *testing.T) *wasmModuleV1Env {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := config.Config{
		EnableWasm: true,
	}
	svc := service.New(cfg, logger, st, &noopRuntime{}, nil, nil, nil, nil, nil)
	svc.SetWasmModuleResolver(stubWasmModuleResolver{path: "/tmp/fake.wasm", digest: "abc"})

	mux := http.NewServeMux()
	RegisterRoutes(mux, Deps{
		Service: svc,
		Logger:  logger,
		Auth:    func(h http.Handler) http.Handler { return h },
	})
	return &wasmModuleV1Env{svc: svc, store: st, handler: mux}
}

func TestV1CreateWasmModule_Success(t *testing.T) {
	env := newWasmModuleV1TestEnv(t)

	// Write a fake wasm file so service.CreateWasmModule resolution succeeds
	fakeWasm := filepath.Join(t.TempDir(), "test.wasm")
	if err := os.WriteFile(fakeWasm, []byte("\\0asm"), 0o644); err != nil {
		t.Fatalf("write fake wasm: %v", err)
	}

	reqBody := models.CreateWasmModuleRequest{
		ID:        "my-module",
		ModuleRef: "file://" + fakeWasm,
	}
	b, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/v1/wasm-modules", bytes.NewReader(b))
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rr.Code, rr.Body.String())
	}
	var resp models.WasmModule
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.ID != "my-module" {
		t.Fatalf("resp.ID = %q, want my-module", resp.ID)
	}
}

func TestV1CreateWasmModule_InvalidJSON(t *testing.T) {
	env := newWasmModuleV1TestEnv(t)
	req := httptest.NewRequest(http.MethodPost, "/v1/wasm-modules", bytes.NewReader([]byte("{bad")))
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
}

func TestV1ListWasmModules_Success(t *testing.T) {
	env := newWasmModuleV1TestEnv(t)

	mod := store.WasmModuleRecord{
		ID:        "mod-1",
		ModuleRef: "docker://alpine:latest",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := env.store.UpsertWasmModule(context.Background(), mod); err != nil {
		t.Fatalf("UpsertWasmModule: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/wasm-modules", nil)
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var rows []models.WasmModule
	if err := json.NewDecoder(rr.Body).Decode(&rows); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(rows) != 1 || rows[0].ID != "mod-1" {
		t.Fatalf("rows = %+v, want exactly [mod-1]", rows)
	}
}

func TestV1GetWasmModule_Success(t *testing.T) {
	env := newWasmModuleV1TestEnv(t)

	mod := store.WasmModuleRecord{
		ID:        "mod-get",
		ModuleRef: "docker://alpine:latest",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := env.store.UpsertWasmModule(context.Background(), mod); err != nil {
		t.Fatalf("UpsertWasmModule: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/wasm-modules/mod-get", nil)
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var resp models.WasmModule
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.ID != "mod-get" {
		t.Fatalf("resp.ID = %q, want mod-get", resp.ID)
	}
}

func TestV1DeleteWasmModule_Success(t *testing.T) {
	env := newWasmModuleV1TestEnv(t)

	mod := store.WasmModuleRecord{
		ID:        "mod-del",
		ModuleRef: "docker://alpine:latest",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := env.store.UpsertWasmModule(context.Background(), mod); err != nil {
		t.Fatalf("UpsertWasmModule: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/v1/wasm-modules/mod-del", nil)
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", rr.Code, rr.Body.String())
	}
}

func TestV1DeleteWasmModule_NotFound(t *testing.T) {
	env := newWasmModuleV1TestEnv(t)
	req := httptest.NewRequest(http.MethodDelete, "/v1/wasm-modules/mod-nope", nil)
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", rr.Code, rr.Body.String())
	}
}
