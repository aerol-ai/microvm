package v1

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
)

func TestPushWasmModuleHandlerBranches(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Run("wasm_disabled", func(t *testing.T) {
		h := &handlers{deps: Deps{Service: service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil), Logger: logger}}
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/wasm-modules/push?name=demo&tag=latest", strings.NewReader("\x00asm"))
		h.pushWasmModule(rr, req)
		if rr.Code == http.StatusCreated {
			t.Fatal("expected push failure when wasm disabled")
		}
	})

	t.Run("missing_push_host", func(t *testing.T) {
		svc := service.New(config.Config{EnableWasm: true}, logger, nil, nil, nil, nil, nil, nil, nil)
		h := &handlers{deps: Deps{Service: svc, Logger: logger}}
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/wasm-modules/push?name=demo&tag=latest", strings.NewReader("\x00asm"))
		h.pushWasmModule(rr, req)
		if rr.Code == http.StatusCreated {
			t.Fatal("expected push failure without registry host")
		}
	})
}

func TestListWasmModulesStoreError(t *testing.T) {
	env := newWasmModuleV1TestEnv(t)
	_ = env.store.Close()
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/wasm-modules", nil))
	if rr.Code == http.StatusOK {
		t.Fatal("expected list failure with closed store")
	}
}

func TestGetWasmModuleStoreError(t *testing.T) {
	env := newWasmModuleV1TestEnv(t)
	_ = env.store.Close()
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/wasm-modules/missing", nil))
	if rr.Code == http.StatusOK {
		t.Fatal("expected get failure with closed store")
	}
}
