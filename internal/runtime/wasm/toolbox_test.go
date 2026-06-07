package wasm_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	wasmruntime "github.com/aerol-ai/microvm/internal/runtime/wasm"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestDriverServeToolboxNotFound(t *testing.T) {
	d := wasmruntime.New(wasmruntime.Config{RunDir: t.TempDir()}, nil)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	d.ServeToolbox(req.Context(), "missing", "", rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d", rec.Code)
	}
}

// Ensure compile-time ToolboxHost satisfaction.
var _ wasmruntime.ToolboxHost = (*wasmruntime.Driver)(nil)

func TestToolboxHostInterface(t *testing.T) {
	var d *wasmruntime.Driver
	var _ wasmruntime.ToolboxHost = d
	_ = models.RuntimeWasm
}
