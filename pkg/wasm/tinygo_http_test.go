package wasm

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/wasmtestguest"
)

// ensureWasip1HTTPWasm returns the wasip1 HTTP guest, compiled on demand by
// the shared internal/wasmtestguest helper.
func ensureWasip1HTTPWasm(t *testing.T) string {
	t.Helper()
	return wasmtestguest.Path(t, wasmtestguest.HTTP)
}

func TestTinygoHTTPModuleRequest(t *testing.T) {
	modPath := ensureWasip1HTTPWasm(t)
	ctx := context.Background()
	e, err := newWazeroEngine(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = e.Close(ctx) }()
	if err := e.LoadModule(ctx, modPath, LoadOptions{}); err != nil {
		t.Fatalf("LoadModule: %v", err)
	}
	caps := Capabilities{
		WASIListenPort: 0,
		WASIListenHost: "127.0.0.1",
		Args:           []string{"wasi", "http"},
	}
	if err := e.Instantiate(ctx, caps); err != nil {
		t.Fatalf("Instantiate: %v", err)
	}
	port, ok := ResolvedListenPort(e.module)
	if !ok || port == 0 {
		t.Fatalf("resolved listen port = %d ok=%v", port, ok)
	}

	go func() { _ = e.InvokeExport(ctx, "_start") }()
	time.Sleep(200 * time.Millisecond)

	resp, err := http.Post(
		"http://"+net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		"text/plain",
		bytes.NewReader([]byte("wazero")),
	)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "wazero\n" {
		t.Fatalf("body=%q", body)
	}
}
