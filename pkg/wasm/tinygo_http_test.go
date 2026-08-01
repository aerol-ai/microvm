package wasm

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"
)

const wasip1HTTPWasmName = "wasip1-http.wasm"

func wasip1HTTPSourceDir() (string, error) {
	base, err := filepath.Abs(filepath.Join("testdata", "aerolhttp"))
	if err != nil {
		return "", fmt.Errorf("resolve aerolhttp guest source: %w", err)
	}
	if st, err := os.Stat(base); err != nil || !st.IsDir() {
		return "", fmt.Errorf("aerolhttp wasip1 guest source missing at %s", base)
	}
	return base, nil
}

func ensureWasip1HTTPWasm(t *testing.T) string {
	t.Helper()
	// Absolute output: the build runs with cmd.Dir = the guest source dir, so a
	// relative -o would land next to the source instead of in pkg/wasm/testdata.
	out, err := filepath.Abs(filepath.Join("testdata", wasip1HTTPWasmName))
	if err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(out); err == nil && st.Size() > 0 {
		return out
	}
	if runtime.GOOS == "windows" {
		t.Skip("wasip1-http.wasm compile skipped on windows")
	}
	src, err := wasip1HTTPSourceDir()
	if err != nil {
		t.Skip(err)
	}
	// A missing toolchain is an environment limitation, not a defect under
	// test — same class as Windows above. Checked before the build so the
	// failure mode is a clear skip rather than a confusing exec error.
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain unavailable; cannot compile wasip1-http.wasm")
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "build", "-o", out, ".")
	cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm")
	cmd.Dir = src
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile wasip1-http.wasm: %v\n%s", err, combined)
	}
	return out
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
