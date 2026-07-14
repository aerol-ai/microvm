package worker

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

func ensureWasip1HTTPWasm(t *testing.T) string {
	t.Helper()
	out, err := filepath.Abs(filepath.Join("..", "testdata", "wasip1-http.wasm"))
	if err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(out); err == nil && st.Size() > 0 {
		return out
	}
	if runtime.GOOS == "windows" {
		t.Skip("wasip1-http.wasm compile skipped on windows")
	}
	src, err := filepath.Abs(filepath.Join("..", "testdata", "aerolhttp"))
	if err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(src); err != nil || !st.IsDir() {
		t.Skip("aerolhttp wasip1 guest source missing")
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

func TestGuestWasip1HTTPServerEndToEnd(t *testing.T) {
	modPath := ensureWasip1HTTPWasm(t)

	client, cleanup := startTestWorker(t)
	defer cleanup()

	sandboxID := "sb-wasip1-http"
	if _, err := client.LoadModule(sandboxID, modPath, 0); err != nil {
		t.Fatalf("LoadModule: %v", err)
	}
	caps := wasmengine.Capabilities{
		WASIListenPort: 0,
		WASIListenHost: "127.0.0.1",
		Args:           []string{"wasi", "http"},
	}
	if err := client.Instantiate(sandboxID, caps); err != nil {
		t.Fatalf("Instantiate: %v", err)
	}
	guestPort, err := client.ResolvedListenPort(sandboxID)
	if err != nil {
		t.Fatalf("ResolvedListenPort: %v", err)
	}
	if guestPort <= 0 {
		t.Fatalf("expected resolved listen port > 0, got %d", guestPort)
	}

	go func() {
		_ = client.Invoke(sandboxID, "_start")
	}()
	for i := 0; i < 50; i++ {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(guestPort)), 50*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			break
		}
		if i == 49 {
			t.Fatalf("guest did not listen on %d: %v", guestPort, err)
		}
		time.Sleep(50 * time.Millisecond)
	}

	req, err := http.NewRequest(http.MethodPost, "http://gateway/", bytes.NewReader([]byte("wazero")))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	rec := httptest.NewRecorder()
	if err := client.ProxyHTTP(sandboxID, 0, rec, req); err != nil {
		t.Fatalf("ProxyHTTP: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
	if got := rec.Body.String(); got != "wazero\n" {
		t.Fatalf("body=%q", got)
	}

	in, out, err := client.NetstatsTick(sandboxID)
	if err != nil {
		t.Fatalf("NetstatsTick: %v", err)
	}
	if in == 0 || out == 0 {
		t.Fatalf("expected metered guest HTTP bytes in=%d out=%d", in, out)
	}
}
