package worker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"testing"
	"time"

	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

type fakeNetworkAwareEngine struct {
	setHook   bool
	clearHook bool
	port      int
}

func (f *fakeNetworkAwareEngine) LoadModule(ctx context.Context, path string, opts wasmengine.LoadOptions) error {
	return nil
}
func (f *fakeNetworkAwareEngine) Instantiate(ctx context.Context, caps wasmengine.Capabilities) error {
	return nil
}
func (f *fakeNetworkAwareEngine) InvokeExport(ctx context.Context, name string) error { return nil }
func (f *fakeNetworkAwareEngine) Run(ctx context.Context, caps wasmengine.Capabilities, export string) (wasmengine.RunResult, error) {
	return wasmengine.RunResult{}, nil
}
func (f *fakeNetworkAwareEngine) StopInstance(ctx context.Context) error { return nil }
func (f *fakeNetworkAwareEngine) CaptureSnapshot(ctx context.Context) (wasmengine.SnapshotCapture, error) {
	return wasmengine.SnapshotCapture{}, nil
}
func (f *fakeNetworkAwareEngine) RestoreSnapshot(ctx context.Context, snap wasmengine.SnapshotRestoreInput, caps wasmengine.Capabilities) error {
	return nil
}
func (f *fakeNetworkAwareEngine) Close(ctx context.Context) error { return nil }
func (f *fakeNetworkAwareEngine) ResolvedListenPort() (int, bool) {
	return f.port, f.port > 0
}
func (f *fakeNetworkAwareEngine) SupportsListen() bool { return true }
func (f *fakeNetworkAwareEngine) SetNetworkHook(hook *wasmengine.NetworkHook) {
	f.setHook = true
}
func (f *fakeNetworkAwareEngine) ClearNetworkHook() {
	f.clearHook = true
}

func TestClient_expectOK_UnexpectedType(t *testing.T) {
	c := NewClient("dummy")
	if err := c.expectOK(Envelope{Type: MsgInvokeResult}); err == nil {
		t.Fatal("expected error for unexpected reply type")
	}
}

func TestClient_roundTripContext_NilContext(t *testing.T) {
	c := NewClient("dummy")
	c.dial = mockDialer(t, Envelope{Type: MsgPong})
	_, err := c.roundTripContext(nil, Envelope{Type: MsgHealthPing})
	if err != nil {
		t.Fatalf("roundTripContext(nil) failed: %v", err)
	}
}

func TestClient_roundTripContext_Deadline(t *testing.T) {
	c := NewClient("dummy")
	c.dial = mockDialer(t, Envelope{Type: MsgPong})
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	_, err := c.roundTripContext(ctx, Envelope{Type: MsgHealthPing})
	if err != nil {
		t.Fatalf("roundTripContext with deadline failed: %v", err)
	}
}

func TestServer_syncResolvedListenPortAndNetworkHooks(t *testing.T) {
	fake := &fakeNetworkAwareEngine{port: 12345}
	s := &Server{eng: fake}
	caps := wasmengine.Capabilities{WASIListenPort: 0}
	s.syncResolvedListenPort(&caps)
	if caps.WASIListenPort != 12345 {
		t.Fatalf("expected WASIListenPort 12345, got %d", caps.WASIListenPort)
	}

	s.bindNetworkHook("sandbox")
	if !fake.setHook {
		t.Fatal("expected SetNetworkHook to be called")
	}

	s.clearNetworkHook()
	if !fake.clearHook {
		t.Fatal("expected ClearNetworkHook to be called")
	}
}

func TestWorkerEngineNameFromEnv(t *testing.T) {
	old := os.Getenv("AEROL_WASM_ENGINE")
	defer os.Setenv("AEROL_WASM_ENGINE", old)
	os.Setenv("AEROL_WASM_ENGINE", "  wazero  ")
	if got := workerEngineName(); got != "wazero" {
		t.Fatalf("expected trimmed engine name, got %q", got)
	}
}

func TestServer_ProxyGuestHTTPFromPayload(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test", "yes")
		_, _ = w.Write([]byte("hello"))
	}))
	defer backend.Close()

	u, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("parse backend URL: %v", err)
	}
	pPort := u.Port()
	if pPort == "" {
		t.Fatal("backend URL missing port")
	}
	port, err := strconv.Atoi(pPort)
	if err != nil {
		t.Fatalf("parse backend port: %v", err)
	}

	s := &Server{}
	p := proxyHTTPPayload{
		GuestPort:  port,
		Method:     http.MethodGet,
		RequestURI: "/test",
		Header:     http.Header{"Accept": {"text/plain"}},
		Body:       []byte{},
	}

	result, err := s.proxyGuestHTTPFromPayload(context.Background(), "sb", p)
	if err != nil {
		t.Fatalf("proxyGuestHTTPFromPayload: %v", err)
	}
	if result.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", result.StatusCode)
	}
	if got := string(result.Body); got != "hello" {
		t.Fatalf("expected body hello, got %q", got)
	}
	if got := result.Header["X-Test"]; len(got) != 1 || got[0] != "yes" {
		t.Fatalf("expected X-Test header, got %v", got)
	}
}

func TestResidentServer_InvokeCallsGuest(t *testing.T) {
	dir := t.TempDir()
	modPath := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")
	client, _ := serveResident(t)

	if _, err := client.LoadModule("host", modPath, 0); err != nil {
		t.Fatalf("LoadModule: %v", err)
	}
	caps := nonListenCaps("wasm")
	if err := client.Instantiate("sb-invoke", caps); err != nil {
		t.Fatalf("Instantiate: %v", err)
	}
	if err := client.Invoke("sb-invoke", ""); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
}
