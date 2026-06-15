package wasm

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	wasmpool "github.com/aerol-ai/microvm/internal/pool/wasm"
	"github.com/aerol-ai/microvm/pkg/models"
	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
	"github.com/aerol-ai/microvm/pkg/wasm/worker"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

// TestWorkerClientAdapterDelegates exercises the workerClientAdapter pass-throughs
// (seams.go Invoke, SetCapability, NetstatsTick, SetNetworkBlocks, SetListenPort,
// ResolvedListenPort, ProxyHTTP) which are otherwise unreachable because tests
// inject fake WorkerClient implementations. Each call fails with a connection
// error (no real worker socket), but the adapter statement itself is executed.
func TestWorkerClientAdapterDelegates(t *testing.T) {
	adapter := workerClientAdapter{client: worker.NewClient("/nonexistent/coverage-test.sock")}

	_ = adapter.Invoke("sb", "_start")
	_ = adapter.SetCapability("sb", wasmengine.Capabilities{})
	_, _, _ = adapter.NetstatsTick("sb")
	_ = adapter.SetNetworkBlocks("sb", false, false)
	_ = adapter.SetListenPort("sb", 8080, "127.0.0.1")
	_, _ = adapter.ResolvedListenPort("sb")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_ = adapter.ProxyHTTP("sb", 8080, rec, req)
}

// TestResolveWithRequestAuthUsesAuthResolver covers the auth path of
// resolveWithRequestAuth: when registry credentials are present and the
// resolver implements the authResolver interface.
func TestResolveWithRequestAuthUsesAuthResolver(t *testing.T) {
	res := &authRecordingResolver{path: "/tmp/coverage-m.wasm", digest: "d1"}
	reg := &models.RegistryAuth{Username: "tenantuser", Password: "tenant-pat-xyz"}
	if _, err := resolveWithRequestAuth(context.Background(), res, "demo.wasm", reg); err != nil {
		t.Fatal(err)
	}
	if !res.withAuth {
		t.Fatal("expected ResolveWithAuth to be called when registry credentials are set")
	}
}

// TestModuleAuthFromSandboxWhitespaceCredentials covers the whitespace-only
// credential case: a non-nil RegistryAuth with blank strings should return nil.
func TestModuleAuthFromSandboxWhitespaceCredentials(t *testing.T) {
	sb := &models.Sandbox{RegistryAuth: &models.RegistryAuth{Username: "  ", Password: " "}}
	if got := moduleAuthFromSandbox(sb); got != nil {
		t.Fatalf("expected nil auth for whitespace-only creds, got %+v", got)
	}
}

// TestResolvePinnedDigestMismatch covers the error path where the resolved
// module digest differs from the digest pinned at create time (codex C2).
func TestResolvePinnedDigestMismatch(t *testing.T) {
	res := &authRecordingResolver{path: "/tmp/coverage-m.wasm", digest: "actual-digest-abc"}
	d := &Driver{resolver: res}
	// pinnedDigest != resolved.Digest → must return ErrModuleDigestMismatch
	if _, err := d.resolvePinned(context.Background(), "demo.wasm", "pinned-digest-xyz", nil); err == nil || !errors.Is(err, wasmmod.ErrModuleDigestMismatch) {
		t.Fatalf("expected ErrModuleDigestMismatch, got: %v", err)
	}
}

// noSlotPool is a WarmPool that always returns ErrNoSlot.
type noSlotPool struct{}

func (noSlotPool) NoteModule(string, string) {}
func (noSlotPool) Acquire(context.Context, string, string) (*wasmpool.Slot, error) {
	return nil, wasmpool.ErrNoSlot
}

// hitSlotPool is a WarmPool that always returns a pre-built slot.
type hitSlotPool struct{}

func (hitSlotPool) NoteModule(string, string) {}
func (hitSlotPool) Acquire(context.Context, string, string) (*wasmpool.Slot, error) {
	return &wasmpool.Slot{
		ID:         "warm-cov-1",
		SocketPath: "/tmp/warm-cov.sock",
		WorkerKey:  "wk-cov-1",
		LoadedAt:   time.Now(),
	}, nil
}

// TestTryAcquireWarmErrNoSlot covers the ErrNoSlot branch in tryAcquireWarm:
// the pool returns a miss without an error.
func TestTryAcquireWarmErrNoSlot(t *testing.T) {
	d := New(Config{ModulesDir: t.TempDir()}, nil)
	d.SetWarmPool(noSlotPool{})
	slot, err := d.tryAcquireWarm(context.Background(), "digest-noSlot", "/path/m.wasm")
	if err != nil || slot != nil {
		t.Fatalf("ErrNoSlot must yield (nil, nil): slot=%v err=%v", slot, err)
	}
}

// TestTryAcquireWarmHit covers the successful warm-pool hit branch in
// tryAcquireWarm: pool returns a slot, driver logs the hit and returns it.
func TestTryAcquireWarmHit(t *testing.T) {
	d := New(Config{ModulesDir: t.TempDir()}, nil)
	d.SetWarmPool(hitSlotPool{})
	slot, err := d.tryAcquireWarm(context.Background(), "digest-hit", "/path/m.wasm")
	if err != nil || slot == nil {
		t.Fatalf("expected warm hit: slot=%v err=%v", slot, err)
	}
	if slot.ID != "warm-cov-1" {
		t.Fatalf("slot.ID = %q, want warm-cov-1", slot.ID)
	}
}

// TestCopyFileOpenDstError covers the dst-open failure path in copyFile: the
// destination directory does not exist so os.OpenFile returns an error.
func TestCopyFileOpenDstError(t *testing.T) {
	src := filepath.Join(t.TempDir(), "src.txt")
	if err := os.WriteFile(src, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copyFile(src, "/nonexistent-dir/dst.txt"); err == nil {
		t.Fatal("expected error writing to nonexistent directory")
	}
}

// TestSyncGuestListenPortEphemeral covers the ephemeral (port==0) path in
// syncGuestListenPort: worker returns a resolved port via ResolvedListenPort,
// and the driver records it on the instance.
func TestSyncGuestListenPortEphemeral(t *testing.T) {
	d := New(Config{ModulesDir: t.TempDir()}, nil)
	d.waitListenReady = func(string, int) error { return nil }
	client := &invokeWorkerClient{invokeCh: make(chan string, 2)}
	inst := &sandboxInstance{sandboxID: "sb-ephemeral-cov", entryExport: "_start"}
	inst.bumpRunGeneration()
	if err := d.syncGuestListenPort(context.Background(), inst, client, 0); err != nil {
		t.Fatalf("syncGuestListenPort ephemeral: %v", err)
	}
	// invokeWorkerClient.ResolvedListenPort returns 19081
	if inst.resolvedListenPort != 19081 {
		t.Fatalf("resolved port = %d, want 19081", inst.resolvedListenPort)
	}
}
