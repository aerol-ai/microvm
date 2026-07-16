package worker

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

// serveResident starts a ResidentServer on a fresh unix socket and returns a
// client + the socket path. Mirrors the cold_path_test harness.
func serveResident(t *testing.T) (*Client, string) {
	t.Helper()
	socketPath := filepath.Join(os.TempDir(), fmt.Sprintf("aerol-wasm-res-%d.sock", time.Now().UnixNano()))
	t.Cleanup(func() { _ = os.Remove(socketPath) })
	_ = os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	srv := &ResidentServer{}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { _ = srv.Serve(c) }(conn)
		}
	}()
	return NewClient(socketPath), socketPath
}

// nonListenCaps builds caps that are explicitly NOT a wasip1 listener. The zero
// value of WASIListenPort is 0, which ListenEnabled() treats as ephemeral-listen
// ENABLED, so a resident host would (correctly) reject it — the driver sets
// WASIListenPortDisabled for non-HTTP sandboxes, and so must this test.
func nonListenCaps(args ...string) wasmengine.Capabilities {
	return wasmengine.Capabilities{Args: args, WASIListenPort: wasmengine.WASIListenPortDisabled}
}

// TestResidentServer_LoadOnceInstantiateManyExec is the Phase 2 regression guard
// for the resident-host worker: one LoadModule compiles once, many sandboxes
// Instantiate + Exec against the resident module, the bucket refuses a second
// distinct module, and StopInstance is per-sandbox.
func TestResidentServer_LoadOnceInstantiateManyExec(t *testing.T) {
	dir := t.TempDir()
	modPath := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")
	client, _ := serveResident(t)

	if err := client.Ping("host"); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if _, err := client.LoadModule("host", modPath, 0); err != nil {
		t.Fatalf("LoadModule: %v", err)
	}

	caps := nonListenCaps("wasm")
	for _, id := range []string{"sb-1", "sb-2"} {
		if err := client.Instantiate(id, caps); err != nil {
			t.Fatalf("Instantiate %s: %v", id, err)
		}
	}
	for _, id := range []string{"sb-1", "sb-2"} {
		res, err := client.Exec(id, caps, "_start")
		if err != nil {
			t.Fatalf("Exec %s: %v", id, err)
		}
		if res.ExitCode != 0 {
			t.Fatalf("Exec %s exit=%d stderr=%q", id, res.ExitCode, res.Stderr)
		}
	}

	// Re-loading the same module is idempotent (same bucket).
	if _, err := client.LoadModule("host", modPath, 0); err != nil {
		t.Fatalf("re-LoadModule same path: %v", err)
	}
	// A different module is refused — a resident host is one (module, memoryMB)
	// bucket, and swapping it would pull the compiled code out from under live
	// instances.
	other := wasmmod.WriteMinimalWasm(t, dir, "other.wasm")
	if _, err := client.LoadModule("host", other, 0); err == nil {
		t.Fatal("expected error loading a second distinct module into a bound resident host")
	}

	// Per-sandbox stop.
	if err := client.StopInstance("sb-1"); err != nil {
		t.Fatalf("StopInstance sb-1: %v", err)
	}
	time.Sleep(10 * time.Millisecond)
}

// TestResidentServer_RejectsListener confirms a listener (expose_port/HTTP)
// Instantiate is rejected — the driver routes those to the per-sandbox cold path.
func TestResidentServer_RejectsListener(t *testing.T) {
	dir := t.TempDir()
	modPath := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")
	client, _ := serveResident(t)
	if _, err := client.LoadModule("host", modPath, 0); err != nil {
		t.Fatalf("LoadModule: %v", err)
	}
	// WASIListenPort 0 = ephemeral listen enabled → must be rejected here.
	listenCaps := wasmengine.Capabilities{Args: []string{"wasm"}, WASIListenPort: 0}
	if err := client.Instantiate("sb-listen", listenCaps); err == nil {
		t.Fatal("expected resident host to reject a wasip1-listener Instantiate")
	}
	time.Sleep(10 * time.Millisecond)
}

// TestResidentServer_NetworkBlocksAndNetstats confirms MsgSetNetworkBlocks /
// MsgNetstatsTick are keyed per-sandbox (were rejected before PR-A) and that
// Instantiate binds a hook so mediated dial works.
func TestResidentServer_NetworkBlocksAndNetstats(t *testing.T) {
	dir := t.TempDir()
	modPath := wasmmod.WriteMinimalWasm(t, dir, "demo.wasm")
	client, _ := serveResident(t)
	if _, err := client.LoadModule("host", modPath, 0); err != nil {
		t.Fatalf("LoadModule: %v", err)
	}
	caps := nonListenCaps("wasm")
	if err := client.Instantiate("sb-net", caps); err != nil {
		t.Fatalf("Instantiate: %v", err)
	}
	if err := client.SetNetworkBlocks("sb-net", false, true); err != nil {
		t.Fatalf("SetNetworkBlocks: %v", err)
	}
	in, out, err := client.NetstatsTick("sb-net")
	if err != nil {
		t.Fatalf("NetstatsTick: %v", err)
	}
	if in != 0 || out != 0 {
		t.Fatalf("netstats = (%d,%d), want (0,0)", in, out)
	}
	if err := client.StopInstance("sb-net"); err != nil {
		t.Fatalf("StopInstance: %v", err)
	}
}

// TestResidentServer_LoadModuleConcurrentDistinctPathsKeepsOneModule guards the
// D8 check-then-load race: two concurrent different-path loads must not both
// pass prev=="" — one wins, the other is refused.
func TestResidentServer_LoadModuleConcurrentDistinctPathsKeepsOneModule(t *testing.T) {
	dir := t.TempDir()
	a := wasmmod.WriteMinimalWasm(t, dir, "a.wasm")
	b := wasmmod.WriteMinimalWasm(t, dir, "b.wasm")
	client, _ := serveResident(t)

	errCh := make(chan error, 2)
	go func() { _, err := client.LoadModule("host", a, 0); errCh <- err }()
	go func() { _, err := client.LoadModule("host", b, 0); errCh <- err }()
	var ok, fail int
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			fail++
		} else {
			ok++
		}
	}
	if ok != 1 || fail != 1 {
		t.Fatalf("concurrent distinct loads: ok=%d fail=%d, want 1/1", ok, fail)
	}
}
