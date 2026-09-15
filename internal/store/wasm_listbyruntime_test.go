package store

import (
	"context"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// TestListByRuntime confirms the per-runtime sweep query returns only the rows
// for the requested runtime — the scaling fix relies on it not loading the
// whole mixed-runtime fleet.
func TestListByRuntime(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	wasmA := sampleSandbox("sb-wasm-a")
	wasmA.Runtime = models.RuntimeWasm
	wasmB := sampleSandbox("sb-wasm-b")
	wasmB.Runtime = models.RuntimeWasm
	fc := sampleSandbox("sb-fc")
	fc.Runtime = models.RuntimeFirecracker

	for _, sb := range []*models.Sandbox{wasmA, wasmB, fc} {
		if err := st.Create(ctx, sb); err != nil {
			t.Fatalf("Create(%s): %v", sb.ID, err)
		}
	}

	wasm, err := st.ListByRuntime(ctx, models.RuntimeWasm)
	if err != nil {
		t.Fatalf("ListByRuntime(wasm): %v", err)
	}
	if len(wasm) != 2 {
		t.Fatalf("ListByRuntime(wasm) = %d, want 2", len(wasm))
	}
	for _, sb := range wasm {
		if sb.Runtime != models.RuntimeWasm {
			t.Fatalf("ListByRuntime(wasm) leaked %s (runtime %q)", sb.ID, sb.Runtime)
		}
	}

	fcRows, err := st.ListByRuntime(ctx, models.RuntimeFirecracker)
	if err != nil {
		t.Fatalf("ListByRuntime(firecracker): %v", err)
	}
	if len(fcRows) != 1 || fcRows[0].ID != "sb-fc" {
		t.Fatalf("ListByRuntime(firecracker) = %+v, want [sb-fc]", fcRows)
	}
}

// TestListOrphanedWasmCheckpointPushes confirms only push rows whose sandbox is
// gone are returned — the orphan-ref GC sweep depends on this to avoid touching
// rows for live sandboxes.
func TestListOrphanedWasmCheckpointPushes(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	live := sampleSandbox("sb-live")
	live.Runtime = models.RuntimeWasm
	if err := st.Create(ctx, live); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := st.InsertWasmCheckpointPush(ctx, "sb-live", "aocr://sb-live:x", "d1"); err != nil {
		t.Fatalf("InsertWasmCheckpointPush(live): %v", err)
	}
	// Push row for a sandbox that was never created / already destroyed.
	if _, err := st.InsertWasmCheckpointPush(ctx, "sb-gone", "aocr://sb-gone:y", "d2"); err != nil {
		t.Fatalf("InsertWasmCheckpointPush(gone): %v", err)
	}

	orphans, err := st.ListOrphanedWasmCheckpointPushes(ctx, 0)
	if err != nil {
		t.Fatalf("ListOrphanedWasmCheckpointPushes: %v", err)
	}
	if len(orphans) != 1 || orphans[0].SandboxID != "sb-gone" {
		t.Fatalf("orphans = %+v, want exactly [sb-gone]", orphans)
	}
}

// TestListByRuntime_QueryErrorOnClosedDB covers the query-error branch.
func TestListByRuntime_QueryErrorOnClosedDB(t *testing.T) {
	st := newTestStore(t)
	_ = st.Close()
	if _, err := st.ListByRuntime(context.Background(), models.RuntimeWasm); err == nil {
		t.Fatal("ListByRuntime on a closed DB must return an error")
	}
}

func TestDeleteOrphanedWasmStateKV(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	live := sampleSandbox("sb-live-kv")
	live.Runtime = models.RuntimeWasm
	if err := st.Create(ctx, live); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := st.PutWasmStateKV(ctx, "sb-live-kv", "counter", []byte("1")); err != nil {
		t.Fatalf("PutWasmStateKV(live): %v", err)
	}
	if err := st.PutWasmStateKV(ctx, "sb-gone-kv", "counter", []byte("2")); err != nil {
		t.Fatalf("PutWasmStateKV(gone): %v", err)
	}

	n, err := st.DeleteOrphanedWasmStateKV(ctx, 0)
	if err != nil {
		t.Fatalf("DeleteOrphanedWasmStateKV: %v", err)
	}
	if n != 1 {
		t.Fatalf("deleted = %d, want 1", n)
	}
	keys, err := st.ListWasmStateKVKeys(ctx, "sb-live-kv")
	if err != nil || len(keys) != 1 || keys[0] != "counter" {
		t.Fatalf("live keys = %v err=%v, want [counter]", keys, err)
	}
	gone, err := st.ListWasmStateKVKeys(ctx, "sb-gone-kv")
	if err != nil || len(gone) != 0 {
		t.Fatalf("gone keys = %v err=%v, want empty", gone, err)
	}
}

// TestListOrphanedWasmCheckpointPushes_QueryErrorOnClosedDB covers the
// query-error branch.
func TestListOrphanedWasmCheckpointPushes_QueryErrorOnClosedDB(t *testing.T) {
	st := newTestStore(t)
	_ = st.Close()
	if _, err := st.ListOrphanedWasmCheckpointPushes(context.Background(), 0); err == nil {
		t.Fatal("ListOrphanedWasmCheckpointPushes on a closed DB must return an error")
	}
}
