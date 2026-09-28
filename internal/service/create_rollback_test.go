package service

import (
	"context"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// A create-path rollback needs its OWN budget, started when it begins. The
// detached cleanup context used to be taken at function entry, so a create
// that legitimately outlasted it — a cold module pull and compile, well inside
// the 600s create default — reached its rollback with no time left. The
// rollback could not even open its transaction, the error was ignored, and the
// sandbox row stayed committed as "started" after its runtime was torn down.
func TestWasmCreateRollbackGetsAFreshCleanupBudget(t *testing.T) {
	restore := createRollbackTimeout
	createRollbackTimeout = 200 * time.Millisecond
	t.Cleanup(func() { createRollbackTimeout = restore })

	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	svc.cfg.EnableWasm = true
	svc.admitter = nil
	svc.SetWasmRuntime(rt)
	svc.testSealedMountsOverride = []byte("wasm-sealed")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc.testAfterStoreCreate = func() {
		// The create has taken longer than the rollback budget...
		time.Sleep(300 * time.Millisecond)
		// ...and the request is then cancelled, so mount persistence fails
		// after the parent row committed. The store itself stays healthy: a
		// rollback that gets real time will succeed.
		cancel()
	}
	if _, err := svc.createWasmSandbox(ctx, models.CreateSandboxRequest{
		Runtime: models.RuntimeWasm, ModuleRef: "mod.wasm",
	}, "sb-wasm-slow"); err == nil {
		t.Fatal("expected the create to fail once mount persistence was cancelled")
	}
	if len(rt.destroyIDs) == 0 {
		t.Fatal("the runtime was not torn down")
	}
	if sb, err := st.Get(context.Background(), "sb-wasm-slow"); err == nil {
		t.Fatalf("the sandbox row survived its own rollback with status %q: the cleanup budget expired before the rollback began, so the runtime is gone but the database still says it is running",
			sb.Status)
	}
}

// The budget starts on first use, and one rollback shares it across its steps.
func TestRollbackBudgetStartsWhenFirstUsed(t *testing.T) {
	restore := createRollbackTimeout
	createRollbackTimeout = 150 * time.Millisecond
	t.Cleanup(func() { createRollbackTimeout = restore })

	var b rollbackBudget
	defer b.Release()
	time.Sleep(200 * time.Millisecond) // longer than the budget itself
	ctx := b.Context()
	if err := ctx.Err(); err != nil {
		t.Fatalf("a budget first used after %s was already %v; its clock started at construction", 200*time.Millisecond, err)
	}
	if again := b.Context(); again != ctx {
		t.Fatal("one rollback's steps got different budgets")
	}

	var unused rollbackBudget
	unused.Release() // releasing a budget nobody used is a no-op
}
