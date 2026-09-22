package service

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// newWasmEnvRecreateHarness builds the failover-recreate fixture: a local
// checkpoint on disk, a cipher (so env can be sealed), and a WASM driver whose
// restore can be made to fail.
func newWasmEnvRecreateHarness(t *testing.T, id string) (*Service, *store.Store, *fakeWasmRecreateRuntime) {
	t.Helper()
	modulesDir := t.TempDir()
	seedWasmSnapshot(t, filepath.Join(modulesDir, id, "mem.snap"), "gen-"+id)
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	rt := &fakeWasmRecreateRuntime{}
	svc := New(config.Config{EnableWasm: true, WasmModulesDir: modulesDir},
		slog.Default(), st, rt, nil, nil, newTestCipher(t), nil, nil)
	svc.SetWasmRuntime(rt)
	return svc, st, rt
}

// The first recreate attempt persists the row (sealing env) and then restores.
// If that restore fails, the retry finds the row already there and takes the
// existing-row branch — which reads it back with store.Get. Store rows never
// carry env in the hardened schema, so the retry must re-materialise the
// sealed environment; otherwise the sandbox comes back with an empty one and
// every later exec silently loses its credentials.
func TestRecreateWasmDurableSandboxRetryRestoresSealedEnv(t *testing.T) {
	ctx := context.Background()
	const id = "sb-failover-env"
	svc, st, rt := newWasmEnvRecreateHarness(t, id)

	spec := models.CreateSandboxRequest{
		Runtime:    models.RuntimeWasm,
		Durability: models.DurabilityDurable,
		ModuleRef:  "file:///tmp/demo.wasm",
		Env:        map[string]string{"TOKEN": "from-cluster-secret"},
	}

	rt.rehydrateErr = errors.New("restore boom")
	if _, err := svc.recreateWasmDurableSandbox(ctx, id, "inc-1", spec, nil); err == nil {
		t.Fatal("seeded restore failure did not surface")
	}
	if _, err := st.Get(ctx, id); err != nil {
		t.Fatalf("first attempt must leave the row behind for the retry: %v", err)
	}
	if len(rt.rehydratedEnv) != 0 {
		t.Fatalf("failed restore recorded an environment: %v", rt.rehydratedEnv)
	}

	// The retry: the placement spec is not consulted for env here (this asserts
	// the sealed row is the source of truth, not a spec that happens to repeat
	// the same values).
	rt.rehydrateErr = nil
	retrySpec := spec
	retrySpec.Env = nil
	if _, err := svc.recreateWasmDurableSandbox(ctx, id, "inc-1", retrySpec, nil); err != nil {
		t.Fatalf("retry after a failed restore: %v", err)
	}
	if len(rt.rehydratedEnv) != 1 {
		t.Fatalf("restores recorded = %d, want 1", len(rt.rehydratedEnv))
	}
	if got := rt.rehydratedEnv[0]["TOKEN"]; got != "from-cluster-secret" {
		t.Fatalf("restored environment = %v, want TOKEN=from-cluster-secret", rt.rehydratedEnv[0])
	}
}

// A row whose sealed env is missing (never written, or lost) falls back to the
// decrypted placement spec, and repairs the seal so the next restore on this
// node does not depend on the spec being available again.
func TestRecreateWasmDurableSandboxRepairsMissingSealedEnvFromSpec(t *testing.T) {
	ctx := context.Background()
	const id = "sb-failover-env-repair"
	svc, st, rt := newWasmEnvRecreateHarness(t, id)

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID:                 id,
		Runtime:            models.RuntimeWasm,
		Durability:         models.DurabilityDurable,
		ModuleRef:          "file:///tmp/demo.wasm",
		Status:             models.SandboxStatusPassivated,
		CheckpointPath:     filepath.Join(svc.cfg.WasmModulesDir, id, "mem.snap"),
		AuditIncarnationID: "inc-" + id,
		CreatedAt:          now,
		UpdatedAt:          now,
		LastActiveAt:       now,
	}); err != nil {
		t.Fatalf("seed row without sealed env: %v", err)
	}

	// The placement is the same lifetime as the seeded row.
	if _, err := svc.recreateWasmDurableSandbox(ctx, id, "inc-"+id, models.CreateSandboxRequest{
		Runtime:    models.RuntimeWasm,
		Durability: models.DurabilityDurable,
		ModuleRef:  "file:///tmp/demo.wasm",
		Env:        map[string]string{"TOKEN": "from-spec"},
	}, nil); err != nil {
		t.Fatalf("recreate with an unsealed row: %v", err)
	}
	if len(rt.rehydratedEnv) != 1 || rt.rehydratedEnv[0]["TOKEN"] != "from-spec" {
		t.Fatalf("restored environment = %v, want TOKEN=from-spec", rt.rehydratedEnv)
	}
	env, err := svc.loadEnv(ctx, id, "inc-"+id)
	if err != nil || env["TOKEN"] != "from-spec" {
		t.Fatalf("seal was not repaired: env=%v err=%v", env, err)
	}
}

// An unreadable seal is fatal on its own — restoring a sandbox without the
// credentials it was created with is worse than failing the attempt — but the
// authenticated cluster-secret bag is the same material the seal was written
// from, so when the caller has one it recovers and repairs the seal.
func TestHydrateSandboxEnvForRestoreUnreadableSeal(t *testing.T) {
	ctx := context.Background()
	const id = "sb-hydrate-unreadable"
	svc, st, _ := newWasmEnvRecreateHarness(t, id)

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: id, Runtime: models.RuntimeWasm, Durability: models.DurabilityDurable,
		Status: models.SandboxStatusPassivated, AuditIncarnationID: "inc-" + id,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutEnv(ctx, id, []byte("not-a-sealed-blob")); err != nil {
		t.Fatal(err)
	}

	unreadable := &models.Sandbox{ID: id, AuditIncarnationID: "inc-" + id}
	if err := svc.hydrateSandboxEnvForRestore(ctx, unreadable, nil); err == nil {
		t.Fatal("an unreadable seal with no fallback must fail the attempt")
	}
	if len(unreadable.Env) != 0 {
		t.Fatalf("failed hydration left an environment behind: %v", unreadable.Env)
	}

	recovered := &models.Sandbox{ID: id, AuditIncarnationID: "inc-" + id}
	if err := svc.hydrateSandboxEnvForRestore(ctx, recovered, map[string]string{"TOKEN": "from-spec"}); err != nil {
		t.Fatalf("recovery from the placement spec: %v", err)
	}
	if recovered.Env["TOKEN"] != "from-spec" {
		t.Fatalf("recovered environment = %v", recovered.Env)
	}
	env, err := svc.loadEnv(ctx, id, "inc-"+id)
	if err != nil || env["TOKEN"] != "from-spec" {
		t.Fatalf("seal was not repaired: env=%v err=%v", env, err)
	}
}

// Hydration never invents a lifecycle to seal against, and a store that cannot
// seal is reported rather than swallowed.
func TestHydrateSandboxEnvForRestoreRepairGuards(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newWasmEnvRecreateHarness(t, "sb-hydrate-guards")

	// No lifecycle to bind a seal to: hydrate in memory, write nothing.
	noIncarnation := &models.Sandbox{ID: "sb-no-incarnation"}
	if err := svc.hydrateSandboxEnvForRestore(ctx, noIncarnation, map[string]string{"TOKEN": "t"}); err != nil {
		t.Fatalf("missing incarnation must not fail hydration: %v", err)
	}
	if noIncarnation.Env["TOKEN"] != "t" {
		t.Fatalf("environment = %v", noIncarnation.Env)
	}
	if _, err := st.GetEnv(ctx, "sb-no-incarnation"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a seal was written without a lifecycle to bind it to: %v", err)
	}

	// No cipher: the repair cannot be done and must be surfaced.
	cipherless := &Service{store: st}
	if err := cipherless.hydrateSandboxEnvForRestore(ctx, &models.Sandbox{
		ID: "sb-cipherless", AuditIncarnationID: "inc-cipherless",
	}, map[string]string{"TOKEN": "t"}); err == nil {
		t.Fatal("sealing without a cipher must not report success")
	}

	// Already materialised: no store access, no overwrite.
	prefilled := &models.Sandbox{ID: "sb-prefilled", Env: map[string]string{"TOKEN": "already-here"}}
	if err := svc.hydrateSandboxEnvForRestore(ctx, prefilled, map[string]string{"TOKEN": "from-spec"}); err != nil {
		t.Fatal(err)
	}
	if prefilled.Env["TOKEN"] != "already-here" {
		t.Fatalf("hydration overwrote a materialised environment: %v", prefilled.Env)
	}
	if err := (*Service)(nil).hydrateSandboxEnvForRestore(ctx, nil, nil); err != nil {
		t.Fatalf("nil hydration: %v", err)
	}
}

// Nothing to hydrate is not an error, and a sandbox that genuinely has no
// environment must not acquire one.
func TestRecreateWasmDurableSandboxWithoutEnvStaysEmpty(t *testing.T) {
	ctx := context.Background()
	const id = "sb-failover-env-none"
	svc, st, rt := newWasmEnvRecreateHarness(t, id)

	spec := models.CreateSandboxRequest{
		Runtime:    models.RuntimeWasm,
		Durability: models.DurabilityDurable,
		ModuleRef:  "file:///tmp/demo.wasm",
	}
	rt.rehydrateErr = errors.New("restore boom")
	if _, err := svc.recreateWasmDurableSandbox(ctx, id, "inc-1", spec, nil); err == nil {
		t.Fatal("seeded restore failure did not surface")
	}
	rt.rehydrateErr = nil
	if _, err := svc.recreateWasmDurableSandbox(ctx, id, "inc-1", spec, nil); err != nil {
		t.Fatalf("retry without env: %v", err)
	}
	if len(rt.rehydratedEnv) != 1 || len(rt.rehydratedEnv[0]) != 0 {
		t.Fatalf("restored environment = %v, want empty", rt.rehydratedEnv)
	}
	// An env-less sandbox still has a row — every create writes one so that a
	// LATER missing row reads as loss rather than "no env" — but its seal
	// stays empty: the recreate must not invent ciphertext.
	blob, err := st.GetEnv(ctx, id)
	if err != nil {
		t.Fatalf("env-less sandbox lost its env row: %v", err)
	}
	if len(blob) != 0 {
		t.Fatalf("an env-less sandbox gained a %d-byte seal", len(blob))
	}
}
