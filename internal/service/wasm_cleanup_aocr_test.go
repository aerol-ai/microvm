package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"sort"
	"testing"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// recordingWasmCheckpointStore records DeleteRef calls so the test can assert
// every AOCR ref a sandbox ever pushed is torn down on cleanup.
type recordingWasmCheckpointStore struct {
	deleted []string
}

func (r *recordingWasmCheckpointStore) DestRefFor(id string) string {
	return r.DestRefTagged(id, "latest")
}

func (r *recordingWasmCheckpointStore) DestRefTagged(id, tag string) string {
	return "aocr://" + id + ":" + tag
}

func (r *recordingWasmCheckpointStore) PushOnceTo(context.Context, string, string, string) (WasmCheckpointPushResult, error) {
	return WasmCheckpointPushResult{}, nil
}

func (r *recordingWasmCheckpointStore) PullOnce(context.Context, string, string) error { return nil }

func (r *recordingWasmCheckpointStore) DeleteRef(_ context.Context, ref string) error {
	r.deleted = append(r.deleted, ref)
	return nil
}

type failingDeleteWasmCheckpointStore struct {
	recordingWasmCheckpointStore
}

func (f *failingDeleteWasmCheckpointStore) DeleteRef(context.Context, string) error {
	return errors.New("delete ref failed")
}

func newAOCRCleanupTestService(t *testing.T) (*Service, *store.Store, *recordingWasmCheckpointStore) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	pusher := &recordingWasmCheckpointStore{}
	svc := &Service{
		logger:               slog.New(slog.NewTextHandler(io.Discard, nil)),
		store:                st,
		wasmCheckpointPusher: pusher,
	}
	return svc, st, pusher
}

// TestCleanupWasmSandboxArtifacts_DeletesAllAOCRRefs is the B#1 regression test:
// destroy must delete every retained checkpoint manifest (all keep-last-N digest
// tags + :latest), not just sandbox.WasmRegistryRef, BEFORE dropping the
// push-history rows — otherwise the older manifests leak in the registry with no
// record left to GC them by. It also asserts the host-KV + push-row teardown.
func TestCleanupWasmSandboxArtifacts_DeletesAllAOCRRefs(t *testing.T) {
	svc, st, pusher := newAOCRCleanupTestService(t)
	ctx := context.Background()

	const id = "wasm-1"
	sb := &models.Sandbox{
		ID:              id,
		Image:           "registry/foo:wasm",
		Runtime:         models.RuntimeWasm,
		Status:          models.SandboxStatusPassivated,
		Durability:      models.DurabilityDurable,
		ModuleRef:       "registry/foo:wasm",
		WasmRegistryRef: "aocr://" + id + ":sha256-newest",
	}
	if err := st.Create(ctx, sb); err != nil {
		t.Fatalf("store.Create: %v", err)
	}

	// Three distinct digest-tagged pushes (keep-last-N history). The oldest two
	// are NOT the current WasmRegistryRef and would leak under the naive fix that
	// only deletes WasmRegistryRef.
	pushRefs := []string{
		"aocr://" + id + ":sha256-old1",
		"aocr://" + id + ":sha256-old2",
		"aocr://" + id + ":sha256-newest",
	}
	for _, ref := range pushRefs {
		if _, err := st.InsertWasmCheckpointPush(ctx, id, ref, "digest-of-"+ref); err != nil {
			t.Fatalf("InsertWasmCheckpointPush: %v", err)
		}
	}

	if err := st.PutWasmStateKV(ctx, id, "counter", []byte("42")); err != nil {
		t.Fatalf("PutWasmStateKV: %v", err)
	}
	if err := st.PutWasmStateKV(ctx, id, "cursor", []byte("abc")); err != nil {
		t.Fatalf("PutWasmStateKV: %v", err)
	}

	if err := svc.cleanupWasmSandboxArtifacts(ctx, sb); err != nil {
		t.Fatalf("cleanupWasmSandboxArtifacts: %v", err)
	}

	got := append([]string(nil), pusher.deleted...)
	sort.Strings(got)
	want := []string{
		"aocr://" + id + ":latest",
		"aocr://" + id + ":sha256-newest",
		"aocr://" + id + ":sha256-old1",
		"aocr://" + id + ":sha256-old2",
	}
	if len(got) != len(want) {
		t.Fatalf("deleted refs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("deleted refs = %v, want %v", got, want)
		}
	}

	pushes, err := st.ListWasmCheckpointPushes(ctx, id)
	if err != nil {
		t.Fatalf("ListWasmCheckpointPushes: %v", err)
	}
	if len(pushes) != 0 {
		t.Fatalf("push history not cleared: %d rows remain", len(pushes))
	}

	keys, err := st.ListWasmStateKVKeys(ctx, id)
	if err != nil {
		t.Fatalf("ListWasmStateKVKeys: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("state kv not cleared: %v", keys)
	}
}

// TestCleanupWasmSandboxArtifacts_NonWasmNoop confirms the cleanup is inert for
// docker/firecracker sandboxes so the shared destroy path is unaffected.
func TestCleanupWasmSandboxArtifacts_NonWasmNoop(t *testing.T) {
	svc, st, pusher := newAOCRCleanupTestService(t)
	ctx := context.Background()

	const id = "docker-1"
	if err := st.PutWasmStateKV(ctx, id, "k", []byte("v")); err != nil {
		t.Fatalf("PutWasmStateKV: %v", err)
	}

	sb := &models.Sandbox{ID: id, Runtime: models.RuntimeDocker, Status: models.SandboxStatusStarted}
	if err := svc.cleanupWasmSandboxArtifacts(ctx, sb); err != nil {
		t.Fatalf("cleanupWasmSandboxArtifacts: %v", err)
	}
	if len(pusher.deleted) != 0 {
		t.Fatalf("non-wasm cleanup deleted refs: %v", pusher.deleted)
	}
	keys, err := st.ListWasmStateKVKeys(ctx, id)
	if err != nil {
		t.Fatalf("ListWasmStateKVKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("non-wasm cleanup touched kv rows: %v", keys)
	}
}

// flakyDeleteWasmCheckpointStore fails the first failBudget DeleteRef calls,
// then succeeds. Lets the test prove a transient registry failure retains the
// tracking row (no premature drop) and the orphan-ref sweep reclaims it later.
type flakyDeleteWasmCheckpointStore struct {
	recordingWasmCheckpointStore
	failBudget int
}

func (f *flakyDeleteWasmCheckpointStore) DeleteRef(_ context.Context, ref string) error {
	if f.failBudget > 0 {
		f.failBudget--
		return errors.New("transient registry failure")
	}
	f.deleted = append(f.deleted, ref)
	return nil
}

// TestCleanupWasmSandboxArtifacts_NoVacuumOnDeleteFailure is the regression test
// for the data-vacuum fix: when a registry DeleteRef fails transiently, destroy
// must NOT drop the push-history row (doing so would strand the manifest with no
// record left to GC by — a permanent leak). The row is retained, and once the
// sandbox itself is gone the orphan-ref sweep retries the delete and reclaims
// the row, leaving zero vacuum.
func TestCleanupWasmSandboxArtifacts_NoVacuumOnDeleteFailure(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	// Every DeleteRef during cleanup fails; the per-digest tracking row must
	// survive so the sweep can retry it.
	pusher := &flakyDeleteWasmCheckpointStore{failBudget: 1 << 30}
	svc := &Service{
		logger:               slog.New(slog.NewTextHandler(io.Discard, nil)),
		store:                st,
		wasmCheckpointPusher: pusher,
	}
	ctx := context.Background()

	const id = "wasm-leak"
	sb := &models.Sandbox{
		ID: id, Image: "registry/foo:wasm", Runtime: models.RuntimeWasm,
		Status: models.SandboxStatusPassivated, Durability: models.DurabilityDurable,
		ModuleRef: "registry/foo:wasm", WasmRegistryRef: "aocr://" + id + ":sha256-x",
	}
	if err := st.Create(ctx, sb); err != nil {
		t.Fatalf("store.Create: %v", err)
	}
	if _, err := st.InsertWasmCheckpointPush(ctx, id, "aocr://"+id+":sha256-x", "d"); err != nil {
		t.Fatalf("InsertWasmCheckpointPush: %v", err)
	}

	if err := svc.cleanupWasmSandboxArtifacts(ctx, sb); err != nil {
		t.Fatalf("cleanupWasmSandboxArtifacts: %v", err)
	}
	// The failed delete must have RETAINED the tracking row.
	pushes, err := st.ListWasmCheckpointPushes(ctx, id)
	if err != nil {
		t.Fatalf("ListWasmCheckpointPushes: %v", err)
	}
	if len(pushes) != 1 {
		t.Fatalf("failed DeleteRef should retain the tracking row, got %d rows", len(pushes))
	}

	// Sandbox row goes away (destroy completes). The row is now orphaned but the
	// sweep should not yet reclaim it while DeleteRef keeps failing.
	if err := st.Delete(ctx, id); err != nil {
		t.Fatalf("store.Delete: %v", err)
	}
	orphans, err := st.ListOrphanedWasmCheckpointPushes(ctx, 0)
	if err != nil {
		t.Fatalf("ListOrphanedWasmCheckpointPushes: %v", err)
	}
	if len(orphans) != 1 {
		t.Fatalf("expected 1 orphaned push row, got %d", len(orphans))
	}
	svc.runWasmOrphanRefSweep(ctx) // DeleteRef still failing → row retained
	if orphans, _ := st.ListOrphanedWasmCheckpointPushes(ctx, 0); len(orphans) != 1 {
		t.Fatalf("orphan row must survive a failed sweep, got %d", len(orphans))
	}

	// Registry recovers: the next sweep deletes the ref and drops the row.
	pusher.failBudget = 0
	svc.runWasmOrphanRefSweep(ctx)
	if orphans, _ := st.ListOrphanedWasmCheckpointPushes(ctx, 0); len(orphans) != 0 {
		t.Fatalf("orphan-ref sweep must reclaim the row once DeleteRef succeeds, got %d", len(orphans))
	}
	if len(pusher.deleted) != 1 || pusher.deleted[0] != "aocr://"+id+":sha256-x" {
		t.Fatalf("sweep deleted refs = %v, want the retained per-digest ref", pusher.deleted)
	}
}

func TestCleanupWasmSandboxArtifacts_ErrorBranches(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newAOCRCleanupTestService(t)
	svc.wasmCheckpointPusher = &failingDeleteWasmCheckpointStore{}
	_ = st.Close()

	sb := &models.Sandbox{
		ID:              "wasm-err",
		Image:           "registry/foo:wasm",
		Runtime:         models.RuntimeWasm,
		Status:          models.SandboxStatusPassivated,
		Durability:      models.DurabilityDurable,
		ModuleRef:       "registry/foo:wasm",
		WasmRegistryRef: "aocr://wasm-err:sha256-newest",
	}
	if err := svc.cleanupWasmSandboxArtifacts(ctx, sb); err == nil {
		t.Fatal("cleanupWasmSandboxArtifacts should return a store error when the DB is closed")
	}
}
