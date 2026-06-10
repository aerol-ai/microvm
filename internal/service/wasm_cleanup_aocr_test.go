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
