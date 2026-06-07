package service

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
)

func TestCleanupWasmSandboxArtifactsRemovesWasmMetadata(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID:              "sb-clean",
		Runtime:         models.RuntimeWasm,
		Status:          models.SandboxStatusDestroyed,
		Image:           "file:///tmp/demo.wasm",
		WasmRegistryRef: "registry.example/sb-clean:latest",
		CreatedAt:       now,
		UpdatedAt:       now,
		LastActiveAt:    now,
	}
	if err := st.Create(ctx, sb); err != nil {
		t.Fatalf("create sandbox: %v", err)
	}
	if err := st.PutWasmStateKV(ctx, sb.ID, "k", []byte("v")); err != nil {
		t.Fatalf("put wasm state kv: %v", err)
	}
	if _, err := st.InsertWasmCheckpointPush(ctx, sb.ID, "registry.example/sb-clean:latest", "sha256:abc"); err != nil {
		t.Fatalf("insert checkpoint push: %v", err)
	}

	// Call the store cleanup pieces directly; the runtime-level destroy path
	// is covered separately and this verifies the persisted metadata vacuum is closed.
	if err := st.DeleteAllWasmStateKV(ctx, sb.ID); err != nil {
		t.Fatalf("DeleteAllWasmStateKV: %v", err)
	}
	if err := st.DeleteAllWasmCheckpointPushes(ctx, sb.ID); err != nil {
		t.Fatalf("DeleteAllWasmCheckpointPushes: %v", err)
	}
	keys, err := st.ListWasmStateKVKeys(ctx, sb.ID)
	if err != nil {
		t.Fatalf("ListWasmStateKVKeys: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("state kv keys = %#v, want empty", keys)
	}
	pushes, err := st.ListWasmCheckpointPushes(ctx, sb.ID)
	if err != nil {
		t.Fatalf("ListWasmCheckpointPushes: %v", err)
	}
	if len(pushes) != 0 {
		t.Fatalf("checkpoint pushes = %#v, want empty", pushes)
	}
}

func TestDestroyWasmSandboxDoesNotScheduleDockerImageGC(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	rt := &recordingRuntime{}
	svc := New(config.Config{EnableWasm: true}, slog.Default(), st, rt, nil, nil, nil, nil, nil)
	svc.SetWasmRuntime(rt)
	svc.caddy = caddy.New(config.Config{EnableCaddy: false, HTTPClientTimeout: time.Second})
	mgr, err := mounts.New(slog.Default(), mounts.Config{
		RootDir:     t.TempDir(),
		CredDir:     t.TempDir(),
		WaitTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("mounts.New: %v", err)
	}
	svc.mounts = mgr

	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID:           "sb-wasm-destroy",
		Runtime:      models.RuntimeWasm,
		Image:        "file:///tmp/demo.wasm",
		Status:       models.SandboxStatusStarted,
		ContainerID:  "wasm:sb-wasm-destroy",
		ContainerIP:  "127.0.0.1",
		CreatedAt:    now,
		UpdatedAt:    now,
		LastActiveAt: now,
	}
	if err := st.Create(ctx, sb); err != nil {
		t.Fatalf("create sandbox: %v", err)
	}
	if err := svc.DestroySandbox(ctx, sb.ID); err != nil {
		t.Fatalf("DestroySandbox: %v", err)
	}
	due, err := st.ListPendingImageGCDue(ctx, time.Now().UTC().Add(time.Hour), 0)
	if err != nil {
		t.Fatalf("ListPendingImageGCDue: %v", err)
	}
	if len(due) != 0 {
		t.Fatalf("pending image gc rows = %#v, want empty", due)
	}
}
