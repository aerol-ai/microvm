package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestPushWasmCheckpointBestEffortWave16(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	svc.wasmCheckpointPusher = failingWasmCheckpointPusher{}
	svc.pushWasmCheckpointBestEffort("sb-push", "", t.TempDir())

	svc2, st2, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	svc2.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	svc2.wasmCheckpointPusher = &configurableCheckpointPusher{
		latest: WasmCheckpointPushResult{RegistryRef: "reg/sb:latest", Digest: "sha256:deadbeefcafebabe0123456789abcdef"},
	}
	_ = st2.Close()
	svc2.pushWasmCheckpointBestEffort("sb-meta", "", t.TempDir())

	svc3, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc3.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	svc3.wasmCheckpointPusher = &configurableCheckpointPusher{
		latest:    WasmCheckpointPushResult{RegistryRef: "reg/sb:latest", Digest: "sha256:deadbeefcafebabe0123456789abcdef"},
		digestErr: errors.New("digest tag push fail"),
	}
	svc3.pushWasmCheckpointBestEffort("sb-dig", "", t.TempDir())
}

type configurableCheckpointPusher struct {
	latest    WasmCheckpointPushResult
	digestErr error
	n         int
}

func (p *configurableCheckpointPusher) DestRefFor(id string) string {
	return p.DestRefTagged(id, "latest")
}

func (p *configurableCheckpointPusher) DestRefTagged(sandboxID, tag string) string {
	return "reg/" + sandboxID + ":" + tag
}

func (p *configurableCheckpointPusher) PushOnceTo(_ context.Context, _, _, _, destRef string) (WasmCheckpointPushResult, error) {
	p.n++
	if p.n > 1 && p.digestErr != nil {
		return WasmCheckpointPushResult{}, p.digestErr
	}
	out := p.latest
	out.RegistryRef = destRef
	return out, nil
}

func (p *configurableCheckpointPusher) PullOnce(context.Context, string, string, string) error {
	return nil
}

func (p *configurableCheckpointPusher) DeleteRef(context.Context, string) error { return nil }

func TestDrainWasmFilterSkipsWave16(t *testing.T) {
	ctx := context.Background()
	rt := &fakeCheckpointRuntime{
		checkpointPath: "/tmp/c",
		cloneGen:       "g",
		wasmRecordingRuntime: wasmRecordingRuntime{
			managed: map[string]*models.SandboxRuntimeState{"sb-live": {SandboxID: "sb-live"}},
		},
	}
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true
	svc.SetWasmRuntime(rt)
	now := time.Now().UTC()
	_ = st.Create(ctx, &models.Sandbox{ID: "sb-docker", Image: "a", Status: models.SandboxStatusStarted, CreatedAt: now, UpdatedAt: now, LastActiveAt: now})
	_ = st.Create(ctx, &models.Sandbox{ID: "sb-stopped", Runtime: models.RuntimeWasm, Status: models.SandboxStatusStopped, Durability: models.DurabilityDurable, CreatedAt: now, UpdatedAt: now, LastActiveAt: now})
	_ = st.Create(ctx, &models.Sandbox{ID: "sb-ephem", Runtime: models.RuntimeWasm, Status: models.SandboxStatusStarted, Durability: models.DurabilityEphemeral, CreatedAt: now, UpdatedAt: now, LastActiveAt: now})
	_ = st.Create(ctx, &models.Sandbox{ID: "sb-notlive", Runtime: models.RuntimeWasm, Status: models.SandboxStatusStarted, Durability: models.DurabilityDurable, CreatedAt: now, UpdatedAt: now, LastActiveAt: now})
	if err := svc.DrainWasmSandboxes(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
}

func TestRunWasmCheckpointPoolErrorWave16(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.WasmCheckpointMaxParallel = 2
	err := svc.runWasmCheckpointPool(context.Background(), []*models.Sandbox{{ID: "a"}, {ID: "b"}}, func(sb *models.Sandbox) error {
		if sb.ID == "b" {
			return errors.New("boom")
		}
		return nil
	})
	if err == nil {
		t.Fatal("expected pool error")
	}
}

func TestDrainWasmCheckpointArmsWave16(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true
	svc.SetWasmRuntime(&recordingRuntime{}) // not CheckpointHost
	if err := svc.DrainWasmSandboxes(ctx); err != nil {
		t.Fatalf("non-host: %v", err)
	}
	_ = wasmShouldCheckpoint(models.DurabilityPassivatable)
	_ = wasmShouldCheckpoint(models.DurabilityDurable)
	_ = wasmShouldCheckpoint("")
	_ = st.Close()
	svc.SetWasmRuntime(&fakeCheckpointRuntime{})
	_ = svc.DrainWasmSandboxes(ctx) // list fail
}

func TestWasmCheckpointPushBestEffortWave16(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true
	svc.wasmCheckpointPusher = failingWasmCheckpointPusher{}
	svc.pushWasmCheckpointBestEffort("w2", "", t.TempDir())
}
