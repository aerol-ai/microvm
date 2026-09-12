package service

import (
	"context"
	"testing"
	"time"
)

func TestStartWasmDurablePushSweepWave23(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.StartWasmDurablePushSweep(context.Background())
	svc.cfg.WasmDurablePushInterval = 0
	svc.wasmCheckpointPusher = &wasmCheckpointPusherStub{}
	svc.StartWasmDurablePushSweep(context.Background())
	svc.cfg.WasmDurablePushInterval = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	svc.StartWasmDurablePushSweep(ctx)
	cancel()
}
