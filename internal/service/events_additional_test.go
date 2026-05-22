package service

import (
	"context"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestConsumeEventsProcessesStopEvent(t *testing.T) {
	ctx := context.Background()
	svc, admitter, st := newCapacityHarness(t, nil, nil)

	const sandboxID = "sb-consume-stop"
	seedSandbox(t, st, sandboxID, models.SandboxStatusStarted, 2, 2048)
	admitter.Reserve(sandboxID, capacity.Request{CPU: 2, MemoryMB: 2048})

	events := make(chan docker.DockerEvent, 1)
	events <- docker.DockerEvent{SandboxID: sandboxID, Action: "stop", Time: time.Now().UTC()}
	close(events)

	svc.consumeEvents(ctx, events)

	got, err := st.Get(ctx, sandboxID)
	if err != nil {
		t.Fatalf("store.Get() error = %v", err)
	}
	if got.Status != models.SandboxStatusStopped {
		t.Fatalf("sandbox status = %q, want stopped", got.Status)
	}
	if snap := admitter.Snapshot(); snap.SandboxesActive != 0 {
		t.Fatalf("admitter snapshot = %+v, want released capacity", snap)
	}
}

func TestConsumeEventsReturnsWhenContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	svc, admitter, st := newCapacityHarness(t, nil, nil)

	const sandboxID = "sb-consume-canceled"
	seedSandbox(t, st, sandboxID, models.SandboxStatusStarted, 1, 1024)
	admitter.Reserve(sandboxID, capacity.Request{CPU: 1, MemoryMB: 1024})

	events := make(chan docker.DockerEvent, 1)
	events <- docker.DockerEvent{SandboxID: sandboxID, Action: "stop", Time: time.Now().UTC()}
	close(events)
	cancel()

	svc.consumeEvents(ctx, events)

	got, err := st.Get(context.Background(), sandboxID)
	if err != nil {
		t.Fatalf("store.Get() error = %v", err)
	}
	if got.Status != models.SandboxStatusStarted {
		t.Fatalf("sandbox status = %q, want unchanged started", got.Status)
	}
	if snap := admitter.Snapshot(); snap.SandboxesActive != 1 {
		t.Fatalf("admitter snapshot = %+v, want reservation unchanged", snap)
	}
}
