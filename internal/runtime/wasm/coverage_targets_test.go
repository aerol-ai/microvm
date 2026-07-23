package wasm

// coverage_targets_test.go exercises wasm driver functions that were at 0%
// before this file:
//   - healthCheckResidentHost (both error and success paths)
//   - RunResidentReaper (disabled-by-flag path and cancellation path)
//   - noteWorkerSpawnCount (nil, with counter, without counter)

import (
	"context"
	"errors"
	"testing"
	"time"

	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

// -------------------------------------------------------------------
// healthCheckResidentHost
// -------------------------------------------------------------------

// instanceLoadedFailClient makes InstanceLoaded always return an error.
type instanceLoadedFailClient struct {
	recordingWorkerClient
}

func (c *instanceLoadedFailClient) InstanceLoaded(_ context.Context, _ string) (bool, error) {
	return false, errors.New("host unreachable")
}

// instanceLoadedFalseClient returns loaded=false (module not compiled yet).
type instanceLoadedFalseClient struct {
	recordingWorkerClient
}

func (c *instanceLoadedFalseClient) InstanceLoaded(_ context.Context, _ string) (bool, error) {
	return false, nil
}

// instanceLoadedOKClient returns loaded=true — healthy resident host.
type instanceLoadedOKClient struct {
	recordingWorkerClient
}

func (c *instanceLoadedOKClient) InstanceLoaded(_ context.Context, _ string) (bool, error) {
	return true, nil
}

func TestHealthCheckResidentHost_Error(t *testing.T) {
	d, _, _, _ := residentTestDriver(t, true)
	d.SetWorkerClientFactory(func(string) WorkerClient { return &instanceLoadedFailClient{} })

	h := &residentHost{socket: "fake.sock", ready: true}
	err := d.healthCheckResidentHost(context.Background(), h, "bucket-id")
	if err == nil {
		t.Fatal("healthCheckResidentHost should error when InstanceLoaded fails")
	}
}

func TestHealthCheckResidentHost_NotLoaded(t *testing.T) {
	d, _, _, _ := residentTestDriver(t, true)
	d.SetWorkerClientFactory(func(string) WorkerClient { return &instanceLoadedFalseClient{} })

	h := &residentHost{socket: "fake.sock", ready: true}
	err := d.healthCheckResidentHost(context.Background(), h, "bucket-id")
	if err == nil {
		t.Fatal("healthCheckResidentHost should error when module is not loaded")
	}
}

func TestHealthCheckResidentHost_Success(t *testing.T) {
	d, _, _, _ := residentTestDriver(t, true)
	d.SetWorkerClientFactory(func(string) WorkerClient { return &instanceLoadedOKClient{} })

	h := &residentHost{socket: "fake.sock", ready: true}
	if err := d.healthCheckResidentHost(context.Background(), h, "bucket-id"); err != nil {
		t.Fatalf("healthCheckResidentHost should succeed: %v", err)
	}
}

// When the context already carries a deadline the inner guard should not create
// a new one — exercises the !ok branch inside healthCheckResidentHost.
func TestHealthCheckResidentHost_ContextWithDeadline(t *testing.T) {
	d, _, _, _ := residentTestDriver(t, true)
	d.SetWorkerClientFactory(func(string) WorkerClient { return &instanceLoadedOKClient{} })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	h := &residentHost{socket: "fake.sock", ready: true}
	if err := d.healthCheckResidentHost(ctx, h, "bucket-id"); err != nil {
		t.Fatalf("healthCheckResidentHost with deadline context: %v", err)
	}
}

// -------------------------------------------------------------------
// RunResidentReaper
// -------------------------------------------------------------------

// TestRunResidentReaper_DisabledByTTL ensures a non-positive TTL returns
// immediately (the ttl<=0 guard).
func TestRunResidentReaper_DisabledByTTL(t *testing.T) {
	d, _, _, _ := residentTestDriver(t, true)

	done := make(chan struct{})
	go func() {
		d.RunResidentReaper(context.Background(), 0)
		close(done)
	}()
	select {
	case <-done:
		// good — returned immediately
	case <-time.After(500 * time.Millisecond):
		t.Fatal("RunResidentReaper(ttl=0) did not return immediately")
	}
}

// TestRunResidentReaper_DisabledByFlag: resident host flag off → returns
// immediately regardless of TTL.
func TestRunResidentReaper_DisabledByFlag(t *testing.T) {
	d, _, _, _ := residentTestDriver(t, false)

	done := make(chan struct{})
	go func() {
		d.RunResidentReaper(context.Background(), 10*time.Second)
		close(done)
	}()
	select {
	case <-done:
		// good — flag off → immediate return
	case <-time.After(500 * time.Millisecond):
		t.Fatal("RunResidentReaper with flag off did not return immediately")
	}
}

// TestRunResidentReaper_CancellationStops confirms the reaper exits when the
// context is cancelled (the ctx.Done() select arm).
func TestRunResidentReaper_CancellationStops(t *testing.T) {
	d, _, _, _ := residentTestDriver(t, true)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		// Large TTL so no actual reaping happens; we want the goroutine to
		// enter the ticker-loop and then exit on cancel.
		d.RunResidentReaper(ctx, 10*time.Minute)
		close(done)
	}()

	// Give the goroutine a moment to enter the select, then cancel.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// good
	case <-time.After(2 * time.Second):
		t.Fatal("RunResidentReaper did not stop after context cancellation")
	}
}

// -------------------------------------------------------------------
// noteWorkerSpawnCount
// -------------------------------------------------------------------

// spawnCountSupervisor implements WorkerSupervisorSpawnCounter.
type spawnCountSupervisor struct {
	fakeSupervisor
	count int
}

func (s *spawnCountSupervisor) SpawnCount(_ string) int { return s.count }

func TestNoteWorkerSpawnCount_WithCounter(t *testing.T) {
	d, _, _, _ := residentTestDriver(t, false)
	sup := &spawnCountSupervisor{count: 3}
	d.SetWorkerSupervisor(sup)
	inst := &sandboxInstance{sandboxID: "sb-1"}
	d.noteWorkerSpawnCount(inst)
	// SpawnCount returns 3 so inst.workerSpawnCount should be 3.
	if inst.workerSpawnCount != 3 {
		t.Fatalf("workerSpawnCount = %d, want 3", inst.workerSpawnCount)
	}
}

func TestNoteWorkerSpawnCount_WithoutCounter(t *testing.T) {
	d, _, _, _ := residentTestDriver(t, false)
	// fakeSupervisor does NOT implement SpawnCounter → no-op.
	inst := &sandboxInstance{sandboxID: "sb-2"}
	d.noteWorkerSpawnCount(inst)
}

func TestNoteWorkerSpawnCount_NilInst(t *testing.T) {
	d, _, _, _ := residentTestDriver(t, false)
	d.noteWorkerSpawnCount(nil) // must not panic
}

// keep wasmengine import active
var _ wasmengine.Capabilities
