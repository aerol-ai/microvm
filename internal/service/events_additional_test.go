package service

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

func newEventMonitorDockerClient(t *testing.T, handler http.Handler) *docker.Client {
	t.Helper()
	socketPath := fmt.Sprintf("/tmp/aerolvm-events-%d.sock", time.Now().UnixNano())
	_ = os.Remove(socketPath)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix socket: %v", err)
	}
	server := &http.Server{Handler: handler}
	go func() {
		_ = server.Serve(listener)
	}()
	t.Cleanup(func() {
		_ = server.Close()
		_ = listener.Close()
		_ = os.Remove(socketPath)
	})
	t.Setenv("DOCKER_HOST", "unix://"+socketPath)

	client, err := docker.New(slog.New(slog.NewTextHandler(io.Discard, nil)), config.Config{
		ToolboxBinaryPath: "toolboxd",
		HTTPClientTimeout: time.Second,
	}, nil)
	if err != nil {
		t.Fatalf("docker.New: %v", err)
	}
	return client
}

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

func TestStartEventMonitorDisabledSkipsDockerStream(t *testing.T) {
	var requests atomic.Int32
	client := newEventMonitorDockerClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))

	svc, _, _ := newCapacityHarness(t, nil, nil)
	svc.events = client
	svc.cfg.EnableEventMonitor = false

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc.StartEventMonitor(ctx)
	time.Sleep(50 * time.Millisecond)

	if got := requests.Load(); got != 0 {
		t.Fatalf("docker event requests = %d, want 0 when monitor disabled", got)
	}
}

func TestStartEventMonitorReconnectsAfterStreamError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	svc, admitter, st := newCapacityHarness(t, nil, nil)
	const sandboxID = "sb-event-reconnect"
	seedSandbox(t, st, sandboxID, models.SandboxStatusStarted, 2, 2048)
	admitter.Reserve(sandboxID, capacity.Request{CPU: 2, MemoryMB: 2048})

	firstRequest := make(chan struct{}, 1)
	secondRequest := make(chan struct{}, 1)
	var requests atomic.Int32
	client := newEventMonitorDockerClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/events" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		switch requests.Add(1) {
		case 1:
			firstRequest <- struct{}{}
			http.Error(w, "boom", http.StatusInternalServerError)
		case 2:
			secondRequest <- struct{}{}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"stop","id":"ctr-event-reconnect","time":1716336000,"Actor":{"Attributes":{"name":"/sb-event-reconnect"}}}` + "\n"))
		default:
			http.Error(w, "unexpected extra request", http.StatusInternalServerError)
		}
	}))
	svc.events = client
	svc.cfg.EnableEventMonitor = true

	svc.StartEventMonitor(ctx)

	select {
	case <-firstRequest:
	case <-time.After(2 * time.Second):
		t.Fatal("first docker /events request did not arrive")
	}
	select {
	case <-secondRequest:
	case <-time.After(2500 * time.Millisecond):
		t.Fatal("second docker /events request did not arrive after reconnect backoff")
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		got, err := st.Get(ctx, sandboxID)
		if err != nil {
			t.Fatalf("store.Get: %v", err)
		}
		if got.Status == models.SandboxStatusStopped {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("sandbox status = %q, want stopped after streamed event", got.Status)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if snap := admitter.Snapshot(); snap.SandboxesActive != 0 {
		t.Fatalf("admitter snapshot = %+v, want released capacity after streamed stop event", snap)
	}
	if got := requests.Load(); got < 2 {
		t.Fatalf("docker event requests = %d, want at least 2", got)
	}
	cancel()
}

type failingInspectRuntime struct {
	*recordingRuntime
	err error
}

func (r failingInspectRuntime) Inspect(context.Context, string) (*models.SandboxRuntimeState, error) {
	return nil, r.err
}

func TestHandleDockerEventErrorBranches(t *testing.T) {
	ctx := context.Background()

	t.Run("store error", func(t *testing.T) {
		svc, _, st := newCapacityHarness(t, nil, nil)
		if err := st.Close(); err != nil {
			t.Fatalf("store.Close: %v", err)
		}
		if err := svc.handleDockerEvent(ctx, dockerEvent("sb-missing", "stop")); err == nil {
			t.Fatal("handleDockerEvent should fail when the store is closed")
		}
	})

	t.Run("oom and exit codes update last error", func(t *testing.T) {
		svc, admitter, st := newCapacityHarness(t, nil, nil)
		seedSandbox(t, st, "sb-oom", models.SandboxStatusStarted, 1, 512)
		admitter.Reserve("sb-oom", capacity.Request{CPU: 1, MemoryMB: 512})

		if err := svc.handleDockerEvent(ctx, docker.DockerEvent{SandboxID: "sb-oom", Action: "oom", Time: time.Now().UTC()}); err != nil {
			t.Fatalf("oom event: %v", err)
		}
		got, err := st.Get(ctx, "sb-oom")
		if err != nil {
			t.Fatalf("store.Get: %v", err)
		}
		if got.LastError != "container killed by OOM" {
			t.Fatalf("oom last error = %q, want OOM message", got.LastError)
		}

		seedSandbox(t, st, "sb-die", models.SandboxStatusStarted, 1, 512)
		admitter.Reserve("sb-die", capacity.Request{CPU: 1, MemoryMB: 512})
		if err := svc.handleDockerEvent(ctx, docker.DockerEvent{SandboxID: "sb-die", Action: "die", ExitCode: 7, Time: time.Now().UTC()}); err != nil {
			t.Fatalf("die event: %v", err)
		}
		got, err = st.Get(ctx, "sb-die")
		if err != nil {
			t.Fatalf("store.Get: %v", err)
		}
		if got.LastError != "container exited with code 7" {
			t.Fatalf("die last error = %q, want exit code message", got.LastError)
		}
	})

	t.Run("destroy and start edge cases", func(t *testing.T) {
		svc, admitter, st := newCapacityHarness(t, nil, nil)
		seedSandbox(t, st, "sb-destroy", models.SandboxStatusStarted, 1, 512)
		admitter.Reserve("sb-destroy", capacity.Request{CPU: 1, MemoryMB: 512})
		if err := svc.handleDockerEvent(ctx, dockerEvent("sb-destroy", "destroy")); err != nil {
			t.Fatalf("destroy event: %v", err)
		}
		if _, err := st.Get(ctx, "sb-destroy"); err == nil {
			t.Fatal("destroy should remove the sandbox row")
		}

		svc.docker = failingInspectRuntime{recordingRuntime: &recordingRuntime{}, err: fmt.Errorf("inspect failed")}
		seedSandbox(t, st, "sb-start", models.SandboxStatusStopped, 1, 512)
		if err := svc.handleDockerEvent(ctx, docker.DockerEvent{SandboxID: "sb-start", Action: "start", Time: time.Now().UTC()}); err == nil {
			t.Fatal("start event should fail when inspect fails")
		}
	})
}
