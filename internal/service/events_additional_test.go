package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
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

func TestEventMonitorProcessesStartAndDestroyStream(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	svc, _, st := newCapacityHarness(t, nil, map[string]*models.SandboxRuntimeState{
		"ctr-stream-event": {
			SandboxID:   "sb-stream-event",
			ContainerID: "ctr-stream-event",
			ContainerIP: "10.0.0.88",
			Status:      models.SandboxStatusStarted,
		},
	})
	seedSandbox(t, st, "sb-stream-event", models.SandboxStatusStopped, 2, 1024)
	if err := st.UpsertPort(ctx, models.ExposedPort{
		SandboxID: "sb-stream-event",
		Port:      8080,
		Protocol:  models.ExposedPortProtocolHTTP,
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("UpsertPort(http): %v", err)
	}
	if err := st.UpsertPort(ctx, models.ExposedPort{
		SandboxID: "sb-stream-event",
		Port:      5432,
		Protocol:  models.ExposedPortProtocolTCP,
		HostPort:  25432,
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("UpsertPort(tcp): %v", err)
	}

	var requests atomic.Int32
	client := newEventMonitorDockerClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/events" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if requests.Add(1) > 1 {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"start","id":"ctr-stream-event","time":1716336000,"Actor":{"Attributes":{"name":"/sb-stream-event"}}}` + "\n"))
		_, _ = w.Write([]byte(`{"status":"destroy","id":"ctr-stream-event","time":1716336001,"Actor":{"Attributes":{"name":"/sb-stream-event"}}}` + "\n"))
	}))
	svc.events = client
	svc.cfg.EnableEventMonitor = true

	svc.StartEventMonitor(ctx)

	deadline := time.Now().Add(2 * time.Second)
	for {
		_, err := st.Get(ctx, "sb-stream-event")
		if err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("sandbox row still present after streamed destroy event")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
}

func TestRunEventMonitorCanceledContextReturnsImmediately(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	svc := &Service{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	svc.runEventMonitor(ctx)
}

type failingInspectRuntime struct {
	*recordingRuntime
	err error
}

func (r failingInspectRuntime) Inspect(context.Context, string) (*models.SandboxRuntimeState, error) {
	return nil, r.err
}

type failingClearRuntime struct {
	*recordingRuntime
	err error
}

func (r failingClearRuntime) ClearNetworkRules(string) error {
	return r.err
}

type closingWasmCheckpointStore struct {
	recordingWasmCheckpointStore
	store *store.Store
}

func (s *closingWasmCheckpointStore) DeleteRef(context.Context, string) error {
	if s.store != nil {
		_ = s.store.Close()
		s.store = nil
	}
	return nil
}

func setMountRootDir(t *testing.T, mgr *mounts.Manager, root string) {
	t.Helper()
	rv := reflect.ValueOf(mgr).Elem().FieldByName("rootDir")
	reflect.NewAt(rv.Type(), unsafe.Pointer(rv.UnsafeAddr())).Elem().SetString(root)
}

func newAlwaysDeleteCaddy(t *testing.T) *caddy.Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodDelete:
			http.Error(w, "boom", http.StatusInternalServerError)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(server.Close)
	return caddy.New(config.Config{
		CaddyAdminURL:     server.URL,
		CaddyServerID:     "srv0",
		EnableCaddy:       true,
		HTTPClientTimeout: 50 * time.Millisecond,
	})
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

func TestHandleDockerEventRouteErrorBranches(t *testing.T) {
	ctx := context.Background()
	svc, admitter, st := newCapacityHarness(t, nil, nil)
	svc.caddy = caddy.New(config.Config{
		CaddyAdminURL:     "http://127.0.0.1:1",
		CaddyServerID:     "srv0",
		EnableCaddy:       true,
		HTTPClientTimeout: 50 * time.Millisecond,
	})

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID:           "sb-destroy-route",
		Image:        "alpine",
		Status:       models.SandboxStatusStarted,
		ContainerID:  "ctr-destroy-route",
		ContainerIP:  "10.0.0.99",
		Runtime:      models.RuntimeDocker,
		CPU:          1,
		MemoryMB:     512,
		CreatedAt:    now,
		UpdatedAt:    now,
		LastActiveAt: now,
	}); err != nil {
		t.Fatalf("seed destroy sandbox: %v", err)
	}
	if err := st.UpsertPort(ctx, models.ExposedPort{
		SandboxID: "sb-destroy-route",
		Port:      8080,
		Protocol:  models.ExposedPortProtocolHTTP,
		HostPort:  18080,
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("UpsertPort(http): %v", err)
	}
	if err := st.UpsertPort(ctx, models.ExposedPort{
		SandboxID: "sb-destroy-route",
		Port:      5432,
		Protocol:  models.ExposedPortProtocolTCP,
		HostPort:  25432,
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("UpsertPort(tcp): %v", err)
	}
	admitter.Reserve("sb-destroy-route", capacity.Request{CPU: 1, MemoryMB: 512})
	if err := svc.handleDockerEvent(ctx, docker.DockerEvent{SandboxID: "sb-destroy-route", Action: "destroy", Time: time.Now().UTC()}); err != nil {
		t.Fatalf("destroy event with route errors: %v", err)
	}
	if _, err := st.Get(ctx, "sb-destroy-route"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("destroy event should remove row even if route deletes fail: %v", err)
	}
	if snap := admitter.Snapshot(); snap.SandboxesActive != 0 {
		t.Fatalf("admitter should release on destroy: %+v", snap)
	}

	svc.docker = &recordingRuntime{
		inspect: map[string]*models.SandboxRuntimeState{
			"ctr-start-route": {
				SandboxID:   "sb-start-route",
				ContainerID: "ctr-start-route",
				ContainerIP: "10.0.0.100",
				Status:      models.SandboxStatusStarted,
			},
		},
	}
	if err := st.Create(ctx, &models.Sandbox{
		ID:           "sb-start-route",
		Image:        "alpine",
		Status:       models.SandboxStatusStopped,
		ContainerID:  "ctr-start-route",
		ContainerIP:  "10.0.0.1",
		Runtime:      models.RuntimeDocker,
		CPU:          1,
		MemoryMB:     512,
		CreatedAt:    now,
		UpdatedAt:    now,
		LastActiveAt: now,
	}); err != nil {
		t.Fatalf("seed start sandbox: %v", err)
	}
	if err := st.UpsertPort(ctx, models.ExposedPort{
		SandboxID: "sb-start-route",
		Port:      8080,
		Protocol:  models.ExposedPortProtocolHTTP,
		HostPort:  18081,
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("UpsertPort(start http): %v", err)
	}
	if err := svc.handleDockerEvent(ctx, docker.DockerEvent{SandboxID: "sb-start-route", ContainerID: "ctr-start-route", Action: "start", Time: time.Now().UTC()}); err == nil {
		t.Fatal("start event should fail when route upsert fails")
	}
}

func TestHandleDockerEventAdditionalBranches(t *testing.T) {
	ctx := context.Background()

	t.Run("start empty IP returns nil", func(t *testing.T) {
		svc, _, st := newCapacityHarness(t, nil, map[string]*models.SandboxRuntimeState{
			"ctr-start-empty": {
				SandboxID:   "sb-start-empty",
				ContainerID: "ctr-start-empty",
				ContainerIP: "",
				Status:      models.SandboxStatusStarted,
			},
		})
		seedSandbox(t, st, "sb-start-empty", models.SandboxStatusStopped, 1, 512)
		if err := svc.handleDockerEvent(ctx, docker.DockerEvent{SandboxID: "sb-start-empty", ContainerID: "ctr-start-empty", Action: "start", Time: time.Now().UTC()}); err != nil {
			t.Fatalf("start with empty IP: %v", err)
		}
	})

	t.Run("destroy deletes after store closed", func(t *testing.T) {
		svc, admitter, st := newCapacityHarness(t, nil, nil)
		closed := atomic.Bool{}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodDelete && closed.CompareAndSwap(false, true) {
				_ = st.Close()
			}
			w.WriteHeader(http.StatusInternalServerError)
		}))
		t.Cleanup(server.Close)
		svc.caddy = caddy.New(config.Config{
			CaddyAdminURL:     server.URL,
			CaddyServerID:     "srv0",
			EnableCaddy:       true,
			HTTPClientTimeout: 50 * time.Millisecond,
		})

		seedSandbox(t, st, "sb-destroy-close", models.SandboxStatusStarted, 1, 512)
		admitter.Reserve("sb-destroy-close", capacity.Request{CPU: 1, MemoryMB: 512})
		if err := svc.handleDockerEvent(ctx, docker.DockerEvent{SandboxID: "sb-destroy-close", Action: "destroy", Time: time.Now().UTC()}); err == nil {
			t.Fatal("destroy should fail after store close")
		}
	})
}

func TestRunEventMonitorContextCanceledDuringStream(t *testing.T) {
	started := make(chan struct{})
	client := newEventMonitorDockerClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/events" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		close(started)
		<-r.Context().Done()
	}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	svc := &Service{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	svc.events = client

	done := make(chan struct{})
	go func() {
		defer close(done)
		svc.runEventMonitor(ctx)
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("docker /events request did not start")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runEventMonitor did not exit after cancellation")
	}
}

func TestConsumeEventsErrorBranch(t *testing.T) {
	ctx := context.Background()
	svc, _, st := newCapacityHarness(t, nil, nil)
	if err := st.Close(); err != nil {
		t.Fatalf("store.Close: %v", err)
	}

	events := make(chan docker.DockerEvent, 1)
	events <- docker.DockerEvent{SandboxID: "sb-consume-error", Action: "stop", Time: time.Now().UTC()}
	close(events)

	svc.consumeEvents(ctx, events)
}

func TestMarkSandboxStoppedErrorBranches(t *testing.T) {
	ctx := context.Background()

	t.Run("warn branches", func(t *testing.T) {
		svc, _, _ := newCapacityHarness(t, nil, nil)
		svc.cfg.EnableCaddy = true
		svc.caddy = newAlwaysDeleteCaddy(t)
		svc.docker = failingClearRuntime{
			recordingRuntime: &recordingRuntime{},
			err:              errors.New("clear network rules failed"),
		}

		sb := &models.Sandbox{
			ID:          "sb-stop-error",
			ContainerIP: "10.0.0.10",
			Runtime:     models.RuntimeDocker,
		}
		if err := svc.markSandboxStopped(ctx, sb, docker.DockerEvent{
			SandboxID: "sb-stop-error",
			Action:    "die",
			ExitCode:  7,
			Time:      time.Now().UTC(),
		}); err != nil {
			t.Fatalf("markSandboxStopped warning path: %v", err)
		}
	})

	t.Run("store upsert failure", func(t *testing.T) {
		svc, _, st := newCapacityHarness(t, nil, nil)
		if err := st.Close(); err != nil {
			t.Fatalf("store.Close: %v", err)
		}
		svc.docker = failingClearRuntime{
			recordingRuntime: &recordingRuntime{},
			err:              errors.New("clear network rules failed"),
		}

		sb := &models.Sandbox{
			ID:          "sb-stop-upsert-fail",
			ContainerIP: "10.0.0.11",
			Runtime:     models.RuntimeDocker,
		}
		if err := svc.markSandboxStopped(ctx, sb, docker.DockerEvent{
			SandboxID: "sb-stop-upsert-fail",
			Action:    "stop",
			Time:      time.Now().UTC(),
		}); err == nil {
			t.Fatal("markSandboxStopped should fail when store.Upsert fails")
		}
	})
}

func TestHandleDestroyEventErrorBranches(t *testing.T) {
	ctx := context.Background()

	t.Run("warn branches", func(t *testing.T) {
		svc, _, _ := newCapacityHarness(t, nil, nil)
		svc.cfg.EnableCaddy = true
		svc.caddy = newAlwaysDeleteCaddy(t)
		svc.docker = failingClearRuntime{
			recordingRuntime: &recordingRuntime{},
			err:              errors.New("clear network rules failed"),
		}
		setMountRootDir(t, svc.mounts, "/dev/null")

		sb := &models.Sandbox{
			ID:          "sb-destroy-error",
			ContainerIP: "10.0.0.12",
			Runtime:     models.RuntimeDocker,
			ExposedPorts: []models.ExposedPort{
				{
					Port:     5432,
					Protocol: models.ExposedPortProtocolTCP,
					HostPort: 25432,
				},
			},
		}
		if err := svc.handleDestroyEvent(ctx, sb); err != nil {
			t.Fatalf("handleDestroyEvent warning path: %v", err)
		}
	})

	t.Run("store delete failure", func(t *testing.T) {
		svc, _, st := newCapacityHarness(t, nil, nil)
		if err := st.Close(); err != nil {
			t.Fatalf("store.Close: %v", err)
		}
		svc.cfg.EnableCaddy = true
		svc.caddy = newAlwaysDeleteCaddy(t)

		sb := &models.Sandbox{
			ID:          "sb-destroy-delete-fail",
			ContainerIP: "10.0.0.13",
			Runtime:     models.RuntimeDocker,
		}
		if err := svc.handleDestroyEvent(ctx, sb); err == nil {
			t.Fatal("handleDestroyEvent should fail when store.Delete fails")
		}
	})

	t.Run("cleanup wasm failure", func(t *testing.T) {
		svc, _, st := newCapacityHarness(t, nil, nil)
		svc.wasmCheckpointPusher = &closingWasmCheckpointStore{
			recordingWasmCheckpointStore: recordingWasmCheckpointStore{},
			store:                        st,
		}

		sb := &models.Sandbox{
			ID:              "sb-wasm-cleanup",
			Runtime:         models.RuntimeWasm,
			ContainerIP:     "10.0.0.14",
			WasmRegistryRef: "aocr://sb-wasm-cleanup:sha256-1",
		}
		if err := svc.handleDestroyEvent(ctx, sb); err == nil {
			t.Fatal("handleDestroyEvent should fail when WASM cleanup fails")
		}
	})
}

func TestHandleStartEventBranchErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("port route warning", func(t *testing.T) {
		svc, _, _ := newCapacityHarness(t, nil, map[string]*models.SandboxRuntimeState{
			"ctr-start-port": {
				SandboxID:   "sb-start-port",
				ContainerID: "ctr-start-port",
				ContainerIP: "10.0.0.20",
				Status:      models.SandboxStatusStarted,
			},
		})
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodPatch && strings.Contains(r.URL.Path, "sandbox-sb-start-port-port-8080"):
				http.Error(w, "boom", http.StatusInternalServerError)
			case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/id/sandbox-sb-start-port"):
				w.WriteHeader(http.StatusOK)
			default:
				w.WriteHeader(http.StatusOK)
			}
		}))
		t.Cleanup(server.Close)
		svc.cfg.EnableCaddy = true
		svc.caddy = caddy.New(config.Config{
			CaddyAdminURL:     server.URL,
			CaddyServerID:     "srv0",
			EnableCaddy:       true,
			HTTPClientTimeout: 50 * time.Millisecond,
		})
		svc.docker = &recordingRuntime{
			inspect: map[string]*models.SandboxRuntimeState{
				"ctr-start-port": {
					SandboxID:   "sb-start-port",
					ContainerID: "ctr-start-port",
					ContainerIP: "10.0.0.20",
					Status:      models.SandboxStatusStarted,
				},
			},
		}

		sb := &models.Sandbox{
			ID:          "sb-start-port",
			ContainerID: "ctr-start-port",
			ContainerIP: "10.0.0.1",
			Runtime:     models.RuntimeDocker,
			ExposedPorts: []models.ExposedPort{
				{
					Port:     8080,
					Protocol: models.ExposedPortProtocolHTTP,
				},
			},
		}
		if err := svc.handleStartEvent(ctx, sb); err != nil {
			t.Fatalf("handleStartEvent port warning path: %v", err)
		}
	})

	t.Run("store upsert failure", func(t *testing.T) {
		svc, _, st := newCapacityHarness(t, nil, nil)
		if err := st.Close(); err != nil {
			t.Fatalf("store.Close: %v", err)
		}
		svc.docker = &recordingRuntime{
			inspect: map[string]*models.SandboxRuntimeState{
				"ctr-start-fail": {
					SandboxID:   "sb-start-fail",
					ContainerID: "ctr-start-fail",
					ContainerIP: "10.0.0.21",
					Status:      models.SandboxStatusStarted,
				},
			},
		}

		sb := &models.Sandbox{
			ID:          "sb-start-fail",
			ContainerID: "ctr-start-fail",
			ContainerIP: "10.0.0.2",
			Runtime:     models.RuntimeDocker,
		}
		if err := svc.handleStartEvent(ctx, sb); err == nil {
			t.Fatal("handleStartEvent should fail when store.Upsert fails")
		}
	})
}
