package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// hangingToolbox is a toolbox whose answers wait until the test says so: an
// exec whose command is still running.
type hangingToolbox struct {
	srv     *httptest.Server
	port    int
	arrived chan string
	answer  chan struct{}
	once    sync.Once
}

func newHangingToolbox(t *testing.T) *hangingToolbox {
	t.Helper()
	h := &hangingToolbox{arrived: make(chan string, 16), answer: make(chan struct{})}
	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/partial" {
			// Headers and some output, then the command keeps running.
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "first line\n")
			w.(http.Flusher).Flush()
		}
		h.arrived <- r.URL.Path
		select {
		case <-h.answer:
			if r.URL.Path != "/partial" {
				w.WriteHeader(http.StatusOK)
			}
			_, _ = io.WriteString(w, "done")
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() {
		h.release()
		h.srv.Close()
	})
	port, err := strconv.Atoi(h.srv.URL[strings.LastIndex(h.srv.URL, ":")+1:])
	if err != nil {
		t.Fatal(err)
	}
	h.port = port
	return h
}

func (h *hangingToolbox) release() { h.once.Do(func() { close(h.answer) }) }

func (h *hangingToolbox) waitArrived(t *testing.T) {
	t.Helper()
	select {
	case <-h.arrived:
	case <-time.After(5 * time.Second):
		t.Fatal("the request never reached the toolbox")
	}
}

// seedToolboxSandbox writes a started docker sandbox whose toolbox is at
// 127.0.0.1.
func seedCallSandbox(t *testing.T, st *store.Store, id string) *models.Sandbox {
	t.Helper()
	now := time.Now().UTC()
	sb := &models.Sandbox{
		ID: id, Image: "ubuntu:22.04", Runtime: models.RuntimeDocker, Status: models.SandboxStatusStarted,
		ContainerID: id, ContainerIP: "127.0.0.1", ToolboxToken: "token-" + id,
		CPU: 1, MemoryMB: 256, AuditIncarnationID: "inc-" + id,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}
	if err := st.Create(context.Background(), sb); err != nil {
		t.Fatalf("seed %s: %v", id, err)
	}
	return sb
}

// endedWith asserts ctx's toolbox request ended because its sandbox stopped,
// with detail in the error.
func endedWith(t *testing.T, ctx context.Context, detail string) {
	t.Helper()
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the toolbox request was not ended")
	}
	err := toolboxCallEnded(ctx)
	if err == nil {
		t.Fatalf("ended with %v, not because the sandbox stopped", context.Cause(ctx))
	}
	if !errors.Is(err, ErrSandboxNotRunning) || !strings.Contains(err.Error(), "("+detail+")") {
		t.Fatalf("ended with %q, want ErrSandboxNotRunning with (%s)", err, detail)
	}
}

func stillRunning(t *testing.T, ctx context.Context) {
	t.Helper()
	if ctx.Err() != nil {
		t.Fatalf("a toolbox request to a running sandbox was ended: %v", context.Cause(ctx))
	}
}

func TestToolboxCallRegistry(t *testing.T) {
	var s Service // the zero value works: tests build &Service{} directly
	a1, releaseA1 := s.TrackToolboxCall(context.Background(), "sb-a")
	a2, releaseA2 := s.TrackToolboxCall(context.Background(), "sb-a")
	b, releaseB := s.TrackToolboxCall(context.Background(), "sb-b")
	defer releaseB()
	if n := s.toolboxCalls.inFlight("sb-a"); n != 2 {
		t.Fatalf("sb-a in flight = %d", n)
	}

	// A finished request leaves; release twice is harmless.
	releaseA2()
	releaseA2()
	if n := s.toolboxCalls.inFlight("sb-a"); n != 1 {
		t.Fatalf("sb-a in flight after one release = %d", n)
	}
	if toolboxCallEnded(a2) != nil {
		t.Fatal("a released request reads as ended by a stop")
	}

	before := expvarMapInt(t, "aerolvm_toolbox_calls_ended_total", toolboxEndStopped)
	s.endToolboxCalls("sb-a", toolboxEndStopped, "")
	endedWith(t, a1, toolboxEndStopped) // no detail: the reason stands in
	stillRunning(t, b)
	if got := expvarMapInt(t, "aerolvm_toolbox_calls_ended_total", toolboxEndStopped) - before; got != 1 {
		t.Fatalf("ended metric moved by %d, want 1", got)
	}
	if n := s.toolboxCalls.inFlight("sb-a"); n != 0 {
		t.Fatalf("sb-a in flight after end = %d", n)
	}
	// Releasing after the end keeps the stop's cause, and ending again
	// (the stop paths do) finds nothing.
	releaseA1()
	if toolboxCallEnded(a1) == nil {
		t.Fatal("release overwrote the stop's cause")
	}
	s.endToolboxCalls("sb-a", toolboxEndStopped, "again")
	s.toolboxCalls.remove("sb-missing", &toolboxCall{})
}

func TestSandboxStoppedErrorMatches(t *testing.T) {
	err := error(&sandboxStoppedError{detail: "exited with code 137"})
	if !errors.Is(err, ErrSandboxStoppedMidRequest) || !errors.Is(err, ErrSandboxNotRunning) {
		t.Fatal("the stopped error does not match its sentinels")
	}
	if errors.Is(err, store.ErrNotFound) {
		t.Fatal("the stopped error reads as not found")
	}
	const want = "sandbox is not running: it stopped while the request was in flight (exited with code 137)"
	if err.Error() != want {
		t.Fatalf("message = %q, want %q", err.Error(), want)
	}
	if !errors.Is(ErrSandboxStoppedMidRequest, ErrSandboxNotRunning) {
		t.Fatal("the bare sentinel does not classify as not running")
	}
	if ToolboxCallEnded(context.Background()) != nil {
		t.Fatal("a plain context reads as ended")
	}
	if got := stopDetail("die", 137); got != "exited with code 137" {
		t.Fatalf("stopDetail(die, 137) = %q", got)
	}
	for _, action := range []string{"die", "stop"} {
		if got := stopDetail(action, 0); got != "stopped" {
			t.Fatalf("stopDetail(%s, 0) = %q", action, got)
		}
	}
}

// TestToolboxCallsEndOnLifecyclePaths: every path that learns a sandbox is
// gone ends its in-flight toolbox requests, with what happened; the paths
// that do not know it is gone leave them running.
func TestToolboxCallsEndOnLifecyclePaths(t *testing.T) {
	ctx := context.Background()
	const id = "sb-calls"
	cases := []struct {
		name   string
		setup  func(rt *recordingRuntime)
		run    func(s *Service) error
		detail string // "" = the request must keep running
	}{
		{name: "die event with exit code", run: func(s *Service) error {
			return s.handleDockerEvent(ctx, docker.DockerEvent{SandboxID: id, Action: "die", ExitCode: 137, Time: time.Now()})
		}, detail: "exited with code 137"},
		{name: "die event", run: func(s *Service) error { return s.handleDockerEvent(ctx, dockerEvent(id, "die")) }, detail: "stopped"},
		{name: "stop event", run: func(s *Service) error { return s.handleDockerEvent(ctx, dockerEvent(id, "stop")) }, detail: "stopped"},
		// A process in the sandbox was OOM-killed; the sandbox may live on.
		{name: "oom event", run: func(s *Service) error { return s.handleDockerEvent(ctx, dockerEvent(id, "oom")) }},
		{name: "destroy event", run: func(s *Service) error { return s.handleDockerEvent(ctx, dockerEvent(id, "destroy")) }, detail: "destroyed"},
		{name: "event for another sandbox", run: func(s *Service) error {
			return s.handleDockerEvent(ctx, dockerEvent("sb-other", "die"))
		}},
		{name: "API stop", run: func(s *Service) error { _, err := s.StopSandbox(ctx, id); return err }, detail: "stopped"},
		{name: "pause", run: func(s *Service) error { _, err := s.PauseSandbox(ctx, id); return err }, detail: "stopped"},
		{name: "lifecycle stop", run: func(s *Service) error {
			_, err := s.stopSandboxInternal(ctx, id, stopModeLifecycle)
			return err
		}, detail: "stopped by its lifecycle"},
		{name: "API stop that fails", setup: func(rt *recordingRuntime) { rt.stopErr = errors.New("engine busy") }, run: func(s *Service) error {
			if _, err := s.StopSandbox(ctx, id); err == nil {
				return errors.New("stop succeeded")
			}
			return nil
		}},
		{name: "API destroy", run: func(s *Service) error { return s.DestroySandbox(ctx, id) }, detail: "destroyed"},
		{name: "API destroy that fails", setup: func(rt *recordingRuntime) { rt.destroyErr = errors.New("engine busy") }, run: func(s *Service) error {
			if err := s.DestroySandbox(ctx, id); err == nil {
				return errors.New("destroy succeeded")
			}
			return nil
		}},
		// A listing that says stopped is not proof: a Firecracker VM paused
		// for a snapshot lists as stopped and resumes with its exec intact.
		{name: "reconcile lists it stopped", setup: func(rt *recordingRuntime) {
			rt.managed = map[string]*models.SandboxRuntimeState{id: {SandboxID: id, ContainerID: id, Status: models.SandboxStatusStopped}}
		}, run: func(s *Service) error { return s.Reconcile(ctx) }},
		{name: "reconcile finds it running", setup: func(rt *recordingRuntime) {
			rt.managed = map[string]*models.SandboxRuntimeState{id: {SandboxID: id, ContainerID: id, ContainerIP: "127.0.0.1", Status: models.SandboxStatusStarted}}
		}, run: func(s *Service) error { return s.Reconcile(ctx) }},
		// Absent from the listing and not found by Inspect: definitively gone.
		{name: "reconcile reaps it", run: func(s *Service) error { return s.Reconcile(ctx) }, detail: "runtime gone"},
		{name: "stale local copy after ownership moved", run: func(s *Service) error {
			sb, err := s.store.Get(ctx, id)
			if err != nil {
				return err
			}
			return s.finalizeStaleLocalSandbox(ctx, sb, cluster.Placement{SandboxID: id, IncarnationID: "inc-new", OwnerNodeID: "node-b"}, false)
		}, detail: "moved to another node"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := &recordingRuntime{}
			if tc.setup != nil {
				tc.setup(rt)
			}
			svc, st, _ := newServiceRuntimeHarness(t, rt)
			seedCallSandbox(t, st, id)
			seedCallSandbox(t, st, "sb-other")
			callCtx, release := svc.TrackToolboxCall(ctx, id)
			defer release()
			if err := tc.run(svc); err != nil {
				t.Fatalf("lifecycle path: %v", err)
			}
			if tc.detail == "" {
				stillRunning(t, callCtx)
				if n := svc.toolboxCalls.inFlight(id); n != 1 {
					t.Fatalf("in flight = %d, want the request still registered", n)
				}
				return
			}
			endedWith(t, callCtx, tc.detail)
		})
	}
}

// TestToolboxCallsKeepRunningWhenRuntimeUnknown: reconcile cannot say
// whether the sandbox exists (a shim that does not answer). It may be
// running a long command, so its requests are left alone, on every pass up
// to and including the one that marks it status=error.
func TestToolboxCallsKeepRunningWhenRuntimeUnknown(t *testing.T) {
	ctx := context.Background()
	svc, _, _, _, _, clock := newUnknownMarkService(t)
	callCtx, release := svc.TrackToolboxCall(ctx, "sb-stuck")
	defer release()
	for pass := 1; pass <= 3; pass++ {
		if err := svc.Reconcile(ctx); err != nil {
			t.Fatalf("Reconcile pass %d: %v", pass, err)
		}
		clock.advance(5 * time.Minute)
	}
	stillRunning(t, callCtx)
}

// proxyResult is what one ServeToolboxReverseProxy call did.
type proxyResult struct {
	err  error
	rec  *httptest.ResponseRecorder
	took time.Duration
}

func serveInBackground(svc *Service, id, path string) <-chan proxyResult {
	done := make(chan proxyResult, 1)
	go func() {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "http://sandboxd/v1/sandboxes/"+id+"/toolbox"+path, strings.NewReader(`{"command":"sleep 600"}`))
		start := time.Now()
		err := svc.ServeToolboxReverseProxy(context.Background(), id, rec, req, path)
		done <- proxyResult{err: err, rec: rec, took: time.Since(start)}
	}()
	return done
}

func waitProxy(t *testing.T, done <-chan proxyResult) proxyResult {
	t.Helper()
	select {
	case res := <-done:
		return res
	case <-time.After(5 * time.Second):
		t.Fatal("the toolbox request is still waiting on a stopped sandbox")
		return proxyResult{}
	}
}

// TestServeToolboxReverseProxyEndsWhenSandboxStops is the live failure: an
// exec in flight when its sandbox dies. It answered 502 after 3m18s; now the
// stop ends it at once with ErrSandboxStoppedMidRequest, which the handler
// writes as 409, and nothing was written to the client before that.
func TestServeToolboxReverseProxyEndsWhenSandboxStops(t *testing.T) {
	ctx := context.Background()
	const id = "sb-exec"
	paths := []struct {
		name   string
		stop   func(s *Service) error
		detail string
	}{
		{name: "gVisor sandbox killed (die event)", stop: func(s *Service) error {
			return s.handleDockerEvent(ctx, docker.DockerEvent{SandboxID: id, Action: "die", ExitCode: 137, Time: time.Now()})
		}, detail: "exited with code 137"},
		{name: "API stop", stop: func(s *Service) error { _, err := s.StopSandbox(ctx, id); return err }, detail: "stopped"},
		{name: "API destroy", stop: func(s *Service) error { return s.DestroySandbox(ctx, id) }, detail: "destroyed"},
	}
	for _, p := range paths {
		t.Run(p.name, func(t *testing.T) {
			tb := newHangingToolbox(t)
			svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
			svc.cfg.ToolboxPort = tb.port
			seedCallSandbox(t, st, id)

			done := serveInBackground(svc, id, "/process/execute")
			tb.waitArrived(t)
			if err := p.stop(svc); err != nil {
				t.Fatalf("stop: %v", err)
			}
			res := waitProxy(t, done)
			if !errors.Is(res.err, ErrSandboxStoppedMidRequest) || !strings.Contains(res.err.Error(), p.detail) {
				t.Fatalf("ServeToolboxReverseProxy = %v, want the sandbox-stopped error (%s)", res.err, p.detail)
			}
			if res.rec.Body.Len() != 0 || len(res.rec.Header()) != 0 {
				t.Fatalf("the proxy wrote %d %q before returning the error", res.rec.Code, res.rec.Body.String())
			}
			if n := svc.toolboxCalls.inFlight(id); n != 0 {
				t.Fatalf("in flight after the request returned = %d", n)
			}
		})
	}
}

// TestServeToolboxReverseProxyLongExecSurvivesOOMEvent: an OOM kill of one
// process in the sandbox is not the sandbox's death; the exec runs on and
// gets its answer.
func TestServeToolboxReverseProxyLongExecSurvivesOOMEvent(t *testing.T) {
	ctx := context.Background()
	const id = "sb-oom"
	tb := newHangingToolbox(t)
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.ToolboxPort = tb.port
	seedCallSandbox(t, st, id)

	done := serveInBackground(svc, id, "/process/execute")
	tb.waitArrived(t)
	if err := svc.handleDockerEvent(ctx, dockerEvent(id, "oom")); err != nil {
		t.Fatal(err)
	}
	select {
	case res := <-done:
		t.Fatalf("the exec ended on an oom event: %v", res.err)
	case <-time.After(200 * time.Millisecond):
	}
	tb.release()
	res := waitProxy(t, done)
	if res.err != nil || res.rec.Code != http.StatusOK || res.rec.Body.String() != "done" {
		t.Fatalf("exec after an oom event = %v %d %q", res.err, res.rec.Code, res.rec.Body.String())
	}
}

// TestRoundTripToolboxEndsWhenSandboxStops covers the facades' path
// (Daytona exec, Runloop): before the answer, and while reading a streamed
// body. The registration lasts until the body is closed.
func TestRoundTripToolboxEndsWhenSandboxStops(t *testing.T) {
	ctx := context.Background()
	const id = "sb-rt-stop"

	t.Run("before the answer", func(t *testing.T) {
		tb := newHangingToolbox(t)
		svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg.ToolboxPort = tb.port
		seedCallSandbox(t, st, id)
		errc := make(chan error, 1)
		go func() {
			resp, err := svc.RoundTripToolbox(ctx, id, http.MethodPost, "/process/execute", nil, strings.NewReader("{}"), nil)
			if err == nil {
				resp.Body.Close()
			}
			errc <- err
		}()
		tb.waitArrived(t)
		if err := svc.handleDockerEvent(ctx, dockerEvent(id, "die")); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-errc:
			if !errors.Is(err, ErrSandboxStoppedMidRequest) {
				t.Fatalf("RoundTripToolbox = %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("RoundTripToolbox still waiting on a stopped sandbox")
		}
		if n := svc.toolboxCalls.inFlight(id); n != 0 {
			t.Fatalf("in flight after the error = %d", n)
		}
	})

	t.Run("while reading the body", func(t *testing.T) {
		tb := newHangingToolbox(t)
		svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg.ToolboxPort = tb.port
		seedCallSandbox(t, st, id)
		resp, err := svc.RoundTripToolbox(ctx, id, http.MethodGet, "/partial", nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		tb.waitArrived(t)
		if n := svc.toolboxCalls.inFlight(id); n != 1 {
			t.Fatalf("a streaming response is not registered: in flight = %d", n)
		}
		go func() {
			time.Sleep(50 * time.Millisecond)
			_ = svc.handleDockerEvent(ctx, dockerEvent(id, "die"))
		}()
		body, err := io.ReadAll(resp.Body)
		if !errors.Is(err, ErrSandboxStoppedMidRequest) || string(body) != "first line\n" {
			t.Fatalf("read = %q, %v; want the first line, then the sandbox-stopped error", body, err)
		}
		if err := resp.Body.Close(); err != nil {
			t.Fatal(err)
		}
		if n := svc.toolboxCalls.inFlight(id); n != 0 {
			t.Fatalf("in flight after Close = %d", n)
		}
	})

	t.Run("a finished request is released", func(t *testing.T) {
		tb := newHangingToolbox(t)
		tb.release()
		svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg.ToolboxPort = tb.port
		seedCallSandbox(t, st, id)
		resp, err := svc.RoundTripToolbox(ctx, id, http.MethodGet, "/x", nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || string(body) != "done" {
			t.Fatalf("body = %q, %v", body, err)
		}
		if n := svc.toolboxCalls.inFlight(id); n != 0 {
			t.Fatalf("in flight after Close = %d", n)
		}
	})
}

// slammingToolbox closes every connection without an answer, as a runc
// container's kernel does when the container is killed.
func slammingToolbox(t *testing.T) int {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			conn.Close()
		}
	}))
	t.Cleanup(srv.Close)
	port, _ := strconv.Atoi(srv.URL[strings.LastIndex(srv.URL, ":")+1:])
	return port
}

func withToolboxEndSettle(t *testing.T, d time.Duration) {
	t.Helper()
	old := toolboxEndSettle
	toolboxEndSettle = d
	t.Cleanup(func() { toolboxEndSettle = old })
}

// TestBrokenToolboxConnectionWaitsForTheStopEvent: a killed runc container
// closes its connections a moment before its die event arrives. The broken
// request waits briefly for the event, so it answers 409 like any other
// stopped sandbox; with no event it is the gateway error it always was, and
// where no event can come it does not wait at all.
func TestBrokenToolboxConnectionWaitsForTheStopEvent(t *testing.T) {
	ctx := context.Background()
	const id = "sb-slam"
	setup := func(t *testing.T, monitor bool) *Service {
		svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		svc.cfg.ToolboxPort = slammingToolbox(t)
		svc.cfg.EnableEventMonitor = monitor
		seedCallSandbox(t, st, id)
		return svc
	}

	t.Run("the die event arrives", func(t *testing.T) {
		withToolboxEndSettle(t, 5*time.Second)
		svc := setup(t, true)
		done := serveInBackground(svc, id, "/process/execute")
		for svc.toolboxCalls.inFlight(id) == 0 {
			time.Sleep(time.Millisecond)
		}
		time.Sleep(100 * time.Millisecond) // the connection has broken by now
		if err := svc.handleDockerEvent(ctx, docker.DockerEvent{SandboxID: id, Action: "die", ExitCode: 137, Time: time.Now()}); err != nil {
			t.Fatal(err)
		}
		res := waitProxy(t, done)
		if !errors.Is(res.err, ErrSandboxStoppedMidRequest) || res.rec.Body.Len() != 0 {
			t.Fatalf("= %v, wrote %d %q; want the sandbox-stopped error", res.err, res.rec.Code, res.rec.Body.String())
		}
	})

	t.Run("no event", func(t *testing.T) {
		withToolboxEndSettle(t, 100*time.Millisecond)
		svc := setup(t, true)
		res := waitProxy(t, serveInBackground(svc, id, "/process/execute"))
		if res.err != nil || res.rec.Code != http.StatusBadGateway {
			t.Fatalf("= %v, %d; want the 502 written", res.err, res.rec.Code)
		}
		if res.took < 100*time.Millisecond {
			t.Fatalf("answered after %v, before the settle window", res.took)
		}
	})

	t.Run("no event monitor", func(t *testing.T) {
		withToolboxEndSettle(t, 5*time.Second)
		svc := setup(t, false)
		res := waitProxy(t, serveInBackground(svc, id, "/process/execute"))
		if res.err != nil || res.rec.Code != http.StatusBadGateway || res.took > 2*time.Second {
			t.Fatalf("= %v, %d after %v; want an immediate 502", res.err, res.rec.Code, res.took)
		}
	})

	t.Run("round trip", func(t *testing.T) {
		withToolboxEndSettle(t, 5*time.Second)
		svc := setup(t, true)
		go func() {
			for svc.toolboxCalls.inFlight(id) == 0 {
				time.Sleep(time.Millisecond)
			}
			time.Sleep(100 * time.Millisecond)
			_ = svc.handleDockerEvent(ctx, dockerEvent(id, "die"))
		}()
		_, err := svc.RoundTripToolbox(ctx, id, http.MethodPost, "/process/execute", nil, strings.NewReader("{}"), nil)
		if !errors.Is(err, ErrSandboxStoppedMidRequest) {
			t.Fatalf("RoundTripToolbox = %v", err)
		}
	})

	t.Run("round trip, no event", func(t *testing.T) {
		svc := setup(t, false)
		_, err := svc.RoundTripToolbox(ctx, id, http.MethodPost, "/process/execute", nil, strings.NewReader("{}"), nil)
		if err == nil || errors.Is(err, ErrSandboxStoppedMidRequest) {
			t.Fatalf("RoundTripToolbox = %v, want the transport error itself", err)
		}
		if n := svc.toolboxCalls.inFlight(id); n != 0 {
			t.Fatalf("in flight after the error = %d", n)
		}
	})

	t.Run("runtimes without exit events do not wait", func(t *testing.T) {
		svc := setup(t, true)
		for _, sb := range []*models.Sandbox{
			nil,
			{Runtime: models.RuntimeFirecracker},
			{Runtime: models.RuntimeWasm},
			{Runtime: models.RuntimeIsolate},
		} {
			if svc.toolboxEndsByEvent(sb) {
				t.Fatalf("%+v reads as reporting exits by event", sb)
			}
		}
		if !svc.toolboxEndsByEvent(&models.Sandbox{Runtime: models.RuntimeGvisor}) {
			t.Fatal("a gVisor container does not read as reporting exits by event")
		}
	})

	t.Run("the caller went away", func(t *testing.T) {
		svc := setup(t, true)
		gone, cancel := context.WithCancel(ctx)
		cancel()
		start := time.Now()
		if err := svc.toolboxBrokenCause(gone, &models.Sandbox{Runtime: models.RuntimeDocker}); err != nil || time.Since(start) > time.Second {
			t.Fatalf("= %v after %v", err, time.Since(start))
		}
	})
}

// TestToolboxErrorsBeforeTheProxyKeepTheirMeaning: a request ended by a stop
// while it was still resolving its sandbox reports the stop, and an ordinary
// error (a missing sandbox, an admin path) is untouched.
func TestToolboxErrorsBeforeTheProxyKeepTheirMeaning(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://sandboxd/x", nil)
	if err := svc.ServeToolboxReverseProxy(ctx, "sb-missing", rec, req, "/x"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing sandbox = %v", err)
	}
	if _, err := svc.RoundTripToolbox(ctx, "sb-missing", http.MethodGet, "/x", nil, nil, nil); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing sandbox round trip = %v", err)
	}
	if _, err := svc.RoundTripToolbox(ctx, "sb-missing", http.MethodGet, "/admin/allowed-ports", nil, nil, nil); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("admin path = %v", err)
	}
	if n := svc.toolboxCalls.inFlight("sb-missing"); n != 0 {
		t.Fatalf("a failed request stayed registered: %d", n)
	}
}

// TestToolboxCallEndRace: requests registering, finishing and being ended
// at once (run with -race). Every request ends exactly once, and nothing is
// left registered.
func TestToolboxCallEndRace(t *testing.T) {
	var s Service
	const workers, perWorker = 16, 200
	var wg sync.WaitGroup
	stop := make(chan struct{})
	var enders sync.WaitGroup
	for e := 0; e < 4; e++ {
		enders.Add(1)
		go func(e int) {
			defer enders.Done()
			for {
				select {
				case <-stop:
					return
				default:
					s.endToolboxCalls(fmt.Sprintf("sb-%d", e%2), toolboxEndStopped, "race")
				}
			}
		}(e)
	}
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				ctx, release := s.TrackToolboxCall(context.Background(), fmt.Sprintf("sb-%d", (w+i)%2))
				if i%3 == 0 {
					release()
				}
				release()
				// Ended by a stop or by its own release: one cause, never lost.
				if cause := context.Cause(ctx); ctx.Err() == nil || (cause != context.Canceled && !errors.Is(cause, ErrSandboxStoppedMidRequest)) {
					t.Errorf("after release: err %v, cause %v", ctx.Err(), cause)
				}
			}
		}(w)
	}
	wg.Wait()
	close(stop)
	enders.Wait()
	for _, id := range []string{"sb-0", "sb-1"} {
		if n := s.toolboxCalls.inFlight(id); n != 0 {
			t.Fatalf("%s: %d requests left registered", id, n)
		}
	}
}

// TestToolboxProxyCompletionRacesStop: an exec that finishes just as its
// sandbox stops either answers normally or reports the stop, never both,
// never neither (run with -race). Odd iterations answer after 20ms, so the
// stop lands first; even ones answer at once and race it.
func TestToolboxProxyCompletionRacesStop(t *testing.T) {
	const id = "sb-race"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			select {
			case <-time.After(20 * time.Millisecond):
			case <-r.Context().Done():
				return
			}
		}
		_, _ = io.WriteString(w, "done")
	}))
	defer srv.Close()
	port, _ := strconv.Atoi(srv.URL[strings.LastIndex(srv.URL, ":")+1:])
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.ToolboxPort = port
	seedCallSandbox(t, st, id)
	answered, stopped := 0, 0
	for i := 0; i < 60; i++ {
		path := "/process/execute"
		if i%2 == 1 {
			path = "/slow"
		}
		done := serveInBackground(svc, id, path)
		go func(i int) {
			for svc.toolboxCalls.inFlight(id) == 0 {
				select {
				case <-time.After(10 * time.Microsecond):
				case <-time.After(time.Second):
					return
				}
			}
			// Even: 0-3ms, about one local round trip, so it lands before,
			// during or after the answer. Odd: well inside the 20ms wait.
			delay := time.Duration(i%8/2) * time.Millisecond
			if i%2 == 1 {
				delay = 5 * time.Millisecond
			}
			time.Sleep(delay)
			svc.endToolboxCalls(id, toolboxEndStopped, "race")
		}(i)
		res := waitProxy(t, done)
		switch {
		case res.err == nil && res.rec.Code == http.StatusOK && res.rec.Body.String() == "done":
			answered++
		case errors.Is(res.err, ErrSandboxStoppedMidRequest) && res.rec.Body.Len() == 0:
			stopped++
		case res.err == nil && res.rec.Code == http.StatusOK:
			// Ended while the answer's body was being copied: the headers
			// were out, so the response is cut short (a real server aborts
			// the connection), never answered twice.
			answered++
		default:
			t.Fatalf("iteration %d: err %v, wrote %d %q", i, res.err, res.rec.Code, res.rec.Body.String())
		}
	}
	t.Logf("answered %d, stopped %d", answered, stopped)
	if stopped < 30 {
		t.Fatalf("only %d of the 30 slow execs were ended by the stop", stopped)
	}
	if n := svc.toolboxCalls.inFlight(id); n != 0 {
		t.Fatalf("%d requests left registered", n)
	}
}
