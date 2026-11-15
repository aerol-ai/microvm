package wasm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
)

// interpTestDriver is a driver with one started sandbox whose interpreter
// launches fake instances that answer READY.
type interpTestDriver struct {
	d       *Driver
	inst    *sandboxInstance
	client  *fakeStreamingClient
	mu      sync.Mutex
	streams []*fakeInterpStream
}

func newInterpTestDriver(t *testing.T, cfg Config) *interpTestDriver {
	t.Helper()
	cfg.RunDir = t.TempDir()
	d := New(cfg, nil)
	e := &interpTestDriver{d: d, client: &fakeStreamingClient{}}
	d.SetWorkerClientFactory(func(string) WorkerClient { return e.client })
	d.SetWorkerSupervisor(&fakeSupervisor{})
	e.inst = &sandboxInstance{sandboxID: "sb-int", status: models.SandboxStatusStarted, socketPath: "/tmp/sb-int.sock", workDir: t.TempDir()}
	d.byID["sb-int"] = e.inst
	t.Cleanup(func() { d.closeInterpreters(e.inst) })
	return e
}

// state returns the sandbox's interpreter state with a fake launch.
func (e *interpTestDriver) state(t *testing.T) *interpState {
	t.Helper()
	st := e.d.interpreters("sb-int")
	if st == nil {
		t.Fatal("no interpreter state")
	}
	st.launcher.module = func() (string, error) { return "/modules/python.wasm", nil }
	st.launcher.start = func(context.Context, StreamSpec) (interpStream, error) {
		s := newFakeInterpStream()
		s.out(64, "READY", "1")
		e.mu.Lock()
		e.streams = append(e.streams, s)
		e.mu.Unlock()
		return s, nil
	}
	return st
}

func (e *interpTestDriver) allClosed(t *testing.T) {
	t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	for i, s := range e.streams {
		select {
		case <-s.closed:
		case <-time.After(5 * time.Second):
			t.Fatalf("interpreter %d still running", i)
		}
	}
}

func serveInterp(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
	return rec
}

func TestInterpreterStateIsLazyAndShared(t *testing.T) {
	e := newInterpTestDriver(t, Config{InterpMaxContexts: 3})
	if e.inst.interp != nil {
		t.Fatal("interpreter state made before any request")
	}
	if e.d.interpreters("missing") != nil {
		t.Fatal("state for an unknown sandbox")
	}
	st := e.state(t)
	if e.d.interpreters("sb-int") != st {
		t.Fatal("a second request got new state")
	}
	if st.daytonaMgr != nil || st.e2bMgr != nil {
		t.Fatal("managers built before their protocol was used")
	}
	ip := sandboxInterpreters{driver: e.d, id: "sb-int"}

	// The cap of 3 is shared: a Daytona context, E2B's python default
	// (registered on E2B's first request, as E2B's server has it from the
	// start) and an E2B context fill it.
	if rec := serveInterp(ip.Daytona(), http.MethodPost, "/context", `{}`); rec.Code != http.StatusOK {
		t.Fatalf("daytona create = %d %s", rec.Code, rec.Body.String())
	}
	var created map[string]any
	rec := serveInterp(ip.E2B(), http.MethodPost, "/contexts", `{}`)
	if err := json.Unmarshal(rec.Body.Bytes(), &created); rec.Code != http.StatusOK || err != nil || created["cwd"] != "/work" {
		t.Fatalf("e2b create = %d %s", rec.Code, rec.Body.String())
	}
	if rec := serveInterp(ip.Daytona(), http.MethodPost, "/context", `{}`); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("fourth context = %d %s, want 429", rec.Code, rec.Body.String())
	}
	var list []map[string]any
	rec = serveInterp(ip.E2B(), http.MethodGet, "/contexts", "")
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list) != 2 || list[0]["language"] != "python" || list[0]["cwd"] != "/work" {
		t.Fatalf("e2b contexts = %s", rec.Body.String())
	}
	if rec := serveInterp(ip.Daytona(), http.MethodPost, "/context", `{"language":"javascript"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("javascript = %d %s, want 400", rec.Code, rec.Body.String())
	}
	e.mu.Lock()
	launched := len(e.streams)
	e.mu.Unlock()
	if launched != 2 {
		t.Fatalf("%d interpreters started, want 2", launched)
	}
}

func TestInterpretersClosedWithTheSandbox(t *testing.T) {
	ops := []struct {
		name string
		run  func(t *testing.T, d *Driver)
	}{
		{name: "stop", run: func(t *testing.T, d *Driver) {
			if err := d.Stop(context.Background(), "sb-int"); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "destroy", run: func(t *testing.T, d *Driver) {
			if err := d.Destroy(context.Background(), &models.Sandbox{ID: "sb-int"}); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "passivate", run: func(t *testing.T, d *Driver) {
			if _, _, err := d.CheckpointSandbox(context.Background(), &models.Sandbox{ID: "sb-int"}); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, op := range ops {
		t.Run(op.name, func(t *testing.T) {
			e := newInterpTestDriver(t, Config{})
			st := e.state(t)
			ip := sandboxInterpreters{driver: e.d, id: "sb-int"}
			if rec := serveInterp(ip.Daytona(), http.MethodPost, "/context", `{"cwd":"/work/a"}`); rec.Code != http.StatusOK {
				t.Fatalf("create = %d %s", rec.Code, rec.Body.String())
			}
			if rec := serveInterp(ip.E2B(), http.MethodPost, "/contexts", `{}`); rec.Code != http.StatusOK {
				t.Fatalf("e2b create = %d %s", rec.Code, rec.Body.String())
			}
			op.run(t, e.d)
			e.allClosed(t)
			if e.inst.interp != nil {
				t.Fatal("state kept after the sandbox ended")
			}
			// A request that still holds the old state finds it closed.
			for _, h := range []http.Handler{st.daytona(), st.e2b()} {
				if rec := serveInterp(h, http.MethodGet, "/contexts", ""); rec.Code != http.StatusServiceUnavailable {
					t.Fatalf("closed state = %d %s", rec.Code, rec.Body.String())
				}
			}
			// A stopped or gone sandbox gets no new state.
			if rec := serveInterp(ip.Daytona(), http.MethodGet, "/context", ""); rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("after %s = %d %s", op.name, rec.Code, rec.Body.String())
			}
			if op.name == "stop" {
				// Started again, the sandbox has no contexts left.
				e.inst.status = models.SandboxStatusStarted
				e.state(t)
				rec := serveInterp(ip.Daytona(), http.MethodGet, "/context", "")
				if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != `{"contexts":[]}` {
					t.Fatalf("after restart = %d %s", rec.Code, rec.Body.String())
				}
			}
		})
	}
}

func TestInterpreterIdleTTLStopsTheInterpreter(t *testing.T) {
	e := newInterpTestDriver(t, Config{InterpIdleTTL: time.Second})
	e.state(t)
	ip := sandboxInterpreters{driver: e.d, id: "sb-int"}
	rec := serveInterp(ip.Daytona(), http.MethodPost, "/context", `{}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("create = %d %s", rec.Code, rec.Body.String())
	}
	// The reaper runs every second; the idle interpreter goes, the context
	// stays and reports that its state is gone.
	e.allClosed(t)
	var info struct {
		ID     string `json:"id"`
		Active bool   `json:"active"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &info)
	deadline := time.Now().Add(5 * time.Second)
	for {
		rec = serveInterp(ip.Daytona(), http.MethodGet, "/context/"+info.ID, "")
		if strings.Contains(rec.Body.String(), `"active":false`) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("context after idle stop = %d %s", rec.Code, rec.Body.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestInterpreterSettings(t *testing.T) {
	cfg := FromDaemonConfig(config.Config{WasmInterpMaxContexts: 6, WasmInterpIdleTTL: time.Minute})
	if cfg.InterpMaxContexts != 6 || cfg.InterpIdleTTL != time.Minute {
		t.Fatalf("projected = %+v", cfg)
	}
	d := New(cfg, nil)
	if d.interpMaxContexts() != 6 || d.interpIdleTTL() != time.Minute {
		t.Fatalf("configured = %d %s", d.interpMaxContexts(), d.interpIdleTTL())
	}
	d = New(Config{}, nil)
	if d.interpMaxContexts() != 4 || d.interpIdleTTL() != 15*time.Minute {
		t.Fatalf("defaults = %d %s", d.interpMaxContexts(), d.interpIdleTTL())
	}
	// closeInterpreters tolerates a sandbox with no state, or none at all.
	d.closeInterpreters(nil)
	d.closeInterpreters(&sandboxInstance{})
}
