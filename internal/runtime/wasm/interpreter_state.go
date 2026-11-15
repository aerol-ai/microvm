package wasm

import (
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/codeinterp"
	"github.com/aerol-ai/microvm/internal/codeinterp/daytona"
	"github.com/aerol-ai/microvm/internal/codeinterp/e2b"
	"github.com/aerol-ai/microvm/pkg/models"
)

// A sandbox's code interpreter state lives on the driver, not in the
// toolhost: toolhost.New runs for every request, and a context has to
// outlive the request that made it. Nothing is built on the create path;
// the first interpreter request builds it (plans/code-interpreter.md D6).

const (
	defaultInterpMaxContexts = 4
	defaultInterpIdleTTL     = 15 * time.Minute
)

// interpState is one sandbox's interpreter: a Manager per protocol (each
// has its own default contexts), one launcher, and one context cap shared
// by both.
//
// Contexts count against the sandbox's streaming run cap as well
// (MaxStreamsPerSandbox): a running context is a python.wasm instance
// started with StartStream like an exec stream, so it holds a run slot and
// is ended by everything that ends runs. An idle context gives its slot
// back when IdleTTL stops its interpreter.
type interpState struct {
	launcher *interpreterLauncher
	limit    *codeinterp.Limit
	idleTTL  time.Duration
	logger   *slog.Logger

	mu         sync.Mutex
	closed     bool
	daytonaMgr *codeinterp.Manager
	daytonaH   http.Handler
	e2bMgr     *codeinterp.Manager
	e2bH       http.Handler
}

func (d *Driver) interpMaxContexts() int {
	if d.cfg.InterpMaxContexts > 0 {
		return d.cfg.InterpMaxContexts
	}
	return defaultInterpMaxContexts
}

func (d *Driver) interpIdleTTL() time.Duration {
	if d.cfg.InterpIdleTTL > 0 {
		return d.cfg.InterpIdleTTL
	}
	return defaultInterpIdleTTL
}

// interpreters returns the sandbox's interpreter state, making it on first
// use, or nil for a sandbox that is gone or not running. It is made under
// Driver.mu and only for a registered, started instance, so a destroy
// (which unregisters the instance before it closes the state) never misses
// one that a racing request made, and a stopped sandbox gets none.
func (d *Driver) interpreters(sandboxID string) *interpState {
	d.mu.Lock()
	defer d.mu.Unlock()
	inst := d.byID[sandboxID]
	if inst == nil || inst.status != models.SandboxStatusStarted {
		return nil
	}
	if inst.interp == nil {
		inst.interp = &interpState{
			launcher: d.interpreterLauncher(sandboxID),
			limit:    codeinterp.NewLimit(d.interpMaxContexts()),
			idleTTL:  d.interpIdleTTL(),
			logger:   d.logger,
		}
	}
	return inst.interp
}

// closeInterpreters ends a sandbox's contexts: their interpreters are
// killed, and the first request after a restart finds none, as on Daytona
// and E2B (D6). It runs wherever the sandbox's streaming runs are killed:
// stop, destroy, passivate and migrate.
func (d *Driver) closeInterpreters(inst *sandboxInstance) {
	if inst == nil {
		return
	}
	d.mu.Lock()
	st := inst.interp
	inst.interp = nil
	d.mu.Unlock()
	st.close()
}

func (s *interpState) close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.closed = true
	managers := []*codeinterp.Manager{s.daytonaMgr, s.e2bMgr}
	s.mu.Unlock()
	for _, m := range managers {
		if m != nil {
			m.Close()
		}
	}
}

// daytona serves Daytona's protocol (and the AerolVM SDKs'), with paths
// relative to /process/interpreter.
func (s *interpState) daytona() http.Handler {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return interpStoppedHandler
	}
	if s.daytonaH == nil {
		opts := daytona.ManagerOptions(s.launcher, s.limit, interpreterDefaultCwd)
		opts.IdleTTL = s.idleTTL
		s.daytonaMgr = codeinterp.NewManager(opts)
		s.daytonaH = daytona.NewHandler(s.daytonaMgr, s.logger)
	}
	return s.daytonaH
}

// e2b serves E2B's Code Interpreter protocol, with paths relative to
// /interpreter/e2b. E2B's contexts start in /home/user, which a WASM
// sandbox does not have: they start in /work, its only folder.
func (s *interpState) e2b() http.Handler {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return interpStoppedHandler
	}
	if s.e2bH == nil {
		opts := e2b.ManagerOptionsAt(s.launcher, s.limit, interpreterDefaultCwd)
		opts.IdleTTL = s.idleTTL
		s.e2bMgr = codeinterp.NewManager(opts)
		s.e2bH = e2b.NewHandler(s.e2bMgr, s.logger)
	}
	return s.e2bH
}

// interpStoppedHandler answers a request that reached a sandbox's
// interpreter while the sandbox stopped under it.
var interpStoppedHandler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
	writeToolboxError(w, http.StatusServiceUnavailable, "the wasm sandbox is not running; its code interpreter contexts are gone")
})

// sandboxInterpreters gives the per-request toolhost the sandbox's
// interpreter handlers.
type sandboxInterpreters struct {
	driver *Driver
	id     string
}

func (s sandboxInterpreters) Daytona() http.Handler { return s.handler((*interpState).daytona) }

func (s sandboxInterpreters) E2B() http.Handler { return s.handler((*interpState).e2b) }

func (s sandboxInterpreters) handler(pick func(*interpState) http.Handler) http.Handler {
	st := s.driver.interpreters(s.id)
	if st == nil {
		// ServeToolbox found the sandbox, so it stopped or went since.
		return interpStoppedHandler
	}
	return pick(st)
}
