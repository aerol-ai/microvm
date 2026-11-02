package service

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// ruleRecordingRuntime records every call that removes host rules from an
// address, so a test can tell "the sandbox's egress enforcement was left
// alone" from "it was torn down".
type ruleRecordingRuntime struct {
	*recordingRuntime
	mu     sync.Mutex
	clears []string
}

func (r *ruleRecordingRuntime) note(call string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.clears = append(r.clears, call)
}

func (r *ruleRecordingRuntime) clearsFor(ip string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, c := range r.clears {
		if strings.HasSuffix(c, " "+ip) {
			out = append(out, c)
		}
	}
	return out
}

func (r *ruleRecordingRuntime) ClearNetworkRules(ip string) error {
	r.note("ClearNetworkRules " + ip)
	return nil
}

func (r *ruleRecordingRuntime) ClearEgressPolicy(ip string, _, _ []string) error {
	r.note("ClearEgressPolicy " + ip)
	return nil
}

func (r *ruleRecordingRuntime) ClearNetworkBlockEgress(ip string) error {
	r.note("ClearNetworkBlockEgress " + ip)
	return nil
}

func (r *ruleRecordingRuntime) ClearNetworkBlockIngress(ip string) error {
	r.note("ClearNetworkBlockIngress " + ip)
	return nil
}

// oomEngine is one engine/runtime pair whose events reach the service.
type oomEngine struct {
	name    string
	engine  string // models.ContainerEngine*
	runtime string
}

var oomEngines = []oomEngine{
	{name: "docker", engine: models.ContainerEngineDocker, runtime: models.RuntimeDocker},
	{name: "containerd-runc", engine: models.ContainerEngineContainerd, runtime: models.RuntimeDocker},
	{name: "containerd-gvisor", engine: models.ContainerEngineContainerd, runtime: models.RuntimeGvisor},
}

type oomHarness struct {
	svc      *Service
	st       *store.Store
	admitter *capacity.Admitter
	rt       *ruleRecordingRuntime
	routes   *recordingRouteWriter
}

func newOOMHarness(t *testing.T, eng oomEngine) *oomHarness {
	t.Helper()
	rt := &ruleRecordingRuntime{recordingRuntime: &recordingRuntime{}}
	svc, st, admitter := newServiceRuntimeHarnessAtPath(t, filepath.Join(t.TempDir(), "state.db"), rt)
	if eng.engine == models.ContainerEngineContainerd {
		svc.containerd = rt
	}
	routes := &recordingRouteWriter{}
	svc.routeWriter = routes
	return &oomHarness{svc: svc, st: st, admitter: admitter, rt: rt, routes: routes}
}

// seedEgressSandbox writes a started block-all sandbox with a CIDR allow
// rule at ip, holding its admitter slot and the warm cache.
func (h *oomHarness) seedEgressSandbox(t *testing.T, eng oomEngine, id, ip string) {
	t.Helper()
	now := time.Now().UTC()
	if err := h.st.Create(context.Background(), &models.Sandbox{
		ID: id, Image: "ubuntu:22.04", Runtime: eng.runtime, Engine: eng.engine,
		Status: models.SandboxStatusStarted, ContainerID: id, ContainerIP: ip,
		CPU: 1, MemoryMB: 256, NetworkBlockAll: true, NetworkAllowOut: []string{"10.200.0.0/24"},
		AuditIncarnationID: "inc-" + id, CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatalf("seed %s: %v", id, err)
	}
	h.admitter.Reserve(id, capacity.Request{CPU: 1, MemoryMB: 256})
	h.svc.warmCacheSet(id)
}

func (h *oomHarness) event(t *testing.T, id, action string, exitCode int) {
	t.Helper()
	if err := h.svc.handleDockerEvent(context.Background(), docker.DockerEvent{SandboxID: id, Action: action, ExitCode: exitCode, Time: time.Now().UTC()}); err != nil {
		t.Fatalf("%s event for %s: %v", action, id, err)
	}
}

func (h *oomHarness) row(t *testing.T, id string) *models.Sandbox {
	t.Helper()
	sb, err := h.st.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("get %s: %v", id, err)
	}
	return sb
}

// TestOOMEventOnASurvivingSandboxChangesNothing: a process in the sandbox
// was OOM-killed and the sandbox lives on (its init and toolboxd survive).
// On every engine the row stays started, the admitter slot, the warm cache,
// the routes, every host egress rule and an in-flight toolbox request are
// left exactly as they were. Before: the stop path ran, and the sandbox's
// block-all and CIDR rules were removed while it kept running.
func TestOOMEventOnASurvivingSandboxChangesNothing(t *testing.T) {
	for _, eng := range oomEngines {
		t.Run(eng.name, func(t *testing.T) {
			h := newOOMHarness(t, eng)
			const id, ip = "sb-oom-lives", "10.88.0.21"
			h.seedEgressSandbox(t, eng, id, ip)
			call, release := h.svc.TrackToolboxCall(context.Background(), id)
			defer release()
			before := sandboxOOMEventsTotal.Value()

			h.event(t, id, "oom", 0)
			h.event(t, id, "oom", 0) // a second child, same story

			got := h.row(t, id)
			if got.Status != models.SandboxStatusStarted || got.LastError != "" || got.WakeArmed {
				t.Fatalf("row after oom: status %q last error %q wake %v; want started, untouched", got.Status, got.LastError, got.WakeArmed)
			}
			if clears := h.rt.clearsFor(ip); len(clears) != 0 {
				t.Fatalf("egress rules of a running sandbox were removed on an oom event: %v", clears)
			}
			if h.routes.seen()["DeleteSandboxRoute"] || h.routes.seen()["DeletePortRoute"] {
				t.Fatalf("routes of a running sandbox were deleted on an oom event: %v", h.routes.calls)
			}
			if snap := h.admitter.Snapshot(); snap.SandboxesActive != 1 {
				t.Fatalf("an oom event released the slot: %+v", snap)
			}
			if !h.svc.warmCacheHit(id) {
				t.Fatal("an oom event dropped the sandbox from the warm cache")
			}
			stillRunning(t, call)
			if got := sandboxOOMEventsTotal.Value() - before; got != 2 {
				t.Fatalf("oom metric moved by %d, want 2", got)
			}
		})
	}
}

// TestOOMThenDieRunsTheFullStop: the init itself was OOM-killed. The die
// that follows runs the whole stop path on every engine, and the stop is
// recorded as an OOM kill: last error, an involuntary stop, the toolbox
// request's error.
func TestOOMThenDieRunsTheFullStop(t *testing.T) {
	for _, eng := range oomEngines {
		t.Run(eng.name, func(t *testing.T) {
			h := newOOMHarness(t, eng)
			const id, ip = "sb-oom-dies", "10.88.0.22"
			h.seedEgressSandbox(t, eng, id, ip)
			call, release := h.svc.TrackToolboxCall(context.Background(), id)
			defer release()
			// An expected API stop racing the OOM kill: the kernel killed it,
			// so it is still involuntary.
			h.svc.recordExpectedStop(id, stopModeManual)

			h.event(t, id, "oom", 0)
			h.event(t, id, "die", 137)

			got := h.row(t, id)
			if got.Status != models.SandboxStatusStopped || got.LastError != "container killed by OOM" {
				t.Fatalf("row after oom+die: status %q last error %q", got.Status, got.LastError)
			}
			if clears := h.rt.clearsFor(ip); len(clears) == 0 {
				t.Fatal("the stop after an OOM kill left the sandbox's host rules in place")
			}
			if !h.routes.seen()["DeleteSandboxRoute"] {
				t.Fatalf("the stop after an OOM kill kept the sandbox route: %v", h.routes.calls)
			}
			if snap := h.admitter.Snapshot(); snap.SandboxesActive != 0 {
				t.Fatalf("the stop after an OOM kill kept the slot: %+v", snap)
			}
			if h.svc.warmCacheHit(id) {
				t.Fatal("a stopped sandbox is still in the warm cache")
			}
			endedWith(t, call, "killed by OOM")
			if mode := h.svc.consumeExpectedStop(id); mode != stopModeInvoluntary {
				t.Fatalf("the manual expectation survived the OOM kill: %v", mode)
			}

			// Docker's stop event after its die changes nothing more.
			h.event(t, id, "stop", 0)
			if got := h.row(t, id); got.LastError != "container killed by OOM" {
				t.Fatalf("the stop event overwrote the OOM reason: %q", got.LastError)
			}
		})
	}
}

// TestOOMReasonNeedsAnOOMJustBefore: only a die right after an oom event is
// an OOM kill. A die first (the events can arrive in either order), a die
// long after a child's OOM, a clean exit, or a die after a restart keep
// their own reason; every one of them still runs the full stop.
func TestOOMReasonNeedsAnOOMJustBefore(t *testing.T) {
	eng := oomEngines[1]
	cases := []struct {
		name   string
		drive  func(t *testing.T, h *oomHarness, clock *unknownClock, id, ip string)
		reason string
	}{
		{name: "die before its oom", reason: "container exited with code 137", drive: func(t *testing.T, h *oomHarness, _ *unknownClock, id, ip string) {
			h.event(t, id, "die", 137)
			h.event(t, id, "oom", 0)
		}},
		{name: "a child's oom long before the exit", reason: "container exited with code 137", drive: func(t *testing.T, h *oomHarness, clock *unknownClock, id, ip string) {
			h.event(t, id, "oom", 0)
			clock.advance(oomExitWindow + time.Second)
			h.event(t, id, "die", 137)
		}},
		{name: "a clean exit after a child's oom", reason: "", drive: func(t *testing.T, h *oomHarness, _ *unknownClock, id, ip string) {
			h.event(t, id, "oom", 0)
			h.event(t, id, "die", 0)
		}},
		{name: "a restart between the oom and the exit", reason: "container exited with code 1", drive: func(t *testing.T, h *oomHarness, _ *unknownClock, id, ip string) {
			h.event(t, id, "oom", 0)
			h.rt.inspect = map[string]*models.SandboxRuntimeState{id: {SandboxID: id, ContainerID: id, ContainerIP: ip, Status: models.SandboxStatusStarted}}
			h.event(t, id, "start", 0)
			h.event(t, id, "die", 1)
		}},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newOOMHarness(t, eng)
			clock := newUnknownClock()
			h.svc.sandboxOOMs.now = clock.now
			id, ip := fmt.Sprintf("sb-oom-%d", i), fmt.Sprintf("10.88.0.%d", 30+i)
			h.seedEgressSandbox(t, eng, id, ip)
			tc.drive(t, h, clock, id, ip)
			got := h.row(t, id)
			if got.Status != models.SandboxStatusStopped || got.LastError != tc.reason {
				t.Fatalf("status %q last error %q, want stopped with %q", got.Status, got.LastError, tc.reason)
			}
			if len(h.rt.clearsFor(ip)) == 0 {
				t.Fatal("an exit did not tear down the sandbox's host rules")
			}
		})
	}
}

// TestOOMEventsForUnknownOrDestroyedSandboxes: an oom event for a container
// with no row is ignored, and a destroy forgets a recorded OOM.
func TestOOMEventsForUnknownOrDestroyedSandboxes(t *testing.T) {
	h := newOOMHarness(t, oomEngines[0])
	before := sandboxOOMEventsTotal.Value()
	h.event(t, "sb-no-row", "oom", 0)
	if sandboxOOMEventsTotal.Value() != before {
		t.Fatal("an oom event for a container with no sandbox row was counted")
	}
	const id = "sb-oom-destroyed"
	h.seedEgressSandbox(t, oomEngines[0], id, "10.88.0.40")
	h.event(t, id, "oom", 0)
	h.event(t, id, "destroy", 0)
	if h.svc.sandboxOOMs.take(id) {
		t.Fatal("a destroyed sandbox's OOM record was kept")
	}
}

func TestSandboxOOMTracker(t *testing.T) {
	clock := newUnknownClock()
	tr := &sandboxOOMTracker{now: clock.now}
	if tr.take("sb-a") {
		t.Fatal("an empty tracker reported an OOM")
	}
	tr.note("sb-a")
	tr.note("sb-b")
	if !tr.take("sb-a") || tr.take("sb-a") {
		t.Fatal("take must report a recent OOM once")
	}
	clock.advance(oomExitWindow + time.Second)
	tr.note("sb-c") // prunes sb-b
	tr.mu.Lock()
	_, kept := tr.seen["sb-b"]
	tr.mu.Unlock()
	if kept {
		t.Fatal("an OOM past the window was not pruned")
	}
	tr.forget("sb-c")
	if tr.take("sb-c") {
		t.Fatal("forget did not drop the record")
	}
	var zero sandboxOOMTracker
	zero.note("sb-z")
	if !zero.take("sb-z") {
		t.Fatal("the zero-value tracker does not record")
	}
}

// TestOOMEventOrderingRace: oom and die events for many sandboxes handled
// concurrently, in both orders, with oom-only sandboxes alongside (run with
// -race). Every sandbox that died is stopped with its rules torn down; every
// sandbox that only had OOMs is running with its rules, slot and route
// untouched.
func TestOOMEventOrderingRace(t *testing.T) {
	eng := oomEngines[1]
	h := newOOMHarness(t, eng)
	const n = 8
	type sb struct {
		id, ip string
		dies   bool
	}
	var all []sb
	for i := 0; i < n; i++ {
		s := sb{id: fmt.Sprintf("sb-race-%d", i), ip: fmt.Sprintf("10.88.1.%d", 10+i), dies: i%2 == 0}
		h.seedEgressSandbox(t, eng, s.id, s.ip)
		all = append(all, s)
	}
	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make(chan error, 4*n)
	for i, s := range all {
		events := []docker.DockerEvent{{SandboxID: s.id, Action: "oom"}, {SandboxID: s.id, Action: "oom"}}
		if s.dies {
			events = append(events, docker.DockerEvent{SandboxID: s.id, Action: "die", ExitCode: 137})
			if i%4 == 0 {
				events[0], events[2] = events[2], events[0] // the die first
			}
		}
		for _, ev := range events {
			wg.Add(1)
			go func(ev docker.DockerEvent) {
				defer wg.Done()
				if err := h.svc.handleDockerEvent(ctx, ev); err != nil {
					errs <- err
				}
			}(ev)
		}
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	active := 0
	for _, s := range all {
		got := h.row(t, s.id)
		if s.dies {
			if got.Status != models.SandboxStatusStopped || len(h.rt.clearsFor(s.ip)) == 0 {
				t.Errorf("%s died: status %q, clears %v", s.id, got.Status, h.rt.clearsFor(s.ip))
			}
			continue
		}
		active++
		if got.Status != models.SandboxStatusStarted || len(h.rt.clearsFor(s.ip)) != 0 || !h.svc.warmCacheHit(s.id) {
			t.Errorf("%s only had OOMs: status %q, clears %v, warm %v", s.id, got.Status, h.rt.clearsFor(s.ip), h.svc.warmCacheHit(s.id))
		}
	}
	if snap := h.admitter.Snapshot(); snap.SandboxesActive != active {
		t.Fatalf("admitter holds %d slots, want the %d survivors", snap.SandboxesActive, active)
	}
}
