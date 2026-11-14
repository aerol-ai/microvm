package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

type dockerEventForTest = docker.DockerEvent

// channelEventsSource streams the events a test puts on its channel.
type channelEventsSource struct{ events chan docker.DockerEvent }

func (c *channelEventsSource) StreamEvents(ctx context.Context, out chan<- docker.DockerEvent) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ev := <-c.events:
			out <- ev
		}
	}
}

func (c *channelEventsSource) ContainerPID(context.Context, string) (int, error) {
	return 0, errors.New("no pid")
}

// auditRecord is what a lifecycle test checks on a system action record.
type auditRecord struct {
	ref, reason, caller, result string
}

// captureAudit attaches an in-memory audit sink to h's service.
func captureAudit(svc *Service) *memSecretAuditSink {
	sink := &memSecretAuditSink{}
	svc.secretAudit = sink
	svc.secretAuditOnce.Do(func() {})
	if svc.cluster == nil {
		svc.cluster = cluster.NewNoop("node-a", "", "")
	}
	return sink
}

// systemRecords lists the system action records for id, in order.
func systemRecords(sink *memSecretAuditSink, id string) []auditRecord {
	var out []auditRecord
	for _, ev := range sink.Events() {
		if ev.SandboxID != id || ev.Request == nil || ev.Request.Method != systemActionMethod {
			continue
		}
		caller := ""
		if ev.Caller != nil {
			caller = ev.Caller.ID
		}
		out = append(out, auditRecord{ref: ev.Ref, reason: ev.Reason, caller: caller, result: ev.Result})
	}
	return out
}

func wantRecords(t *testing.T, got []auditRecord, want ...auditRecord) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("records = %+v, want %+v", got, want)
	}
	for i := range want {
		w := want[i]
		g := got[i]
		if g.ref != w.ref || g.reason != w.reason || (w.caller != "" && g.caller != w.caller) || (w.result != "" && g.result != w.result) {
			t.Fatalf("record %d = %+v, want %+v (all: %+v)", i, g, w, got)
		}
	}
}

func sys(action string) string { return systemActionMethod + " " + action }

// TestEveryAutomaticStopAndDeleteIsAudited is plan L3: each way the daemon
// stops, deletes, restarts or recreates a sandbox on its own writes one
// system record naming the subsystem, with the reason; a stop someone asked
// for writes none here (its API call has its own record).
func TestEveryAutomaticStopAndDeleteIsAudited(t *testing.T) {
	runtimeCtx := withAuditSubsystem(context.Background(), auditSubsystemRuntime)
	lifecycleCtx := withAuditSubsystem(context.Background(), auditSubsystemLifecycle)
	reconcileCtx := withAuditSubsystem(context.Background(), auditSubsystemReconcile)
	cases := []struct {
		name string
		lc   models.Lifecycle
		age  time.Duration
		idle time.Duration
		act  func(t *testing.T, h *restartHarness, id string)
		want []auditRecord
	}{
		{name: "crash", act: func(t *testing.T, h *restartHarness, id string) {
			mustEvent(t, h, runtimeCtx, id, "die", 3)
			mustEvent(t, h, runtimeCtx, id, "stop", 0) // the same exit again: no second record
		}, want: []auditRecord{{ref: sys(systemActionRuntimeExited), reason: models.StatusReasonCrashed, caller: "system:runtime", result: "ok"}}},
		{name: "out of memory", act: func(t *testing.T, h *restartHarness, id string) {
			mustEvent(t, h, runtimeCtx, id, "oom", 0)
			mustEvent(t, h, runtimeCtx, id, "die", 137)
		}, want: []auditRecord{{ref: sys(systemActionRuntimeExited), reason: models.StatusReasonOutOfMemory}}},
		{name: "a requested stop's die", act: func(t *testing.T, h *restartHarness, id string) {
			h.svc.recordExpectedStopReason(id, stopModeManual, models.StatusReasonUserStop)
			mustEvent(t, h, runtimeCtx, id, "die", 143)
		}},
		{name: "removed out of band", act: func(t *testing.T, h *restartHarness, id string) {
			mustEvent(t, h, runtimeCtx, id, "destroy", 0)
		}, want: []auditRecord{{ref: sys(systemActionRuntimeRemoved), caller: "system:runtime", result: "ok"}}},
		{name: "idle stop", lc: models.Lifecycle{StopIfIdleFor: time.Minute}, idle: 2 * time.Minute,
			act:  func(t *testing.T, h *restartHarness, _ string) { h.svc.runLifecycleSweep(lifecycleCtx) },
			want: []auditRecord{{ref: sys(systemActionAutoStop), reason: models.StatusReasonIdle, caller: "system:lifecycle"}}},
		{name: "age delete", lc: models.Lifecycle{DestroyAtAge: time.Minute}, age: 2 * time.Minute,
			act:  func(t *testing.T, h *restartHarness, _ string) { h.svc.runLifecycleSweep(lifecycleCtx) },
			want: []auditRecord{{ref: sys(systemActionAutoDelete), reason: models.StatusReasonMaxAge, result: "ok"}}},
		{name: "idle delete", lc: models.Lifecycle{DestroyIfIdleFor: time.Minute}, idle: 2 * time.Minute,
			act:  func(t *testing.T, h *restartHarness, _ string) { h.svc.runLifecycleSweep(lifecycleCtx) },
			want: []auditRecord{{ref: sys(systemActionAutoDelete), reason: models.StatusReasonIdle}}},
		{name: "disk limit", act: func(t *testing.T, h *restartHarness, id string) {
			h.svc.stopForDiskLimit(lifecycleCtx, h.row(t, id), 9<<30)
		}, want: []auditRecord{{ref: sys(systemActionDiskStop), reason: models.StatusReasonDiskLimit}}},
		{name: "restart on failure", lc: models.Lifecycle{RestartOnFailure: true}, act: func(t *testing.T, h *restartHarness, id string) {
			mustEvent(t, h, runtimeCtx, id, "die", 1)
			h.clock.advance(5 * time.Second)
			h.svc.setRestartBase(lifecycleCtx)
			h.fire(t)
		}, want: []auditRecord{
			{ref: sys(systemActionRuntimeExited), reason: models.StatusReasonCrashed},
			{ref: sys(systemActionRestart), reason: models.StatusReasonCrashed, caller: "system:lifecycle", result: "ok"},
		}},
		{name: "reconcile found it stopped", act: func(t *testing.T, h *restartHarness, id string) {
			h.rt.managed = map[string]*models.SandboxRuntimeState{id: {ContainerID: id, ContainerIP: "10.0.0.7", Status: models.SandboxStatusStopped}}
			if err := h.svc.Reconcile(reconcileCtx); err != nil {
				t.Fatal(err)
			}
		}, want: []auditRecord{{ref: sys(systemActionFoundStopped), reason: models.StatusReasonReconcile, caller: "system:reconcile"}}},
		{name: "failover recreate", act: func(t *testing.T, h *restartHarness, id string) {
			h.svc.recordFailoverReason(withAuditSubsystem(context.Background(), auditSubsystemFailover), id)
		}, want: []auditRecord{{ref: sys(systemActionFailoverRecreated), reason: models.StatusReasonFailover, caller: "system:failover"}}},
		{name: "fleet suspend", act: func(t *testing.T, h *restartHarness, _ string) {
			if err := h.svc.StopByOwner(context.Background(), ""); err != nil {
				t.Fatal(err)
			}
		}, want: []auditRecord{{ref: sys(systemActionFleetSuspend), reason: models.StatusReasonUserStop, caller: "system:fleet", result: "ok"}}},
		{name: "fleet delete", act: func(t *testing.T, h *restartHarness, _ string) {
			if err := h.svc.DeleteByOwner(context.Background(), ""); err != nil {
				t.Fatal(err)
			}
		}, want: []auditRecord{{ref: sys(systemActionFleetDelete), caller: "system:fleet", result: "ok"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newRestartHarness(t)
			sink := captureAudit(h.svc)
			id := "sb-audit"
			h.seedStarted(t, id, tc.lc, tc.age, tc.idle)
			tc.act(t, h, id)
			wantRecords(t, systemRecords(sink, id), tc.want...)
		})
	}
}

// TestReconcileStaleReadWritesNoFoundStoppedRecord: a reconcile pass that
// read the row before the event path stopped it does not claim it found the
// stop; the die's record is the only one.
func TestReconcileStaleReadWritesNoFoundStoppedRecord(t *testing.T) {
	ctx := withAuditSubsystem(context.Background(), auditSubsystemReconcile)
	h := newRestartHarness(t)
	sink := captureAudit(h.svc)
	h.seedStarted(t, "sb-stale", models.Lifecycle{}, 0, 0)
	h.event(t, "sb-stale", "die", 4)
	if h.svc.rowStillStarted(ctx, "sb-stale") || h.svc.rowStillStarted(ctx, "sb-missing") {
		t.Fatal("a stopped or missing row reads as started")
	}
	h.rt.managed = map[string]*models.SandboxRuntimeState{"sb-stale": {ContainerID: "sb-stale", ContainerIP: "10.0.0.7", Status: models.SandboxStatusStopped}}
	if err := h.svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	wantRecords(t, systemRecords(sink, "sb-stale"), auditRecord{ref: sys(systemActionRuntimeExited), reason: models.StatusReasonCrashed})
}

// TestEventMonitorRecordsAsRuntime: the event monitor's context names
// system:runtime, so an exit it reports is not filed under system:daemon.
func TestEventMonitorRecordsAsRuntime(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h := newRestartHarness(t)
	sink := captureAudit(h.svc)
	h.seedStarted(t, "sb-mon", models.Lifecycle{}, 0, 0)
	src := &channelEventsSource{events: make(chan dockerEventForTest, 1)}
	h.svc.events = src
	h.svc.cfg.EnableEventMonitor = true
	src.events <- dockerEventForTest{SandboxID: "sb-mon", Action: "die", ExitCode: 9}
	h.svc.StartEventMonitor(ctx)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && len(systemRecords(sink, "sb-mon")) == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	wantRecords(t, systemRecords(sink, "sb-mon"), auditRecord{ref: sys(systemActionRuntimeExited), reason: models.StatusReasonCrashed, caller: "system:runtime"})
}

// TestWasmLostOnRestartIsAudited: an ephemeral WASM sandbox reconcile finds
// gone after a daemon restart is recorded as found stopped.
func TestWasmLostOnRestartIsAudited(t *testing.T) {
	ctx := withAuditSubsystem(context.Background(), auditSubsystemReconcile)
	h := newRestartHarness(t)
	sink := captureAudit(h.svc)
	h.svc.cfg.EnableWasm = true
	now := time.Now().UTC()
	sb := &models.Sandbox{ID: "sb-w", Image: "m", Runtime: models.RuntimeWasm, Status: models.SandboxStatusStarted,
		Durability: models.DurabilityEphemeral, AuditIncarnationID: "inc-w", CreatedAt: now, UpdatedAt: now, LastActiveAt: now}
	if err := h.st.Create(ctx, sb); err != nil {
		t.Fatal(err)
	}
	h.svc.reconcileWasmOfflineRow(ctx, sb)
	wantRecords(t, systemRecords(sink, "sb-w"), auditRecord{ref: sys(systemActionFoundStopped), reason: models.StatusReasonReconcile, caller: "system:reconcile", result: "ok"})
}

func mustEvent(t *testing.T, h *restartHarness, ctx context.Context, id, action string, code int) {
	t.Helper()
	if err := h.svc.handleDockerEvent(ctx, dockerEventForTest{SandboxID: id, Action: action, ExitCode: code, Time: time.Now().UTC()}); err != nil {
		t.Fatalf("%s event: %v", action, err)
	}
}
