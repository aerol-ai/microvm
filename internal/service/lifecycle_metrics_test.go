package service

import (
	"context"
	"expvar"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/scaleobs"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
)

// counter reads one key of an expvar map counter (0 when absent).
func counter(t *testing.T, name, key string) int64 {
	t.Helper()
	return expvarMapInt(t, name, key)
}

// TestLifecycleCountersMove is plan O1: each lifecycle transition moves its
// counter once, labelled from the fixed reason set, including the paths
// where two writers see one stop (the stop call and its die event).
func TestLifecycleCountersMove(t *testing.T) {
	ctx := context.Background()
	type delta struct{ name, key string }
	cases := []struct {
		name string
		lc   models.Lifecycle
		age  time.Duration
		idle time.Duration
		act  func(t *testing.T, h *restartHarness, id string)
		want []delta
	}{
		{name: "user stop and its die event count once", act: func(t *testing.T, h *restartHarness, id string) {
			if _, err := h.svc.StopSandbox(ctx, id); err != nil {
				t.Fatal(err)
			}
			h.event(t, id, "die", 143)
			h.event(t, id, "stop", 0)
		}, want: []delta{{"aerolvm_sandbox_stops_total", models.StatusReasonUserStop}}},
		{name: "crash", act: func(t *testing.T, h *restartHarness, id string) {
			h.event(t, id, "die", 2)
			h.event(t, id, "stop", 0)
		}, want: []delta{{"aerolvm_sandbox_stops_total", models.StatusReasonCrashed}}},
		{name: "init exited cleanly is a stop and a finish", act: func(t *testing.T, h *restartHarness, id string) {
			h.event(t, id, "die", 0)
		}, want: []delta{{"aerolvm_sandbox_stops_total", models.StatusReasonProgramExited}, {"aerolvm_sandbox_finished_total", "success"}}},
		{name: "idle stop", lc: models.Lifecycle{StopIfIdleFor: time.Minute}, idle: 2 * time.Minute,
			act:  func(t *testing.T, h *restartHarness, _ string) { h.svc.runLifecycleSweep(ctx) },
			want: []delta{{"aerolvm_sandbox_stops_total", models.StatusReasonIdle}}},
		{name: "age delete", lc: models.Lifecycle{DestroyAtAge: time.Minute}, age: 2 * time.Minute,
			act:  func(t *testing.T, h *restartHarness, _ string) { h.svc.runLifecycleSweep(ctx) },
			want: []delta{{"aerolvm_sandbox_expired_total", models.StatusReasonMaxAge}}},
		{name: "start", act: func(t *testing.T, h *restartHarness, id string) {
			if _, err := h.svc.StopSandbox(ctx, id); err != nil {
				t.Fatal(err)
			}
			if _, err := h.svc.StartSandbox(ctx, id); err != nil {
				t.Fatal(err)
			}
		}, want: []delta{{"aerolvm_sandbox_stops_total", models.StatusReasonUserStop}, {"aerolvm_sandbox_starts_total", startKindRequested}}},
		{name: "restart on failure", lc: models.Lifecycle{RestartOnFailure: true}, act: func(t *testing.T, h *restartHarness, id string) {
			h.event(t, id, "die", 1)
			h.clock.advance(5 * time.Second)
			h.fire(t)
		}, want: []delta{{"aerolvm_sandbox_stops_total", models.StatusReasonCrashed}, {"aerolvm_sandbox_starts_total", startKindRestarted}}},
		{name: "failover", act: func(t *testing.T, h *restartHarness, id string) { h.svc.recordFailoverReason(ctx, id) },
			want: []delta{{"aerolvm_sandbox_starts_total", startKindFailover}}},
		{name: "reconcile found it stopped", act: func(t *testing.T, h *restartHarness, id string) {
			h.rt.managed = map[string]*models.SandboxRuntimeState{id: {ContainerID: id, ContainerIP: "10.0.0.7", Status: models.SandboxStatusStopped}}
			if err := h.svc.Reconcile(ctx); err != nil {
				t.Fatal(err)
			}
		}, want: []delta{{"aerolvm_sandbox_stops_total", models.StatusReasonReconcile}}},
	}
	tracked := []delta{
		{"aerolvm_sandbox_stops_total", models.StatusReasonUserStop}, {"aerolvm_sandbox_stops_total", models.StatusReasonCrashed},
		{"aerolvm_sandbox_stops_total", models.StatusReasonIdle}, {"aerolvm_sandbox_stops_total", models.StatusReasonProgramExited},
		{"aerolvm_sandbox_stops_total", models.StatusReasonReconcile},
		{"aerolvm_sandbox_starts_total", startKindRequested}, {"aerolvm_sandbox_starts_total", startKindRestarted},
		{"aerolvm_sandbox_starts_total", startKindFailover},
		{"aerolvm_sandbox_expired_total", models.StatusReasonMaxAge},
		{"aerolvm_sandbox_finished_total", "success"}, {"aerolvm_sandbox_finished_total", "failure"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newRestartHarness(t)
			id := "sb-metric"
			h.seedStarted(t, id, tc.lc, tc.age, tc.idle)
			before := map[delta]int64{}
			for _, d := range tracked {
				before[d] = counter(t, d.name, d.key)
			}
			tc.act(t, h, id)
			for _, d := range tracked {
				want := int64(0)
				for _, w := range tc.want {
					if w == d {
						want++
					}
				}
				if got := counter(t, d.name, d.key) - before[d]; got != want {
					t.Fatalf("%s{%s} moved %d, want %d", d.name, d.key, got, want)
				}
			}
		})
	}
}

// TestLifecycleCounterHelpers: an unknown reason folds into "other", and an
// exit code picks success or failure.
func TestLifecycleCounterHelpers(t *testing.T) {
	before := counter(t, "aerolvm_sandbox_stops_total", "other")
	recordSandboxStop("something-new")
	if counter(t, "aerolvm_sandbox_stops_total", "other") != before+1 {
		t.Fatal("an unknown reason did not fold into other")
	}
	for _, r := range models.StatusReasons {
		if metricReason(r) != r {
			t.Fatalf("metricReason(%q) changed it", r)
		}
	}
	fail := counter(t, "aerolvm_sandbox_finished_total", "failure")
	recordSandboxFinished(3)
	if counter(t, "aerolvm_sandbox_finished_total", "failure") != fail+1 {
		t.Fatal("a non-zero exit is not a failure")
	}
}

// TestCreateLatencyIsLabelledWarmOrCold: a successful create lands in the
// warm or cold histogram by its marker; a failed one in neither.
func TestCreateLatencyIsLabelledWarmOrCold(t *testing.T) {
	count := func(label string) int64 {
		sub, ok := expvar.Get("aerolvm_create_latency_by_start_seconds_bucket").(*expvar.Map).Get(label).(*expvar.Map)
		if !ok {
			return 0
		}
		var n int64
		sub.Do(func(kv expvar.KeyValue) { n += scaleobs.IntValue(kv.Value) })
		return n
	}
	warm, cold := count("warm"), count("cold")

	marked := new(atomic.Bool)
	marked.Store(true)
	beginSandboxCreateMetric(marked)(nil)
	beginSandboxCreateMetric(new(atomic.Bool))(nil)
	beginSandboxCreateMetric(nil)(nil)
	beginSandboxCreateMetric(marked)(context.DeadlineExceeded)
	if count("warm") != warm+1 || count("cold") != cold+2 {
		t.Fatalf("warm %d->%d cold %d->%d", warm, count("warm"), cold, count("cold"))
	}

	// A real Docker create from a parked container is warm; one without is
	// cold.
	rt := &parkedCreateRuntime{recordingRuntime: &recordingRuntime{}, park: "park-1"}
	svc, _, _ := newServiceRuntimeHarnessAtPath(t, filepath.Join(t.TempDir(), "state.db"), rt)
	warm, cold = count("warm"), count("cold")
	if _, err := svc.CreateSandbox(context.Background(), models.CreateSandboxRequest{Image: "alpine"}); err != nil {
		t.Fatal(err)
	}
	rt.park = ""
	if _, err := svc.CreateSandbox(context.Background(), models.CreateSandboxRequest{Image: "alpine"}); err != nil {
		t.Fatal(err)
	}
	if count("warm") != warm+1 || count("cold") != cold+1 {
		t.Fatalf("creates: warm %d->%d cold %d->%d", warm, count("warm"), cold, count("cold"))
	}
}

// parkedCreateRuntime answers a create as if it adopted a parked container.
type parkedCreateRuntime struct {
	*recordingRuntime
	park string
}

func (r *parkedCreateRuntime) Create(ctx context.Context, req models.CreateSandboxRequest, id, token string, binds []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	state, err := r.recordingRuntime.Create(ctx, req, id, token, binds)
	if state != nil {
		state.AdoptedParkID = r.park
	}
	return state, err
}
