package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/models"
)

// runStateCluster is the server tier as a reporter sees it: a page of this
// node's placements, point reads, and the batches it is sent.
type runStateCluster struct {
	*cluster.Noop
	page          []cluster.Placement
	authoritative bool
	point         map[string]cluster.Placement
	sent          [][]cluster.RunStateReport
	sendErr       error
}

func (c *runStateCluster) PlacementPage(cluster.PlacementPageRequest) cluster.PlacementPageResponse {
	return cluster.PlacementPageResponse{Placements: c.page, Authoritative: c.authoritative}
}

func (c *runStateCluster) PlacementOf(id string) (cluster.Placement, bool) {
	p, ok := c.point[id]
	return p, ok
}

func (c *runStateCluster) SetRunStates(_ context.Context, reports []cluster.RunStateReport) (int, error) {
	if c.sendErr != nil {
		return 0, c.sendErr
	}
	c.sent = append(c.sent, append([]cluster.RunStateReport(nil), reports...))
	return len(reports), nil
}

func (c *runStateCluster) last() map[string]cluster.RunStateReport {
	out := map[string]cluster.RunStateReport{}
	if len(c.sent) == 0 {
		return out
	}
	for _, r := range c.sent[len(c.sent)-1] {
		out[r.SandboxID] = r
	}
	return out
}

func placed(id string, state cluster.RunState) cluster.Placement {
	return cluster.Placement{SandboxID: id, OwnerNodeID: "self", IncarnationID: "inc-" + id, RunState: state}
}

func newRunStateHarness(t *testing.T, c *runStateCluster) (*Service, *runStateReporter, *time.Time) {
	t.Helper()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCluster, svc.cfg.AgentSandboxAPI = true, true
	svc.AttachCluster(c)
	clock := time.Unix(1000, 0)
	r := svc.newRunStateReporter()
	if r == nil {
		t.Fatal("no reporter with the API on in a cluster")
	}
	r.now = func() time.Time { return clock }
	_ = st
	return svc, r, &clock
}

func putRow(t *testing.T, svc *Service, id string, status models.SandboxStatus, lastError string) {
	t.Helper()
	now := time.Now().UTC()
	if err := svc.store.Upsert(context.Background(), &models.Sandbox{
		ID: id, Image: "alpine:3.20", Status: status, LastError: lastError,
		CPU: 1, MemoryMB: 256, DiskGB: 1, OSUser: "root",
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRunStateReporterSendsOnlyChanges(t *testing.T) {
	c := &runStateCluster{Noop: cluster.NewNoop("self", "", ""), authoritative: true, page: []cluster.Placement{
		placed("sb-run", cluster.RunStateRunning),
		placed("sb-stop", cluster.RunStateRunning),
		placed("sb-err", ""),
	}}
	svc, r, clock := newRunStateHarness(t, c)
	ctx := context.Background()
	putRow(t, svc, "sb-run", models.SandboxStatusStarted, "")
	putRow(t, svc, "sb-stop", models.SandboxStatusStopped, "")
	putRow(t, svc, "sb-err", models.SandboxStatusError, strings.Repeat("x", 300))
	putRow(t, svc, "sb-new", models.SandboxStatusCreating, "")

	if err := r.tick(ctx); err != nil {
		t.Fatal(err)
	}
	got := c.last()
	if len(c.sent) != 1 || len(got) != 2 {
		t.Fatalf("sent %+v, want sb-stop and sb-err in one batch", c.sent)
	}
	if s := got["sb-stop"]; s.State != cluster.RunStateSuspended || s.IncarnationID != "inc-sb-stop" || s.OwnerNodeID != "self" {
		t.Fatalf("sb-stop = %+v", s)
	}
	if e := got["sb-err"]; e.State != cluster.RunStateFailed || len(e.Reason) != runStateReasonMax {
		t.Fatalf("sb-err = %+v, want failed with a %d-byte reason", e, runStateReasonMax)
	}

	// Nothing changed: nothing sent.
	if err := r.tick(ctx); err != nil || len(c.sent) != 1 {
		t.Fatalf("a quiet tick sent %d batches, %v", len(c.sent)-1, err)
	}

	// A sandbox made since the resync: its lifetime comes from a point read.
	putRow(t, svc, "sb-late", models.SandboxStatusStarted, "")
	c.point = map[string]cluster.Placement{"sb-late": placed("sb-late", "")}
	if err := r.tick(ctx); err != nil {
		t.Fatal(err)
	}
	if l := c.last()["sb-late"]; l.State != cluster.RunStateRunning || l.IncarnationID != "inc-sb-late" {
		t.Fatalf("sb-late = %+v", l)
	}

	// A failed send changes nothing known, so the next tick sends it again.
	putRow(t, svc, "sb-run", models.SandboxStatusStopped, "")
	c.sendErr = errors.New("leader lost")
	if err := r.tick(ctx); err == nil {
		t.Fatal("a failed send reported no error")
	}
	c.sendErr = nil
	if err := r.tick(ctx); err != nil || c.last()["sb-run"].State != cluster.RunStateSuspended {
		t.Fatalf("resend = %+v, %v", c.last(), err)
	}

	// Raft got a row wrong (a failover): the next resync learns it, and the
	// tick after puts it right.
	c.page = []cluster.Placement{placed("sb-run", cluster.RunStateRunning), placed("sb-stop", cluster.RunStateSuspended), placed("sb-late", cluster.RunStateRunning)}
	*clock = clock.Add(runStateResyncInterval)
	if err := r.tick(ctx); err != nil {
		t.Fatal(err)
	}
	if s := c.last()["sb-run"]; s.State != cluster.RunStateSuspended {
		t.Fatalf("after a resync = %+v, want sb-run suspended again", c.last())
	}

	// A row that is gone is forgotten.
	if err := svc.store.Delete(ctx, "sb-late"); err != nil {
		t.Fatal(err)
	}
	if err := r.tick(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.known["sb-late"]; ok {
		t.Fatal("a deleted row is still known")
	}
}

// Until the server tier answers a page for sure, nothing is sent: every row
// would otherwise cost a point read each tick.
func TestRunStateReporterWaitsForAnAuthoritativePage(t *testing.T) {
	c := &runStateCluster{Noop: cluster.NewNoop("self", "", ""), page: []cluster.Placement{placed("sb-a", "")}}
	svc, r, _ := newRunStateHarness(t, c)
	putRow(t, svc, "sb-a", models.SandboxStatusStarted, "")
	if err := r.tick(context.Background()); err != nil || len(c.sent) != 0 {
		t.Fatalf("sent %+v before any authoritative page, %v", c.sent, err)
	}
	c.authoritative = true
	if err := r.tick(context.Background()); err != nil || c.last()["sb-a"].State != cluster.RunStateRunning {
		t.Fatalf("after one = %+v, %v", c.sent, err)
	}
}

func TestRunStateReporterBatches(t *testing.T) {
	c := &runStateCluster{Noop: cluster.NewNoop("self", "", ""), authoritative: true}
	svc, r, _ := newRunStateHarness(t, c)
	for i := 0; i < runStateBatch+1; i++ {
		id := fmt.Sprintf("sb-%04d", i)
		c.page = append(c.page, placed(id, ""))
		putRow(t, svc, id, models.SandboxStatusStarted, "")
	}
	if err := r.tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(c.sent) != 2 || len(c.sent[0]) != runStateBatch || len(c.sent[1]) != 1 {
		t.Fatalf("batches = %d", len(c.sent))
	}
}

func TestRunStateReporterOnlyWhenOn(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	if svc.newRunStateReporter() != nil {
		t.Fatal("a reporter with the API off")
	}
	svc.cfg.AgentSandboxAPI = true
	if svc.newRunStateReporter() != nil {
		t.Fatal("a reporter outside cluster mode")
	}
	svc.cfg.EnableCluster = true
	if svc.newRunStateReporter() != nil {
		t.Fatal("a reporter with a client that cannot carry reports (Noop)")
	}
	svc.StartRunStateReports(context.Background()) // a no-op, and must not panic
	var nilSvc *Service
	if nilSvc.newRunStateReporter() != nil {
		t.Fatal("a reporter from a nil service")
	}
}

func TestRunStateOf(t *testing.T) {
	for _, tc := range []struct {
		status models.SandboxStatus
		want   cluster.RunState
		ok     bool
	}{
		{models.SandboxStatusStarted, cluster.RunStateRunning, true},
		{models.SandboxStatusStopped, cluster.RunStateSuspended, true},
		{models.SandboxStatusPassivated, cluster.RunStateSuspended, true},
		{models.SandboxStatusAwaitingRuntime, cluster.RunStateSuspended, true},
		{models.SandboxStatusError, cluster.RunStateFailed, true},
		{models.SandboxStatusPassivateFailed, cluster.RunStateFailed, true},
		{models.SandboxStatusCreating, "", false},
		{models.SandboxStatusDestroyed, "", false},
	} {
		got, _, ok := runStateOf(&models.Sandbox{Status: tc.status})
		if got != tc.want || ok != tc.ok {
			t.Errorf("%s = %q %v, want %q %v", tc.status, got, ok, tc.want, tc.ok)
		}
	}
}

// The loop sends on its ticker, keeps going after a failed send, and stops
// with its context.
func TestStartRunStateReportsLoop(t *testing.T) {
	old := runStateReportInterval
	runStateReportInterval = 10 * time.Millisecond
	t.Cleanup(func() { runStateReportInterval = old })
	c := &syncRunStateCluster{runStateCluster: runStateCluster{Noop: cluster.NewNoop("self", "", ""), authoritative: true,
		page: []cluster.Placement{placed("sb-a", "")}, sendErr: errors.New("leader lost")}}
	svc, _, _ := newRunStateHarness(t, &c.runStateCluster)
	svc.AttachCluster(c)
	putRow(t, svc, "sb-a", models.SandboxStatusStarted, "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc.StartRunStateReports(ctx)
	time.Sleep(50 * time.Millisecond) // a few failed ticks
	c.mu.Lock()
	c.sendErr = nil
	c.mu.Unlock()
	deadline := time.Now().Add(5 * time.Second)
	for {
		c.mu.Lock()
		n := len(c.sent)
		c.mu.Unlock()
		if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the loop never sent")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
}

// syncRunStateCluster guards the stub for a test that runs the loop.
type syncRunStateCluster struct {
	runStateCluster
	mu sync.Mutex
}

func (c *syncRunStateCluster) SetRunStates(ctx context.Context, reports []cluster.RunStateReport) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.runStateCluster.SetRunStates(ctx, reports)
}
