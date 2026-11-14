package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/models"
)

// preparingRuntime is the capacity fake plus PrepareImage.
type preparingRuntime struct {
	*fakeCapacityRuntime
	prepared []string
	err      error
}

func (p *preparingRuntime) PrepareImage(_ context.Context, ref string) error {
	p.prepared = append(p.prepared, ref)
	return p.err
}

func putRunning(t *testing.T, svc *Service, id string) {
	t.Helper()
	if err := svc.store.Create(context.Background(), &models.Sandbox{ID: id, Name: id, Image: "alpine", Status: models.SandboxStatusStarted, ContainerID: "c-" + id}); err != nil {
		t.Fatal(err)
	}
}

func TestMoveFences(t *testing.T) {
	var f moveFences
	now := time.Unix(100, 0)
	if f.held("a", now) {
		t.Fatal("empty fence held")
	}
	f.set("a", now.Add(time.Minute))
	if !f.held("a", now) {
		t.Fatal("fence not held")
	}
	// It lapses at its expiry and is forgotten.
	if f.held("a", now.Add(time.Minute)) || len(f.until) != 0 {
		t.Fatal("expired fence still held")
	}
	f.set("b", now.Add(time.Minute))
	f.clear("b")
	if f.held("b", now) {
		t.Fatal("cleared fence held")
	}
	var nilSvc *Service
	if nilSvc.moveFenced("a") {
		t.Fatal("nil service fenced")
	}
}

// The source's release: stopped, then fenced against every start until the
// placement moves, and idempotent.
func TestReleaseForMoveStopsAndFences(t *testing.T) {
	svc, _, st := newCapacityHarness(t, nil, nil)
	putRunning(t, svc, "sb-move")
	got := svc.ReleaseForMove(context.Background(), []string{"sb-move", "sb-none", " "}, nil)
	if got["sb-move"] != MoveReleased || got["sb-none"] != MoveGone || len(got) != 2 {
		t.Fatalf("release = %v", got)
	}
	// The row's reason is the fence a restarted sandboxd reads (R11).
	sb, _ := st.Get(context.Background(), "sb-move")
	if sb.Status != models.SandboxStatusStopped || sb.StatusReason != statusReasonMoveReleased {
		t.Fatalf("after release: %s (%s)", sb.Status, sb.StatusReason)
	}
	if !svc.OwnershipFenced("sb-move") {
		t.Fatal("a released sandbox is not fenced")
	}
	if _, err := svc.StartSandbox(context.Background(), "sb-move"); !errors.Is(err, ErrOwnershipFenced) {
		t.Fatalf("start of a released sandbox = %v, want ErrOwnershipFenced", err)
	}
	// Again: already stopped, released again (the fence is renewed). It
	// still says the release stopped it, so a lapsed move starts it again.
	if got := svc.ReleaseForMove(context.Background(), []string{"sb-move"}, nil); got["sb-move"] != MoveReleased {
		t.Fatalf("second release = %v", got)
	}
	if sb, _ := st.Get(context.Background(), "sb-move"); sb.StatusReason != statusReasonMoveReleased {
		t.Fatalf("after the second release: %s", sb.StatusReason)
	}
}

// At the deadline a sandbox that cannot move is stopped but not fenced:
// until the node is deleted it is still this node's.
func TestStopForDecommission(t *testing.T) {
	svc, _, st := newCapacityHarness(t, nil, nil)
	putRunning(t, svc, "sb-stay")
	if got := svc.StopForDecommission(context.Background(), []string{"sb-stay"}, nil); got["sb-stay"] != MoveStopped {
		t.Fatalf("stop = %v", got)
	}
	if sb, _ := st.Get(context.Background(), "sb-stay"); sb.Status != models.SandboxStatusStopped {
		t.Fatalf("status %s", sb.Status)
	}
	if svc.OwnershipFenced("sb-stay") {
		t.Fatal("a deadline stop fenced the sandbox")
	}
}

// A sandbox this node no longer owns is not this node's to stop.
func TestReleaseForMoveRefusesAForeignPlacement(t *testing.T) {
	svc, _, _ := newCapacityHarness(t, nil, nil)
	putRunning(t, svc, "sb-x")
	svc.AttachCluster(&ownerStubCluster{Noop: cluster.NewNoop("self", "", ""), owner: "other"})
	got := svc.ReleaseForMove(context.Background(), []string{"sb-x"}, nil)
	if !strings.HasPrefix(got["sb-x"], "error:") || svc.OwnershipFenced("sb-x") {
		t.Fatalf("release of a foreign placement = %v, fenced %v", got, svc.OwnershipFenced("sb-x"))
	}
}

func TestPrepareMove(t *testing.T) {
	svc, _, _ := newCapacityHarness(t, nil, nil)
	ctx := context.Background()
	if err := svc.PrepareMove(ctx, models.CreateSandboxRequest{Image: "alpine"}); !errors.Is(err, ErrPrepareUnsupported) {
		t.Fatalf("runtime without PrepareImage = %v", err)
	}
	prt := &preparingRuntime{fakeCapacityRuntime: svc.docker.(*fakeCapacityRuntime)}
	svc.docker = prt
	if err := svc.PrepareMove(ctx, models.CreateSandboxRequest{Image: " python:3.12 "}); err != nil || len(prt.prepared) != 1 || prt.prepared[0] != "python:3.12" {
		t.Fatalf("prepare = %v %v", err, prt.prepared)
	}
	// Registry credentials are the recreate's to unseal.
	if err := svc.PrepareMove(ctx, models.CreateSandboxRequest{Image: "private/x", Registry: &models.RegistryAuth{Username: "u"}}); !errors.Is(err, ErrPrepareUnsupported) {
		t.Fatalf("with registry auth = %v", err)
	}
	if err := svc.PrepareMove(ctx, models.CreateSandboxRequest{}); err == nil {
		t.Fatal("no image accepted")
	}
	prt.err = errors.New("pull failed")
	if err := svc.PrepareMove(ctx, models.CreateSandboxRequest{Image: "alpine"}); err == nil {
		t.Fatal("pull error lost")
	}
}

func TestNoticeDecommission(t *testing.T) {
	svc, _, _ := newCapacityHarness(t, nil, nil)
	putRunning(t, svc, "sb-n")
	sink := &decomCaptureSink{}
	svc.secretAudit = sink
	deadline := time.Unix(2000000000, 0)
	if n := svc.NoticeDecommission(context.Background(), []string{"sb-n", "sb-missing"}, deadline); n != 1 {
		t.Fatalf("noticed %d, want 1", n)
	}
	evs := sink.evs
	if len(evs) != 1 || evs[0].Kind != KindDecommissionNotice || evs[0].SandboxID != "sb-n" || !strings.Contains(evs[0].Reason, "2033-05-18") {
		t.Fatalf("events = %+v", evs)
	}
}

// ownerStubCluster places every sandbox on owner.
type ownerStubCluster struct {
	*cluster.Noop
	owner       string
	incarnation string // the placement's lifetime; empty matches any row
	readErr     error
}

func (c *ownerStubCluster) PlacementOf(id string) (cluster.Placement, bool) {
	return cluster.Placement{SandboxID: id, OwnerNodeID: c.owner, IncarnationID: c.incarnation}, true
}

// AuthoritativePlacementsByIDs is the leader's answer: the same placement,
// or readErr.
func (c *ownerStubCluster) AuthoritativePlacementsByIDs(_ context.Context, ids []string) (map[string]cluster.Placement, error) {
	if c.readErr != nil {
		return nil, c.readErr
	}
	out := make(map[string]cluster.Placement, len(ids))
	for _, id := range ids {
		out[id], _ = c.PlacementOf(id)
	}
	return out, nil
}

// The service is the worker side the leader calls.
var _ cluster.MoveHandler = (*Service)(nil)

type decomCaptureSink struct{ evs []SecretAuditEvent }

func (s *decomCaptureSink) Emit(ev SecretAuditEvent) { s.evs = append(s.evs, ev) }

// A move whose release worked but whose swap never came (the leader lost
// leadership, the swap was refused, the decommission was called off): once
// the fence lapses, the node starts the sandbox again, unless it moved, a
// later release renewed the fence, or something else changed it.
func TestResumeLapsedMove(t *testing.T) {
	ctx := context.Background()
	svc, _, st := newCapacityHarness(t, nil, nil)
	svc.docker.(*fakeCapacityRuntime).startResult = &models.SandboxRuntimeState{Status: models.SandboxStatusStarted, ContainerID: "c"}
	owner := &ownerStubCluster{Noop: cluster.NewNoop("self", "", ""), owner: "self"}
	svc.AttachCluster(owner)
	for _, id := range []string{"sb-stuck", "sb-moved", "sb-renewed", "sb-user"} {
		putRunning(t, svc, id)
	}
	release := func(id string) {
		if got := svc.ReleaseForMove(ctx, []string{id}, nil); got[id] != MoveReleased {
			t.Fatalf("release %s = %v", id, got)
		}
	}
	for _, id := range []string{"sb-stuck", "sb-moved", "sb-renewed"} {
		release(id)
	}
	if svc.resumeLapsedMove(ctx, "sb-stuck") {
		t.Fatal("resumed while the fence still holds")
	}
	// The fences lapse.
	for _, id := range []string{"sb-stuck", "sb-moved", "sb-renewed"} {
		svc.moves.set(id, time.Now().Add(-time.Second))
	}
	if !svc.resumeLapsedMove(ctx, "sb-stuck") {
		t.Fatal("a sandbox whose move never happened stayed stopped")
	}
	if sb, _ := st.Get(ctx, "sb-stuck"); sb.Status == models.SandboxStatusStopped {
		t.Fatalf("status %s", sb.Status)
	}
	if svc.resumeLapsedMove(ctx, "sb-stuck") {
		t.Fatal("resumed twice")
	}
	release("sb-renewed") // a later pass's release renews the fence
	if svc.resumeLapsedMove(ctx, "sb-renewed") {
		t.Fatal("resumed past a renewed fence")
	}
	owner.owner = "other" // the move did happen
	if svc.resumeLapsedMove(ctx, "sb-moved") {
		t.Fatal("resumed a sandbox another node now owns")
	}
	owner.owner = "self"
	// Stopped by its user, not by a decommission: not ours to start.
	if _, err := svc.StopSandbox(ctx, "sb-user"); err != nil {
		t.Fatal(err)
	}
	if svc.resumeLapsedMove(ctx, "sb-user") {
		t.Fatal("started a sandbox its user stopped")
	}
	var nilSvc *Service
	if nilSvc.resumeLapsedMove(ctx, "x") {
		t.Fatal("nil service resumed")
	}
}

// End to end through the timer the release sets.
func TestReleaseSchedulesTheResume(t *testing.T) {
	svc, _, st := newCapacityHarness(t, nil, nil)
	svc.moveTimings.fenceTTL = 10 * time.Millisecond
	svc.docker.(*fakeCapacityRuntime).startResult = &models.SandboxRuntimeState{Status: models.SandboxStatusStarted, ContainerID: "c"}
	putRunning(t, svc, "sb-timer")
	if got := svc.ReleaseForMove(context.Background(), []string{"sb-timer"}, nil); got["sb-timer"] != MoveReleased {
		t.Fatalf("release = %v", got)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if sb, _ := st.Get(context.Background(), "sb-timer"); sb.Status != models.SandboxStatusStopped {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the lapsed move was never resumed")
}

// A move request is built from a placement read up to minutes before it
// arrives (the target's pre-pull comes first). If the id has become a new
// lifetime of the sandbox by then, the request is not about it: neither a
// release nor a deadline stop touches it (R10). The same request for the
// lifetime that is here goes through.
func TestDelayedMoveMustNotStopReplacement(t *testing.T) {
	ctx := context.Background()
	for _, action := range []string{"release", "stop"} {
		t.Run(action, func(t *testing.T) {
			svc, _, st := newCapacityHarness(t, nil, nil)
			svc.AttachCluster(&ownerStubCluster{Noop: cluster.NewNoop("self", "", ""), owner: "self"})
			const id = "sb-reused"
			// The leader built the action for the old lifetime, which was
			// deleted; the id came back as a new one.
			delayed := cluster.MoveAction{Action: action, IDs: []string{id}, Incarnations: map[string]string{id: "old-incarnation"}}
			if err := st.Create(ctx, &models.Sandbox{ID: id, Image: "alpine", ContainerID: "new-task", Status: models.SandboxStatusStarted, AuditIncarnationID: "new-incarnation"}); err != nil {
				t.Fatal(err)
			}
			out, err := cluster.RunMoveAction(ctx, svc, delayed)
			if err != nil {
				t.Fatal(err)
			}
			got, err := st.Get(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			if got.Status != models.SandboxStatusStarted || out.Results[id] != MoveGone || svc.OwnershipFenced(id) {
				t.Fatalf("a %s for the old lifetime touched the new one: status=%s results=%v fenced=%v", action, got.Status, out.Results, svc.OwnershipFenced(id))
			}
			current := cluster.MoveAction{Action: action, IDs: []string{id}, Incarnations: map[string]string{id: "new-incarnation"}}
			if out, _ := cluster.RunMoveAction(ctx, svc, current); out.Results[id] != MoveReleased && out.Results[id] != MoveStopped {
				t.Fatalf("a %s for the current lifetime: %v", action, out.Results)
			}
		})
	}
}

// restartedService is a new sandboxd process on the same store and runtime:
// fresh process state, the same rows and tasks.
func restartedService(t *testing.T, svc *Service, c *ownerStubCluster) *Service {
	r := &Service{cfg: svc.cfg, logger: svc.logger, store: svc.store, docker: svc.docker,
		caddy: svc.caddy, mounts: svc.mounts, admitter: svc.admitter, moveTimings: svc.moveTimings}
	r.AttachCluster(c)
	t.Cleanup(r.moveTimers.stop)
	return r
}

// A release's fence survives a restart of sandboxd (R11). The row records
// it, so a fresh process refuses every start until it lapses, and re-arms it
// at start without waiting for one. Once it lapses, the sandbox the release
// stopped is started again (the leader says the move never happened); one
// its user had stopped stays stopped.
func TestMoveFenceSurvivesAgentRestart(t *testing.T) {
	ctx := context.Background()
	svc, _, st := newCapacityHarness(t, nil, nil)
	svc.moveTimings.fenceTTL = 400 * time.Millisecond
	svc.cfg.EnableCluster = true
	svc.docker.(*fakeCapacityRuntime).startResult = &models.SandboxRuntimeState{Status: models.SandboxStatusStarted, ContainerID: "c"}
	// The process that releases dies right after: its own resume check can
	// never reach the leader.
	dead := &ownerStubCluster{Noop: cluster.NewNoop("self", "", ""), owner: "self"}
	svc.AttachCluster(dead)
	putRunning(t, svc, "sb-released")
	putRunning(t, svc, "sb-user")
	if _, err := svc.StopSandbox(ctx, "sb-user"); err != nil {
		t.Fatal(err)
	}
	got := svc.ReleaseForMove(ctx, []string{"sb-released", "sb-user"}, nil)
	if got["sb-released"] != MoveReleased || got["sb-user"] != MoveReleased {
		t.Fatalf("release: %v", got)
	}
	dead.readErr = errors.New("this process is gone")

	restarted := restartedService(t, svc, &ownerStubCluster{Noop: cluster.NewNoop("self", "", ""), owner: "self", readErr: errors.New("gone too")})
	restarted.beginOwnershipLease(time.Now())
	for _, id := range []string{"sb-released", "sb-user"} {
		if _, err := restarted.StartSandbox(ctx, id); !errors.Is(err, ErrOwnershipFenced) {
			t.Fatalf("restarted process started released %s: %v", id, err)
		}
		if !restarted.OwnershipFenced(id) {
			t.Fatalf("the refused start did not fence %s for its routes", id)
		}
	}

	again := restartedService(t, svc, &ownerStubCluster{Noop: cluster.NewNoop("self", "", ""), owner: "self"})
	again.rearmMoveFences(ctx)
	if !again.OwnershipFenced("sb-released") || !again.OwnershipFenced("sb-user") {
		t.Fatal("a process starting up did not re-arm the fences in the rows")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if sb, _ := st.Get(ctx, "sb-released"); sb.Status == models.SandboxStatusStarted {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the restarted process never started a sandbox whose move never happened")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if sb, _ := st.Get(ctx, "sb-user"); sb.Status != models.SandboxStatusStopped || sb.StatusReason != statusReasonMoveReleasedStopped {
		t.Fatalf("the sandbox its user stopped: status %s reason %s", sb.Status, sb.StatusReason)
	}
}

// A lapsed move is started again only on the leader's word: an unanswered
// read is checked again later, and a placement that now holds another
// lifetime is left alone.
func TestResumeLapsedMoveAsksTheLeader(t *testing.T) {
	ctx := context.Background()
	svc, _, st := newCapacityHarness(t, nil, nil)
	svc.moveTimings.resumeRetry = 50 * time.Millisecond
	svc.docker.(*fakeCapacityRuntime).startResult = &models.SandboxRuntimeState{Status: models.SandboxStatusStarted, ContainerID: "c"}
	owner := &ownerStubCluster{Noop: cluster.NewNoop("self", "", ""), owner: "self", incarnation: "inc-now"}
	svc.AttachCluster(owner)
	for _, id := range []string{"sb-wait", "sb-old"} {
		if err := st.Create(ctx, &models.Sandbox{ID: id, Name: id, Image: "alpine", Status: models.SandboxStatusStarted, ContainerID: "c-" + id, AuditIncarnationID: "inc-now"}); err != nil {
			t.Fatal(err)
		}
		if got := svc.ReleaseForMove(ctx, []string{id}, map[string]string{id: "inc-now"}); got[id] != MoveReleased {
			t.Fatalf("release %s: %v", id, got)
		}
		svc.moves.set(id, time.Now().Add(-time.Second))
	}

	owner.incarnation = "inc-next" // the swap happened: a new lifetime
	if svc.resumeLapsedMove(ctx, "sb-old") {
		t.Fatal("started a sandbox whose placement holds another lifetime")
	}
	owner.incarnation = "inc-now"
	owner.readErr = errors.New("no leader")
	if svc.resumeLapsedMove(ctx, "sb-wait") {
		t.Fatal("started without the leader's answer")
	}
	// The leader answers again. A fresh stub, not a write to owner: the
	// retry already scheduled reads the stub from its own goroutine, and
	// AttachCluster's lock is what orders the two.
	svc.AttachCluster(&ownerStubCluster{Noop: cluster.NewNoop("self", "", ""), owner: "self", incarnation: "inc-now"})
	deadline := time.Now().Add(5 * time.Second)
	for {
		if sb, _ := st.Get(ctx, "sb-wait"); sb.Status == models.SandboxStatusStarted {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the check after an unanswered read never came")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A process that cannot list its rows at start re-arms nothing, and says
// so; the start gate still reads each row it is asked to start.
func TestRearmMoveFencesWithoutTheRows(t *testing.T) {
	svc, _, st := newCapacityHarness(t, nil, nil)
	putRunning(t, svc, "sb-x")
	if got := svc.ReleaseForMove(context.Background(), []string{"sb-x"}, nil); got["sb-x"] != MoveReleased {
		t.Fatalf("release: %v", got)
	}
	fresh := restartedService(t, svc, &ownerStubCluster{Noop: cluster.NewNoop("self", "", ""), owner: "self"})
	_ = st.Close()
	fresh.rearmMoveFences(context.Background())
	if fresh.OwnershipFenced("sb-x") {
		t.Fatal("re-armed a fence without reading the rows")
	}
}
