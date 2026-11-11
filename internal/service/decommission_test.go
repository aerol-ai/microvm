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
	got := svc.ReleaseForMove(context.Background(), []string{"sb-move", "sb-none", " "})
	if got["sb-move"] != MoveReleased || got["sb-none"] != MoveGone || len(got) != 2 {
		t.Fatalf("release = %v", got)
	}
	sb, _ := st.Get(context.Background(), "sb-move")
	if sb.Status != models.SandboxStatusStopped || sb.StatusReason != statusReasonDecommission {
		t.Fatalf("after release: %s (%s)", sb.Status, sb.StatusReason)
	}
	if !svc.OwnershipFenced("sb-move") {
		t.Fatal("a released sandbox is not fenced")
	}
	if _, err := svc.StartSandbox(context.Background(), "sb-move"); !errors.Is(err, ErrOwnershipFenced) {
		t.Fatalf("start of a released sandbox = %v, want ErrOwnershipFenced", err)
	}
	// Again: already stopped, released again (the fence is renewed).
	if got := svc.ReleaseForMove(context.Background(), []string{"sb-move"}); got["sb-move"] != MoveReleased {
		t.Fatalf("second release = %v", got)
	}
}

// At the deadline a sandbox that cannot move is stopped but not fenced:
// until the node is deleted it is still this node's.
func TestStopForDecommission(t *testing.T) {
	svc, _, st := newCapacityHarness(t, nil, nil)
	putRunning(t, svc, "sb-stay")
	if got := svc.StopForDecommission(context.Background(), []string{"sb-stay"}); got["sb-stay"] != MoveStopped {
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
	got := svc.ReleaseForMove(context.Background(), []string{"sb-x"})
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
	owner string
}

func (c *ownerStubCluster) PlacementOf(id string) (cluster.Placement, bool) {
	return cluster.Placement{SandboxID: id, OwnerNodeID: c.owner, IncarnationID: "i"}, true
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
		if got := svc.ReleaseForMove(ctx, []string{id}); got[id] != MoveReleased {
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
	old := moveFenceTTL
	moveFenceTTL = 10 * time.Millisecond
	t.Cleanup(func() { moveFenceTTL = old })
	svc, _, st := newCapacityHarness(t, nil, nil)
	svc.docker.(*fakeCapacityRuntime).startResult = &models.SandboxRuntimeState{Status: models.SandboxStatusStarted, ContainerID: "c"}
	putRunning(t, svc, "sb-timer")
	if got := svc.ReleaseForMove(context.Background(), []string{"sb-timer"}); got["sb-timer"] != MoveReleased {
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
