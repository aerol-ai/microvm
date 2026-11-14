package service

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// handoffLedger stands in for the FSM's move handoff
// (cluster/fsm_move_handoff.go) across the fixtures of a two-worker move:
// the leader opens it, the source's abort clears it while the source owns
// the sandbox, and the swap lands only while it still holds the token.
type handoffLedger struct {
	mu     sync.Mutex
	token  string
	owner  string
	aborts int
	// abortErr, when set, is the leader's answer to an abort.
	abortErr error
}

func (l *handoffLedger) begin(token, owner string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.token, l.owner = token, owner
}

func (l *handoffLedger) abort(self string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.aborts++
	if l.abortErr != nil {
		return l.abortErr
	}
	if l.owner != self {
		return cluster.ErrMoveHandoffMoved
	}
	l.token = ""
	return nil
}

func (l *handoffLedger) swap(token, to string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.token != token {
		return cluster.ErrMoveHandoffAborted
	}
	l.token, l.owner = "", to
	return nil
}

// handoffMoveCluster is a worker's moveStubCluster that aborts through the
// shared ledger.
type handoffMoveCluster struct {
	*moveStubCluster
	ledger *handoffLedger
}

func (c *handoffMoveCluster) AbortMoveHandoff(_ context.Context, _, _ string) error {
	return c.ledger.abort(c.self)
}

// The review's N3: a source whose fence lapses while the target is still
// importing (a slow import of a VM's memory) takes the sandbox back only
// after aborting the move's handoff, so the import's late swap is refused
// and the target never starts its copy: one executor. In the other order
// the swap lands first, and the source leaves its copy stopped.
func TestSlowSnapshotMoveCannotOutliveTheSourceFence(t *testing.T) {
	oldTTL := moveFenceTTL
	moveFenceTTL = 40 * time.Millisecond
	t.Cleanup(func() { moveFenceTTL = oldTTL })
	for _, swapFirst := range []bool{false, true} {
		name := "fence lapses first"
		if swapFirst {
			name = "swap lands first"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			cipher, err := secrets.NewCipher("", filepath.Join(t.TempDir(), "key"))
			if err != nil {
				t.Fatal(err)
			}
			src, srcRT, srcC := moveWorker(t, "worker-a", cipher)
			dst, dstRT, dstC := moveWorker(t, "worker-b", cipher)
			ledger := &handoffLedger{}
			src.AttachCluster(&handoffMoveCluster{moveStubCluster: srcC, ledger: ledger})
			srcRT.snapshot = []byte("memory")
			if err := src.store.Create(ctx, &models.Sandbox{ID: "sb-vm", Name: "sb-vm", Image: "alpine", Runtime: models.RuntimeFirecracker,
				Status: models.SandboxStatusStarted, ContainerID: "vm"}); err != nil {
				t.Fatal(err)
			}
			srv := serveBundles(src, "worker-b")
			defer srv.Close()
			dstC.srv = srv

			ledger.begin("tok-1", "worker-a") // the leader, before its release
			if got := src.ReleaseForSnapshotMove(ctx, "sb-vm", "worker-b", ""); got != MoveReleased {
				t.Fatal(got)
			}
			if err := dst.ImportMove(ctx, "sb-vm", "worker-a", nil); err != nil {
				t.Fatal(err)
			}
			leaderSwap := func() {
				if err := ledger.swap("tok-1", "worker-b"); err != nil {
					// The leader drops the target's copy (moveSnapshotOne).
					if derr := dst.DropMove(ctx, "sb-vm"); derr != nil {
						t.Fatalf("drop: %v", derr)
					}
					return
				}
				srcC.owner, dstC.owner = "worker-b", "worker-b"
				if err := dst.StartMoved(ctx, "sb-vm", nil); err != nil {
					t.Fatal(err)
				}
			}
			time.Sleep(60 * time.Millisecond) // the fence lapses; the import's swap has not come
			if swapFirst {
				leaderSwap()
			}
			resumed := src.resumeLapsedMove(ctx, "sb-vm")
			if !swapFirst {
				leaderSwap()
			}

			a, _ := src.store.Get(ctx, "sb-vm")
			b, berr := dst.store.Get(ctx, "sb-vm")
			sourceRuns := a != nil && a.Status == models.SandboxStatusStarted
			targetRuns := berr == nil && b.Status == models.SandboxStatusStarted
			if sourceRuns && targetRuns {
				t.Fatalf("both copies run: source starts=%d target starts=%d", srcRT.startCount, dstRT.startCount)
			}
			if swapFirst {
				if resumed || sourceRuns || !targetRuns {
					t.Fatalf("after the swap: resumed %v, source runs %v, target runs %v", resumed, sourceRuns, targetRuns)
				}
				return
			}
			if !resumed || !sourceRuns || targetRuns || ledger.aborts != 1 {
				t.Fatalf("after the fence lapsed: resumed %v, source runs %v, target runs %v, aborts %d", resumed, sourceRuns, targetRuns, ledger.aborts)
			}
			if !errors.Is(berr, store.ErrNotFound) || dstRT.imported != nil {
				t.Fatalf("the target kept a copy of a move that did not happen: %v, %d bytes", berr, len(dstRT.imported))
			}
		})
	}
}

// The review's N3 restart gap: a restarted agent finds a row a release
// stopped, its fence long lapsed. A start needs the leader's proof that the
// move did not happen: a leader that cannot answer means no start, a
// placement that moved means no start, and one this node still owns starts.
func TestExpiredMoveFenceNeedsTheLeaderToStart(t *testing.T) {
	ctx := context.Background()
	svc, _, st := newCapacityHarness(t, nil, nil)
	svc.cfg.EnableCluster = true
	rt := svc.docker.(*fakeCapacityRuntime)
	rt.startResult = &models.SandboxRuntimeState{Status: models.SandboxStatusStarted, ContainerID: "task-old"}
	stale := &ownerStubCluster{Noop: cluster.NewNoop("self", "", ""), owner: "self", readErr: errors.New("leader unreachable")}
	svc.AttachCluster(stale)
	old := time.Now().Add(-10 * time.Minute)
	for _, reason := range []string{statusReasonMoveReleased, statusReasonMoveReleasedStopped} {
		id := "sb-" + reason
		if err := st.Create(ctx, &models.Sandbox{ID: id, Name: id, Image: "alpine", ContainerID: "task-old", Status: models.SandboxStatusStopped,
			StatusReason: reason, CreatedAt: old, UpdatedAt: old, LastActiveAt: old}); err != nil {
			t.Fatal(err)
		}
	}
	fresh := restartedService(svc, stale)
	fresh.beginOwnershipLease(time.Now())
	fresh.rearmMoveFences(ctx)
	for _, id := range []string{"sb-" + statusReasonMoveReleased, "sb-" + statusReasonMoveReleasedStopped} {
		_, err := fresh.StartSandbox(ctx, id)
		if !errors.Is(err, ErrOwnershipFenced) || !errors.Is(err, errMoveUnproven) || rt.startCount != 0 {
			t.Fatalf("%s with no leader: err=%v runtime starts=%d", id, err, rt.startCount)
		}
	}
	stale.readErr = nil
	stale.owner = "worker-b"
	if _, err := fresh.StartSandbox(ctx, "sb-"+statusReasonMoveReleasedStopped); !errors.Is(err, errMovedAway) || rt.startCount != 0 {
		t.Fatalf("a row that moved away: err=%v runtime starts=%d", err, rt.startCount)
	}
	stale.owner = "self"
	if _, err := fresh.StartSandbox(ctx, "sb-"+statusReasonMoveReleasedStopped); err != nil || rt.startCount != 1 {
		t.Fatalf("a row this node still owns: err=%v runtime starts=%d", err, rt.startCount)
	}
}

// proveMoveAborted's answers from a cluster that records handoffs: an abort
// the leader accepts lets the start go on, "moved" refuses it for good, an
// unanswered abort refuses it for now, and a cluster from before handoffs
// leaves the ownership read alone.
func TestProveMoveAbortedAbortsTheHandoff(t *testing.T) {
	ctx := context.Background()
	sb := &models.Sandbox{ID: "sb-p", AuditIncarnationID: "inc-1"}
	ledger := &handoffLedger{owner: "worker-a", token: "tok"}
	svc, _, _ := newCapacityHarness(t, nil, nil)
	c := &handoffMoveCluster{moveStubCluster: &moveStubCluster{Noop: cluster.NewNoop("worker-a", "", ""), self: "worker-a", owner: "worker-a"}, ledger: ledger}
	svc.AttachCluster(c)
	if err := svc.proveMoveAborted(ctx, sb); err != nil || ledger.token != "" {
		t.Fatalf("abort accepted: %v, token %q", err, ledger.token)
	}
	ledger.owner = "worker-b" // the swap landed between the read and the abort
	if err := svc.proveMoveAborted(ctx, sb); !errors.Is(err, errMovedAway) {
		t.Fatalf("abort after the swap = %v, want errMovedAway", err)
	}
	ledger.abortErr = errors.New("leader unreachable")
	if err := svc.proveMoveAborted(ctx, sb); !errors.Is(err, errMoveUnproven) {
		t.Fatalf("unanswered abort = %v, want errMoveUnproven", err)
	}
	ledger.abortErr = cluster.ErrMoveHandoffUnsupported
	if err := svc.proveMoveAborted(ctx, sb); err != nil {
		t.Fatalf("a cluster from before handoffs = %v, want the read alone", err)
	}
	if err := (&Service{}).proveMoveAborted(ctx, sb); err != nil {
		t.Fatalf("no cluster = %v", err)
	}
}

// The review's N4: a gVisor checkpoint move's target stores what its bundle
// carried before it acknowledges the import, so an agent restart between
// the import and the start loses nothing: the fresh agent starts the
// sandbox after the swap, with the leader's recreate inputs or the ones
// stored at the import.
func TestCheckpointMoveSurvivesATargetAgentRestart(t *testing.T) {
	ctx := context.Background()
	src, dst, _, dstRT, dstC := gvisorMovePair(t)
	if got := src.ReleaseForSnapshotMove(ctx, "sb-g", "worker-b", ""); got != MoveReleased {
		t.Fatal(got)
	}
	if err := dst.ImportMove(ctx, "sb-g", "worker-a", gvisorRecreate(dstC)); err != nil {
		t.Fatal(err)
	}
	if len(dstRT.imported) == 0 {
		t.Fatal("control: checkpoint was not staged")
	}
	stored, err := dst.store.GetMovedInRow(ctx, "sb-g")
	if err != nil || len(stored.Sealed) == 0 {
		t.Fatalf("the import was acknowledged without a stored row: %v", err)
	}
	if bytes.Contains(stored.Sealed, []byte("guest-token")) {
		t.Fatal("the stored row holds the toolbox token in the clear")
	}
	// A fresh Service keeps the disk, the runtime and SQLite, and loses
	// only process memory, as an agent-container restart does.
	fresh := freshAgent(dst, dstC)
	dstC.owner = "worker-b" // the leader commits the swap on the import's answer
	if err := fresh.StartMoved(ctx, "sb-g", nil); err != nil {
		t.Fatalf("start after a restart, with the stored recreate inputs: %v", err)
	}
	row, err := fresh.store.Get(ctx, "sb-g")
	if err != nil || row.Status != models.SandboxStatusStarted || row.ToolboxToken != "guest-token" {
		t.Fatalf("the moved sandbox after a restart: %+v %v", row, err)
	}
	if _, err := fresh.store.GetMovedInRow(ctx, "sb-g"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the stored row outlived the start: %v", err)
	}
	// A retry of the leader's start (its first answer was lost) finds the
	// sandbox already here.
	if err := fresh.StartMoved(ctx, "sb-g", gvisorRecreate(dstC)); err != nil {
		t.Fatalf("a repeated start: %v", err)
	}
}

// At its start, an agent finishes the moves it took in before a restart:
// one the placement names it for is started without the leader asking, and
// one whose move never happened is held from the sweep, then dropped when
// the move's time is up.
func TestResumeMovedInAtAgentStart(t *testing.T) {
	oldTTL := moveInFenceTTL
	t.Cleanup(func() { moveInFenceTTL = oldTTL })
	ctx := context.Background()

	t.Run("moved here: started", func(t *testing.T) {
		src, dst, _, _, dstC := gvisorMovePair(t)
		if got := src.ReleaseForSnapshotMove(ctx, "sb-g", "worker-b", ""); got != MoveReleased {
			t.Fatal(got)
		}
		if err := dst.ImportMove(ctx, "sb-g", "worker-a", gvisorRecreate(dstC)); err != nil {
			t.Fatal(err)
		}
		dstC.owner = "worker-b"
		fresh := freshAgent(dst, dstC)
		fresh.resumeMovedIn(ctx)
		if !waitFor(5*time.Second, func() bool {
			sb, err := fresh.store.Get(ctx, "sb-g")
			return err == nil && sb.Status == models.SandboxStatusStarted
		}) {
			t.Fatal("the moved sandbox did not start")
		}
	})
	t.Run("never moved: dropped when its time is up", func(t *testing.T) {
		moveInFenceTTL = 50 * time.Millisecond
		src, dst, _, dstRT, dstC := gvisorMovePair(t)
		if got := src.ReleaseForSnapshotMove(ctx, "sb-g", "worker-b", ""); got != MoveReleased {
			t.Fatal(got)
		}
		if err := dst.ImportMove(ctx, "sb-g", "worker-a", gvisorRecreate(dstC)); err != nil {
			t.Fatal(err)
		}
		fresh := freshAgent(dst, dstC) // the placement still names worker-a
		fresh.resumeMovedIn(ctx)
		if !fresh.movesIn.held("sb-g", time.Now()) {
			t.Fatal("a fresh agent does not hold the import from the sweep")
		}
		if !waitFor(5*time.Second, func() bool {
			_, err := fresh.store.GetMovedInRow(ctx, "sb-g")
			return errors.Is(err, store.ErrNotFound) && dstRT.imported == nil
		}) {
			t.Fatal("the import of a move that never happened was not dropped")
		}
	})
	t.Run("no cluster: nothing", func(t *testing.T) {
		(&Service{}).resumeMovedIn(ctx)
	})
}

// A Firecracker row a move imported is held from the stale-ownership sweep
// by its own state, for an agent that restarted since its import, and only
// within the move's time.
func TestMovedInHeldReadsTheRow(t *testing.T) {
	svc, _, _ := newCapacityHarness(t, nil, nil)
	now := time.Now()
	in := &models.Sandbox{ID: "sb-in", Status: models.SandboxStatusStopped, StatusReason: statusReasonMovedIn, UpdatedAt: now.Add(-time.Minute)}
	if !svc.movedInHeld(in, now) {
		t.Fatal("a fresh import is not held")
	}
	in.UpdatedAt = now.Add(-moveInFenceTTL - time.Minute)
	if svc.movedInHeld(in, now) {
		t.Fatal("an import past the move's time is still held")
	}
	started := &models.Sandbox{ID: "sb-run", Status: models.SandboxStatusStarted, StatusReason: statusReasonMovedIn, UpdatedAt: now}
	if svc.movedInHeld(started, now) {
		t.Fatal("a started sandbox is held")
	}
	svc.movesIn.set("sb-run", now.Add(time.Minute))
	if !svc.movedInHeld(started, now) {
		t.Fatal("this process's own hold is not honoured")
	}
}

// What a stored row meets: an earlier import of the same move is dropped
// before the next; a row that does not open is dropped from every runtime;
// no cluster key means nothing is stored and nothing opened.
func TestMovedInRowEdges(t *testing.T) {
	ctx := context.Background()
	src, dst, _, dstRT, dstC := gvisorMovePair(t)
	if got := src.ReleaseForSnapshotMove(ctx, "sb-g", "worker-b", ""); got != MoveReleased {
		t.Fatal(got)
	}
	if err := dst.ImportMove(ctx, "sb-g", "worker-a", gvisorRecreate(dstC)); err != nil {
		t.Fatal(err)
	}
	src.moveTargets.set("sb-g", "worker-b")
	dropped := dstRT.dropped
	if err := dst.ImportMove(ctx, "sb-g", "worker-a", gvisorRecreate(dstC)); err != nil {
		t.Fatalf("import again: %v", err)
	}
	if dstRT.dropped != dropped+1 {
		t.Fatalf("the earlier import was not dropped first: %d drops", dstRT.dropped-dropped)
	}
	// A stored row that does not open: the drop still clears it.
	if err := dst.store.PutMovedInRow(ctx, "sb-g", []byte("not sealed"), time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, _, ok, err := dst.loadMovedIn(ctx, "sb-g"); !ok || err == nil {
		t.Fatalf("an unreadable row: ok %v, err %v", ok, err)
	}
	if err := dst.StartMoved(ctx, "sb-g", nil); err == nil {
		t.Fatal("started from an unreadable row")
	}
	if err := dst.DropMove(ctx, "sb-g"); err != nil {
		t.Fatalf("drop an unreadable row: %v", err)
	}
	if _, err := dst.store.GetMovedInRow(ctx, "sb-g"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the unreadable row survived its drop: %v", err)
	}
	// No cluster key.
	keyless := &Service{store: dst.store}
	if err := keyless.putMovedIn(ctx, "sb-k", movedInRecord{}); err == nil {
		t.Fatal("stored a row with no key to seal it")
	}
	if err := dst.store.PutMovedInRow(ctx, "sb-k", []byte("x"), time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, _, ok, err := keyless.loadMovedIn(ctx, "sb-k"); !ok || err == nil {
		t.Fatalf("opened a row with no key: ok %v, err %v", ok, err)
	}
}

// freshAgent is a new sandboxd process on svc's store and runtimes, with c
// attached: fresh process state, the same rows, staged files and tasks.
func freshAgent(svc *Service, c *moveStubCluster) *Service {
	fresh := &Service{cfg: svc.cfg, logger: svc.logger, store: svc.store, docker: svc.docker, firecracker: svc.firecracker,
		containerd: svc.containerd, caddy: svc.caddy, mounts: svc.mounts, admitter: svc.admitter, cipher: svc.cipher}
	fresh.AttachCluster(c)
	return fresh
}
