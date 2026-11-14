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
			src.moveTimings.fenceTTL = 40 * time.Millisecond
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
	fresh := restartedService(t, svc, stale)
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
	fresh := freshAgent(t, dst, dstC)
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
		fresh := freshAgent(t, dst, dstC)
		fresh.resumeMovedIn(ctx)
		if !waitFor(5*time.Second, func() bool {
			sb, err := fresh.store.Get(ctx, "sb-g")
			return err == nil && sb.Status == models.SandboxStatusStarted
		}) {
			t.Fatal("the moved sandbox did not start")
		}
	})
	t.Run("never moved: dropped when its time is up", func(t *testing.T) {
		src, dst, _, dstRT, dstC := gvisorMovePair(t)
		if got := src.ReleaseForSnapshotMove(ctx, "sb-g", "worker-b", ""); got != MoveReleased {
			t.Fatal(got)
		}
		if err := dst.ImportMove(ctx, "sb-g", "worker-a", gvisorRecreate(dstC)); err != nil {
			t.Fatal(err)
		}
		fresh := freshAgent(t, dst, dstC) // the placement still names worker-a
		fresh.moveTimings = moveTimings{inFenceTTL: 50 * time.Millisecond, resumeRetry: 20 * time.Millisecond}
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
	t.Run("a Firecracker row moved here: started", func(t *testing.T) {
		cipher, err := secrets.NewCipher("", filepath.Join(t.TempDir(), "key"))
		if err != nil {
			t.Fatal(err)
		}
		src, srcRT, _ := moveWorker(t, "worker-a", cipher)
		dst, dstRT, dstC := moveWorker(t, "worker-b", cipher)
		srcRT.snapshot = []byte("memory")
		if err := src.store.Create(ctx, &models.Sandbox{ID: "sb-vm", Name: "sb-vm", Image: "alpine", Runtime: models.RuntimeFirecracker,
			Status: models.SandboxStatusStarted, ContainerID: "vm"}); err != nil {
			t.Fatal(err)
		}
		srv := serveBundles(src, "worker-b")
		defer srv.Close()
		dstC.srv = srv
		if got := src.ReleaseForSnapshotMove(ctx, "sb-vm", "worker-b", ""); got != MoveReleased {
			t.Fatal(got)
		}
		if err := dst.ImportMove(ctx, "sb-vm", "worker-a", nil); err != nil {
			t.Fatal(err)
		}
		dstC.owner = "worker-b"
		fresh := freshAgent(t, dst, dstC)
		fresh.resumeMovedIn(ctx)
		if !waitFor(5*time.Second, func() bool {
			sb, err := fresh.store.Get(ctx, "sb-vm")
			return err == nil && sb.Status == models.SandboxStatusStarted
		}) || dstRT.startCount == 0 {
			t.Fatal("the imported Firecracker row did not start")
		}
	})
	t.Run("an unanswered read: checked again", func(t *testing.T) {
		src, dst, _, _, dstC := gvisorMovePair(t)
		if got := src.ReleaseForSnapshotMove(ctx, "sb-g", "worker-b", ""); got != MoveReleased {
			t.Fatal(got)
		}
		if err := dst.ImportMove(ctx, "sb-g", "worker-a", gvisorRecreate(dstC)); err != nil {
			t.Fatal(err)
		}
		dstC.owner = "worker-b"
		flaky := &flakyReadCluster{moveStubCluster: dstC, failures: 2}
		fresh := freshAgent(t, dst, dstC)
		fresh.moveTimings.resumeRetry = 20 * time.Millisecond
		fresh.AttachCluster(flaky)
		fresh.resumeMovedIn(ctx)
		if !waitFor(5*time.Second, func() bool {
			sb, err := fresh.store.Get(ctx, "sb-g")
			return err == nil && sb.Status == models.SandboxStatusStarted
		}) {
			t.Fatal("the move was not finished after the leader came back")
		}
		if flaky.reads() < 3 {
			t.Fatalf("reads = %d, want the failed ones tried again", flaky.reads())
		}
	})
	t.Run("no cluster: nothing", func(t *testing.T) {
		(&Service{}).resumeMovedIn(ctx)
	})
}

// flakyReadCluster fails its first failures authoritative reads.
type flakyReadCluster struct {
	*moveStubCluster
	mu       sync.Mutex
	failures int
	n        int
}

func (c *flakyReadCluster) AuthoritativePlacementsByIDs(ctx context.Context, ids []string) (map[string]cluster.Placement, error) {
	c.mu.Lock()
	c.n++
	fail := c.n <= c.failures
	c.mu.Unlock()
	if fail {
		return nil, errors.New("leader unreachable")
	}
	return c.moveStubCluster.AuthoritativePlacementsByIDs(ctx, ids)
}

func (c *flakyReadCluster) reads() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
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
	in.UpdatedAt = now.Add(-defaultMoveInFenceTTL - time.Minute)
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
func freshAgent(t *testing.T, svc *Service, c *moveStubCluster) *Service {
	svc.moveTimers.stop() // the old process's timers die with it
	fresh := &Service{cfg: svc.cfg, logger: svc.logger, store: svc.store, docker: svc.docker, firecracker: svc.firecracker,
		containerd: svc.containerd, caddy: svc.caddy, mounts: svc.mounts, admitter: svc.admitter, cipher: svc.cipher,
		moveTimings: svc.moveTimings}
	fresh.AttachCluster(c)
	t.Cleanup(fresh.moveTimers.stop)
	return fresh
}

// stop ends a Service's pending move checks, refuses new ones, and waits
// for a running one: a test's cleanup calls it before the store closes, so
// no check outlives its test (newCapacityHarness, restartedService).
func (m *moveTimers) stop() {
	m.mu.Lock()
	m.stopped = true
	for t := range m.pending {
		t.Stop()
	}
	m.pending = nil
	m.mu.Unlock()
	m.running.Wait()
}

// armed reports whether id has a live move-in check.
func (m *moveInChecks) armed(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.gen[id]
	return ok
}

// movedOwner attaches to svc a copy of c whose placements name owner: the
// swap, seen by a check already running through AttachCluster's lock.
func movedOwner(svc *Service, c *moveStubCluster, owner string) {
	next := *c
	next.owner = owner
	svc.AttachCluster(&next)
}

// importedGvisor is a gVisor sandbox released on worker-a for a checkpoint
// move and imported on worker-b (with timings tm), with the leader's
// recreate inputs or without; its placement still names worker-a.
func importedGvisor(t *testing.T, rc bool, tm moveTimings) (*Service, *fakeGvisorMoveRuntime, *moveStubCluster) {
	t.Helper()
	ctx := context.Background()
	src, dst, _, dstRT, dstC := gvisorMovePair(t)
	dst.moveTimings = tm
	if got := src.ReleaseForSnapshotMove(ctx, "sb-g", "worker-b", ""); got != MoveReleased {
		t.Fatal(got)
	}
	var recreate *cluster.MoveRecreate
	if rc {
		recreate = gvisorRecreate(dstC)
	}
	if err := dst.ImportMove(ctx, "sb-g", "worker-a", recreate); err != nil {
		t.Fatal(err)
	}
	return dst, dstRT, dstC
}

// importedFirecracker is the same for a Firecracker sandbox and its memory.
func importedFirecracker(t *testing.T, tm moveTimings) (*Service, *fakeMoverRuntime, *moveStubCluster) {
	t.Helper()
	ctx := context.Background()
	cipher, err := secrets.NewCipher("", filepath.Join(t.TempDir(), "key"))
	if err != nil {
		t.Fatal(err)
	}
	src, srcRT, _ := moveWorker(t, "worker-a", cipher)
	dst, dstRT, dstC := moveWorker(t, "worker-b", cipher)
	dst.moveTimings = tm
	srcRT.snapshot = bytes.Repeat([]byte("vm memory "), 10_000)
	if err := src.store.Create(ctx, &models.Sandbox{ID: "sb-vm", Name: "sb-vm", Image: "alpine", Runtime: models.RuntimeFirecracker,
		Status: models.SandboxStatusStarted, ContainerID: "vm", AuditIncarnationID: "inc-1"}); err != nil {
		t.Fatal(err)
	}
	srv := serveBundles(src, "worker-b")
	t.Cleanup(srv.Close)
	dstC.srv = srv
	if got := src.ReleaseForSnapshotMove(ctx, "sb-vm", "worker-b", ""); got != MoveReleased {
		t.Fatal(got)
	}
	if err := dst.ImportMove(ctx, "sb-vm", "worker-a", nil); err != nil {
		t.Fatal(err)
	}
	return dst, dstRT, dstC
}

// The review's liveness gap in N4, on a target agent that stays up (no
// restart, no resumeMovedIn): the import's own check finishes what the
// leader leaves undone. The swap commits and the leader dies before its
// start: the check starts the sandbox once the placement names this node.
// The swap is refused or aborted and the leader's drop never comes: the
// check drops the import, its stored row and its staged memory once the
// move's time is up.
func TestMoveInCheckOnALiveAgent(t *testing.T) {
	fast := moveTimings{inFenceTTL: 80 * time.Millisecond, resumeRetry: 20 * time.Millisecond}
	ctx := context.Background()
	// finished waits for id's check to end; its lock orders what the check
	// did before the assertions.
	finished := func(t *testing.T, svc *Service, id string) {
		t.Helper()
		if !waitFor(5*time.Second, func() bool { return !svc.moveInChecks.armed(id) }) {
			t.Fatalf("the move-in check of %s never ended", id)
		}
	}

	t.Run("gVisor: the swap commits, the leader's start never comes", func(t *testing.T) {
		dst, dstRT, dstC := importedGvisor(t, true, fast)
		movedOwner(dst, dstC, "worker-b")
		finished(t, dst, "sb-g")
		sb, err := dst.store.Get(ctx, "sb-g")
		if err != nil || sb.Status != models.SandboxStatusStarted || sb.ToolboxToken != "guest-token" {
			t.Fatalf("the moved sandbox: %+v %v", sb, err)
		}
		if len(dstRT.createRestored) == 0 || !dstRT.createRestored[0] {
			t.Fatalf("not rebuilt from its checkpoint: %v", dstRT.createRestored)
		}
		if _, err := dst.store.GetMovedInRow(ctx, "sb-g"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("the stored row outlived the start: %v", err)
		}
	})
	t.Run("gVisor: the move never happens, the leader's drop never comes", func(t *testing.T) {
		dst, dstRT, _ := importedGvisor(t, true, fast)
		finished(t, dst, "sb-g")
		if _, err := dst.store.GetMovedInRow(ctx, "sb-g"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("the stored row of a move that never happened stayed: %v", err)
		}
		if dstRT.imported != nil || dstRT.dropped == 0 {
			t.Fatalf("the staged checkpoint stayed: %d bytes, %d drops", len(dstRT.imported), dstRT.dropped)
		}
	})
	t.Run("Firecracker: the swap commits, the leader's start never comes", func(t *testing.T) {
		dst, dstRT, dstC := importedFirecracker(t, fast)
		movedOwner(dst, dstC, "worker-b")
		finished(t, dst, "sb-vm")
		sb, err := dst.store.Get(ctx, "sb-vm")
		if err != nil || sb.Status != models.SandboxStatusStarted || dstRT.startCount == 0 {
			t.Fatalf("the moved VM: %+v %v, runtime starts %d", sb, err, dstRT.startCount)
		}
	})
	t.Run("Firecracker: the move never happens, the leader's drop never comes", func(t *testing.T) {
		dst, dstRT, _ := importedFirecracker(t, fast)
		finished(t, dst, "sb-vm")
		if _, err := dst.store.Get(ctx, "sb-vm"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("the imported row of a move that never happened stayed: %v", err)
		}
		if dstRT.imported != nil || dstRT.dropped == 0 {
			t.Fatalf("the staged memory stayed: %d bytes, %d drops", len(dstRT.imported), dstRT.dropped)
		}
	})
}

// A sandbox has at most one move-in check: arming another (a re-import, an
// agent's start) retires the one before, which then stops at its next step
// and cannot retire its successor.
func TestMoveInChecksGenerations(t *testing.T) {
	var m moveInChecks
	first := m.arm("sb")
	second := m.arm("sb")
	if m.live("sb", first) || !m.live("sb", second) {
		t.Fatal("the later check does not replace the earlier")
	}
	m.done("sb", first)
	if !m.armed("sb") {
		t.Fatal("a replaced check retired its successor")
	}
	// A check that is not live returns at once, before any read.
	(&Service{}).checkMovedIn(context.Background(), moveInCheck{id: "sb", gen: first})
	m.done("sb", second)
	if m.armed("sb") {
		t.Fatal("a finished check is still armed")
	}
}

// One step of the check on each answer that leaves the move unfinished: a
// start that fails, a leader that cannot answer, a drop that fails, a store
// that cannot be read. Each is an error, so the check looks again later.
// An import that is no longer pending ends the check.
func TestCheckMovedInOnceUnfinished(t *testing.T) {
	ctx := context.Background()
	step := func(svc *Service, id string) error {
		return svc.checkMovedInOnce(ctx, moveInCheck{id: id})
	}

	t.Run("a start that fails within the move's time", func(t *testing.T) {
		dst, dstRT, dstC := importedFirecracker(t, moveTimings{})
		dstRT.startErr = errors.New("runtime busy")
		movedOwner(dst, dstC, "worker-b")
		if err := step(dst, "sb-vm"); err == nil {
			t.Fatal("a start that failed ended the check")
		}
		if sb, _ := dst.store.Get(ctx, "sb-vm"); sb.StatusReason != statusReasonMovedIn {
			t.Fatalf("gave up within the move's time: reason %q", sb.StatusReason)
		}
		// The failed start left the row in error; it still awaits its
		// start, so the next step starts it.
		dstRT.startErr = nil
		if err := step(dst, "sb-vm"); err != nil {
			t.Fatalf("the next step: %v", err)
		}
		if sb, _ := dst.store.Get(ctx, "sb-vm"); sb.Status != models.SandboxStatusStarted {
			t.Fatalf("not started on the next step: %s", sb.Status)
		}
	})
	t.Run("a leader that cannot answer", func(t *testing.T) {
		dst, _, dstC := importedGvisor(t, true, moveTimings{})
		flaky := &flakyReadCluster{moveStubCluster: dstC, failures: 1}
		dst.AttachCluster(flaky)
		if err := step(dst, "sb-g"); err == nil || flaky.reads() != 1 {
			t.Fatalf("an unanswered read: err %v, reads %d", err, flaky.reads())
		}
	})
	t.Run("a drop that fails: tried again, then given up", func(t *testing.T) {
		dst, _, dstC := importedGvisor(t, true, moveTimings{inFenceTTL: time.Minute})
		// This node's own view already names it; the leader's does not.
		dst.AttachCluster(&splitViewCluster{moveStubCluster: dstC, leaderOwner: "worker-a"})
		importedAgo(t, dst, "sb-g", 90*time.Second) // the move's time is up
		if err := step(dst, "sb-g"); err == nil {
			t.Fatal("a drop that failed ended the check")
		}
		if _, err := dst.store.GetMovedInRow(ctx, "sb-g"); err != nil {
			t.Fatalf("a failed drop removed the row: %v", err)
		}
		importedAgo(t, dst, "sb-g", 3*time.Minute) // and passed again
		if err := step(dst, "sb-g"); err != nil {
			t.Fatalf("a drop that kept failing did not end the check: %v", err)
		}
	})
	t.Run("a store that cannot be read", func(t *testing.T) {
		dst, _, _ := importedGvisor(t, true, moveTimings{})
		_ = dst.store.Close()
		if err := step(dst, "sb-g"); err == nil {
			t.Fatal("an unreadable store ended the check")
		}
	})
	t.Run("nothing pending", func(t *testing.T) {
		svc, _, _ := newCapacityHarness(t, nil, nil)
		if err := step(svc, "sb-none"); err != nil {
			t.Fatalf("no import: %v", err)
		}
	})
}

// What a target refuses or reports instead of losing track of an import: a
// sandbox it already runs, an earlier import it cannot drop, a staged
// checkpoint the runtime will not drop, and a store it cannot read.
func TestMoveInFailures(t *testing.T) {
	ctx := context.Background()
	released := func(t *testing.T) (*Service, *fakeGvisorMoveRuntime, *moveStubCluster) {
		t.Helper()
		src, dst, _, dstRT, dstC := gvisorMovePair(t)
		if got := src.ReleaseForSnapshotMove(ctx, "sb-g", "worker-b", ""); got != MoveReleased {
			t.Fatal(got)
		}
		return dst, dstRT, dstC
	}

	t.Run("a sandbox this node already runs", func(t *testing.T) {
		dst, dstRT, dstC := released(t)
		if err := dst.store.Create(ctx, &models.Sandbox{ID: "sb-g", Name: "sb-g", Image: "alpine", Status: models.SandboxStatusStarted}); err != nil {
			t.Fatal(err)
		}
		if err := dst.ImportMove(ctx, "sb-g", "worker-a", gvisorRecreate(dstC)); err == nil || dstRT.imported != nil {
			t.Fatalf("imported over a running sandbox: err %v, %d bytes staged", err, len(dstRT.imported))
		}
	})
	t.Run("an earlier import that cannot be dropped", func(t *testing.T) {
		dst, _, dstC := released(t)
		// A stored row naming a runtime that moves nothing.
		if err := dst.putMovedIn(ctx, "sb-g", movedInRecord{Row: moveRow{Sandbox: models.Sandbox{ID: "sb-g", Runtime: models.RuntimeDocker}}}); err != nil {
			t.Fatal(err)
		}
		if err := dst.DropMove(ctx, "sb-g"); err == nil {
			t.Fatal("dropped an import with no runtime to drop it from")
		}
		if err := dst.ImportMove(ctx, "sb-g", "worker-a", gvisorRecreate(dstC)); err == nil {
			t.Fatal("imported over an earlier import it could not drop")
		}
		if _, err := dst.store.GetMovedInRow(ctx, "sb-g"); err != nil {
			t.Fatalf("the earlier row went without its drop: %v", err)
		}
	})
	t.Run("a staged checkpoint the runtime will not drop", func(t *testing.T) {
		dst, dstRT, dstC := released(t)
		if err := dst.ImportMove(ctx, "sb-g", "worker-a", gvisorRecreate(dstC)); err != nil {
			t.Fatal(err)
		}
		dstRT.dropErr = errors.New("busy")
		if err := dst.DropMove(ctx, "sb-g"); err == nil {
			t.Fatal("a failed drop reported success")
		}
		if _, err := dst.store.GetMovedInRow(ctx, "sb-g"); err != nil {
			t.Fatalf("the row went before its checkpoint: %v", err)
		}
	})
	t.Run("a store that cannot be read", func(t *testing.T) {
		dst, _, dstC := released(t)
		_ = dst.store.Close()
		if err := dst.ImportMove(ctx, "sb-g", "worker-a", gvisorRecreate(dstC)); err == nil {
			t.Fatal("acknowledged an import it could not store")
		}
		if err := dst.DropMove(ctx, "sb-g"); err == nil {
			t.Fatal("a drop that could not read the store reported success")
		}
		movedOwner(dst, dstC, "worker-b")
		if err := dst.StartMoved(ctx, "sb-g", nil); err == nil {
			t.Fatal("a start that could not read the store reported success")
		}
		dst.resumeMovedIn(ctx)
		if dst.moveInChecks.armed("sb-g") {
			t.Fatal("an agent start armed a check from a store it could not read")
		}
	})
}

// A lapsed move whose start fails in the runtime is not retried by the
// resume: only an unanswered leader is, and the start's own error says why.
func TestResumeLapsedMoveRuntimeFailure(t *testing.T) {
	ctx := context.Background()
	svc, _, st := newCapacityHarness(t, nil, nil)
	svc.docker.(*fakeCapacityRuntime).startErr = errors.New("runtime down")
	svc.AttachCluster(&ownerStubCluster{Noop: cluster.NewNoop("self", "", ""), owner: "self", incarnation: "inc-now"})
	if err := st.Create(ctx, &models.Sandbox{ID: "sb-rt", Name: "sb-rt", Image: "alpine", Status: models.SandboxStatusStarted, ContainerID: "c-rt", AuditIncarnationID: "inc-now"}); err != nil {
		t.Fatal(err)
	}
	if got := svc.ReleaseForMove(ctx, []string{"sb-rt"}, map[string]string{"sb-rt": "inc-now"}); got["sb-rt"] != MoveReleased {
		t.Fatalf("release: %v", got)
	}
	svc.moves.set("sb-rt", time.Now().Add(-time.Second))
	if svc.resumeLapsedMove(ctx, "sb-rt") {
		t.Fatal("reported a start the runtime refused")
	}
}

// importedAgo moves id's stored import back by ago, as if it came then.
func importedAgo(t *testing.T, svc *Service, id string, ago time.Duration) {
	t.Helper()
	row, err := svc.store.GetMovedInRow(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.store.PutMovedInRow(context.Background(), id, row.Sealed, time.Now().Add(-ago)); err != nil {
		t.Fatal(err)
	}
}

// The move-in check gives up instead of trying forever, with one log line
// and a status: a gVisor import with no recreate inputs (a target newer
// than its leader) at once, a Firecracker start that keeps failing once
// the move's time is up, and a stored row that does not open at once. The
// sandbox is left stopped with reason move_start_failed; a Firecracker one
// keeps its staged memory, so a user's start tries again.
func TestMoveInCheckGivesUp(t *testing.T) {
	ctx := context.Background()
	step := func(svc *Service, id string) error {
		return svc.checkMovedInOnce(ctx, moveInCheck{id: id})
	}

	t.Run("gVisor with no recreate inputs", func(t *testing.T) {
		dst, dstRT, dstC := importedGvisor(t, false, moveTimings{})
		movedOwner(dst, dstC, "worker-b")
		if err := step(dst, "sb-g"); err != nil {
			t.Fatalf("a start that can never work was not given up: %v", err)
		}
		sb, err := dst.store.Get(ctx, "sb-g")
		if err != nil || sb.Status != models.SandboxStatusStopped || sb.StatusReason != statusReasonMoveStartFailed || sb.ToolboxToken != "guest-token" {
			t.Fatalf("the row left behind: %+v %v", sb, err)
		}
		if _, err := dst.store.GetMovedInRow(ctx, "sb-g"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("the stored row stayed: %v", err)
		}
		if dstRT.imported != nil || len(dstRT.createRestored) != 0 {
			t.Fatalf("staged %d bytes, %d creates", len(dstRT.imported), len(dstRT.createRestored))
		}
		if err := step(dst, "sb-g"); err != nil {
			t.Fatalf("a check after giving up: %v", err)
		}
	})
	t.Run("a Firecracker start that keeps failing", func(t *testing.T) {
		dst, dstRT, dstC := importedFirecracker(t, moveTimings{inFenceTTL: time.Nanosecond}) // the move's time is up
		dstRT.startErr = errors.New("runtime busy")
		movedOwner(dst, dstC, "worker-b")
		if err := step(dst, "sb-vm"); err != nil {
			t.Fatalf("a start that kept failing was not given up: %v", err)
		}
		sb, err := dst.store.Get(ctx, "sb-vm")
		if err != nil || sb.Status != models.SandboxStatusError || sb.LastError == "" || sb.StatusReason != statusReasonMoveStartFailed || dstRT.imported == nil {
			t.Fatalf("the row left behind: %+v %v, %d bytes staged", sb, err, len(dstRT.imported))
		}
		dstRT.startErr = nil
		if _, err := dst.StartSandbox(ctx, "sb-vm"); err != nil {
			t.Fatalf("a user's start after the check gave up: %v", err)
		}
	})
	t.Run("a stored row that does not open", func(t *testing.T) {
		dst, dstRT, dstC := importedGvisor(t, true, moveTimings{})
		if err := dst.store.PutMovedInRow(ctx, "sb-g", []byte("not sealed"), time.Now()); err != nil {
			t.Fatal(err)
		}
		movedOwner(dst, dstC, "worker-b")
		dropped := dstRT.dropped
		if err := step(dst, "sb-g"); err != nil {
			t.Fatalf("an unreadable row was not given up: %v", err)
		}
		if _, err := dst.store.GetMovedInRow(ctx, "sb-g"); !errors.Is(err, store.ErrNotFound) || dstRT.dropped == dropped {
			t.Fatalf("the unreadable row: %v, drops %d", err, dstRT.dropped-dropped)
		}
		if _, err := dst.store.Get(ctx, "sb-g"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("a row was made from nothing: %v", err)
		}
	})
}

// Giving up reports what it could not do, and changes nothing then: a
// lifecycle lock it cannot take before its caller leaves, and a store it
// cannot read.
func TestGiveUpMovedInFailures(t *testing.T) {
	ctx := context.Background()
	dst, _, _ := importedFirecracker(t, moveTimings{})
	unlock := dst.lifecycleLocks.lock("sb-vm")
	gone, cancel := context.WithCancel(ctx)
	cancel()
	if err := dst.giveUpMovedIn(gone, "sb-vm", errors.New("x")); err == nil {
		t.Fatal("gave up without the sandbox's lock")
	}
	unlock()
	if sb, _ := dst.store.Get(ctx, "sb-vm"); sb.StatusReason != statusReasonMovedIn {
		t.Fatalf("changed the row without the lock: %q", sb.StatusReason)
	}
	_ = dst.store.Close()
	if err := dst.giveUpMovedIn(ctx, "sb-vm", errors.New("x")); err == nil {
		t.Fatal("gave up on a store it could not read")
	}
}

// A Firecracker import whose row cannot be stored (its name is taken here)
// is refused, and leaves no staged memory behind.
func TestFirecrackerImportRowNotStored(t *testing.T) {
	ctx := context.Background()
	cipher, err := secrets.NewCipher("", filepath.Join(t.TempDir(), "key"))
	if err != nil {
		t.Fatal(err)
	}
	src, srcRT, _ := moveWorker(t, "worker-a", cipher)
	dst, dstRT, dstC := moveWorker(t, "worker-b", cipher)
	srcRT.snapshot = []byte("vm memory")
	if err := src.store.Create(ctx, &models.Sandbox{ID: "sb-vm", Name: "sb-vm", Image: "alpine", Runtime: models.RuntimeFirecracker,
		Status: models.SandboxStatusStarted, ContainerID: "vm"}); err != nil {
		t.Fatal(err)
	}
	if err := dst.store.Create(ctx, &models.Sandbox{ID: "sb-other", Name: "sb-vm", Image: "alpine", Status: models.SandboxStatusStarted}); err != nil {
		t.Fatal(err)
	}
	srv := serveBundles(src, "worker-b")
	t.Cleanup(srv.Close)
	dstC.srv = srv
	if got := src.ReleaseForSnapshotMove(ctx, "sb-vm", "worker-b", ""); got != MoveReleased {
		t.Fatal(got)
	}
	if err := dst.ImportMove(ctx, "sb-vm", "worker-a", nil); err == nil {
		t.Fatal("acknowledged an import whose row was not stored")
	}
	if _, err := dst.store.Get(ctx, "sb-vm"); !errors.Is(err, store.ErrNotFound) || dstRT.imported != nil {
		t.Fatalf("left behind: row %v, %d bytes staged", err, len(dstRT.imported))
	}
}

// lifetimeCluster is a placement of another lifetime with the same id,
// owned by this node.
type lifetimeCluster struct {
	*moveStubCluster
	incarnation string
}

func (c *lifetimeCluster) AuthoritativePlacementsByIDs(_ context.Context, ids []string) (map[string]cluster.Placement, error) {
	out := make(map[string]cluster.Placement, len(ids))
	for _, id := range ids {
		out[id] = cluster.Placement{SandboxID: id, OwnerNodeID: c.self, IncarnationID: c.incarnation}
	}
	return out, nil
}

// A placement here of another lifetime with the same id (a keyed create
// after a delete) never starts an import of the old one: the check drops
// the import, and a row of the current lifetime is never touched.
func TestMoveInCheckDropsAnotherLifetime(t *testing.T) {
	ctx := context.Background()
	step := func(svc *Service, id string) error {
		return svc.checkMovedInOnce(ctx, moveInCheck{id: id})
	}
	t.Run("gVisor", func(t *testing.T) {
		dst, dstRT, dstC := importedGvisor(t, true, moveTimings{})
		rec, _, _, err := dst.loadMovedIn(ctx, "sb-g")
		if err != nil {
			t.Fatal(err)
		}
		rec.Row.AuditIncarnationID = "inc-old"
		if err := dst.putMovedIn(ctx, "sb-g", rec); err != nil {
			t.Fatal(err)
		}
		dst.AttachCluster(&lifetimeCluster{moveStubCluster: dstC, incarnation: "inc-new"})
		if err := step(dst, "sb-g"); err != nil {
			t.Fatal(err)
		}
		if _, err := dst.store.GetMovedInRow(ctx, "sb-g"); !errors.Is(err, store.ErrNotFound) || dstRT.imported != nil || len(dstRT.createRestored) != 0 {
			t.Fatalf("the old lifetime's import: row %v, %d bytes staged, %d creates", err, len(dstRT.imported), len(dstRT.createRestored))
		}
	})
	t.Run("Firecracker", func(t *testing.T) {
		dst, dstRT, dstC := importedFirecracker(t, moveTimings{})
		dst.AttachCluster(&lifetimeCluster{moveStubCluster: dstC, incarnation: "inc-new"})
		// The import's own lifetime is not the one dropImport is asked
		// for: the row stays.
		if err := dst.dropImport(ctx, "sb-vm", "inc-other"); err != nil {
			t.Fatal(err)
		}
		if _, err := dst.store.Get(ctx, "sb-vm"); err != nil {
			t.Fatalf("a row of another lifetime went: %v", err)
		}
		if err := step(dst, "sb-vm"); err != nil {
			t.Fatal(err)
		}
		if _, err := dst.store.Get(ctx, "sb-vm"); !errors.Is(err, store.ErrNotFound) || dstRT.imported != nil || dstRT.startCount != 0 {
			t.Fatalf("the old lifetime's import: row %v, %d bytes staged, %d starts", err, len(dstRT.imported), dstRT.startCount)
		}
	})
	if !sameIncarnation("", "inc") || !sameIncarnation("inc", " inc ") || sameIncarnation("a", "b") {
		t.Fatal("sameIncarnation")
	}
}

// splitViewCluster is a worker whose own placement view names it while the
// leader's names leaderOwner.
type splitViewCluster struct {
	*moveStubCluster
	leaderOwner string
}

func (c *splitViewCluster) PlacementOf(id string) (cluster.Placement, bool) {
	return cluster.Placement{SandboxID: id, OwnerNodeID: c.self, IncarnationID: "inc-1"}, true
}

func (c *splitViewCluster) AuthoritativePlacementsByIDs(_ context.Context, ids []string) (map[string]cluster.Placement, error) {
	out := make(map[string]cluster.Placement, len(ids))
	for _, id := range ids {
		out[id] = cluster.Placement{SandboxID: id, OwnerNodeID: c.leaderOwner, IncarnationID: "inc-1"}
	}
	return out, nil
}
