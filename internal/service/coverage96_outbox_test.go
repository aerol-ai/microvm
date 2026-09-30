package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// cov96OutboxCluster serves both the non-authoritative holder batch and the
// authoritative read from one placement table, and lets a test fail or hook
// the authoritative read independently.
type cov96OutboxCluster struct {
	*cluster.Noop
	mu         sync.Mutex
	members    []cluster.Member
	placements map[string]cluster.Placement
	authErr    error
	onAuth     func()
	authCalls  int
}

func newCov96OutboxCluster(self string, alive ...string) *cov96OutboxCluster {
	c := &cov96OutboxCluster{
		Noop:       cluster.NewNoop(self, "http://"+self, ""),
		placements: map[string]cluster.Placement{},
	}
	for _, id := range alive {
		c.members = append(c.members, cluster.Member{NodeID: id, Alive: true})
	}
	return c
}

func (c *cov96OutboxCluster) snapshot(ids []string) map[string]cluster.Placement {
	out := make(map[string]cluster.Placement, len(ids))
	for _, id := range ids {
		if p, ok := c.placements[id]; ok {
			out[id] = p
		}
	}
	return out
}

func (c *cov96OutboxCluster) PlacementsByIDs(ids []string) map[string]cluster.Placement {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.snapshot(ids)
}

func (c *cov96OutboxCluster) AuthoritativePlacementsByIDs(_ context.Context, ids []string) (map[string]cluster.Placement, error) {
	c.mu.Lock()
	c.authCalls++
	hook, err := c.onAuth, c.authErr
	out := c.snapshot(ids)
	c.mu.Unlock()
	if hook != nil {
		hook()
	}
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *cov96OutboxCluster) LocalMembers() []cluster.Member {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]cluster.Member(nil), c.members...)
}

func (c *cov96OutboxCluster) Members() []cluster.Member { return c.LocalMembers() }

func (c *cov96OutboxCluster) authCallCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.authCalls
}

func cov96OutboxLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

// cov96OutboxHolder seeds a holder set whose ACKs are old enough to be due
// for a probe, with the given lastProbe stamp.
func cov96OutboxHolder(t *testing.T, id, inc string, gen int64, lastProbe time.Time, targets ...string) *holderNodeSet {
	t.Helper()
	clearSecretFanoutHolders(id)
	t.Cleanup(func() { clearSecretFanoutHolders(id) })
	resetSecretHoldersForGeneration(id, inc, gen, targets...)
	v, ok := secretFanoutHolders.Load(secretHolderKey{sandboxID: id, incarnationID: inc})
	if !ok {
		t.Fatalf("holder set for %s was not created", id)
	}
	hs := v.(*holderNodeSet)
	stale := time.Now().Add(-secretHolderACKTTL)
	hs.mu.Lock()
	for node := range hs.nodes {
		hs.nodes[node] = stale
	}
	hs.lastProbe = lastProbe
	hs.mu.Unlock()
	return hs
}

func cov96OutboxProbeCalls(p *fakePeerPusher) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.probeCalls
}

// A holder map larger than one scan page logs the paging and still advances
// the fair cursor even when the tick's budget is already gone: both passes
// stop at their first entry instead of probing anything.
func TestCov96OutboxRefreshPagesAndStopsOnExpiredBudget(t *testing.T) {
	holders := secretHolderRefreshScan + 1
	for i := range holders {
		id := fmt.Sprintf("cov96ob-page-%05d", i)
		resetSecretHoldersForGeneration(id, "inc", 1, "node-b")
	}
	t.Cleanup(func() {
		for i := range holders {
			clearSecretFanoutHolders(fmt.Sprintf("cov96ob-page-%05d", i))
		}
	})

	pusher := &fakePeerPusher{}
	svc := &Service{logger: cov96OutboxLogger(), testSecretPeerPusher: pusher}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	svc.refreshSecretHolderPossession(ctx)

	if got := cov96OutboxProbeCalls(pusher); got != 0 {
		t.Fatalf("probes = %d after an expired budget, want 0", got)
	}
	if svc.takeSecretHolderCursor() == "" {
		t.Fatal("cursor did not advance past the captured page; later holders would starve")
	}
}

// A failed authoritative read for the reseal sweep must drop the whole expand
// batch rather than act on a missing placement, and must not retire holders.
func TestCov96OutboxRefreshExpandReadFailureSkipsReseal(t *testing.T) {
	const id, inc = "cov96ob-autherr", "inc-autherr"
	cl := newCov96OutboxCluster("node-a", "node-a")
	cl.placements[id] = cluster.Placement{
		SandboxID: id, OwnerNodeID: "node-a", IncarnationID: inc,
		SecretSealGeneration: 1, SecretRecipients: []string{"node-a", "node-dead"},
	}
	cl.authErr = errors.New("leader unavailable")
	clearSecretFanoutHolders(id)
	t.Cleanup(func() { clearSecretFanoutHolders(id) })
	resetSecretHoldersForGeneration(id, inc, 1, "node-a", "node-dead")

	svc := &Service{
		cfg:                  config.Config{EnableCluster: true, SecretRecipientBackupCount: 2},
		cluster:              cl,
		logger:               cov96OutboxLogger(),
		testSecretPeerPusher: &fakePeerPusher{},
	}
	svc.refreshSecretHolderPossession(context.Background())

	if cl.authCallCount() != 1 {
		t.Fatalf("authoritative reads = %d, want 1 (the reseal sweep)", cl.authCallCount())
	}
	v, ok := secretFanoutHolders.Load(secretHolderKey{sandboxID: id, incarnationID: inc})
	if !ok {
		t.Fatal("holder retired on an unavailable authoritative read")
	}
	hs := v.(*holderNodeSet)
	hs.mu.Lock()
	stamped := !hs.lastExpand.IsZero()
	hs.mu.Unlock()
	if !stamped {
		t.Fatal("expand attempt was not stamped on the captured holder")
	}
}

// A reseal that fails (no provider on this node) is logged and the refresh
// carries on to the probe pass.
func TestCov96OutboxRefreshLogsResealFailure(t *testing.T) {
	const id, inc = "cov96ob-resealerr", "inc-resealerr"
	cl := newCov96OutboxCluster("node-a", "node-a")
	cl.placements[id] = cluster.Placement{
		SandboxID: id, OwnerNodeID: "node-a", IncarnationID: inc,
		SecretSealGeneration: 1, SecretRecipients: []string{"node-a", "node-dead"},
	}
	clearSecretFanoutHolders(id)
	t.Cleanup(func() { clearSecretFanoutHolders(id) })
	resetSecretHoldersForGeneration(id, inc, 1, "node-a", "node-dead")

	svc := &Service{
		cfg:                  config.Config{EnableCluster: true, SecretRecipientBackupCount: 2},
		cluster:              cl,
		logger:               cov96OutboxLogger(),
		testSecretPeerPusher: &fakePeerPusher{},
	}
	if err := svc.expandAndResealDeadSecretTargetsForPlacement(context.Background(), cl, cl.placements[id]); err == nil ||
		!strings.Contains(err.Error(), "not configured") {
		t.Fatalf("fixture reseal = %v, want the missing-provider error the refresh logs", err)
	}
	svc.refreshSecretHolderPossession(context.Background())

	if cl.authCallCount() != 1 {
		t.Fatalf("authoritative reads = %d, want 1 (the refresh's reseal read)", cl.authCallCount())
	}
	if _, ok := secretFanoutHolders.Load(secretHolderKey{sandboxID: id, incarnationID: inc}); !ok {
		t.Fatal("a failed reseal retired the holder")
	}
}

// The budget can run out while the reseal sweep's placement read is in
// flight; neither the reseal loop nor the probe pass may then do any work.
func TestCov96OutboxRefreshStopsWhenBudgetEndsDuringExpandRead(t *testing.T) {
	const id, inc = "cov96ob-cancel", "inc-cancel"
	cl := newCov96OutboxCluster("node-a", "node-a")
	cl.placements[id] = cluster.Placement{
		SandboxID: id, OwnerNodeID: "node-a", IncarnationID: inc,
		SecretSealGeneration: 1, SecretRecipients: []string{"node-a", "node-dead"},
	}
	cov96OutboxHolder(t, id, inc, 1, time.Time{}, "node-a", "node-dead")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cl.onAuth = cancel
	pusher := &fakePeerPusher{}
	svc := &Service{
		cfg:                  config.Config{EnableCluster: true, SecretRecipientBackupCount: 2},
		cluster:              cl,
		logger:               cov96OutboxLogger(),
		testSecretPeerPusher: pusher,
	}
	svc.refreshSecretHolderPossession(ctx)

	if cl.authCallCount() != 1 {
		t.Fatalf("authoritative reads = %d, want only the reseal read", cl.authCallCount())
	}
	if got := cov96OutboxProbeCalls(pusher); got != 0 {
		t.Fatalf("probes = %d after the budget ended, want 0", got)
	}
	if _, ok := secretFanoutHolders.Load(secretHolderKey{sandboxID: id, incarnationID: inc}); !ok {
		t.Fatal("holder retired after the budget ended")
	}
}

// Probe jobs are ordered never-probed first, then oldest probe first. The
// mix of zero and non-zero stamps below drives every comparator branch.
func TestCov96OutboxRefreshOrdersProbesByLastProbe(t *testing.T) {
	cl := newCov96OutboxCluster("node-a", "node-a", "node-b", "node-c")
	older := time.Now().Add(-time.Hour)
	newer := time.Now().Add(-time.Minute)
	stamps := []time.Time{{}, older, {}, newer}
	ids := make([]string, len(stamps))
	for i, stamp := range stamps {
		id := fmt.Sprintf("cov96ob-sort-%d", i)
		ids[i] = id
		cl.placements[id] = cluster.Placement{
			SandboxID: id, OwnerNodeID: "node-a", IncarnationID: "inc",
			SecretSealGeneration: 1, State: cluster.PlacementStatePlaced,
			SecretRecipients: []string{"node-a", "node-b", "node-c"},
		}
		cov96OutboxHolder(t, id, "inc", 1, stamp, "node-a", "node-b", "node-c")
	}

	pusher := &fakePeerPusher{}
	svc := &Service{
		cfg:                  config.Config{EnableCluster: true, SecretRecipientBackupCount: 2},
		cluster:              cl,
		logger:               cov96OutboxLogger(),
		testSecretPeerPusher: pusher,
	}
	started := time.Now()
	svc.refreshSecretHolderPossession(context.Background())

	if got := cov96OutboxProbeCalls(pusher); got != len(ids) {
		t.Fatalf("probes = %d, want %d", got, len(ids))
	}
	for _, id := range ids {
		v, ok := secretFanoutHolders.Load(secretHolderKey{sandboxID: id, incarnationID: "inc"})
		if !ok {
			t.Fatalf("%s retired by a healthy probe pass", id)
		}
		hs := v.(*holderNodeSet)
		hs.mu.Lock()
		probed := !hs.lastProbe.Before(started)
		hs.mu.Unlock()
		if !probed {
			t.Fatalf("%s was not stamped as probed this pass", id)
		}
	}
}

// When the configured replication factor cannot be exceeded by the live
// fleet, the replacement set equals the current one and reseal is a no-op
// rather than a pointless re-encryption.
func TestCov96OutboxResealNoOpWhenReplacementMatchesCurrent(t *testing.T) {
	st := openSealTestStore(t)
	cl := newCov96OutboxCluster("node-a", "node-a", "node-b")
	svc := &Service{
		cfg:     config.Config{EnableCluster: true, SecretRecipientBackupCount: 2},
		store:   st,
		cluster: cl,
		logger:  cov96OutboxLogger(),
	}
	placement := cluster.Placement{
		SandboxID: "cov96ob-same", OwnerNodeID: "node-a", IncarnationID: "inc-same",
		SecretSealGeneration: 1, SecretRecipients: []string{"node-b", "node-a"},
	}
	// No provider is configured: reaching past the equality check would fail
	// with "not configured", so nil proves the early return.
	if err := svc.expandAndResealDeadSecretTargetsForPlacement(context.Background(), cl, placement); err != nil {
		t.Fatalf("reseal with an unchanged recipient set = %v, want nil", err)
	}
}

// Without a Raft recipient set or generation, the reseal falls back to the
// holder cache for recipients, the local row for the handle, and the store's
// max generation for the CAS expectation.
func TestCov96OutboxResealFallsBackToLocalRowAndStoreGeneration(t *testing.T) {
	const id, inc = "cov96ob-gen0", "inc-gen0"
	ctx := context.Background()
	st := openSealTestStore(t)
	putSecretRow(t, st, id, inc, 3, []string{"node-a", "node-dead"})
	cipher := newTestCipher(t)
	cl := newCov96OutboxCluster("node-a", "node-a", "node-b")
	svc := &Service{
		cfg:            config.Config{EnableCluster: true, SecretRecipientBackupCount: 2},
		store:          st,
		cluster:        cl,
		logger:         cov96OutboxLogger(),
		cipher:         cipher,
		secretProvider: secrets.NewLocalProvider(cipher, newSecretBlobStore(st)),
	}
	clearSecretFanoutHolders(id)
	t.Cleanup(func() { clearSecretFanoutHolders(id) })
	setSecretHolderTargets(id, inc, 0, []string{"node-a", "node-dead"})

	if maxGen, _, err := st.ClusterSecretSealGeneration(ctx, id, inc); err != nil || maxGen != 3 {
		t.Fatalf("fixture max generation = %d, %v; want 3", maxGen, err)
	}
	err := svc.expandAndResealDeadSecretTargetsForPlacement(ctx, cl, cluster.Placement{
		SandboxID: id, OwnerNodeID: "node-a", IncarnationID: inc,
	})
	// The fixture payload is not a real envelope, so the run ends at Open —
	// after every fallback above has been resolved.
	if err == nil || !strings.Contains(err.Error(), "open for reseal") {
		t.Fatalf("reseal = %v, want it to reach Open with the local row's handle", err)
	}
}

func cov96OutboxSweep(sem chan struct{}, list func(context.Context, secretOutboxPass, int) ([]secretOutboxRow, error),
	process func(context.Context, secretOutboxRow, map[string]cluster.Placement)) secretOutboxSweep {
	return secretOutboxSweep{
		sem:      sem,
		inflight: &sync.Map{},
		listDue:  list,
		deferRow: func(context.Context, secretOutboxRow) error { return nil },
		process:  process,
	}
}

func cov96OutboxRows(prefix string, n int) []secretOutboxRow {
	rows := make([]secretOutboxRow, n)
	for i := range rows {
		rows[i] = secretOutboxRow{sandboxID: fmt.Sprintf("%s-%d", prefix, i), incarnationID: "inc", generation: 1}
	}
	return rows
}

// A listing that hits the pass's own time budget ends the pass cleanly; the
// rows stay durable for the next tick.
func TestCov96OutboxSweepListDeadlineIsNotAnError(t *testing.T) {
	calls := 0
	sw := cov96OutboxSweep(make(chan struct{}, 1),
		func(context.Context, secretOutboxPass, int) ([]secretOutboxRow, error) {
			calls++
			return nil, fmt.Errorf("list due: %w", context.DeadlineExceeded)
		},
		func(context.Context, secretOutboxRow, map[string]cluster.Placement) {
			t.Error("process called without any listed rows")
		})
	if err := (&Service{}).sweepSecretOutbox(context.Background(), secretOutboxPass{}, sw); err != nil {
		t.Fatalf("sweep = %v, want nil when only the budget expired", err)
	}
	if calls != 1 {
		t.Fatalf("listDue calls = %d, want 1", calls)
	}
}

// The caller's cancellation while every worker waits for a peer slot and the
// dispatcher still holds a row surfaces as the caller's error, and nothing is
// processed.
func TestCov96OutboxSweepCallerCancelWhileSaturated(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var processed atomic.Int64
		rows := cov96OutboxRows("cov96ob-cancel", deleteReconcileWorkers+1)
		sw := cov96OutboxSweep(make(chan struct{}),
			func(context.Context, secretOutboxPass, int) ([]secretOutboxRow, error) { return rows, nil },
			func(context.Context, secretOutboxRow, map[string]cluster.Placement) { processed.Add(1) })
		ctx, cancel := context.WithCancel(context.Background())
		errc := make(chan error, 1)
		go func() { errc <- (&Service{}).sweepSecretOutbox(ctx, secretOutboxPass{}, sw) }()
		synctest.Wait()
		cancel()
		if err := <-errc; !errors.Is(err, context.Canceled) {
			t.Fatalf("sweep = %v, want context.Canceled", err)
		}
		if processed.Load() != 0 {
			t.Fatalf("processed = %d, want 0 with no free peer slot", processed.Load())
		}
	})
}

// The pass's own budget expiring while saturated ends the pass without an
// error. The 25s budget runs on synctest's fake clock.
func TestCov96OutboxSweepBudgetExpiresWhileSaturated(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var processed atomic.Int64
		calls := 0
		rows := cov96OutboxRows("cov96ob-budget", deleteReconcileWorkers+1)
		sw := cov96OutboxSweep(make(chan struct{}),
			func(context.Context, secretOutboxPass, int) ([]secretOutboxRow, error) {
				calls++
				return rows, nil
			},
			func(context.Context, secretOutboxRow, map[string]cluster.Placement) { processed.Add(1) })
		start := time.Now()
		if err := (&Service{}).sweepSecretOutbox(context.Background(), secretOutboxPass{}, sw); err != nil {
			t.Fatalf("sweep = %v, want nil when only the budget expired", err)
		}
		if elapsed := time.Since(start); elapsed < secretDeleteReconcileBudget {
			t.Fatalf("sweep returned after %v, before its %v budget", elapsed, secretDeleteReconcileBudget)
		}
		if calls != 1 || processed.Load() != 0 {
			t.Fatalf("listDue calls = %d, processed = %d; want 1 and 0", calls, processed.Load())
		}
	})
}

// A row whose handling outlives the budget finishes, and the pass then stops
// without listing another page.
func TestCov96OutboxSweepBudgetExpiresDuringProcess(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		calls := 0
		sw := cov96OutboxSweep(make(chan struct{}, 1),
			func(context.Context, secretOutboxPass, int) ([]secretOutboxRow, error) {
				calls++
				return cov96OutboxRows("cov96ob-slow", 1), nil
			},
			func(context.Context, secretOutboxRow, map[string]cluster.Placement) {
				time.Sleep(secretDeleteReconcileBudget + time.Second)
			})
		if err := (&Service{}).sweepSecretOutbox(context.Background(), secretOutboxPass{}, sw); err != nil {
			t.Fatalf("sweep = %v, want nil when only the budget expired", err)
		}
		if calls != 1 {
			t.Fatalf("listDue calls = %d, want 1", calls)
		}
	})
}

// The caller cancelling while a row is being handled surfaces as the caller's
// error once the page drains.
func TestCov96OutboxSweepCallerCancelDuringProcess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	sw := cov96OutboxSweep(make(chan struct{}, 1),
		func(context.Context, secretOutboxPass, int) ([]secretOutboxRow, error) {
			calls++
			return cov96OutboxRows("cov96ob-cancel-proc", 1), nil
		},
		func(context.Context, secretOutboxRow, map[string]cluster.Placement) { cancel() })
	if err := (&Service{}).sweepSecretOutbox(ctx, secretOutboxPass{}, sw); !errors.Is(err, context.Canceled) {
		t.Fatalf("sweep = %v, want context.Canceled", err)
	}
	if calls != 1 {
		t.Fatalf("listDue calls = %d, want 1", calls)
	}
}

// A backlog that keeps producing full pages of new lifecycles is cut off at
// the per-pass row cap instead of growing the attempted set without bound.
func TestCov96OutboxSweepStopsAtPerPassRowCap(t *testing.T) {
	var processed atomic.Int64
	calls := 0
	sw := cov96OutboxSweep(make(chan struct{}, deleteReconcileWorkers),
		func(_ context.Context, _ secretOutboxPass, limit int) ([]secretOutboxRow, error) {
			if limit != secretDeleteReconcileBatch {
				t.Errorf("limit = %d, want %d", limit, secretDeleteReconcileBatch)
			}
			page := cov96OutboxRows(fmt.Sprintf("cov96ob-cap-%d", calls), limit)
			calls++
			return page, nil
		},
		func(context.Context, secretOutboxRow, map[string]cluster.Placement) { processed.Add(1) })
	if err := (&Service{}).sweepSecretOutbox(context.Background(), secretOutboxPass{}, sw); err != nil {
		t.Fatalf("sweep = %v", err)
	}
	wantPages := secretOutboxSweepMaxRows / secretDeleteReconcileBatch
	if calls != wantPages {
		t.Fatalf("listDue calls = %d, want %d", calls, wantPages)
	}
	if processed.Load() != int64(secretOutboxSweepMaxRows) {
		t.Fatalf("processed = %d, want %d", processed.Load(), secretOutboxSweepMaxRows)
	}
}
