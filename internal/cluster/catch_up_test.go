package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/raft"
)

// catchUpTestCluster is a raft-less Cluster armed the way New arms it, so the
// gate can be driven without real sockets.
func catchUpTestCluster(t *testing.T) *Cluster {
	t.Helper()
	c := &Cluster{
		nodeID: "self",
		fsm:    newPlacementFSM(),
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	c.catchingUp.Store(true)
	return c
}

// applyPlaceAt commits one opPlace at a raft index, as raft would on replay.
func applyPlaceAt(t *testing.T, f *placementFSM, index uint64, id, owner string) {
	t.Helper()
	payload, err := encodeCommand(command{Op: opPlace, SandboxID: id, OwnerNodeID: owner, IncarnationID: "inc-" + id})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if resp := f.Apply(&raft.Log{Index: index, Data: payload}); resp != nil {
		if err, ok := resp.(error); ok {
			t.Fatalf("apply %s@%d: %v", id, index, err)
		}
	}
}

func waitCaughtUp(t *testing.T, c *Cluster, max time.Duration) {
	t.Helper()
	deadline := time.Now().Add(max)
	for time.Now().Before(deadline) {
		if c.PlacementViewCaughtUp() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("not caught up within %s", max)
}

// The gate clears only once the FSM has applied the leader's read index, not
// when the read index arrives — the whole bug was a node answering from a FSM
// that had not replayed what the leader already committed.
func TestWatchCatchUpLatchesOnlyAfterFSMAppliesReadIndex(t *testing.T) {
	c := catchUpTestCluster(t)
	applyPlaceAt(t, c.fsm, 3, "sb-in-snapshot", "self")
	c.readIndexHook = func(context.Context) (uint64, error) { return 7, nil }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		c.watchCatchUp(ctx, time.Millisecond)
		close(done)
	}()

	time.Sleep(30 * time.Millisecond)
	if c.PlacementViewCaughtUp() {
		t.Fatal("caught up at fsm version 3 with read index 7")
	}
	if page := c.PlacementPage(PlacementPageRequest{}); page.Authoritative || len(page.Placements) != 0 {
		t.Fatalf("page while catching up = %+v, want empty non-authoritative", page)
	}

	applyPlaceAt(t, c.fsm, 7, "sb-after-snapshot", "peer")
	waitCaughtUp(t, c, 2*time.Second)
	<-done
	if _, ok := c.PlacementOf("sb-after-snapshot"); !ok {
		t.Fatal("caught up without the placement at the read index")
	}
	page := c.PlacementPage(PlacementPageRequest{})
	if !page.Authoritative || len(page.Placements) != 2 {
		t.Fatalf("page once caught up = %+v, want both placements, authoritative", page)
	}
}

func TestWatchCatchUpRetriesUntilReadIndexAnswers(t *testing.T) {
	c := catchUpTestCluster(t)
	var calls atomic.Int32
	c.readIndexHook = func(context.Context) (uint64, error) {
		if calls.Add(1) < 3 {
			return 0, ErrNoLeader
		}
		return 0, nil
	}
	c.watchCatchUp(context.Background(), time.Millisecond)
	if !c.PlacementViewCaughtUp() {
		t.Fatal("not caught up after the read index answered")
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("read index calls = %d, want 3 (two failures, then one answer; never re-asked)", got)
	}
}

// A leader on the previous build has no read-index endpoint. This node then
// behaves as that build does instead of refusing every unknown id forever.
func TestWatchCatchUpLatchesWhenLeaderPredatesReadIndex(t *testing.T) {
	c := catchUpTestCluster(t)
	c.readIndexHook = func(context.Context) (uint64, error) { return 0, errReadIndexUnsupported }
	c.watchCatchUp(context.Background(), time.Hour)
	if !c.PlacementViewCaughtUp() {
		t.Fatal("legacy leader: want caught up (previous behavior)")
	}
}

// No leader, no verdict: the gate never opens on a timer, and the node says
// so in its log while it waits.
func TestWatchCatchUpStaysClosedWithoutLeader(t *testing.T) {
	c := catchUpTestCluster(t)
	var logs strings.Builder
	c.logger = slog.New(slog.NewTextHandler(&lockedWriter{w: &logs}, nil))
	c.catchUpLogEvery = 5 * time.Millisecond
	c.readIndexHook = func(context.Context) (uint64, error) { return 0, ErrNoLeader }
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	c.watchCatchUp(ctx, time.Millisecond)
	if c.PlacementViewCaughtUp() {
		t.Fatal("caught up with no leader to read from")
	}
	if !strings.Contains(logs.String(), "still catching up") || !strings.Contains(logs.String(), "timed out waiting for leader") {
		t.Fatalf("want a still-catching-up warning naming the last error; got %q", logs.String())
	}
}

type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func TestStartCatchUpWatchArmsAndCloseStops(t *testing.T) {
	c := catchUpTestCluster(t)
	c.catchingUp.Store(false)
	release := make(chan struct{})
	c.readIndexHook = func(ctx context.Context) (uint64, error) {
		select {
		case <-release:
			return 0, nil
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	c.startCatchUpWatch()
	if c.PlacementViewCaughtUp() {
		t.Fatal("startCatchUpWatch must arm the gate")
	}
	close(release)
	waitCaughtUp(t, c, 2*time.Second)
	c.catchUpStop()
}

func TestRecordNotCaughtUpRejectCounts(t *testing.T) {
	before := clusterNotCaughtUpRejects.Value()
	RecordNotCaughtUpReject()
	if got := clusterNotCaughtUpRejects.Value(); got != before+1 {
		t.Fatalf("rejects = %d, want %d", got, before+1)
	}
}

func TestCaughtUpByClientKind(t *testing.T) {
	if !CaughtUp(nil) || !CaughtUp(NewNoop("self", "", "")) || !CaughtUp(&Agent{}) {
		t.Fatal("clients without a local replica must report caught up")
	}
	if !CaughtUp(&Cluster{}) {
		t.Fatal("an unarmed Cluster (struct literal) must report caught up")
	}
	c := catchUpTestCluster(t)
	if CaughtUp(c) {
		t.Fatal("armed Cluster must report not caught up")
	}
	var nilCluster *Cluster
	if !nilCluster.PlacementViewCaughtUp() {
		t.Fatal("nil Cluster must report caught up")
	}
}

// The owner watcher must not recreate from a view that has not caught up: a
// placement deleted after the restored snapshot still looks self-owned there,
// and its local row is gone, which is exactly what a failover looks like.
func TestOwnerWatcherWaitsForCatchUp(t *testing.T) {
	c := catchUpTestCluster(t)
	c.recreateFailures = &recreateFailureTracker{counts: make(map[string]int), permanent: make(map[string]struct{})}
	payload, err := encodeCommand(command{Op: opPlace, SandboxID: "sb-stale", OwnerNodeID: "self", Spec: failoverRecreateSpec(), IncarnationID: "inc-stale"})
	if err != nil {
		t.Fatal(err)
	}
	c.fsm.Apply(&raft.Log{Index: 1, Data: payload})
	rec := newRecordingRecreator()
	c.AttachRecreator(rec)

	c.recreateOwnedSandboxes(context.Background())
	if _, ok := rec.get("sb-stale"); ok {
		t.Fatal("owner watcher recreated from a view still catching up")
	}

	c.catchingUp.Store(false)
	c.recreateOwnedSandboxes(context.Background())
	if _, ok := rec.get("sb-stale"); !ok {
		t.Fatal("owner watcher idle once caught up")
	}
}

func TestReadIndexPaths(t *testing.T) {
	c := catchUpTestCluster(t)
	applyPlaceAt(t, c.fsm, 4, "sb-a", "self")
	got, err := c.readIndex(context.Background())
	if err != nil || got != 4 {
		t.Fatalf("raft-less readIndex = %d, %v; want the local fsm version 4", got, err)
	}
	if _, err := c.LeaderReadIndex(context.Background()); !errors.Is(err, ErrNotLeader) {
		t.Fatalf("raft-less LeaderReadIndex err = %v, want ErrNotLeader", err)
	}
	var nilCluster *Cluster
	if _, err := nilCluster.LeaderReadIndex(context.Background()); !errors.Is(err, ErrNotLeader) {
		t.Fatalf("nil LeaderReadIndex err = %v, want ErrNotLeader", err)
	}
}

func TestRequestReadIndexStatuses(t *testing.T) {
	c := catchUpTestCluster(t)
	c.patToken = "pat"
	var status atomic.Int32
	var body atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer pat" || r.Header.Get(PeerNodeIDHeader) != "self" {
			http.Error(w, "missing peer identity", http.StatusForbidden)
			return
		}
		w.WriteHeader(int(status.Load()))
		_, _ = io.WriteString(w, body.Load().(string))
	}))
	defer srv.Close()

	tests := []struct {
		name    string
		status  int
		body    string
		want    uint64
		wantErr error
		errText string
	}{
		{name: "ok", status: http.StatusOK, body: `{"read_index":42}`, want: 42},
		{name: "leader predates the endpoint", status: http.StatusNotFound, body: "404 page not found", wantErr: errReadIndexUnsupported},
		{name: "leader cannot answer yet", status: http.StatusServiceUnavailable, body: "not leader", errText: "status 503"},
		{name: "garbage body", status: http.StatusOK, body: "<html>", errText: "decode read index"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			status.Store(int32(tc.status))
			body.Store(tc.body)
			got, err := c.requestReadIndex(context.Background(), srv.Client(), srv.URL+InternalReadIndexPath, "leader")
			switch {
			case tc.wantErr != nil:
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
			case tc.errText != "":
				if err == nil || !strings.Contains(err.Error(), tc.errText) {
					t.Fatalf("err = %v, want it to mention %q", err, tc.errText)
				}
			default:
				if err != nil || got != tc.want {
					t.Fatalf("got %d, %v; want %d", got, err, tc.want)
				}
			}
		})
	}

	srv.Close()
	if _, err := c.requestReadIndex(context.Background(), srv.Client(), srv.URL+InternalReadIndexPath, "leader"); err == nil {
		t.Fatal("transport failure must be an error, not a read index")
	}
	if _, err := c.requestReadIndex(context.Background(), srv.Client(), "://bad", "leader"); err == nil {
		t.Fatal("malformed endpoint must be an error")
	}
}

// fetchLeaderReadIndex fails closed (an error, never an index) until it can
// dial the leader; once it can, the answer comes over the internal mTLS
// listener from LeaderReadIndex (here the leader is the node itself).
func TestFetchLeaderReadIndexOverInternalListener(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft sockets")
	}
	c, cleanup := newTestCluster(t, "read-index-solo", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.RecordPlacement(ctx, "sb-over-mtls", nil, PlacementSecrets{}); err != nil {
		t.Fatalf("RecordPlacement: %v", err)
	}

	saved := c.currentInternalClient()
	c.setInternalClient(nil)
	if _, err := c.fetchLeaderReadIndex(ctx); !errors.Is(err, ErrPeerInternalURLRequired) {
		t.Fatalf("no internal client: err = %v, want ErrPeerInternalURLRequired", err)
	}
	c.setInternalClient(saved)
	idx, err := c.fetchLeaderReadIndex(ctx)
	if err != nil {
		t.Fatalf("fetchLeaderReadIndex: %v", err)
	}
	if p, ok := c.PlacementOf("sb-over-mtls"); !ok || idx < p.Version {
		t.Fatalf("read index %d does not cover the committed placement (version %d, found %v)", idx, p.Version, ok)
	}
}

func TestServeReadIndex(t *testing.T) {
	call := func(fn func(context.Context) (uint64, error)) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		serveReadIndex(rr, httptest.NewRequest(http.MethodGet, InternalReadIndexPath, nil), fn)
		return rr
	}
	if rr := call(nil); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("no handler: status %d, want 503", rr.Code)
	}
	rr := call(func(context.Context) (uint64, error) { return 0, ErrNotLeader })
	if rr.Code != http.StatusServiceUnavailable || rr.Header().Get("Retry-After") == "" {
		t.Fatalf("not leader: status %d retry-after %q, want 503 with Retry-After", rr.Code, rr.Header().Get("Retry-After"))
	}
	rr = call(func(context.Context) (uint64, error) { return 9, nil })
	var out ReadIndexResponse
	if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &out) != nil || out.ReadIndex != 9 {
		t.Fatalf("leader: status %d body %q, want 200 read_index 9", rr.Code, rr.Body.String())
	}
}

// The endpoint rides the internal mTLS listener behind the same membership
// check as raft applies, and is never a 404 on a current build.
func TestInternalServerServesReadIndex(t *testing.T) {
	pool, tlsCert, err := generateTestCertForNode("node-read-index")
	if err != nil {
		t.Fatalf("cert gen: %v", err)
	}
	ct := &ClusterTLS{nodeCert: tlsCert, caPool: pool}
	srv, err := startInternalServer("127.0.0.1:0", ct, func(context.Context, []byte) error { return nil }, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer srv.Close()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: ct.clientConfig()}}
	get := func() (int, string) {
		resp, err := client.Get("https://" + srv.Addr() + InternalReadIndexPath)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	if code, _ := get(); code != http.StatusServiceUnavailable {
		t.Fatalf("before membership: status %d, want 503", code)
	}
	srv.SetPeerAuthorizer(func(string) bool { return true })
	if code, _ := get(); code != http.StatusServiceUnavailable {
		t.Fatalf("before a handler is installed: status %d, want 503", code)
	}
	srv.SetReadIndexHandler(func(context.Context) (uint64, error) { return 11, nil })
	if code, body := get(); code != http.StatusOK || !strings.Contains(body, `"read_index":11`) {
		t.Fatalf("installed: status %d body %q, want 200 read_index 11", code, body)
	}
	srv.SetReadIndexHandler(nil)
	if code, _ := get(); code != http.StatusServiceUnavailable {
		t.Fatalf("removed: status %d, want 503", code)
	}
	var nilSrv *internalServer
	nilSrv.SetReadIndexHandler(nil)
}

// A bootstrapped single voter catches up through its own barrier, and its
// read index covers what it has committed.
func TestLeaderCatchesUpThroughOwnBarrier(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft sockets")
	}
	c, cleanup := newTestCluster(t, "catch-up-leader", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.RecordPlacement(ctx, "sb-leader-ri", nil, PlacementSecrets{}); err != nil {
		t.Fatalf("RecordPlacement: %v", err)
	}
	idx, err := c.LeaderReadIndex(ctx)
	if err != nil {
		t.Fatalf("LeaderReadIndex: %v", err)
	}
	p, ok := c.PlacementOf("sb-leader-ri")
	if !ok || idx < p.Version {
		t.Fatalf("read index %d does not cover the committed placement (version %d, found %v)", idx, p.Version, ok)
	}
}

// The restart scenario end to end on real raft: a server whose FSM is behind
// the leader (here a joining follower, the extreme case of a restart — it
// replays everything, across several 64-entry AppendEntries batches) must not
// report caught up, and must not hand out an authoritative placement page,
// until every placement the leader committed before it asked is in its FSM.
func TestFollowerCatchesUpOnlyWithEveryCommittedPlacement(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft/memberlist sockets")
	}
	leader, cleanupLeader := newTestCluster(t, "cu-leader", true, nil)
	defer cleanupLeader()
	waitForLeader(t, leader, 10*time.Second)

	const n = 150
	ids := make([]string, n)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	for i := range ids {
		ids[i] = fmt.Sprintf("sb-cu-%03d", i)
		if err := leader.RecordPlacement(ctx, ids[i], nil, PlacementSecrets{}); err != nil {
			t.Fatalf("RecordPlacement %s: %v", ids[i], err)
		}
	}

	follower, cleanupFollower := newTestCluster(t, "cu-follower", false, []string{leader.gossip.ml.LocalNode().Address()})
	defer cleanupFollower()
	joined := time.Now()

	deadline := time.Now().Add(30 * time.Second)
	sawCatchingUp := false
	for !follower.PlacementViewCaughtUp() {
		if time.Now().After(deadline) {
			t.Fatal("follower never caught up")
		}
		sawCatchingUp = true
		if page := follower.PlacementPage(PlacementPageRequest{Limit: MaxPlacementPageLimit}); page.Authoritative {
			t.Fatal("authoritative page while catching up")
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Logf("follower caught up %v after New returned (%d placements replayed)", time.Since(joined), n)
	for _, id := range ids {
		if _, ok := follower.PlacementOf(id); !ok {
			t.Fatalf("caught up without committed placement %s", id)
		}
	}
	if !sawCatchingUp {
		t.Fatal("follower was never observed catching up; the test proved nothing")
	}
	page := follower.PlacementPage(PlacementPageRequest{Limit: MaxPlacementPageLimit})
	if !page.Authoritative || len(page.Placements) < n {
		t.Fatalf("caught-up page: authoritative=%v rows=%d, want authoritative with %d rows", page.Authoritative, len(page.Placements), n)
	}
}
