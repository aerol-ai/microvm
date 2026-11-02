package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/raft"
)

// Catch-up after a (re)start: when may this node say "no such sandbox"?
//
// A server-role node answers placement reads from its local Raft FSM. On a
// restart NewRaft restores the newest snapshot synchronously, but the entries
// committed after that snapshot (up to SnapshotInterval / SnapshotThreshold of
// churn) and everything the cluster committed while this process was down are
// applied only once the leader's AppendEntries report the commit index. Until
// then the FSM is a past state of the cluster: a sandbox placed after the
// snapshot is simply absent, and the API turned "absent" into a 404. Live
// evidence (UC-337, sb-46779d2f94047af2): DELETE answered 404 in 0.5ms, 0.45s
// after the restarted node opened its listeners, and 204 once it caught up.
//
// Caught up is a Raft read index (Raft thesis §6.4), taken once per process:
//
//  1. Ask the leader for its read index R. The leader proves it is still the
//     leader (VerifyLeader) and that its FSM has applied everything committed
//     before the request (Barrier), then reports its FSM version: the raft
//     index of the last command it applied (placementFSM.version).
//  2. This node is caught up once its own FSM version is >= R.
//
// A leader acknowledges a placement write only after its own FSM applied it,
// so every placement any client was told about before step 1 sits at an index
// <= R. Once step 2 holds none of them can be missing here. The leader runs
// the same two steps against itself (Barrier, then its own version).
//
// Why not raft's own CommitIndex: a follower sets it to
// min(leaderCommit, lastLocalIndex) after each AppendEntries batch (64
// entries), so a follower far behind reads "applied == committed" after the
// FIRST batch while the leader is still hundreds of entries ahead.
//
// The verdict latches for the life of the process: after it the FSM only moves
// forward, and ordinary follower lag is the same as before a restart. It never
// latches on a timer: a node that cannot reach a leader stays not caught up
// and keeps answering "retry", never "absent".

// ErrNotCaughtUp means this node restarted and its placement view has not yet
// applied the cluster's read index, so a sandbox missing from it may still
// exist. Callers answer 503 + Retry-After; it is never evidence of absence.
var ErrNotCaughtUp = errors.New("cluster: placement view is still catching up after a restart")

// CatchUpRetryAfterSeconds is the Retry-After for ErrNotCaughtUp. Catch-up is
// one leader round trip plus the log replay; on the live 3-node cluster the
// restarted node's listeners were up ~0.5s before its view was.
const CatchUpRetryAfterSeconds = 1

// InternalReadIndexPath is served on the cluster-internal mTLS listener: the
// leader half of the read index. Never 404 on a current build, so a follower
// can tell a leader that predates it (404) from one that cannot answer yet.
const InternalReadIndexPath = "/internal/read-index"

// catchUpPollInterval is how often a catching-up node retries the read index
// or rechecks its FSM version. Bounded work: one request per tick until the
// read index is known, then one atomic read per tick, and the loop exits for
// good once caught up.
const catchUpPollInterval = 50 * time.Millisecond

// catchUpStillWaitingLogEvery throttles the warning a node logs while it
// cannot catch up (no leader, leader unreachable, replay stalled).
const catchUpStillWaitingLogEvery = 30 * time.Second

// errReadIndexUnsupported: the leader runs a build without the read-index
// endpoint (a rolling upgrade). See watchCatchUp for what that means.
var errReadIndexUnsupported = errors.New("cluster: leader does not serve the read index")

// ReadIndexResponse is the body of InternalReadIndexPath.
type ReadIndexResponse struct {
	ReadIndex uint64 `json:"read_index"`
}

// CatchUpReporter is implemented by clients that answer placement reads from
// a local replica that can lag the cluster after a restart (*Cluster).
type CatchUpReporter interface {
	PlacementViewCaughtUp() bool
}

// CaughtUp reports whether c may treat a placement missing from its view as
// absent. Clients without a local replica report true: an Agent's reads go to
// a server, which applies this gate itself and answers 503 (the Agent then
// asks the next server); Noop is the whole truth.
func CaughtUp(c Client) bool {
	if r, ok := c.(CatchUpReporter); ok {
		return r.PlacementViewCaughtUp()
	}
	return true
}

// PlacementViewCaughtUp reports whether this node's FSM has applied the read
// index it took after starting. The zero value is caught up, so a Cluster
// built as a struct literal (tests) behaves as before; only New arms it.
func (c *Cluster) PlacementViewCaughtUp() bool {
	return c == nil || !c.catchingUp.Load()
}

// startCatchUpWatch arms the gate and runs the read-index loop. New calls it
// last, once gossip and the internal client exist; New has already armed the
// flag the moment the Cluster was built, so no read sees it unarmed.
func (c *Cluster) startCatchUpWatch() {
	c.catchingUp.Store(true)
	clusterCatchingUp.Set(1)
	ctx, cancel := context.WithCancel(context.Background())
	c.catchUpStop = cancel
	go c.watchCatchUp(ctx, catchUpPollInterval)
}

// watchCatchUp polls until the FSM has applied the read index, then latches.
func (c *Cluster) watchCatchUp(ctx context.Context, interval time.Duration) {
	start := time.Now()
	t := time.NewTicker(interval)
	defer t.Stop()
	logEvery := c.catchUpLogEvery
	if logEvery <= 0 {
		logEvery = catchUpStillWaitingLogEvery
	}
	lastLog := start
	var (
		target     uint64
		haveTarget bool
		lastErr    error
	)
	for {
		if !haveTarget {
			idx, err := c.readIndex(ctx)
			lastErr = err
			switch {
			case err == nil:
				target, haveTarget = idx, true
			case errors.Is(err, errReadIndexUnsupported):
				// A leader on the previous build cannot give a read index.
				// Latch now: this node then behaves exactly as that build
				// does (no gate), and the gate is in force from the first
				// restart after the leader is upgraded.
				c.markCaughtUp(start, 0, "leader_without_read_index")
				return
			}
		}
		if haveTarget && c.fsm.currentVersion() >= target {
			c.markCaughtUp(start, target, "read_index_applied")
			return
		}
		if now := time.Now(); now.Sub(lastLog) >= logEvery {
			// Loud on purpose: until this clears, every unknown sandbox id
			// on this node answers 503.
			lastLog = now
			if c.logger != nil {
				c.logger.Warn("cluster: placement view still catching up; requests for sandboxes it does not hold answer 503",
					"elapsed_ms", now.Sub(start).Milliseconds(),
					"read_index_known", haveTarget,
					"read_index", target,
					"fsm_version", c.fsm.currentVersion(),
					"last_error", lastErr)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (c *Cluster) markCaughtUp(start time.Time, readIndex uint64, reason string) {
	elapsed := time.Since(start)
	c.catchingUp.Store(false)
	clusterCatchingUp.Set(0)
	clusterCatchUpLastNanos.Set(elapsed.Nanoseconds())
	if c.logger != nil {
		c.logger.Info("cluster: placement view caught up",
			"read_index", readIndex,
			"fsm_version", c.fsm.currentVersion(),
			"elapsed_ms", elapsed.Milliseconds(),
			"reason", reason)
	}
}

// readIndex returns the index this node must apply before it is caught up.
func (c *Cluster) readIndex(ctx context.Context) (uint64, error) {
	if c.readIndexHook != nil {
		return c.readIndexHook(ctx)
	}
	if c.raft == nil || c.raft.raft == nil {
		// A single-process FSM is the whole truth.
		return c.fsm.currentVersion(), nil
	}
	if c.raft.raft.State() == raft.Leader {
		return c.LeaderReadIndex(ctx)
	}
	return c.fetchLeaderReadIndex(ctx)
}

// LeaderReadIndex is the leader half of the read index: prove leadership and
// that every committed entry is applied here, then report the FSM version.
func (c *Cluster) LeaderReadIndex(ctx context.Context) (uint64, error) {
	if c == nil || c.fsm == nil || c.raft == nil || c.raft.raft == nil {
		return 0, ErrNotLeader
	}
	if c.raft.raft.State() != raft.Leader {
		return 0, ErrNotLeader
	}
	if err := c.awaitAuthoritativeFSM(ctx); err != nil {
		return 0, err
	}
	return c.fsm.currentVersion(), nil
}

// fetchLeaderReadIndex asks the leader over the node-pinned mTLS channel.
func (c *Cluster) fetchLeaderReadIndex(ctx context.Context) (uint64, error) {
	leader := c.Leader()
	if leader == "" {
		return 0, ErrNoLeader
	}
	if c.currentInternalClient() == nil || c.gossip == nil {
		return 0, ErrPeerInternalURLRequired
	}
	peerInternal := c.gossip.peerInternalURL(leader)
	if peerInternal == "" {
		return 0, ErrPeerInternalURLRequired
	}
	return c.requestReadIndex(ctx, c.ClientForPeer(leader), strings.TrimRight(peerInternal, "/")+InternalReadIndexPath, leader)
}

// requestReadIndex is the HTTP half of fetchLeaderReadIndex.
func (c *Cluster) requestReadIndex(ctx context.Context, client *http.Client, endpoint, leader string) (uint64, error) {
	reqCtx, cancel := context.WithTimeout(ctx, controlPlaneRequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, fmt.Errorf("cluster: build read-index request: %w", err)
	}
	SetPeerNodeIDHeader(req, c.nodeID)
	if c.patToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.patToken)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("cluster: read index from leader %s: %w", leader, err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return 0, errReadIndexUnsupported
	default:
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return 0, fmt.Errorf("cluster: read index from leader %s: status %d: %s", leader, resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	var out ReadIndexResponse
	if err := decodeControlPlaneJSON(resp.Body, &out); err != nil {
		return 0, fmt.Errorf("cluster: decode read index from leader %s: %w", leader, err)
	}
	return out.ReadIndex, nil
}

// serveReadIndex is the InternalReadIndexPath handler. Every failure is a 503:
// a 404 would tell the follower this leader predates the endpoint.
func serveReadIndex(w http.ResponseWriter, r *http.Request, fn func(context.Context) (uint64, error)) {
	if fn == nil {
		http.Error(w, "cluster: read index not available yet", http.StatusServiceUnavailable)
		return
	}
	idx, err := fn(r.Context())
	if err != nil {
		w.Header().Set("Retry-After", fmt.Sprint(LeaderChangeRetryAfterSeconds))
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ReadIndexResponse{ReadIndex: idx})
}

// RecordNotCaughtUpReject counts one request answered 503 because this node's
// placement view was still catching up (it would have been a false 404).
func RecordNotCaughtUpReject() {
	clusterNotCaughtUpRejects.Add(1)
}
