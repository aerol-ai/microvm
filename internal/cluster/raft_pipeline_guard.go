package cluster

import (
	"log/slog"
	"sync"
	"time"

	"github.com/hashicorp/raft"
)

// raftPipelineStallFactor sets how long one pipelined AppendEntries may block
// before the guard closes its pipeline: this many transport timeouts. A
// healthy send waits for its own write (bounded by the write deadline) and
// for the pipeline's decoder to finish the previous response (bounded by the
// read deadline), so about two timeouts at most. Three leaves margin: a false
// alarm only costs that follower a switch to plain replication.
const raftPipelineStallFactor = 3

// raftShutdownGrace is how long Close lets raft.Shutdown finish on its own
// before it closes every replication pipeline (closePipelines). A healthy
// shutdown takes milliseconds. A var so tests can shorten it.
var raftShutdownGrace = 2 * time.Second

// pipelineGuardTransport is raft's NetworkTransport with one change: a
// pipelined AppendEntries can no longer block forever.
//
// Why: in hashicorp/raft (1.7.3, and 1.8.0 has the same code) a leader's
// pipeline to a follower has two parts. pipelineDecode reads the answers;
// pipelineReplicate sends. pipelineDecode returns as soon as the follower
// rejects an append or answers with a newer term (after a follower restart,
// or a leader change). The sender notices only when its select picks
// finishCh, and it may first pick another send. With two RPCs in flight
// (DefaultMaxRPCsInFlight) the second such send blocks in
// netPipeline.AppendEntries waiting for the pipeline's decoder, which is
// itself stuck handing an answer to the reader that left. Only closing the
// pipeline frees it, and raft closes it only after that same send returns.
// Replication to that follower then stops until the next leader change, the
// goroutine never exits, and raft.Shutdown waits for it forever: a server
// stop hung until systemd killed it. Seen in the cluster fault tests
// (goroutine dumps: pipelineSend -> netPipeline.AppendEntries, 5 minutes).
//
// The guard closes a pipeline whose send has been blocked longer than any
// healthy send can take. Raft already handles a closed pipeline: the send
// returns ErrPipelineShutdown, pipelineReplicate returns, and that follower
// falls back to plain AppendEntries until raft opens a new pipeline.
// Everything else (pre-vote, heartbeats, snapshots, Close) is the embedded
// NetworkTransport, unchanged.
type pipelineGuardTransport struct {
	*raft.NetworkTransport
	stallAfter time.Duration
	logger     *slog.Logger

	mu   sync.Mutex
	open map[*guardedPipeline]struct{}
}

func newPipelineGuardTransport(t *raft.NetworkTransport, stallAfter time.Duration, logger *slog.Logger) *pipelineGuardTransport {
	return &pipelineGuardTransport{
		NetworkTransport: t,
		stallAfter:       stallAfter,
		logger:           logger,
		open:             make(map[*guardedPipeline]struct{}),
	}
}

// AppendEntriesPipeline wraps raft's pipeline so each send is watched.
func (t *pipelineGuardTransport) AppendEntriesPipeline(id raft.ServerID, target raft.ServerAddress) (raft.AppendPipeline, error) {
	p, err := t.NetworkTransport.AppendEntriesPipeline(id, target)
	if err != nil {
		return nil, err
	}
	gp := &guardedPipeline{AppendPipeline: p, guard: t, peer: id}
	t.mu.Lock()
	t.open[gp] = struct{}{}
	t.mu.Unlock()
	return gp, nil
}

// closePipelines closes every pipeline still open and returns how many.
// raftNode.Close calls it when raft.Shutdown has not finished within
// raftShutdownGrace, so a send stuck on a pipeline returns at once instead
// of after stallAfter.
func (t *pipelineGuardTransport) closePipelines() int {
	t.mu.Lock()
	open := make([]*guardedPipeline, 0, len(t.open))
	for p := range t.open {
		open = append(open, p)
	}
	t.mu.Unlock()
	for _, p := range open {
		_ = p.Close()
	}
	return len(open)
}

// openPipelines reports how many pipelines are open (tests).
func (t *pipelineGuardTransport) openPipelines() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.open)
}

type guardedPipeline struct {
	raft.AppendPipeline
	guard *pipelineGuardTransport
	peer  raft.ServerID
}

// AppendEntries is the pipeline's send with a stall watchdog. On a healthy
// send the timer is stopped before it fires; nothing else changes.
func (p *guardedPipeline) AppendEntries(args *raft.AppendEntriesRequest, resp *raft.AppendEntriesResponse) (raft.AppendFuture, error) {
	watchdog := time.AfterFunc(p.guard.stallAfter, func() {
		raftPipelineStalls.Add(1)
		if p.guard.logger != nil {
			p.guard.logger.Warn("raft replication pipeline send stalled; closing the pipeline so the follower falls back to plain replication",
				"peer", p.peer, "stalled_for", p.guard.stallAfter)
		}
		_ = p.Close()
	})
	f, err := p.AppendPipeline.AppendEntries(args, resp)
	watchdog.Stop()
	return f, err
}

// Close untracks the pipeline and closes it. raft's netPipeline.Close is
// idempotent, so the watchdog, closePipelines and raft's own deferred Close
// may all call it.
func (p *guardedPipeline) Close() error {
	p.guard.mu.Lock()
	delete(p.guard.open, p)
	p.guard.mu.Unlock()
	return p.AppendPipeline.Close()
}

// awaitRaftShutdown waits for raft's shutdown future. If it has not finished
// after grace, it calls closePipelines once (when non-nil) and keeps
// waiting: a replication send stuck on a pipeline is the one known way
// raft.Shutdown hangs, and closing the pipelines frees it. It does not give
// up after that: closing the stores under a raft that is still running
// could corrupt them, which is worse than a slow stop.
func awaitRaftShutdown(f raft.Future, grace time.Duration, closePipelines func() int, logger *slog.Logger) error {
	done := make(chan error, 1)
	go func() { done <- f.Error() }()
	select {
	case err := <-done:
		return err
	case <-time.After(grace):
	}
	if closePipelines != nil {
		n := closePipelines()
		if logger != nil {
			logger.Warn("raft shutdown still waiting; closed the replication pipelines so a stuck send can return",
				"after", grace, "pipelines_closed", n)
		}
	}
	return <-done
}
