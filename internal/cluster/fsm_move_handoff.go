package cluster

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// Move handoffs: a snapshot move's swap and its source's resume are
// mutually exclusive (review N3).
//
// A snapshot move releases the sandbox on its source, which fences it for
// moveFenceTTL (5 minutes), then imports it on the target, which may take
// longer (importMoveTimeout, 15 minutes for a VM's memory and disks). When
// the source's fence lapsed first, the source asked the leader whether it
// still owned the sandbox, heard yes (the swap had not happened yet) and
// started it again. The swap's compare-and-swap checks only the owner and
// the lifetime, both unchanged, so the import's late swap still landed and
// the target started its copy too: two executors.
//
// So the leader opens a handoff before it releases: opMoveHandoff with a
// fresh token, recorded beside the placement. The swap (opReassign) carries
// the token and lands only while the placement still holds it. A source
// that wants to start a released sandbox again first aborts the handoff:
// opMoveHandoff with no token, which lands only while it is still the
// owner, and clears whatever token is there. Both go through Raft, so one
// of the two wins and the other is refused:
//
//	leader: begin(T) ─► release ─► import ─► reassign(expects T) ─► start on target
//	source: fence lapses ─► abort (expects owner = self) ─► start here
//
// abort first: the reassign finds no T and fails, and the leader drops the
// target's copy. Reassign first: the owner is the target, the abort fails,
// and the source leaves its copy stopped for the stale-ownership sweep.
//
// The tokens are FSM state but not a placement field: one entry per move in
// flight, cleared by the swap, an abort, an orphaning and a delete. Every
// apply reads only the command and the row, never a clock or node config.
//
// Rolling upgrade: an older server would fail opMoveHandoff and ignore the
// reassign's token, splitting the replicas. Nothing proposes either until
// every Raft server applies them (moveHandoffFSMOpsVersion), the leader
// refuses opMoveHandoff and drops the token from a reassign while one does
// not, and a worker falls back to the ownership read alone
// (ErrMoveHandoffUnsupported). Until then a move works as it did before.
const opMoveHandoff opCode = 54

// moveHandoffFSMOpsVersion is the build that applies opMoveHandoff and
// checks opReassign's ExpectedMoveToken.
const moveHandoffFSMOpsVersion = 21

var (
	// ErrMoveHandoffAborted is a snapshot move's swap refused because its
	// source aborted the handoff (it started the sandbox again) or the
	// placement changed hands since the handoff began.
	ErrMoveHandoffAborted = errors.New("cluster: the move's source took the sandbox back before the swap")
	// ErrMoveHandoffMoved is an abort refused because the placement no
	// longer names the node that asked: the move happened.
	ErrMoveHandoffMoved = errors.New("cluster: the sandbox moved to another node")
	// ErrMoveHandoffUnsupported is an abort a cluster cannot record yet:
	// some server predates opMoveHandoff. The caller relies on the
	// ownership read alone, as before.
	ErrMoveHandoffUnsupported = errors.New("cluster: not every server records move handoffs yet")
)

// MoveHandoffClient is implemented by the cluster clients a worker's source
// uses to abort a move before it starts a released sandbox again: Cluster
// and Agent.
type MoveHandoffClient interface {
	// AbortMoveHandoff clears any handoff open on sandboxID, but only while
	// this node owns its incarnation; a later swap of that move then fails.
	// It answers ErrMoveHandoffMoved when the sandbox moved away,
	// ErrMoveHandoffUnsupported when the cluster cannot record handoffs
	// yet, and any other error when the leader could not be asked.
	AbortMoveHandoff(ctx context.Context, sandboxID, incarnationID string) error
}

// applyMoveHandoffLocked opens (cmd.MoveToken set) or aborts (empty) the
// handoff of one placement. Both need the lifetime and the owner the caller
// read; an abort that finds another owner is ErrMoveHandoffMoved.
func (f *placementFSM) applyMoveHandoffLocked(cmd command) error {
	id := strings.TrimSpace(cmd.SandboxID)
	inc := strings.TrimSpace(cmd.ExpectedIncarnationID)
	if id == "" || inc == "" || !cmd.ExpectedOwnerNodeIDSet {
		return fmt.Errorf("%w: a move handoff needs the sandbox, its lifetime and its owner", ErrIncarnationConflict)
	}
	hot, ok := f.placements[id]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownSandbox, id)
	}
	if strings.TrimSpace(hot.IncarnationID) != inc {
		return fmt.Errorf("%w: move handoff want %q have %q", ErrIncarnationConflict, inc, hot.IncarnationID)
	}
	if owner := strings.TrimSpace(cmd.ExpectedOwnerNodeID); strings.TrimSpace(hot.OwnerNodeID) != owner {
		return fmt.Errorf("%w: %s is owned by %q, not %q", ErrMoveHandoffMoved, id, hot.OwnerNodeID, owner)
	}
	token := strings.TrimSpace(cmd.MoveToken)
	if token == "" {
		delete(f.moveHandoffs, id)
		return nil
	}
	if hot.IsDeleting() {
		return fmt.Errorf("%w: %s is being deleted", ErrReservationConflict, id)
	}
	if f.moveHandoffs == nil {
		f.moveHandoffs = make(map[string]string)
	}
	f.moveHandoffs[id] = token
	return nil
}

// moveHandoffRefusesReassign is opReassign's check of its ExpectedMoveToken:
// nil when the reassign asks for none or the placement still holds it.
func (f *placementFSM) moveHandoffRefusesReassign(cmd command) error {
	want := strings.TrimSpace(cmd.ExpectedMoveToken)
	if want == "" || f.moveHandoffs[strings.TrimSpace(cmd.SandboxID)] == want {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrMoveHandoffAborted, cmd.SandboxID)
}

// moveHandoffToken is id's open handoff token, or "".
func (f *placementFSM) moveHandoffToken(id string) string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.moveHandoffs[id]
}

func (f *placementFSM) moveHandoffsSnapshotLocked() map[string]string {
	if len(f.moveHandoffs) == 0 {
		return nil
	}
	out := make(map[string]string, len(f.moveHandoffs))
	for id, token := range f.moveHandoffs {
		out[id] = token
	}
	return out
}

func (f *placementFSM) restoreMoveHandoffsLocked(in map[string]string) {
	f.moveHandoffs = nil
	for id, token := range in {
		// A handoff of a placement the snapshot no longer has is gone with
		// it.
		if _, ok := f.placements[id]; !ok || strings.TrimSpace(token) == "" {
			continue
		}
		if f.moveHandoffs == nil {
			f.moveHandoffs = make(map[string]string, len(in))
		}
		f.moveHandoffs[id] = token
	}
}

// moveHandoffReplicated is the one gate for both sides of a handoff: the
// leader opens one (and admits a swap's token or an abort) only while it
// holds, and a source sends its abort only while it holds. Its server half
// is the part a source can see: every live control-plane member runs the
// handoff version, so the server a worker's abort reaches, and the leader
// it forwards to, record it (controlPlaneAtLeast). The leader adds what
// only it can read, every Raft server or the active cluster version
// (raftServersSupport), and decides each abort with that. Workers do not
// count: they neither apply nor forward the op. Before, a source required
// every live member, workers included, while the leader required the
// servers alone, so one old or stale worker made every source skip its
// abort while the leader kept opening handoffs: the N3 race again.
func (c *Cluster) moveHandoffReplicated() bool {
	if c == nil || c.raft == nil || c.raft.raft == nil {
		return false
	}
	return c.gossip.controlPlaneAtLeast(moveHandoffFSMOpsVersion) &&
		c.raftServersSupport(moveHandoffFSMOpsVersion, "move handoffs") == nil
}

func (a *Agent) moveHandoffReplicated() bool {
	if a == nil {
		return false
	}
	return a.gossip.controlPlaneAtLeast(moveHandoffFSMOpsVersion)
}

// controlPlaneAtLeast reports whether every live control-plane member
// advertises fv >= v; false while it knows of none.
func (g *gossipNode) controlPlaneAtLeast(v int) bool {
	servers := g.currentMemberIndex().controlPlaneSnapshot()
	for _, m := range servers {
		if m.FSMOpsVersion < v {
			return false
		}
	}
	return len(servers) > 0
}

// admitMoveHandoff is the leader's step for the handoff's two writes, from
// this node or forwarded: opMoveHandoff is refused, and a reassign's token
// dropped, while any Raft server would not apply them the same way.
func (c *Cluster) admitMoveHandoff(payload []byte, cmd command) ([]byte, command, error) {
	switch {
	case cmd.Op == opMoveHandoff:
		if !c.moveHandoffReplicated() {
			return nil, cmd, fmt.Errorf("%w: move handoffs", ErrClusterVersion)
		}
	case cmd.Op == opReassign && strings.TrimSpace(cmd.ExpectedMoveToken) != "":
		if !c.moveHandoffReplicated() {
			cmd.ExpectedMoveToken = ""
			out, err := encodeCommand(cmd)
			return out, cmd, err
		}
	}
	return payload, cmd, nil
}

// beginMoveHandoff opens a handoff on p, owned by source, and returns its
// token for the swap. While any Raft server cannot record handoffs, the
// leader refuses the op (admitMoveHandoff, ErrClusterVersion) before it
// reaches Raft: then "" and no error, and the move goes on as before.
func (c *Cluster) beginMoveHandoff(ctx context.Context, p Placement, source string) (string, error) {
	token, err := MintIncarnationID()
	if err == nil {
		err = c.applyCommand(ctx, command{
			Op:                     opMoveHandoff,
			SandboxID:              p.SandboxID,
			ExpectedIncarnationID:  strings.TrimSpace(p.IncarnationID),
			ExpectedOwnerNodeID:    source,
			ExpectedOwnerNodeIDSet: true,
			MoveToken:              token,
		})
	}
	if errors.Is(err, ErrClusterVersion) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return token, nil
}

// abortMoveHandoffCommand is the abort a node sends for itself.
func abortMoveHandoffCommand(sandboxID, incarnationID, self string) command {
	return command{
		Op:                     opMoveHandoff,
		SandboxID:              strings.TrimSpace(sandboxID),
		ExpectedIncarnationID:  strings.TrimSpace(incarnationID),
		ExpectedOwnerNodeID:    self,
		ExpectedOwnerNodeIDSet: true,
	}
}

// classifyAbortError restores the handoff's verdicts on an error that came
// back over a hop as text.
func classifyAbortError(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	switch {
	case errors.Is(err, ErrClusterVersion), strings.Contains(msg, ErrClusterVersion.Error()):
		return fmt.Errorf("%w: %v", ErrMoveHandoffUnsupported, err)
	case errors.Is(err, ErrMoveHandoffMoved), strings.Contains(msg, ErrMoveHandoffMoved.Error()),
		errors.Is(err, ErrUnknownSandbox), strings.Contains(msg, ErrUnknownSandbox.Error()),
		errors.Is(err, ErrIncarnationConflict), strings.Contains(msg, ErrIncarnationConflict.Error()):
		// Moved away, deleted, or another lifetime: not this node's to
		// start.
		return fmt.Errorf("%w: %v", ErrMoveHandoffMoved, err)
	}
	return err
}

// AbortMoveHandoff implements MoveHandoffClient for a server.
func (c *Cluster) AbortMoveHandoff(ctx context.Context, sandboxID, incarnationID string) error {
	if strings.TrimSpace(incarnationID) == "" {
		return fmt.Errorf("%w: an abort needs the sandbox's lifetime", ErrMoveHandoffUnsupported)
	}
	if !c.moveHandoffReplicated() {
		return ErrMoveHandoffUnsupported
	}
	return classifyAbortError(c.applyCommand(ctx, abortMoveHandoffCommand(sandboxID, incarnationID, c.nodeID)))
}

// AbortMoveHandoff implements MoveHandoffClient for a worker: the leader
// applies it.
func (a *Agent) AbortMoveHandoff(ctx context.Context, sandboxID, incarnationID string) error {
	if strings.TrimSpace(incarnationID) == "" {
		return fmt.Errorf("%w: an abort needs the sandbox's lifetime", ErrMoveHandoffUnsupported)
	}
	if !a.moveHandoffReplicated() {
		return ErrMoveHandoffUnsupported
	}
	return classifyAbortError(a.applyCommand(ctx, abortMoveHandoffCommand(sandboxID, incarnationID, a.nodeID)))
}
