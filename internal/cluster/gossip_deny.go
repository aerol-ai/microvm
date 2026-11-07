package cluster

import (
	"errors"
	"expvar"
	"log/slog"
	"sync"
	"time"

	"github.com/hashicorp/memberlist"
)

// Enforcing the deny records (fsm_node_deny.go) on every member.
//
//	gossip ──► gossipAliveDelegate refuses a denied node's alive messages, so
//	           it never (re)enters memberlist; the member index drops one it
//	           already held, so Members(), placement candidates and the peer
//	           membership check stop seeing it
//	mTLS ────► internalServer's deny check and withInternalMTLS refuse a
//	           denied peer with 403 "deleted", before the membership check
//	place ───► SelectPlacement and leader reservation admission skip it
//
// Servers answer from the FSM, workers and ingress nodes from their deny
// mirror (agent_deny_mirror.go). Each refusal counts in
// aerolvm_deny_hits_total{key=peer|gossip|placement}.

// ErrPeerDeleted is the 403 a deleted node gets on every internal call, on
// both the internal listener and the public API's internal routes. It is
// deliberately not "cluster peer not in membership": that wording means
// "retry, gossip has not caught up" to a restarting node (ErrMembershipPending),
// and a deleted node has nothing to wait for.
var ErrPeerDeleted = errors.New("cluster peer node was deleted (aerolvm delete node); it needs a fresh join")

// denyHits is aerolvm_deny_hits_total, keyed by where a deleted node was
// turned away.
var denyHits = expvar.NewMap("aerolvm_deny_hits_total")

const (
	denyHitPeer      = "peer"
	denyHitGossip    = "gossip"
	denyHitPlacement = "placement"
)

// denyHitLogEvery bounds the log to one line per node and place a minute: a
// deleted node that is still running retries its internal calls and
// re-broadcasts alive messages, and the counter already carries the rate.
const denyHitLogEvery = time.Minute

// denyHitRecorder counts every refusal and logs the first one per node and
// place each minute.
type denyHitRecorder struct {
	logger *slog.Logger
	now    func() time.Time
	last   sync.Map // where+"\x00"+nodeID -> time.Time
}

func (r *denyHitRecorder) hit(where, nodeID string) {
	denyHits.Add(where, 1)
	if r == nil || r.logger == nil {
		return
	}
	now := time.Now()
	if r.now != nil {
		now = r.now()
	}
	key := where + "\x00" + nodeID
	if prev, ok := r.last.Load(key); ok && now.Sub(prev.(time.Time)) < denyHitLogEvery {
		return
	}
	r.last.Store(key, now)
	r.logger.Warn("cluster: refused a deleted node", "node_id", nodeID, "where", where)
}

// gossipAliveDelegate is memberlist's AliveDelegate: it refuses alive
// messages for denied nodes, so a deleted node that still holds the gossip
// key cannot come back as a member. It never refuses self, whose own alive
// message passes through here too: refusing it would keep this node out of
// its own member list.
type gossipAliveDelegate struct {
	selfID string
	denied func(string) bool
	hits   *denyHitRecorder
}

func (d *gossipAliveDelegate) NotifyAlive(peer *memberlist.Node) error {
	if d == nil || peer == nil || d.denied == nil || peer.Name == d.selfID || !d.denied(peer.Name) {
		return nil
	}
	d.hits.hit(denyHitGossip, peer.Name)
	return ErrPeerDeleted
}

// applyDenySet drops newly denied members from the view now, without
// waiting for the refresh loop's next rescan of memberlist.
func (g *gossipNode) applyDenySet() {
	if index := g.currentMemberIndex(); index != nil {
		index.replace(index.snapshot())
	}
}

// keep reports whether the index may hold nodeID: not denied, or self. The
// check takes only the deny set's own lock, so it is safe under the index's.
func (i *gossipMemberIndex) keep(nodeID string) bool {
	return i.denied == nil || nodeID == i.selfID || !i.denied(nodeID)
}
