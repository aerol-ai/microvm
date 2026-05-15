package cluster

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/hashicorp/memberlist"
)

// nodeMeta is the per-node metadata broadcast through memberlist. It must stay
// well under memberlist.Config.NodeMeta size limit (default 512 bytes); if
// capacity.Snapshot grows past that, we'd need to switch to gossiped
// user-events instead of node metadata.
type nodeMeta struct {
	NodeID   string `json:"node_id"`
	APIURL   string `json:"api_url"`
	RaftAddr string `json:"raft_addr,omitempty"`
	// InternalURL is this node's cluster-internal mTLS endpoint (e.g.
	// https://10.0.0.5:7002). Set only when the node was started with cluster
	// TLS material — peers receiving an empty value know to fall back to the
	// public APIURL with PAT-only auth.
	InternalURL string            `json:"internal_url,omitempty"`
	Capacity    capacity.Snapshot `json:"capacity"`
}

// gossipDelegate implements memberlist.Delegate. Its job is to publish this
// node's metadata (which includes the capacity snapshot) and accept others'.
type gossipDelegate struct {
	mu          sync.RWMutex
	selfMeta    nodeMeta
	encoded     []byte
	admitter    *capacity.Admitter
	nodeID      string
	apiURL      string
	raftAddr    string
	internalURL string
}

func newGossipDelegate(nodeID, apiURL, raftAddr, internalURL string, admitter *capacity.Admitter) *gossipDelegate {
	d := &gossipDelegate{
		admitter:    admitter,
		nodeID:      nodeID,
		apiURL:      apiURL,
		raftAddr:    raftAddr,
		internalURL: internalURL,
	}
	d.refreshMeta()
	return d
}

// refreshMeta rebuilds the encoded metadata blob from the current capacity
// snapshot. memberlist's NodeMeta() must return a stable byte slice, so we
// double-buffer.
func (d *gossipDelegate) refreshMeta() {
	snap := capacity.Snapshot{}
	if d.admitter != nil {
		snap = d.admitter.Snapshot()
	}
	meta := nodeMeta{NodeID: d.nodeID, APIURL: d.apiURL, RaftAddr: d.raftAddr, InternalURL: d.internalURL, Capacity: snap}
	enc, err := json.Marshal(meta)
	if err != nil {
		// JSON of a capacity.Snapshot can't fail; if it does, fall back to a
		// minimal blob so peers still know we're here.
		minimal, _ := json.Marshal(nodeMeta{NodeID: d.nodeID, APIURL: d.apiURL, InternalURL: d.internalURL})
		enc = minimal
	}
	d.mu.Lock()
	d.selfMeta = meta
	d.encoded = enc
	d.mu.Unlock()
}

func (d *gossipDelegate) NodeMeta(limit int) []byte {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if len(d.encoded) > limit {
		// Truncated metadata is worse than minimal metadata (peers can't
		// decode partial JSON). Fall back to ID+URL only.
		fallback, _ := json.Marshal(nodeMeta{NodeID: d.nodeID, APIURL: d.apiURL})
		if len(fallback) > limit {
			return fallback[:limit]
		}
		return fallback
	}
	return d.encoded
}

// NotifyMsg, GetBroadcasts, LocalState, MergeRemoteState are required by the
// Delegate interface but unused in Phase 1 — we rely on NodeMeta only.
func (d *gossipDelegate) NotifyMsg([]byte)                {}
func (d *gossipDelegate) GetBroadcasts(int, int) [][]byte { return nil }
func (d *gossipDelegate) LocalState(bool) []byte          { return nil }
func (d *gossipDelegate) MergeRemoteState([]byte, bool)   {}

// gossipNode wraps memberlist + the delegate so Close can stop the refresh
// loop alongside leaving the cluster.
type gossipNode struct {
	ml          *memberlist.Memberlist
	delegate    *gossipDelegate
	stopRefresh context.CancelFunc
	logger      *slog.Logger
}

type gossipSetupConfig struct {
	NodeID         string
	BindAddr       string
	AdvertiseAddr  string
	APIURL         string
	RaftAddr       string
	InternalURL    string
	BootstrapPeers []string
	GossipInterval time.Duration
	// SecretKey enables AES gossip encryption + authentication when non-nil.
	// Must be 16, 24, or 32 bytes. When nil, gossip is plaintext — acceptable
	// only on a fully private network the operator controls. Without it, any
	// reachable peer can join the cluster and (via voter auto-promotion) gain
	// raft voter status.
	SecretKey []byte
	// Events, if non-nil, receives memberlist join/leave/update notifications.
	// Auto-voter promotion in Phase 2 plugs in here.
	Events memberlist.EventDelegate
}

func setupGossip(cfg gossipSetupConfig, admitter *capacity.Admitter, logger *slog.Logger) (*gossipNode, error) {
	mlCfg := memberlist.DefaultLANConfig()
	mlCfg.Name = cfg.NodeID
	host, port, err := splitHostPort(cfg.BindAddr)
	if err != nil {
		return nil, fmt.Errorf("gossip setup: parse bind addr %q: %w", cfg.BindAddr, err)
	}
	mlCfg.BindAddr = host
	mlCfg.BindPort = port
	if cfg.AdvertiseAddr != "" {
		ahost, aport, err := splitHostPort(cfg.AdvertiseAddr)
		if err != nil {
			return nil, fmt.Errorf("gossip setup: parse advertise addr %q: %w", cfg.AdvertiseAddr, err)
		}
		mlCfg.AdvertiseAddr = ahost
		mlCfg.AdvertisePort = aport
	}

	delegate := newGossipDelegate(cfg.NodeID, cfg.APIURL, cfg.RaftAddr, cfg.InternalURL, admitter)
	mlCfg.Delegate = delegate
	if cfg.Events != nil {
		mlCfg.Events = cfg.Events
	}
	if len(cfg.SecretKey) > 0 {
		// memberlist accepts 16/24/32-byte keys for AES-128/192/256-GCM. Anything
		// else is rejected at construction so we surface a clear error rather
		// than silently shipping plaintext.
		switch len(cfg.SecretKey) {
		case 16, 24, 32:
		default:
			return nil, fmt.Errorf("gossip setup: SecretKey must be 16, 24, or 32 bytes (got %d)", len(cfg.SecretKey))
		}
		mlCfg.SecretKey = cfg.SecretKey
		// Force-encrypt outgoing traffic and reject unencrypted inbound packets;
		// this is what actually closes the "anyone-on-the-wire can join" gap.
		mlCfg.GossipVerifyIncoming = true
		mlCfg.GossipVerifyOutgoing = true
	}
	// memberlist defaults log to stderr at info level — silence it; we already
	// log meaningful state changes ourselves.
	mlCfg.Logger = nil

	ml, err := memberlist.Create(mlCfg)
	if err != nil {
		return nil, fmt.Errorf("gossip setup: memberlist.Create: %w", err)
	}

	if len(cfg.BootstrapPeers) > 0 {
		joined, err := ml.Join(cfg.BootstrapPeers)
		if err != nil {
			_ = ml.Shutdown()
			return nil, fmt.Errorf("gossip setup: join %v: %w", cfg.BootstrapPeers, err)
		}
		logger.Info("cluster gossip joined peers", "joined", joined, "peers", cfg.BootstrapPeers)
	}

	interval := cfg.GossipInterval
	if interval <= 0 {
		interval = 5 * time.Second
	}
	refreshCtx, cancel := context.WithCancel(context.Background())
	gn := &gossipNode{
		ml:          ml,
		delegate:    delegate,
		stopRefresh: cancel,
		logger:      logger,
	}
	go gn.runRefreshLoop(refreshCtx, interval)
	return gn, nil
}

// runRefreshLoop periodically rebuilds the node-metadata blob and tells
// memberlist to re-disseminate it. Without the UpdateNode call, peers would
// see only the metadata observed at join time — power-of-two-choices
// placement would then score against frozen capacity snapshots and slowly
// pile load onto whichever nodes happened to look empty at gossip-join.
func (g *gossipNode) runRefreshLoop(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			g.delegate.refreshMeta()
			// UpdateNode triggers memberlist's NodeMeta callback and queues
			// the new blob for gossip dissemination. Bound the call so a
			// stalled gossip layer doesn't block the refresh ticker.
			if err := g.ml.UpdateNode(2 * time.Second); err != nil {
				g.logger.Warn("cluster: memberlist UpdateNode failed", "err", err)
			}
		}
	}
}

// members returns peer state, including self. Self's metadata is sourced from
// the local delegate (under its own mutex) rather than from the *memberlist.Node
// pointer returned by ml.Members(): that pointer aliases internal state whose
// Meta field is rewritten by memberlist.aliveNode every time our refresh loop
// calls UpdateNode, which races with members() reads. memberlist exposes no
// safe accessor for self's Meta, so we substitute self ourselves.
func (g *gossipNode) members() []Member {
	all := g.ml.Members()
	out := make([]Member, 0, len(all))
	for _, n := range all {
		if n.Name == g.delegate.nodeID {
			out = append(out, g.selfMember())
			continue
		}
		m := Member{NodeID: n.Name, Alive: n.State == memberlist.StateAlive}
		if n.Meta != nil {
			var meta nodeMeta
			if err := json.Unmarshal(n.Meta, &meta); err == nil {
				if meta.NodeID != "" {
					m.NodeID = meta.NodeID
				}
				m.APIURL = meta.APIURL
				m.RaftAddr = meta.RaftAddr
				m.InternalURL = meta.InternalURL
				m.Capacity = meta.Capacity
			}
		}
		out = append(out, m)
	}
	return out
}

// selfMember snapshots the local node's advertised state from the delegate.
// Always reports Alive=true — self can't observe itself dead, and any caller
// asking "are we still in the cluster" should be using a different signal
// (raft leadership / gossip peer count).
func (g *gossipNode) selfMember() Member {
	g.delegate.mu.RLock()
	meta := g.delegate.selfMeta
	g.delegate.mu.RUnlock()
	return Member{
		NodeID:      meta.NodeID,
		APIURL:      meta.APIURL,
		RaftAddr:    meta.RaftAddr,
		InternalURL: meta.InternalURL,
		Alive:       true,
		Capacity:    meta.Capacity,
	}
}

// peerByNodeID looks up a member's API URL by node ID. Returns "" if unknown.
func (g *gossipNode) peerAPIURL(nodeID string) string {
	for _, m := range g.members() {
		if m.NodeID == nodeID {
			return m.APIURL
		}
	}
	return ""
}

// peerInternalURL returns the gossiped cluster-internal mTLS endpoint for
// nodeID, or "" if the peer hasn't advertised one (it's running without
// SB_CLUSTER_TLS_DIR). Callers fall back to peerAPIURL + PAT-only auth.
func (g *gossipNode) peerInternalURL(nodeID string) string {
	for _, m := range g.members() {
		if m.NodeID == nodeID {
			return m.InternalURL
		}
	}
	return ""
}

func (g *gossipNode) Close() error {
	if g.stopRefresh != nil {
		g.stopRefresh()
	}
	if g.ml != nil {
		// Best-effort graceful leave; bound the wait so Close doesn't hang
		// forever if peers are unreachable.
		_ = g.ml.Leave(2 * time.Second)
		return g.ml.Shutdown()
	}
	return nil
}

func splitHostPort(addr string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, fmt.Errorf("invalid port %q: %w", portStr, err)
	}
	return host, port, nil
}
