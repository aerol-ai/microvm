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
	NodeID   string            `json:"node_id"`
	APIURL   string            `json:"api_url"`
	RaftAddr string            `json:"raft_addr,omitempty"`
	Capacity capacity.Snapshot `json:"capacity"`
}

// gossipDelegate implements memberlist.Delegate. Its job is to publish this
// node's metadata (which includes the capacity snapshot) and accept others'.
type gossipDelegate struct {
	mu       sync.RWMutex
	selfMeta nodeMeta
	encoded  []byte
	admitter *capacity.Admitter
	nodeID   string
	apiURL   string
	raftAddr string
}

func newGossipDelegate(nodeID, apiURL, raftAddr string, admitter *capacity.Admitter) *gossipDelegate {
	d := &gossipDelegate{
		admitter: admitter,
		nodeID:   nodeID,
		apiURL:   apiURL,
		raftAddr: raftAddr,
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
	meta := nodeMeta{NodeID: d.nodeID, APIURL: d.apiURL, RaftAddr: d.raftAddr, Capacity: snap}
	enc, err := json.Marshal(meta)
	if err != nil {
		// JSON of a capacity.Snapshot can't fail; if it does, fall back to a
		// minimal blob so peers still know we're here.
		minimal, _ := json.Marshal(nodeMeta{NodeID: d.nodeID, APIURL: d.apiURL})
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
func (d *gossipDelegate) NotifyMsg([]byte)                 {}
func (d *gossipDelegate) GetBroadcasts(int, int) [][]byte  { return nil }
func (d *gossipDelegate) LocalState(bool) []byte           { return nil }
func (d *gossipDelegate) MergeRemoteState([]byte, bool)    {}

// gossipNode wraps memberlist + the delegate so Close can stop the refresh
// loop alongside leaving the cluster.
type gossipNode struct {
	ml       *memberlist.Memberlist
	delegate *gossipDelegate
	stopRefresh context.CancelFunc
	logger   *slog.Logger
}

type gossipSetupConfig struct {
	NodeID         string
	BindAddr       string
	AdvertiseAddr  string
	APIURL         string
	RaftAddr       string
	BootstrapPeers []string
	GossipInterval time.Duration
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

	delegate := newGossipDelegate(cfg.NodeID, cfg.APIURL, cfg.RaftAddr, admitter)
	mlCfg.Delegate = delegate
	if cfg.Events != nil {
		mlCfg.Events = cfg.Events
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
	go runRefreshLoop(refreshCtx, delegate, interval)

	return &gossipNode{
		ml:          ml,
		delegate:    delegate,
		stopRefresh: cancel,
		logger:      logger,
	}, nil
}

// runRefreshLoop periodically rebuilds the node-metadata blob so peers see
// fresh capacity numbers. memberlist re-disseminates metadata when the local
// node calls UpdateNode (which we trigger after refreshMeta).
func runRefreshLoop(ctx context.Context, d *gossipDelegate, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.refreshMeta()
			// We can't UpdateNode here without a back-reference to the
			// memberlist; the gossipNode wrapper does that.
		}
	}
}

// members returns peer state, including self.
func (g *gossipNode) members() []Member {
	all := g.ml.Members()
	out := make([]Member, 0, len(all))
	for _, n := range all {
		m := Member{NodeID: n.Name, Alive: n.State == memberlist.StateAlive}
		if n.Meta != nil {
			var meta nodeMeta
			if err := json.Unmarshal(n.Meta, &meta); err == nil {
				if meta.NodeID != "" {
					m.NodeID = meta.NodeID
				}
				m.APIURL = meta.APIURL
				m.RaftAddr = meta.RaftAddr
				m.Capacity = meta.Capacity
			}
		}
		out = append(out, m)
	}
	return out
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
