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

// nodeMeta is the per-node identity broadcast through memberlist. memberlist's
// MetaMaxSize is a hardcoded 512-byte constant (not configurable on Config),
// so this struct must stay small. Capacity used to live here but pushed the
// encoded blob past 512 bytes, which triggered NodeMeta()'s fallback path and
// stripped RaftAddr from peers' view — breaking voter auto-join entirely
// (see voter_autojoin.go which gates on peerRaftAddr != ""). Capacity now
// travels as authenticated /v1/capacity heartbeats into capacityLeaseCache;
// placement rejects worker candidates without a fresh heartbeat.
type nodeMeta struct {
	NodeID string `json:"node_id"`
	// NodeName is the operator-friendly label (SB_NODE_NAME). Empty for
	// peers running pre-NodeName builds; consumers fall back to NodeID for
	// display.
	NodeName      string `json:"node_name,omitempty"`
	APIURL        string `json:"api_url"`
	DataPlaneHost string `json:"data_plane_host,omitempty"`
	RaftAddr      string `json:"raft_addr,omitempty"`
	// InternalURL is this node's cluster-internal mTLS endpoint (e.g.
	// https://10.0.0.5:7002). Set only when the node was started with cluster
	// TLS material — peers receiving an empty value know to fall back to the
	// public APIURL with PAT-only auth.
	InternalURL string `json:"internal_url,omitempty"`
	// Role is the gossiped SB_NODE_ROLE — the leader's voter-promotion code
	// uses this to decline to AddVoter a peer that announced itself as
	// worker/ingress. Empty (older builds) is treated as "mixed" to preserve
	// rolling-upgrade compatibility.
	Role string `json:"role,omitempty"`
	// PublicHost is the operator-configured public address users point DNS at
	// — SB_INGRESS_ADVERTISE_HOST in cluster mode, SB_PUBLIC_HOST single-node
	// (see config.EffectivePublicHost). Aggregated across live ingress nodes
	// by Cluster.IngressTargets so the DNS-helper API can return the actual
	// CNAME / A targets without separate operator config. Empty for peers
	// running pre-PublicHost builds or with no public host set (IP-mode
	// deployments where custom domains are disabled anyway).
	PublicHost string `json:"public_host,omitempty"`
}

// gossipDelegate implements memberlist.Delegate. Its job is to publish this
// node's identity metadata and accept others'.
type gossipDelegate struct {
	mu            sync.RWMutex
	selfMeta      nodeMeta
	encoded       []byte
	admitter      *capacity.Admitter
	nodeID        string
	nodeName      string
	apiURL        string
	dataPlaneHost string
	raftAddr      string
	internalURL   string
	role          string
	publicHost    string
}

func newGossipDelegate(nodeID, nodeName, apiURL, dataPlaneHost, raftAddr, internalURL, role, publicHost string, admitter *capacity.Admitter) *gossipDelegate {
	d := &gossipDelegate{
		admitter:      admitter,
		nodeID:        nodeID,
		nodeName:      nodeName,
		apiURL:        apiURL,
		dataPlaneHost: dataPlaneHost,
		raftAddr:      raftAddr,
		internalURL:   internalURL,
		role:          role,
		publicHost:    publicHost,
	}
	d.refreshMeta()
	return d
}

// refreshMeta rebuilds the encoded metadata blob. memberlist's NodeMeta()
// must return a stable byte slice, so we double-buffer.
func (d *gossipDelegate) refreshMeta() {
	meta := nodeMeta{
		NodeID: d.nodeID, NodeName: d.nodeName, APIURL: d.apiURL, DataPlaneHost: d.dataPlaneHost,
		RaftAddr: d.raftAddr, InternalURL: d.internalURL, Role: d.role, PublicHost: d.publicHost,
	}
	enc, err := json.Marshal(meta)
	if err != nil {
		// nodeMeta has only string fields; json.Marshal cannot fail. Keep the
		// minimal fallback for paranoia so peers still see us if it ever does.
		minimal, _ := json.Marshal(nodeMeta{NodeID: d.nodeID, APIURL: d.apiURL, DataPlaneHost: d.dataPlaneHost})
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
	if limit <= 0 {
		return nil
	}
	if len(d.encoded) > limit {
		// Truncated metadata is worse than minimal metadata because peers
		// cannot decode partial JSON. Drop display/convenience fields first,
		// but preserve raft join identity as long as it fits.
		fallbacks := []nodeMeta{
			// PublicHost dropped first — DNS-helper feature degrades cleanly
			// (the node just doesn't show up as a target) whereas
			// raft/identity loss breaks voter join and cross-node routing.
			{NodeID: d.nodeID, APIURL: d.apiURL, DataPlaneHost: d.dataPlaneHost, RaftAddr: d.raftAddr, InternalURL: d.internalURL, Role: d.role},
			{NodeID: d.nodeID, APIURL: d.apiURL, DataPlaneHost: d.dataPlaneHost, RaftAddr: d.raftAddr, Role: d.role},
			{NodeID: d.nodeID, APIURL: d.apiURL, RaftAddr: d.raftAddr, Role: d.role},
			{NodeID: d.nodeID, RaftAddr: d.raftAddr, Role: d.role},
			{NodeID: d.nodeID, RaftAddr: d.raftAddr},
			{NodeID: d.nodeID},
		}
		for _, meta := range fallbacks {
			fallback, _ := json.Marshal(meta)
			if len(fallback) <= limit {
				return fallback
			}
		}
		return []byte("{}")
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
	ml                 *memberlist.Memberlist
	delegate           *gossipDelegate
	memberIndex        *gossipMemberIndex
	memberIndexMu      sync.RWMutex
	stopRefresh        context.CancelFunc
	logger             *slog.Logger
	bootstrapPeers     []string
	joinBootstrapPeers func([]string) (int, error)
}

type gossipMemberIndex struct {
	mu      sync.RWMutex
	members map[string]Member
	seen    map[string]int64
}

func newGossipMemberIndex() *gossipMemberIndex {
	return &gossipMemberIndex{members: make(map[string]Member), seen: make(map[string]int64)}
}

func (i *gossipMemberIndex) upsert(m Member) {
	if i == nil || m.NodeID == "" {
		return
	}
	now := time.Now().UnixNano()
	i.mu.Lock()
	if i.seen == nil {
		i.seen = make(map[string]int64)
	}
	if m.Alive {
		i.seen[m.NodeID] = now
	}
	i.members[m.NodeID] = m
	i.recordMetricsLocked(now)
	i.mu.Unlock()
}

func (i *gossipMemberIndex) replace(members []Member) {
	if i == nil {
		return
	}
	now := time.Now().UnixNano()
	next := make(map[string]Member, len(members))
	for _, m := range members {
		if m.NodeID == "" {
			continue
		}
		next[m.NodeID] = m
	}
	i.mu.Lock()
	if i.seen == nil {
		i.seen = make(map[string]int64)
	}
	for _, m := range next {
		if m.Alive {
			i.seen[m.NodeID] = now
		}
	}
	for id := range i.seen {
		if _, ok := next[id]; !ok {
			delete(i.seen, id)
		}
	}
	i.recordLeaseLossesLocked(next)
	i.members = next
	i.recordMetricsLocked(now)
	i.mu.Unlock()
}

func (i *gossipMemberIndex) snapshot() []Member {
	if i == nil {
		return nil
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	out := make([]Member, 0, len(i.members))
	for _, m := range i.members {
		out = append(out, m)
	}
	return out
}

func (i *gossipMemberIndex) recordLeaseLossesLocked(next map[string]Member) {
	if i == nil {
		return
	}
	for id, prev := range i.members {
		if !prev.Alive || !CanOwnSandboxRole(prev.Role) {
			continue
		}
		if curr, ok := next[id]; !ok || !curr.Alive {
			workerLeaseLostTotal.Add(1)
		}
	}
}

func (i *gossipMemberIndex) recordMetricsLocked(now int64) {
	if i == nil {
		return
	}
	total := len(i.members)
	alive := 0
	workerTotal := 0
	workerAlive := 0
	var maxAge int64
	for id, m := range i.members {
		if m.Alive {
			alive++
		}
		if !CanOwnSandboxRole(m.Role) {
			continue
		}
		workerTotal++
		if m.Alive {
			workerAlive++
		}
		if seen := i.seen[id]; seen > 0 {
			age := now - seen
			if age > maxAge {
				maxAge = age
			}
		}
	}
	gossipMembersTotal.Set(int64(total))
	gossipMembersAlive.Set(int64(alive))
	workerLeasesTotal.Set(int64(workerTotal))
	workerLeasesAlive.Set(int64(workerAlive))
	workerLeaseMaxAgeNanos.Set(maxAge)
	workerLeaseRefreshNanos.Set(now)
}

type indexedEventDelegate struct {
	index  *gossipMemberIndex
	logger *slog.Logger
	next   memberlist.EventDelegate
}

func (d *indexedEventDelegate) NotifyJoin(n *memberlist.Node) {
	m := memberFromMemberlistNode(n)
	if d.index != nil && n != nil {
		d.index.upsert(m)
	}
	if d.logger != nil && n != nil {
		d.logger.Info("cluster gossip member joined",
			"node_id", m.NodeID,
			"role", m.Role,
			"alive", m.Alive,
			"api_url", m.APIURL,
			"internal_url", m.InternalURL,
			"raft_addr", m.RaftAddr,
			"memberlist_name", n.Name,
			"memberlist_addr", n.Address(),
		)
	}
	if d.next != nil {
		d.next.NotifyJoin(n)
	}
}

func (d *indexedEventDelegate) NotifyLeave(n *memberlist.Node) {
	m := memberFromMemberlistNode(n)
	if d.index != nil && n != nil {
		m.Alive = false
		d.index.upsert(m)
	}
	if d.logger != nil && n != nil {
		d.logger.Warn("cluster gossip member left",
			"node_id", m.NodeID,
			"role", m.Role,
			"api_url", m.APIURL,
			"internal_url", m.InternalURL,
			"raft_addr", m.RaftAddr,
			"memberlist_name", n.Name,
			"memberlist_addr", n.Address(),
		)
	}
	if d.next != nil {
		d.next.NotifyLeave(n)
	}
}

func (d *indexedEventDelegate) NotifyUpdate(n *memberlist.Node) {
	m := memberFromMemberlistNode(n)
	if d.index != nil && n != nil {
		d.index.upsert(m)
	}
	if d.logger != nil && n != nil {
		d.logger.Info("cluster gossip member updated",
			"node_id", m.NodeID,
			"role", m.Role,
			"alive", m.Alive,
			"api_url", m.APIURL,
			"internal_url", m.InternalURL,
			"raft_addr", m.RaftAddr,
			"memberlist_name", n.Name,
			"memberlist_addr", n.Address(),
		)
	}
	if d.next != nil {
		d.next.NotifyUpdate(n)
	}
}

type gossipSetupConfig struct {
	NodeID        string
	BindAddr      string
	AdvertiseAddr string
	APIURL        string
	DataPlaneHost string
	RaftAddr      string
	InternalURL   string
	Role          string
	// PublicHost is the operator-configured public ingress address
	// (config.EffectivePublicHost). Used by the DNS-helper API to tell
	// users what to point their custom-domain DNS records at. Empty
	// values are dropped from aggregation — they only happen in IP-mode
	// deployments where custom domains are disabled anyway.
	PublicHost string
	// NodeName is the operator-friendly display label (SB_NODE_NAME). Empty
	// is acceptable; the delegate ships an empty value and dashboard
	// consumers fall back to NodeID.
	NodeName       string
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

	delegate := newGossipDelegate(cfg.NodeID, cfg.NodeName, cfg.APIURL, cfg.DataPlaneHost, cfg.RaftAddr, cfg.InternalURL, cfg.Role, cfg.PublicHost, admitter)
	memberIndex := newGossipMemberIndex()
	mlCfg.Delegate = delegate
	mlCfg.Events = &indexedEventDelegate{index: memberIndex, logger: logger, next: cfg.Events}
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

	if logger != nil {
		logger.Info("cluster gossip starting",
			"node_id", cfg.NodeID,
			"role", cfg.Role,
			"bind_addr", cfg.BindAddr,
			"advertise_addr", cfg.AdvertiseAddr,
			"api_url", cfg.APIURL,
			"data_plane_host", cfg.DataPlaneHost,
			"raft_addr", cfg.RaftAddr,
			"internal_url", cfg.InternalURL,
			"public_host", cfg.PublicHost,
			"bootstrap_peers", cfg.BootstrapPeers,
			"encrypted", len(cfg.SecretKey) > 0,
			"node_meta_bytes", len(delegate.NodeMeta(512)),
		)
	}

	ml, err := memberlist.Create(mlCfg)
	if err != nil {
		return nil, fmt.Errorf("gossip setup: memberlist.Create: %w", err)
	}
	if logger != nil {
		logger.Info("cluster gossip listening",
			"node_id", cfg.NodeID,
			"memberlist_addr", ml.LocalNode().Address(),
			"bootstrap_peers", cfg.BootstrapPeers,
		)
	}

	if len(cfg.BootstrapPeers) > 0 {
		joined, err := ml.Join(cfg.BootstrapPeers)
		if err != nil {
			if logger != nil {
				logger.Warn("cluster gossip initial bootstrap join failed; will retry in background",
					"peers", cfg.BootstrapPeers,
					"error", err,
				)
			}
		} else if logger != nil {
			logger.Info("cluster gossip joined peers", "joined", joined, "peers", cfg.BootstrapPeers)
		}
	} else if logger != nil {
		logger.Info("cluster gossip started without bootstrap peers", "node_id", cfg.NodeID)
	}

	interval := cfg.GossipInterval
	if interval <= 0 {
		interval = 5 * time.Second
	}
	refreshCtx, cancel := context.WithCancel(context.Background())
	gn := &gossipNode{
		ml:                 ml,
		delegate:           delegate,
		memberIndex:        memberIndex,
		stopRefresh:        cancel,
		logger:             logger,
		bootstrapPeers:     append([]string(nil), cfg.BootstrapPeers...),
		joinBootstrapPeers: ml.Join,
	}
	gn.refreshMemberIndex()
	go gn.runRefreshLoop(refreshCtx, interval)
	return gn, nil
}

// runRefreshLoop periodically rebuilds the cached member index from
// memberlist's view so reads served from the index don't go stale. Node
// metadata itself is now static (identity-only — see nodeMeta), so we no
// longer call refreshMeta()+UpdateNode() here; the original purpose of that
// pair was to disseminate live capacity, which is now fetched per-peer via
// authenticated /v1/capacity heartbeats instead.
func (g *gossipNode) runRefreshLoop(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			g.refreshMemberIndex()
			g.maybeRejoinBootstrapPeers(g.memberlistNodes())
		}
	}
}

func (g *gossipNode) memberlistNodes() []*memberlist.Node {
	if g == nil || g.ml == nil {
		return nil
	}
	return g.ml.Members()
}

func (g *gossipNode) maybeRejoinBootstrapPeers(nodes []*memberlist.Node) {
	if g == nil || len(g.bootstrapPeers) == 0 || g.joinBootstrapPeers == nil {
		return
	}
	selfNodeID := ""
	if g.delegate != nil {
		selfNodeID = g.delegate.nodeID
	}
	if hasLiveControlPlaneMember(nodes, selfNodeID) {
		return
	}
	joined, err := g.joinBootstrapPeers(g.bootstrapPeers)
	if err != nil {
		if g.logger != nil {
			g.logger.Warn("cluster gossip bootstrap rejoin failed", "peers", g.bootstrapPeers, "error", err)
		}
		return
	}
	if joined > 0 && g.logger != nil {
		g.logger.Info("cluster gossip bootstrap rejoined peers", "joined", joined, "peers", g.bootstrapPeers)
	}
}

func hasLiveControlPlaneMember(nodes []*memberlist.Node, selfNodeID string) bool {
	if len(nodes) == 0 {
		return false
	}
	for _, n := range nodes {
		if n == nil || n.State != memberlist.StateAlive {
			continue
		}
		m := memberFromMemberlistNode(n)
		if selfNodeID != "" && m.NodeID == selfNodeID {
			continue
		}
		if m.NodeID != "" && CanServeControlPlaneRole(m.Role) && (m.APIURL != "" || m.InternalURL != "") {
			return true
		}
	}
	return false
}

// members returns peer state, including self. Self's metadata is sourced from
// the local delegate (under its own mutex) rather than from the *memberlist.Node
// pointer returned by ml.Members(): that pointer aliases internal state whose
// Meta field is rewritten by memberlist.aliveNode every time our refresh loop
// calls UpdateNode, which races with members() reads. memberlist exposes no
// safe accessor for self's Meta, so we substitute self ourselves.
func (g *gossipNode) members() []Member {
	if index := g.currentMemberIndex(); index != nil {
		return index.snapshot()
	}
	return g.scanMembers()
}

func (g *gossipNode) refreshMemberIndex() {
	index := g.currentMemberIndex()
	if index == nil {
		return
	}
	index.replace(g.scanMembers())
}

func (g *gossipNode) currentMemberIndex() *gossipMemberIndex {
	if g == nil {
		return nil
	}
	g.memberIndexMu.RLock()
	defer g.memberIndexMu.RUnlock()
	return g.memberIndex
}

func (g *gossipNode) setMemberIndex(index *gossipMemberIndex) {
	if g == nil {
		return
	}
	g.memberIndexMu.Lock()
	g.memberIndex = index
	g.memberIndexMu.Unlock()
}

func (g *gossipNode) scanMembers() []Member {
	all := g.ml.Members()
	out := make([]Member, 0, len(all))
	for _, n := range all {
		if n.Name == g.delegate.nodeID {
			out = append(out, g.selfMember())
			continue
		}
		out = append(out, memberFromMemberlistNode(n))
	}
	return out
}

func memberFromMemberlistNode(n *memberlist.Node) Member {
	if n == nil {
		return Member{}
	}
	m := Member{NodeID: n.Name, Alive: n.State == memberlist.StateAlive}
	if n.Meta != nil {
		var meta nodeMeta
		if err := json.Unmarshal(n.Meta, &meta); err == nil {
			if meta.NodeID != "" {
				m.NodeID = meta.NodeID
			}
			m.NodeName = meta.NodeName
			m.APIURL = meta.APIURL
			m.DataPlaneHost = meta.DataPlaneHost
			m.RaftAddr = meta.RaftAddr
			m.InternalURL = meta.InternalURL
			m.Role = meta.Role
			m.PublicHost = meta.PublicHost
			// m.Capacity stays zero here — capacity no longer travels in
			// nodeMeta (see the type comment). Cluster.Members and
			// SelectPlacement overlay fresh capacity leases later.
		}
	}
	return m
}

// selfMember snapshots the local node's advertised state from the delegate.
// Always reports Alive=true — self can't observe itself dead, and any caller
// asking "are we still in the cluster" should be using a different signal
// (raft leadership / gossip peer count).
func (g *gossipNode) selfMember() Member {
	g.delegate.mu.RLock()
	meta := g.delegate.selfMeta
	admitter := g.delegate.admitter
	g.delegate.mu.RUnlock()
	// Self can still report a live capacity snapshot — it's just no longer
	// gossiped to peers. Pull straight from the local admitter.
	var snap capacity.Snapshot
	if admitter != nil {
		snap = admitter.Snapshot()
	}
	return Member{
		NodeID:        meta.NodeID,
		NodeName:      meta.NodeName,
		APIURL:        meta.APIURL,
		DataPlaneHost: meta.DataPlaneHost,
		RaftAddr:      meta.RaftAddr,
		InternalURL:   meta.InternalURL,
		Role:          meta.Role,
		PublicHost:    meta.PublicHost,
		Alive:         true,
		Capacity:      snap,
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

func (g *gossipNode) peerDataPlaneHost(nodeID string) string {
	for _, m := range g.members() {
		if m.NodeID == nodeID {
			return m.DataPlaneHost
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
