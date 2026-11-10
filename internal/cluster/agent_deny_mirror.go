package cluster

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// A worker or ingress node's copy of the deny set (fsm_node_deny.go) and of
// the revoked cert keys (fsm_join.go). It holds no Raft state, so it polls
// the server tier the way it keeps its API token copy: GET
// denied-nodes?since=V every denyMirrorInterval, 304 while nothing changed.
// A reply replaces the copy only when its version is newer than the one
// held, so a server that lags another never hands back an older set; a
// newer one may drop an ID, which is a fresh join replacing its deny
// record. Lookups are map reads; nothing on the request path waits on a
// poll.
//
// Until the first poll lands the set is empty, so a worker that boots while
// a deleted node is still running may accept that node's calls for one poll
// interval. Every server refuses it from its FSM in that time, so the node
// can neither apply a Raft write nor reach the control plane.

// denyMirrorInterval is how often a worker polls. A delete is an operator
// action; 5 s matches the token mirror's sync interval.
const denyMirrorInterval = 5 * time.Second

type agentDenyMirror struct {
	mu      sync.RWMutex
	set     map[string]bool
	revoked map[string]int64 // cert key hash -> expires (unix nano)
	// cutoffs are the by-identity tombstones (RevokedKey.byNodeID), by
	// node ID: every cert for the ID issued before the delete is refused.
	cutoffs map[string]certCutoff
	version uint64
}

// oldCert reports whether a cert for nodeID issued at notBefore predates
// the node's delete (a live by-identity tombstone).
func (m *agentDenyMirror) oldCert(nodeID string, notBefore time.Time, now int64) bool {
	if m == nil || nodeID == "" {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.cutoffs[nodeID]
	return ok && c.refuses(notBefore, now)
}

// revokedKey reports whether keyHash is a live tombstone.
func (m *agentDenyMirror) revokedKey(keyHash string, now int64) bool {
	if m == nil || keyHash == "" {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	exp, ok := m.revoked[keyHash]
	return ok && now < exp
}

func (m *agentDenyMirror) has(nodeID string) bool {
	if m == nil || nodeID == "" {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.set[nodeID]
}

func (m *agentDenyMirror) cursor() uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.version
}

// merge takes resp when it is newer and returns the IDs it added.
func (m *agentDenyMirror) merge(resp DeniedNodesResponse) []string {
	return m.mergeAt(resp, time.Now().UnixNano())
}

// mergeAt is merge at now: tombstones already past their life are not
// kept, so the copy holds only what can still refuse a cert (J10).
func (m *agentDenyMirror) mergeAt(resp DeniedNodesResponse, now int64) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if resp.Version <= m.version {
		return nil
	}
	set := make(map[string]bool, len(resp.Nodes))
	var added []string
	for _, rec := range resp.Nodes {
		if rec.NodeID == "" || set[rec.NodeID] {
			continue
		}
		set[rec.NodeID] = true
		if !m.set[rec.NodeID] {
			added = append(added, rec.NodeID)
		}
	}
	revoked := make(map[string]int64, len(resp.RevokedKeys))
	cutoffs := map[string]certCutoff{}
	for _, k := range resp.RevokedKeys {
		switch {
		case k.KeyHash == "" || now >= k.ExpiresUnixNano:
		case k.byNodeID():
			cutoffs[k.NodeID] = certCutoff{before: k.IssuedBeforeUnixNano, expires: k.ExpiresUnixNano}
		default:
			revoked[k.KeyHash] = k.ExpiresUnixNano
		}
	}
	m.set, m.revoked, m.cutoffs, m.version = set, revoked, cutoffs, resp.Version
	return added
}

// IsNodeDenied reports whether nodeID was deleted, from the mirror.
func (a *Agent) IsNodeDenied(nodeID string) bool {
	if a == nil {
		return false
	}
	return a.deny.has(nodeID)
}

// refuseDeniedPeer is the internal listener's deny check on a worker.
func (a *Agent) refuseDeniedPeer(nodeID string) bool {
	if !a.deny.has(nodeID) {
		return false
	}
	a.denyHits.hit(denyHitPeer, nodeID)
	return true
}

// syncDenied runs one poll. A server on a build without the route answers
// 404: it cannot hold a record either (the write gate), so that is "none".
func (a *Agent) syncDenied(ctx context.Context) error {
	path := PublicInternalDeniedNodesPath + "?since=" + strconv.FormatUint(a.deny.cursor(), 10)
	body, err := a.fetchControlPlaneRaw(ctx, path)
	if isStatus(err, http.StatusNotModified) || isStatus(err, http.StatusNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	var resp DeniedNodesResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("cluster: decode denied nodes: %w", err)
	}
	added := a.deny.merge(resp)
	if len(added) == 0 {
		return nil
	}
	for _, id := range added {
		a.invalidatePeerClient(id)
	}
	// Drop them from the member view now rather than at the next refresh.
	a.gossip.applyDenySet()
	if a.logger != nil {
		a.logger.Info("cluster agent: deny set updated", "added", added, "version", resp.Version)
	}
	return nil
}

// startDenyMirror polls until Close.
func (a *Agent) startDenyMirror(every time.Duration) {
	ctx, cancel := context.WithCancel(context.Background())
	a.denyMirrorStop = cancel
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			if err := a.syncDenied(ctx); err != nil && ctx.Err() == nil && a.logger != nil {
				a.logger.Debug("cluster agent: deny set poll failed; keeping the current copy", "err", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
}
