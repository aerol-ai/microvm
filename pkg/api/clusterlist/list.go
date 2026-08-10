// Package clusterlist aggregates sandbox list reads across cluster owners.
// Used by /v1/sandboxes and the Daytona/E2B facades so enterprise topologies
// (thousands of workers) do not fan out to every alive peer.
package clusterlist

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

const (
	// MaxConcurrentPeerReads bounds in-flight peer GETs during a list merge.
	MaxConcurrentPeerReads = 64
	// PeerTimeout is the per-peer HTTP budget; slow peers must not stall forever.
	PeerTimeout = 5 * time.Second
)

// Options controls cluster-wide list fan-out.
type Options struct {
	// OwnerRef, when non-empty, restricts placement-driven peer selection to
	// sandboxes owned by that tenant. Empty means operator / unscoped.
	OwnerRef string
	// AuthHeader is forwarded to peers (Authorization).
	AuthHeader string
	// RawQuery is the original query string (tag filters, etc.).
	RawQuery string
	// Path is the peer list path (e.g. "/v1/sandboxes").
	Path string
	// ForwardedHeaderName/Value mark the request as already forwarded so peers
	// serve local-only rows and do not re-fan out.
	ForwardedHeaderName  string
	ForwardedHeaderValue string
	// Local is the calling node's local list result (may be nil on error).
	Local []*models.Sandbox
	// Logger receives peer failures; may be nil.
	Warn func(msg string, peer string, err error)
}

// SelectPeers returns alive owner-capable peers to query. When the live owner
// set is large, peers are derived from placement owners (optionally filtered
// by OwnerRef) so a 2k-node fleet does not imply a 2k-way fan-out for a
// tenant with a handful of sandboxes.
func SelectPeers(c cluster.Client, ownerRef string) []cluster.Member {
	if c == nil {
		return nil
	}
	selfID := c.SelfNodeID()
	alive := make([]cluster.Member, 0)
	byID := make(map[string]cluster.Member)
	for _, m := range c.Members() {
		if !m.Alive || m.NodeID == "" || m.NodeID == selfID || m.APIURL == "" {
			continue
		}
		if !cluster.CanOwnSandboxRole(m.Role) {
			continue
		}
		alive = append(alive, m)
		byID[m.NodeID] = m
	}
	if len(alive) == 0 {
		return nil
	}

	ownerRef = strings.TrimSpace(ownerRef)
	placements := c.Placements()
	if len(placements) == 0 {
		// Placement view not ready. Small clusters may still fan out to all
		// alive owners; enterprise-scale membership must not all-peer fan out.
		const smallClusterPeerCap = 256
		if len(alive) > smallClusterPeerCap {
			return nil
		}
		return alive
	}

	want := make(map[string]struct{})
	for _, p := range placements {
		if p.OwnerNodeID == "" || p.OwnerNodeID == selfID {
			continue
		}
		if ownerRef != "" && strings.TrimSpace(p.OwnerRef) != "" && p.OwnerRef != ownerRef {
			continue
		}
		if ownerRef != "" && strings.TrimSpace(p.OwnerRef) == "" {
			// Unscoped placement rows: still include so we do not hide
			// sandboxes that predate OwnerRef replication.
			want[p.OwnerNodeID] = struct{}{}
			continue
		}
		want[p.OwnerNodeID] = struct{}{}
	}
	if len(want) == 0 {
		return nil
	}
	out := make([]cluster.Member, 0, len(want))
	for id := range want {
		if m, ok := byID[id]; ok {
			out = append(out, m)
		}
	}
	return out
}

// OwnerRefFromContext returns the tenant OwnerRef for non-operator callers.
func OwnerRefFromContext(ctx context.Context) string {
	access, ok := controlplane.AccessFromContext(ctx)
	if !ok || access.Operator {
		return ""
	}
	return strings.TrimSpace(access.Identity.OwnerRef)
}

// Merge fetches peer lists and dedupes against Local (local wins).
func Merge(ctx context.Context, peers []cluster.Member, opts Options) []*models.Sandbox {
	merged := make([]*models.Sandbox, 0, len(opts.Local))
	seen := make(map[string]struct{}, len(opts.Local))
	for _, sb := range opts.Local {
		if sb == nil {
			continue
		}
		seen[sb.ID] = struct{}{}
		merged = append(merged, sb)
	}
	if len(peers) == 0 {
		return merged
	}

	type peerResult struct {
		nodeID    string
		sandboxes []*models.Sandbox
		err       error
	}
	results := make(chan peerResult, len(peers))
	path := opts.Path
	if path == "" {
		path = "/v1/sandboxes"
	}
	fwdName := opts.ForwardedHeaderName
	if fwdName == "" {
		fwdName = "X-Cluster-Forwarded"
	}
	fwdVal := opts.ForwardedHeaderValue
	if fwdVal == "" {
		fwdVal = "1"
	}
	httpClient := &http.Client{Timeout: PeerTimeout}
	sem := make(chan struct{}, MaxConcurrentPeerReads)
	for _, peer := range peers {
		peer := peer
		go func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			endpoint := strings.TrimRight(peer.APIURL, "/") + path
			if opts.RawQuery != "" {
				endpoint += "?" + opts.RawQuery
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
			if err != nil {
				results <- peerResult{nodeID: peer.NodeID, err: err}
				return
			}
			req.Header.Set(fwdName, fwdVal)
			if opts.AuthHeader != "" {
				req.Header.Set("Authorization", opts.AuthHeader)
			}
			resp, err := httpClient.Do(req)
			if err != nil {
				results <- peerResult{nodeID: peer.NodeID, err: err}
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
				results <- peerResult{nodeID: peer.NodeID, err: errors.New(strings.TrimSpace(string(body)))}
				return
			}
			var sbs []*models.Sandbox
			if err := json.NewDecoder(resp.Body).Decode(&sbs); err != nil {
				results <- peerResult{nodeID: peer.NodeID, err: err}
				return
			}
			results <- peerResult{nodeID: peer.NodeID, sandboxes: sbs}
		}()
	}

	for i := 0; i < len(peers); i++ {
		res := <-results
		if res.err != nil {
			if opts.Warn != nil {
				opts.Warn("cluster list: peer query failed", res.nodeID, res.err)
			}
			continue
		}
		for _, sb := range res.sandboxes {
			if sb == nil {
				continue
			}
			if _, dup := seen[sb.ID]; dup {
				continue
			}
			seen[sb.ID] = struct{}{}
			merged = append(merged, sb)
		}
	}
	return merged
}
