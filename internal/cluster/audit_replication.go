package cluster

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/auditlog"
)

const auditPeerFetchTimeout = 5 * time.Second

// AuditEventDTO is the wire shape of one secret-audit event on the peer
// internal endpoint. Kept in cluster to avoid an import cycle with service.
type AuditEventDTO = auditlog.Event

// AuditPeerPage is the JSON body returned by the internal audit endpoint.
type AuditPeerPage struct {
	Events     []AuditEventDTO `json:"events"`
	NextCursor string          `json:"next_cursor,omitempty"`
}

// AuditPeerFetcher is the narrow seam Service uses for audit fan-out so tests
// can inject a fake without a full Cluster.
type AuditPeerFetcher interface {
	FetchSandboxAuditFromPeer(ctx context.Context, nodeID, sandboxID string, limit int, cursor, kind, incarnationID string) (AuditPeerPage, error)
}

// FetchSandboxAuditFromPeer GETs a peer's local audit slice for sandboxID.
func (c *Cluster) FetchSandboxAuditFromPeer(ctx context.Context, nodeID, sandboxID string, limit int, cursor, kind, incarnationID string) (AuditPeerPage, error) {
	if c == nil || c.currentInternalClient() == nil || c.gossip == nil {
		return AuditPeerPage{}, fmt.Errorf("cluster: audit fetch unavailable")
	}
	m, ok := c.gossip.lookupMember(strings.TrimSpace(nodeID))
	if !ok || !m.Alive {
		return AuditPeerPage{}, fmt.Errorf("cluster: audit peer %q is unavailable", nodeID)
	}
	client, endpoint, err := c.PeerDialMember(m)
	if err != nil {
		return AuditPeerPage{}, err
	}
	return fetchSandboxAuditFromPeer(ctx, client, c.patToken, c.nodeID, endpoint, sandboxID, limit, cursor, kind, incarnationID)
}

// FetchSandboxAuditFromPeer GETs a peer's local audit slice (worker agent).
func (a *Agent) FetchSandboxAuditFromPeer(ctx context.Context, nodeID, sandboxID string, limit int, cursor, kind, incarnationID string) (AuditPeerPage, error) {
	if a == nil || a.internalClient == nil || a.gossip == nil {
		return AuditPeerPage{}, fmt.Errorf("cluster: audit fetch unavailable")
	}
	m, ok := a.gossip.lookupMember(strings.TrimSpace(nodeID))
	if !ok || !m.Alive {
		return AuditPeerPage{}, fmt.Errorf("cluster: audit peer %q is unavailable", nodeID)
	}
	client, endpoint, err := a.PeerDialMember(m)
	if err != nil {
		return AuditPeerPage{}, err
	}
	return fetchSandboxAuditFromPeer(ctx, client, a.patToken, a.nodeID, endpoint, sandboxID, limit, cursor, kind, incarnationID)
}

// FetchSandboxAuditFromPeer on Noop always fails — single-node mode has no peers.
func (n *Noop) FetchSandboxAuditFromPeer(context.Context, string, string, int, string, string, string) (AuditPeerPage, error) {
	return AuditPeerPage{}, fmt.Errorf("cluster: no peer audit fetch in single-node mode")
}

func fetchSandboxAuditFromPeer(ctx context.Context, client *http.Client, pat, selfID, apiURL, sandboxID string, limit int, cursor, kind, incarnationID string) (AuditPeerPage, error) {
	if client == nil {
		return AuditPeerPage{}, fmt.Errorf("cluster: nil http client")
	}
	sandboxID = strings.TrimSpace(sandboxID)
	if sandboxID == "" {
		return AuditPeerPage{}, fmt.Errorf("cluster: empty sandbox id")
	}
	base := strings.TrimRight(strings.TrimSpace(apiURL), "/")
	if base == "" {
		return AuditPeerPage{}, fmt.Errorf("cluster: empty peer api url")
	}
	q := url.Values{}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	if strings.TrimSpace(cursor) != "" {
		q.Set("cursor", cursor)
	}
	if strings.TrimSpace(kind) != "" {
		q.Set("kind", strings.TrimSpace(kind))
	}
	if strings.TrimSpace(incarnationID) != "" {
		q.Set("incarnation_id", strings.TrimSpace(incarnationID))
	}
	endpoint := base + PublicInternalSandboxAuditPath + url.PathEscape(sandboxID) + "/audit"
	if enc := q.Encode(); enc != "" {
		endpoint += "?" + enc
	}
	reqCtx := ctx
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		reqCtx, cancel = context.WithTimeout(ctx, auditPeerFetchTimeout)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return AuditPeerPage{}, err
	}
	SetPeerNodeIDHeader(req, selfID)
	if pat != "" {
		req.Header.Set("Authorization", "Bearer "+pat)
	}
	resp, err := client.Do(req)
	if err != nil {
		return AuditPeerPage{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return AuditPeerPage{}, fmt.Errorf("peer %s returned %d: %s", endpoint, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var page AuditPeerPage
	if len(body) == 0 {
		return page, nil
	}
	if err := json.Unmarshal(body, &page); err != nil {
		return AuditPeerPage{}, fmt.Errorf("peer audit decode: %w", err)
	}
	return page, nil
}
