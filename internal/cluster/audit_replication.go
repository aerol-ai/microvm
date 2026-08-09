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
)

const auditPeerFetchTimeout = 5 * time.Second

// AuditEventDTO is the wire shape of one secret-audit event on the peer
// internal endpoint. Kept in cluster to avoid an import cycle with service.
type AuditEventDTO struct {
	Time          time.Time `json:"time"`
	Actor         string    `json:"actor,omitempty"`
	SandboxID     string    `json:"sandbox_id,omitempty"`
	Ref           string    `json:"ref,omitempty"`
	Result        string    `json:"result"`
	Reason        string    `json:"reason,omitempty"`
	CorrelationID string    `json:"correlation_id,omitempty"`
	EventID       string    `json:"event_id,omitempty"`
	NodeID        string    `json:"node_id,omitempty"`
	Kind          string    `json:"kind,omitempty"`
	Destination   string    `json:"destination,omitempty"`
	Network       string    `json:"network,omitempty"`
	BytesIn       int64     `json:"bytes_in,omitempty"`
	BytesOut      int64     `json:"bytes_out,omitempty"`
}

// AuditPeerPage is the JSON body returned by the internal audit endpoint.
type AuditPeerPage struct {
	Events     []AuditEventDTO `json:"events"`
	NextCursor string          `json:"next_cursor,omitempty"`
}

// AuditPeerFetcher is the narrow seam Service uses for audit fan-out so tests
// can inject a fake without a full Cluster.
type AuditPeerFetcher interface {
	FetchSandboxAuditFromPeer(ctx context.Context, apiURL, sandboxID string, limit int, cursor, kind string) (AuditPeerPage, error)
}

// SandboxMetaFetcher loads OwnerRef from a placement owner for ingress
// authorization of GET /sandboxes/{id}/audit (no local SQLite row).
type SandboxMetaFetcher interface {
	FetchSandboxOwnerRef(ctx context.Context, apiURL, sandboxID string) (ownerRef string, ok bool, err error)
}

// SandboxOwnerMeta is the peer-local owner-ref probe response.
type SandboxOwnerMeta struct {
	OwnerRef string `json:"owner_ref"`
	Exists   bool   `json:"exists"`
}

// FetchSandboxAuditFromPeer GETs a peer's local audit slice for sandboxID.
func (c *Cluster) FetchSandboxAuditFromPeer(ctx context.Context, apiURL, sandboxID string, limit int, cursor, kind string) (AuditPeerPage, error) {
	if c == nil || c.httpClient == nil {
		return AuditPeerPage{}, fmt.Errorf("cluster: audit fetch unavailable")
	}
	return fetchSandboxAuditFromPeer(ctx, c.httpClient, c.patToken, apiURL, sandboxID, limit, cursor, kind)
}

// FetchSandboxAuditFromPeer GETs a peer's local audit slice (worker agent).
func (a *Agent) FetchSandboxAuditFromPeer(ctx context.Context, apiURL, sandboxID string, limit int, cursor, kind string) (AuditPeerPage, error) {
	if a == nil || a.httpClient == nil {
		return AuditPeerPage{}, fmt.Errorf("cluster: audit fetch unavailable")
	}
	return fetchSandboxAuditFromPeer(ctx, a.httpClient, a.patToken, apiURL, sandboxID, limit, cursor, kind)
}

// FetchSandboxAuditFromPeer on Noop always fails — single-node mode has no peers.
func (n *Noop) FetchSandboxAuditFromPeer(context.Context, string, string, int, string, string) (AuditPeerPage, error) {
	return AuditPeerPage{}, fmt.Errorf("cluster: no peer audit fetch in single-node mode")
}

func fetchSandboxAuditFromPeer(ctx context.Context, client *http.Client, pat, apiURL, sandboxID string, limit int, cursor, kind string) (AuditPeerPage, error) {
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

// FetchSandboxOwnerRef GETs owner metadata from the placement owner.
func (c *Cluster) FetchSandboxOwnerRef(ctx context.Context, apiURL, sandboxID string) (string, bool, error) {
	if c == nil || c.httpClient == nil {
		return "", false, fmt.Errorf("cluster: sandbox meta fetch unavailable")
	}
	return fetchSandboxOwnerRef(ctx, c.httpClient, c.patToken, apiURL, sandboxID)
}

func (a *Agent) FetchSandboxOwnerRef(ctx context.Context, apiURL, sandboxID string) (string, bool, error) {
	if a == nil || a.httpClient == nil {
		return "", false, fmt.Errorf("cluster: sandbox meta fetch unavailable")
	}
	return fetchSandboxOwnerRef(ctx, a.httpClient, a.patToken, apiURL, sandboxID)
}

func (n *Noop) FetchSandboxOwnerRef(context.Context, string, string) (string, bool, error) {
	return "", false, fmt.Errorf("cluster: no sandbox meta fetch in single-node mode")
}

func fetchSandboxOwnerRef(ctx context.Context, client *http.Client, pat, apiURL, sandboxID string) (string, bool, error) {
	if client == nil {
		return "", false, fmt.Errorf("cluster: nil http client")
	}
	sandboxID = strings.TrimSpace(sandboxID)
	base := strings.TrimRight(strings.TrimSpace(apiURL), "/")
	if sandboxID == "" || base == "" {
		return "", false, fmt.Errorf("cluster: empty sandbox id or peer api url")
	}
	endpoint := base + PublicInternalSandboxAuditPath + url.PathEscape(sandboxID) + "/meta"
	reqCtx := ctx
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		reqCtx, cancel = context.WithTimeout(ctx, auditPeerFetchTimeout)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", false, err
	}
	if pat != "" {
		req.Header.Set("Authorization", "Bearer "+pat)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusNotFound {
		return "", false, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", false, fmt.Errorf("peer %s returned %d: %s", endpoint, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var meta SandboxOwnerMeta
	if err := json.Unmarshal(body, &meta); err != nil {
		return "", false, fmt.Errorf("peer sandbox meta decode: %w", err)
	}
	if !meta.Exists {
		return "", false, nil
	}
	return meta.OwnerRef, true, nil
}
