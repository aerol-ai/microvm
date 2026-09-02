// Package clusterlist aggregates sandbox list reads across cluster owners.
// Used by /v1/sandboxes and the Daytona/E2B facades so enterprise topologies
// (thousands of workers) do not fan out to every alive peer.
//
// Security: peer fetches require InternalURL + the caller's cert-pinned mTLS
// client. End-user Authorization is sent only over that mTLS channel. There is
// no public APIURL / fleet-PAT fallback (that path enabled cross-tenant
// enumeration on Daytona/E2B facades).
package clusterlist

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

const (
	// MaxConcurrentPeerReads bounds in-flight peer GETs during a list merge.
	MaxConcurrentPeerReads = 32
	// PeerTimeout is the per-peer HTTP budget; slow peers must not stall forever.
	PeerTimeout = 5 * time.Second
	// MergeTimeout caps the entire list merge across all peer waves.
	MergeTimeout = 5 * time.Second
	// DefaultPageLimit caps how many placement rows one list request hydrates.
	DefaultPageLimit = 100
	// MaxPageLimit is the hard ceiling for limit=.
	MaxPageLimit = 500
	// Coverage header names keep the /v1/sandboxes body a bare array (SDK wire
	// compat) while making partial results observable.
	HeaderPartial        = "X-Cluster-List-Partial"
	HeaderMissing        = "X-Cluster-List-Missing"
	HeaderPlacementReady = "X-Cluster-List-Placement-Ready"
	HeaderNextPageToken  = "X-Cluster-List-Next-Page-Token"
	HeaderAnswered       = "X-Cluster-List-Answered"
)

// Coverage reports which peers contributed to a merged list. Clients must treat
// Partial=true (or PlacementViewReady=false) as incomplete.
type Coverage struct {
	Answered           []string `json:"answered"`
	Missing            []string `json:"missing"`
	Partial            bool     `json:"partial"`
	PlacementViewReady bool     `json:"placement_view_ready"`
}

// Result is one page of cluster-wide list hydration.
type Result struct {
	Sandboxes     []*models.Sandbox `json:"sandboxes"`
	Coverage      Coverage          `json:"coverage"`
	NextPageToken string            `json:"next_page_token,omitempty"`
}

// Transport carries the cert-pinned cluster-internal mTLS client.
type Transport struct {
	InternalClient *http.Client
	// PeerClient, when set, returns a cached per-node mTLS client (no transport
	// clone per dial). Cluster/Agent implement this via ClientForPeer.
	PeerClient func(nodeID string) *http.Client
}

// Options controls cluster-wide list fan-out.
type Options struct {
	OwnerRef string
	// AuthHeader is the caller's Authorization. Sent only on mTLS InternalURL.
	AuthHeader           string
	RawQuery             string
	Path                 string
	ForwardedHeaderName  string
	ForwardedHeaderValue string
	Local                []*models.Sandbox
	Transport            Transport
	// SelfNodeID is stamped on X-Cluster-Peer-Node-ID for inbound mTLS binding.
	SelfNodeID string
	// Limit/PageToken drive PlacementPage-backed peer selection.
	Limit     int
	PageToken string
	// WantIDs, when non-nil, drops peer/local rows whose ID is not in the set.
	// nil means no ID filter; empty non-nil map denies every ID.
	WantIDs map[string]struct{}
	Warn    func(msg string, peer string, err error)
}

// PeerDialer is implemented by cluster.Cluster / cluster.Agent.
type PeerDialer interface {
	PeerInternalHTTPClient() *http.Client
}

// PeerClientProvider is implemented by cluster.Cluster / cluster.Agent.
type PeerClientProvider interface {
	ClientForPeer(nodeID string) *http.Client
}

// MemberLookup resolves one peer without scanning full membership.
type MemberLookup interface {
	LookupMember(id string) (cluster.Member, bool)
}

// TransportFromCluster extracts dial options when c implements PeerDialer.
func TransportFromCluster(c cluster.Client) Transport {
	if c == nil {
		return Transport{}
	}
	tr := Transport{}
	if d, ok := c.(PeerDialer); ok {
		tr.InternalClient = d.PeerInternalHTTPClient()
	}
	if p, ok := c.(PeerClientProvider); ok {
		tr.PeerClient = p.ClientForPeer
	}
	return tr
}

// OwnerRefFromContext returns the tenant OwnerRef for non-operator callers.
func OwnerRefFromContext(ctx context.Context) string {
	access, ok := controlplane.AccessFromContext(ctx)
	if !ok || access.Operator {
		return ""
	}
	return strings.TrimSpace(access.Identity.OwnerRef)
}

// SelectPeersForPage returns owner peers for one placement-index page plus the
// placement rows and next page token. Does not load the full placement view.
// missing lists placement owners that could not be reached (unknown/dead).
//
// Authoritative empty pages (tenant or fleet has zero placements) return
// viewReady=true with peers=nil so callers respond 200 empty — not 503.
// viewReady=false only when PlacementPage failed / FSM not ready (non-authoritative).
func SelectPeersForPage(c cluster.Client, ownerRef, pageToken string, limit int) (peers []cluster.Member, placements []cluster.Placement, next string, viewReady bool, missing []string) {
	if c == nil {
		return nil, nil, "", false, nil
	}
	if limit <= 0 {
		limit = DefaultPageLimit
	}
	if limit > MaxPageLimit {
		limit = MaxPageLimit
	}
	page := c.PlacementPage(cluster.PlacementPageRequest{
		Limit:     limit,
		PageToken: pageToken,
		OwnerRef:  strings.TrimSpace(ownerRef),
	})
	selfID := c.SelfNodeID()
	lookup := memberLookupFn(c)

	if page.Authoritative {
		if len(page.Placements) == 0 {
			// True empty page (including empty tenant). Return a non-nil empty
			// placements slice so FilterLocalToPage / WantIDs deny all rows.
			return nil, []cluster.Placement{}, page.NextPageToken, true, nil
		}
		return peersFromPlacements(page, selfID, lookup)
	}

	if len(page.Placements) == 0 && pageToken == "" {
		// Placement index not authoritative / empty: only fan out on small
		// fleets. Large fleets must wait for the index — returning local-only
		// with viewReady=false so clients see incompleteness instead of a
		// silent vacuum.
		aliveOwners := 0
		out := make([]cluster.Member, 0, 32)
		for _, m := range c.Members() {
			if !m.Alive || m.NodeID == "" || m.NodeID == selfID {
				continue
			}
			if !cluster.CanOwnSandboxRole(m.Role) {
				continue
			}
			aliveOwners++
			if aliveOwners > 256 {
				return nil, nil, "", false, nil
			}
			if strings.TrimSpace(m.InternalURL) == "" {
				continue
			}
			out = append(out, m)
		}
		return out, nil, "", true, nil
	}

	return peersFromPlacements(page, selfID, lookup)
}

func peersFromPlacements(page cluster.PlacementPageResponse, selfID string, lookup func(string) (cluster.Member, bool)) (peers []cluster.Member, placements []cluster.Placement, next string, viewReady bool, missing []string) {
	want := make(map[string]struct{})
	for _, p := range page.Placements {
		if p.OwnerNodeID == "" || p.OwnerNodeID == selfID {
			continue
		}
		want[p.OwnerNodeID] = struct{}{}
	}
	out := make([]cluster.Member, 0, len(want))
	for id := range want {
		m, ok := lookup(id)
		if !ok || !m.Alive {
			missing = append(missing, id)
			continue
		}
		if strings.TrimSpace(m.InternalURL) == "" {
			missing = append(missing, id)
			continue
		}
		if !cluster.CanOwnSandboxRole(m.Role) {
			missing = append(missing, id)
			continue
		}
		out = append(out, m)
	}
	return out, page.Placements, page.NextPageToken, true, missing
}

func memberLookupFn(c cluster.Client) func(string) (cluster.Member, bool) {
	if c == nil {
		return func(string) (cluster.Member, bool) { return cluster.Member{}, false }
	}
	if l, ok := c.(MemberLookup); ok {
		return l.LookupMember
	}
	byID := make(map[string]cluster.Member)
	for _, m := range c.Members() {
		if m.NodeID != "" {
			byID[m.NodeID] = m
		}
	}
	return func(id string) (cluster.Member, bool) {
		m, ok := byID[id]
		return m, ok
	}
}

// SelectPeers is retained for tests; production list uses SelectPeersForPage.
func SelectPeers(c cluster.Client, ownerRef string) []cluster.Member {
	peers, _, _, _, _ := SelectPeersForPage(c, ownerRef, "", DefaultPageLimit)
	return peers
}

// PlacementWantIDs builds the WantIDs set for Merge/MergeJSON from a placement
// page. nil placements means "no filter" (cold-start fan-out). A non-nil empty
// slice yields an empty map that denies every ID (authoritative empty page).
func PlacementWantIDs(placements []cluster.Placement) map[string]struct{} {
	if placements == nil {
		return nil
	}
	want := make(map[string]struct{}, len(placements))
	for _, p := range placements {
		if id := strings.TrimSpace(p.SandboxID); id != "" {
			want[id] = struct{}{}
		}
	}
	return want
}

// FilterLocalToPage keeps local rows that appear on the current placement page.
// nil placements AND pageToken=="" (true cold start / small fleet) keeps all
// local rows. Non-nil empty placements (authoritative empty page) or a
// terminal pageToken with no rows returns an empty slice.
func FilterLocalToPage(local []*models.Sandbox, placements []cluster.Placement, pageToken string) []*models.Sandbox {
	if placements == nil {
		if strings.TrimSpace(pageToken) != "" {
			return nil
		}
		return local
	}
	want := PlacementWantIDs(placements)
	out := make([]*models.Sandbox, 0, len(local))
	for _, sb := range local {
		if sb == nil {
			continue
		}
		if _, ok := want[sb.ID]; ok {
			out = append(out, sb)
		}
	}
	return out
}

// Merge hydrates one page of sandboxes from placement owners.
func Merge(ctx context.Context, peers []cluster.Member, opts Options) Result {
	res := Result{
		Sandboxes: make([]*models.Sandbox, 0, len(opts.Local)),
		Coverage: Coverage{
			Answered:           []string{"local"},
			PlacementViewReady: true,
		},
	}
	seen := make(map[string]struct{}, len(opts.Local))
	for _, sb := range opts.Local {
		if sb == nil {
			continue
		}
		if !wantIDOK(opts.WantIDs, sb.ID) {
			continue
		}
		seen[sb.ID] = struct{}{}
		res.Sandboxes = append(res.Sandboxes, sb)
	}
	if len(peers) == 0 {
		return res
	}

	mergeCtx, cancel := context.WithTimeout(ctx, MergeTimeout)
	defer cancel()

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
	// Acquire the semaphore before spawning so we never create unbounded
	// goroutines under a large owner fan-out.
	sem := make(chan struct{}, MaxConcurrentPeerReads)
	started := 0
	for _, peer := range peers {
		peer := peer
		select {
		case sem <- struct{}{}:
		case <-mergeCtx.Done():
			results <- peerResult{nodeID: peer.NodeID, err: mergeCtx.Err()}
			started++
			continue
		}
		started++
		go func() {
			defer func() { <-sem }()
			sbs, err := fetchPeerSandboxes(mergeCtx, peer, path, fwdName, fwdVal, opts)
			results <- peerResult{nodeID: peer.NodeID, sandboxes: sbs, err: err}
		}()
	}

	for i := 0; i < started; i++ {
		pr := <-results
		if pr.err != nil {
			res.Coverage.Missing = append(res.Coverage.Missing, pr.nodeID)
			res.Coverage.Partial = true
			if opts.Warn != nil {
				opts.Warn("cluster list: peer query failed", pr.nodeID, pr.err)
			}
			continue
		}
		res.Coverage.Answered = append(res.Coverage.Answered, pr.nodeID)
		for _, sb := range pr.sandboxes {
			if sb == nil {
				continue
			}
			if !wantIDOK(opts.WantIDs, sb.ID) {
				continue
			}
			if _, dup := seen[sb.ID]; dup {
				continue
			}
			seen[sb.ID] = struct{}{}
			res.Sandboxes = append(res.Sandboxes, sb)
		}
	}
	if mergeCtx.Err() != nil {
		res.Coverage.Partial = true
	}
	return res
}

// MergeJSON merges peer JSON arrays (facade list shapes) with the same transport rules.
func MergeJSON[T any](ctx context.Context, peers []cluster.Member, local []T, idFn func(T) string, opts Options) (items []T, cov Coverage) {
	cov = Coverage{Answered: []string{"local"}, PlacementViewReady: true}
	seen := make(map[string]struct{}, len(local))
	for _, it := range local {
		id := ""
		if idFn != nil {
			id = idFn(it)
		}
		if id != "" && !wantIDOK(opts.WantIDs, id) {
			continue
		}
		if id != "" {
			seen[id] = struct{}{}
		}
		items = append(items, it)
	}
	if len(peers) == 0 {
		return items, cov
	}
	mergeCtx, cancel := context.WithTimeout(ctx, MergeTimeout)
	defer cancel()
	type peerResult struct {
		nodeID string
		items  []T
		err    error
	}
	results := make(chan peerResult, len(peers))
	path := opts.Path
	fwdName := opts.ForwardedHeaderName
	if fwdName == "" {
		fwdName = "X-Cluster-Forwarded"
	}
	fwdVal := opts.ForwardedHeaderValue
	if fwdVal == "" {
		fwdVal = "1"
	}
	sem := make(chan struct{}, MaxConcurrentPeerReads)
	started := 0
	for _, peer := range peers {
		peer := peer
		select {
		case sem <- struct{}{}:
		case <-mergeCtx.Done():
			results <- peerResult{nodeID: peer.NodeID, err: mergeCtx.Err()}
			started++
			continue
		}
		started++
		go func() {
			defer func() { <-sem }()
			raw, err := fetchPeerJSON(mergeCtx, peer, path, fwdName, fwdVal, opts)
			if err != nil {
				results <- peerResult{nodeID: peer.NodeID, err: err}
				return
			}
			var decoded []T
			if err := json.Unmarshal(raw, &decoded); err != nil {
				results <- peerResult{nodeID: peer.NodeID, err: err}
				return
			}
			results <- peerResult{nodeID: peer.NodeID, items: decoded}
		}()
	}
	for i := 0; i < started; i++ {
		pr := <-results
		if pr.err != nil {
			cov.Missing = append(cov.Missing, pr.nodeID)
			cov.Partial = true
			if opts.Warn != nil {
				opts.Warn("cluster list: peer query failed", pr.nodeID, pr.err)
			}
			continue
		}
		cov.Answered = append(cov.Answered, pr.nodeID)
		for _, it := range pr.items {
			if idFn != nil {
				id := idFn(it)
				if id != "" {
					if !wantIDOK(opts.WantIDs, id) {
						continue
					}
					if _, dup := seen[id]; dup {
						continue
					}
					seen[id] = struct{}{}
				}
			}
			items = append(items, it)
		}
	}
	if mergeCtx.Err() != nil {
		cov.Partial = true
	}
	return items, cov
}

func wantIDOK(want map[string]struct{}, id string) bool {
	if want == nil {
		return true
	}
	_, ok := want[id]
	return ok
}

// StripFacadePagination removes facade-specific pagination keys from a query
// string so peer fetches return full owner pages; the ingress applies facade
// pagination exactly once after the merge.
func StripFacadePagination(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}
	vals, err := url.ParseQuery(rawQuery)
	if err != nil {
		return rawQuery
	}
	for _, key := range []string{"page", "limit", "nextToken", "next_token", "page_token", "pageToken", "offset", "ids"} {
		vals.Del(key)
	}
	return vals.Encode()
}

// WriteCoverageHeaders exposes completeness without changing the JSON body shape.
func WriteCoverageHeaders(w http.ResponseWriter, cov Coverage, nextPageToken string) {
	if w == nil {
		return
	}
	w.Header().Set(HeaderPartial, strconv.FormatBool(cov.Partial || !cov.PlacementViewReady))
	w.Header().Set(HeaderPlacementReady, strconv.FormatBool(cov.PlacementViewReady))
	if len(cov.Missing) > 0 {
		w.Header().Set(HeaderMissing, strings.Join(cov.Missing, ","))
	}
	if len(cov.Answered) > 0 {
		w.Header().Set(HeaderAnswered, strings.Join(cov.Answered, ","))
	}
	if nextPageToken != "" {
		w.Header().Set(HeaderNextPageToken, nextPageToken)
	}
}

func fetchPeerSandboxes(ctx context.Context, peer cluster.Member, path, fwdName, fwdVal string, opts Options) ([]*models.Sandbox, error) {
	raw, err := fetchPeerJSON(ctx, peer, path, fwdName, fwdVal, opts)
	if err != nil {
		return nil, err
	}
	var sbs []*models.Sandbox
	if err := json.Unmarshal(raw, &sbs); err != nil {
		return nil, err
	}
	return sbs, nil
}

func fetchPeerJSON(ctx context.Context, peer cluster.Member, path, fwdName, fwdVal string, opts Options) ([]byte, error) {
	client, base, err := dialPeer(peer, opts.Transport)
	if err != nil {
		return nil, err
	}
	endpoint := strings.TrimRight(base, "/") + path
	q := opts.RawQuery
	if ids := wantIDsQuery(opts.WantIDs); ids != "" {
		if q == "" {
			q = "ids=" + ids
		} else {
			q = q + "&ids=" + ids
		}
	}
	if q != "" {
		endpoint += "?" + q
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(fwdName, fwdVal)
	// mTLS-only: forward the caller's Authorization so tenant scope is preserved.
	// Never substitute the fleet PAT (that was the cross-tenant enumeration hole).
	if opts.AuthHeader != "" {
		req.Header.Set("Authorization", opts.AuthHeader)
	}
	cluster.SetPeerNodeIDHeader(req, opts.SelfNodeID)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	// Read one byte past the cap so a truncated 8MiB body is distinguishable
	// from a complete response that happens to be exactly 8MiB.
	const maxPeerBody = 8 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPeerBody+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxPeerBody {
		return nil, errors.New("peer list response exceeds 8MiB limit")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(strings.TrimSpace(string(body)))
	}
	return body, nil
}

func wantIDsQuery(want map[string]struct{}) string {
	if len(want) == 0 {
		return ""
	}
	ids := make([]string, 0, len(want))
	for id := range want {
		if id != "" {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return ""
	}
	// Stable order keeps peer URLs cache-friendly / debuggable.
	sort.Strings(ids)
	return url.QueryEscape(strings.Join(ids, ","))
}

func dialPeer(m cluster.Member, tr Transport) (*http.Client, string, error) {
	var cached *http.Client
	if tr.PeerClient != nil {
		cached = tr.PeerClient(m.NodeID)
	}
	client, base, err := cluster.PeerDialCached(m, tr.InternalClient, cached)
	if err != nil {
		return nil, "", err
	}
	// Fail closed for list: InternalClient must be present so we never hit
	// plaintext advertise URLs with any credential.
	if tr.InternalClient == nil {
		return nil, "", errors.New("cluster list requires mTLS InternalClient")
	}
	return withTimeout(client), base, nil
}

func withTimeout(c *http.Client) *http.Client {
	if c == nil {
		return &http.Client{Timeout: PeerTimeout}
	}
	if c.Timeout > 0 && c.Timeout <= PeerTimeout {
		return c
	}
	clone := *c
	clone.Timeout = PeerTimeout
	return &clone
}

// ParsePageParams reads limit/page_token from a request URL.
// pageToken is accepted as an alias for page_token (Daytona-style clients).
func ParsePageParams(u *url.URL) (limit int, pageToken string) {
	if u == nil {
		return DefaultPageLimit, ""
	}
	q := u.Query()
	pageToken = strings.TrimSpace(q.Get("page_token"))
	if pageToken == "" {
		pageToken = strings.TrimSpace(q.Get("pageToken"))
	}
	if raw := strings.TrimSpace(q.Get("limit")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil {
			limit = n
		}
	}
	if limit <= 0 {
		limit = DefaultPageLimit
	}
	if limit > MaxPageLimit {
		limit = MaxPageLimit
	}
	return limit, pageToken
}
