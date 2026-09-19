package cluster

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// Replicated artifact catalogue.
//
// Listing templates or JS bundles used to ask every runtime-capable worker in
// the fleet. At 2,000 workers that is 2,000 requests for one list, and the
// per-tenant response cache only bounds how OFTEN it happens, not how much
// work one sweep does. Narrowing by the gossip location index helps only a
// sparse fleet: every worker that holds an artifact is still a target, and a
// dedicated server or ingress holds none locally, so it asks all of them.
//
// The fix is the same one platform volumes already use: replicate the
// METADATA through the bounded control plane and keep the bytes where they
// are. Four properties make it convergent rather than best-effort:
//
//   - Coverage is per KIND, not per tenant. A node publishes everything it
//     holds of one kind, grouped by tenant, so "this node has no bundles for
//     tenant X" is an answer the catalogue can give. Publishing per tenant
//     could never cover the empty case, and every cold list went back to the
//     whole fleet.
//   - A snapshot is versioned by (publisher incarnation, revision) and
//     applied all-or-nothing. An older publish that arrives late is ignored
//     instead of overwriting newer state, and a publisher that restarts is
//     always newer than its previous process.
//   - A snapshot is delivered in CHUNKS. One node's inventory is allowed to
//     be far larger than a raft command (4,096 rows × 16 KiB), so publishing
//     it as a single apply would be refused by the 1 MiB transport cap and
//     the node would silently keep serving stale rows.
//   - Reads are PAGED with a cursor. A single response budget with the
//     remainder dropped sends most of a large fleet back to the sweep.
//
// What is NOT done here, deliberately: publishing bundle digests into gossip.
// Gossip reaches every node in the fleet, and a node-wide digest list would
// let any peer infer the existence and byte-equality of another tenant's
// code. The Raft FSM is server-tier-only state that already holds every
// tenant's placements, so the catalogue adds no disclosure surface.

const (
	// ArtifactKindTemplate / ArtifactKindJSBundle name the two catalogues.
	// Templates are not tenant-scoped, so they publish under the empty
	// tenant; JS bundles carry their owner.
	ArtifactKindTemplate = "template"
	ArtifactKindJSBundle = "js-bundle"

	// maxArtifactCatalogRowsPerNode bounds one node's whole inventory.
	maxArtifactCatalogRowsPerNode = 4096
	// maxArtifactCatalogRowBytes bounds one row. Rows are small metadata
	// (id, name, status, sizes); anything larger is a bug or an attack.
	maxArtifactCatalogRowBytes = 16 << 10
	// MaxArtifactCatalogChunkRows / MaxArtifactCatalogChunkBytes bound ONE
	// raft command. The apply transport caps a request at 1 MiB and the
	// payload is base64-encoded inside the command, so a publisher that sent
	// its whole inventory at once would be refused for an ordinary inventory
	// of small rows — 4,096 of them encode to ~1.6 MB.
	MaxArtifactCatalogChunkRows  = 256
	MaxArtifactCatalogChunkBytes = 512 << 10
	// maxInternalApplyBytes mirrors what the apply handler and the internal
	// listener accept for one forwarded command. The chunk caps above are
	// chosen to stay inside it after base64 expansion.
	maxInternalApplyBytes = 1 << 20
	// MaxArtifactCatalogPageRows / artifactCatalogPageByteBudget bound one
	// READ. The cursor carries the rest, so a large catalogue is walked
	// rather than truncated.
	MaxArtifactCatalogPageRows      = 2048
	artifactCatalogPageByteBudget   = 8 << 20
	artifactCatalogRowOverheadBytes = 96
)

// ArtifactCatalogRow is one artifact's metadata as its holder serialized it.
// The FSM does not interpret Payload — the API layer owns the wire type — so
// adding a field to models.Template cannot require an FSM change.
type ArtifactCatalogRow struct {
	ID string `json:"id"`
	// Tenant scopes the row inside its kind. Empty means "not tenant-scoped"
	// (templates). It lives on the row, not on the publication, because
	// coverage has to be answerable for a tenant the publisher holds nothing
	// for.
	Tenant  string `json:"tenant,omitempty"`
	Payload []byte `json:"payload"`
}

// ArtifactCatalogPage is what a reader gets back.
type ArtifactCatalogPage struct {
	Rows []ArtifactCatalogRow `json:"rows"`
	// Publishers are the nodes whose inventory of this KIND the catalogue
	// holds in full. The aggregator asks everyone else. It does not depend on
	// the tenant being read: a node that published an inventory containing
	// nothing for this tenant has still answered for it.
	Publishers []string `json:"publishers"`
	// NextPageToken continues the walk. Publishers are complete on the first
	// page; rows are not, so a caller that needs every row pages to the end.
	NextPageToken string `json:"next_page_token,omitempty"`
	// Authoritative distinguishes "nothing published yet" from "could not
	// ask". A non-authoritative answer must fall back to the fan-out.
	Authoritative bool `json:"authoritative,omitempty"`
}

// ArtifactCatalogRequest is the agent-facing read.
type ArtifactCatalogRequest struct {
	Kind      string `json:"kind"`
	Tenant    string `json:"tenant,omitempty"`
	Limit     int    `json:"limit,omitempty"`
	PageToken string `json:"page_token,omitempty"`
}

// ArtifactCatalogSnapshot is one node's whole inventory of one kind, as the
// publisher wants it to become. It is delivered as a sequence of chunks and
// applied all-or-nothing.
type ArtifactCatalogSnapshot struct {
	Kind string `json:"kind"`
	// NodeID is the publisher. Callers never supply another node's id: the
	// peer-facing path takes it from the authenticated identity.
	NodeID string `json:"node_id"`
	// Incarnation identifies the publishing PROCESS. A restarted node starts
	// its revisions again, so a plain counter comparison would reject
	// everything it publishes until it caught up; a new incarnation is always
	// newer than the committed one.
	Incarnation string `json:"incarnation"`
	// Revision orders publications from one process. Monotonic per process.
	Revision int64                `json:"revision"`
	Rows     []ArtifactCatalogRow `json:"rows"`
	// First starts a new snapshot (discarding any half-delivered one) and
	// Final commits it. A single-chunk snapshot sets both.
	First bool `json:"first,omitempty"`
	Final bool `json:"final,omitempty"`
}

func artifactCatalogKindKey(kind string) string { return strings.TrimSpace(kind) }

// MaxArtifactCatalogRowsPerNode is the publisher-side cap on one node's whole
// inventory of a kind. A node over it does not publish at all: it stays
// uncovered and the aggregator keeps asking it, which is slower but never
// wrong.
func MaxArtifactCatalogRowsPerNode() int { return maxArtifactCatalogRowsPerNode }

// ChunkArtifactCatalogSnapshot splits an inventory into commands that fit the
// apply transport. The sequence is always non-empty: an EMPTY inventory is a
// real statement ("this node holds nothing of this kind"), and losing it is
// what keeps a tenant's list asking every worker forever.
func ChunkArtifactCatalogSnapshot(kind, nodeID, incarnation string, revision int64, rows []ArtifactCatalogRow) []ArtifactCatalogSnapshot {
	base := ArtifactCatalogSnapshot{
		Kind:        strings.TrimSpace(kind),
		NodeID:      strings.TrimSpace(nodeID),
		Incarnation: strings.TrimSpace(incarnation),
		Revision:    revision,
	}
	if len(rows) == 0 {
		only := base
		only.First, only.Final = true, true
		return []ArtifactCatalogSnapshot{only}
	}
	var (
		out     []ArtifactCatalogSnapshot
		current = base
		bytes   int
	)
	current.First = true
	for _, row := range rows {
		cost := len(row.Payload) + len(row.ID) + len(row.Tenant) + artifactCatalogRowOverheadBytes
		if len(current.Rows) > 0 && (len(current.Rows) >= MaxArtifactCatalogChunkRows || bytes+cost > MaxArtifactCatalogChunkBytes) {
			out = append(out, current)
			current = base
			bytes = 0
		}
		current.Rows = append(current.Rows, row)
		bytes += cost
	}
	current.Final = true
	out = append(out, current)
	return out
}

// PublishArtifactCatalog applies one chunk of a snapshot.
func (c *Cluster) PublishArtifactCatalog(ctx context.Context, chunk ArtifactCatalogSnapshot) error {
	if c == nil {
		return fmt.Errorf("cluster: PublishArtifactCatalog requires a cluster")
	}
	if err := validateArtifactCatalogChunk(chunk); err != nil {
		return err
	}
	return c.applyCommand(ctx, artifactCatalogCommand(chunk))
}

// ArtifactCatalog reads one page of one catalogue from the local FSM.
func (c *Cluster) ArtifactCatalog(_ context.Context, req ArtifactCatalogRequest) (ArtifactCatalogPage, error) {
	if c == nil || c.fsm == nil {
		return ArtifactCatalogPage{}, fmt.Errorf("cluster: node holds no placement state")
	}
	return c.fsm.artifactCatalogPage(req), nil
}

// ArtifactCatalogForPeer answers the agent-facing read.
func (c *Cluster) ArtifactCatalogForPeer(req ArtifactCatalogRequest) ArtifactCatalogPage {
	if c == nil || c.fsm == nil {
		return ArtifactCatalogPage{}
	}
	return c.fsm.artifactCatalogPage(req)
}

// PublishArtifactCatalog forwards one chunk to the control plane.
func (a *Agent) PublishArtifactCatalog(ctx context.Context, chunk ArtifactCatalogSnapshot) error {
	if a == nil {
		return fmt.Errorf("cluster: PublishArtifactCatalog requires an agent")
	}
	if err := validateArtifactCatalogChunk(chunk); err != nil {
		return err
	}
	return a.applyCommand(ctx, artifactCatalogCommand(chunk))
}

// ArtifactCatalog reads one page from the server tier. An unreachable control
// plane is an error: the caller falls back to the fan-out rather than
// reporting a tenant's artifacts as absent.
func (a *Agent) ArtifactCatalog(ctx context.Context, req ArtifactCatalogRequest) (ArtifactCatalogPage, error) {
	if a == nil {
		return ArtifactCatalogPage{}, fmt.Errorf("cluster: agent is not configured")
	}
	reqCtx, cancel := context.WithTimeout(ctx, controlPlaneRequestTimeout)
	defer cancel()
	var resp ArtifactCatalogPage
	if err := a.doControlPlaneJSON(reqCtx, http.MethodPost, PublicInternalArtifactCatalogPath, PublicInternalArtifactCatalogPath, req, &resp); err != nil {
		return ArtifactCatalogPage{}, fmt.Errorf("cluster: read artifact catalogue: %w", err)
	}
	if !resp.Authoritative {
		return ArtifactCatalogPage{}, fmt.Errorf("cluster: artifact catalogue read was not authoritative")
	}
	return resp, nil
}

func artifactCatalogCommand(chunk ArtifactCatalogSnapshot) command {
	return command{
		Op:                  opPublishArtifactCatalog,
		ArtifactKind:        strings.TrimSpace(chunk.Kind),
		NodeID:              strings.TrimSpace(chunk.NodeID),
		ArtifactIncarnation: strings.TrimSpace(chunk.Incarnation),
		ArtifactRevision:    chunk.Revision,
		ArtifactRows:        chunk.Rows,
		ArtifactChunkFirst:  chunk.First,
		ArtifactChunkFinal:  chunk.Final,
	}
}

func validateArtifactCatalogChunk(chunk ArtifactCatalogSnapshot) error {
	switch strings.TrimSpace(chunk.Kind) {
	case ArtifactKindTemplate, ArtifactKindJSBundle:
	default:
		return fmt.Errorf("cluster: unknown artifact catalogue kind %q", chunk.Kind)
	}
	if strings.TrimSpace(chunk.NodeID) == "" {
		return fmt.Errorf("cluster: artifact catalogue publish requires a node id")
	}
	if strings.TrimSpace(chunk.Incarnation) == "" {
		return fmt.Errorf("cluster: artifact catalogue publish requires a publisher incarnation")
	}
	if chunk.Revision <= 0 {
		return fmt.Errorf("cluster: artifact catalogue publish requires a positive revision")
	}
	if len(chunk.Rows) > MaxArtifactCatalogChunkRows {
		return fmt.Errorf("cluster: artifact catalogue chunk of %d rows exceeds %d", len(chunk.Rows), MaxArtifactCatalogChunkRows)
	}
	bytes := 0
	for _, row := range chunk.Rows {
		if strings.TrimSpace(row.ID) == "" {
			return fmt.Errorf("cluster: artifact catalogue row requires an id")
		}
		if len(row.Payload) > maxArtifactCatalogRowBytes {
			return fmt.Errorf("cluster: artifact catalogue row %q is %d bytes, over the %d cap", row.ID, len(row.Payload), maxArtifactCatalogRowBytes)
		}
		bytes += len(row.Payload) + len(row.ID) + len(row.Tenant) + artifactCatalogRowOverheadBytes
	}
	if bytes > MaxArtifactCatalogChunkBytes {
		return fmt.Errorf("cluster: artifact catalogue chunk of %d bytes exceeds %d", bytes, MaxArtifactCatalogChunkBytes)
	}
	return nil
}

// artifactCatalogNodeState is one node's inventory of one kind.
type artifactCatalogNodeState struct {
	Incarnation string
	Revision    int64
	// Rows is id -> row for every tenant this node holds of the kind.
	Rows map[string]ArtifactCatalogRow
}

// artifactCatalogKindState separates the committed snapshot from a
// half-delivered one. Coverage is only ever claimed for a committed snapshot,
// so a publish interrupted between chunks leaves the previous answer standing
// rather than a truncated one.
type artifactCatalogKindState struct {
	Committed map[string]artifactCatalogNodeState
	Pending   map[string]artifactCatalogNodeState
}

// supersedes reports whether an incoming publication is newer than what is
// held. A different publisher incarnation is always newer: the process that
// held the old revisions is gone.
func (s artifactCatalogNodeState) supersedes(incarnation string, revision int64) bool {
	if s.Rows == nil && s.Revision == 0 && s.Incarnation == "" {
		return true
	}
	if s.Incarnation != incarnation {
		return true
	}
	return revision > s.Revision
}

func (f *placementFSM) artifactCatalogPage(req ArtifactCatalogRequest) ArtifactCatalogPage {
	limit := req.Limit
	if limit <= 0 || limit > MaxArtifactCatalogPageRows {
		limit = MaxArtifactCatalogPageRows
	}
	tenant := strings.TrimSpace(req.Tenant)

	f.mu.RLock()
	defer f.mu.RUnlock()
	page := ArtifactCatalogPage{Authoritative: true}
	state := f.artifactCatalog[artifactCatalogKindKey(req.Kind)]
	if state == nil || len(state.Committed) == 0 {
		return page
	}

	nodeIDs := make([]string, 0, len(state.Committed))
	for nodeID := range state.Committed {
		nodeIDs = append(nodeIDs, nodeID)
	}
	sort.Strings(nodeIDs)
	// Coverage is a property of the KIND: a node that published an inventory
	// holding nothing for this tenant has still answered for it. It is
	// therefore complete on the first page, independent of the cursor.
	page.Publishers = nodeIDs

	// The walk is ordered by (node, id) so the cursor is a single comparable
	// string and a page boundary never loses or repeats a row.
	budget := artifactCatalogPageByteBudget
	lastCursor := ""
	for _, nodeID := range nodeIDs {
		entry := state.Committed[nodeID]
		ids := make([]string, 0, len(entry.Rows))
		for id, row := range entry.Rows {
			if strings.TrimSpace(row.Tenant) != tenant {
				continue
			}
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			cursor := artifactCatalogCursor(nodeID, id)
			if req.PageToken != "" && cursor <= req.PageToken {
				continue
			}
			row := entry.Rows[id]
			cost := len(row.Payload) + len(row.ID) + len(row.Tenant) + artifactCatalogRowOverheadBytes
			if len(page.Rows) >= limit || (len(page.Rows) > 0 && cost > budget) {
				// Out of room, not out of rows: the cursor carries the rest.
				page.NextPageToken = lastCursor
				return page
			}
			budget -= cost
			page.Rows = append(page.Rows, row)
			lastCursor = cursor
		}
	}
	return page
}

// artifactCatalogCursor is the (node, id) walk position. The NUL separator
// keeps a node id that is a prefix of another from interleaving.
func artifactCatalogCursor(nodeID, id string) string { return nodeID + "\x00" + id }
