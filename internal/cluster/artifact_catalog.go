package cluster

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/hashicorp/raft"
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

// ErrArtifactCatalogSuperseded reports a publication from a process the
// catalogue has already moved past. The publisher re-seeds its epoch from the
// authority and republishes rather than believing it is clean.
var ErrArtifactCatalogSuperseded = errors.New("cluster: artifact catalogue publication is superseded")

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
	// PublisherEpoch is the epoch the catalogue holds for the node that
	// ASKED. A publisher takes the next one, which is how a restarted process
	// outranks requests its predecessor may still have in flight. It is
	// filled from the authenticated peer identity on the peer path, never
	// from the request body.
	PublisherEpoch int64 `json:"publisher_epoch,omitempty"`
}

// ArtifactCatalogRequest is the agent-facing read.
type ArtifactCatalogRequest struct {
	Kind      string `json:"kind"`
	Tenant    string `json:"tenant,omitempty"`
	Limit     int    `json:"limit,omitempty"`
	PageToken string `json:"page_token,omitempty"`
	// ForNodeID asks for that node's publisher epoch alongside the page. The
	// peer handler overrides it with the authenticated identity; a node may
	// only ever ask for its own.
	ForNodeID string `json:"for_node_id,omitempty"`
}

// ArtifactCatalogSnapshot is one node's whole inventory of one kind, as the
// publisher wants it to become. It is delivered as a sequence of chunks and
// applied all-or-nothing.
type ArtifactCatalogSnapshot struct {
	Kind string `json:"kind"`
	// NodeID is the publisher. Callers never supply another node's id: the
	// peer-facing path takes it from the authenticated identity.
	NodeID string `json:"node_id"`
	// Epoch is the AUTHORITY-ISSUED fencing token for the publishing process:
	// a node reads the catalogue's committed epoch at boot and takes the next
	// one. A process identifier alone (a UUID) identifies a process without
	// ordering processes, so a request delayed in transport from a replaced
	// process could take ownership back and republish an obsolete inventory.
	Epoch int64 `json:"epoch"`
	// Revision orders publications WITHIN one epoch.
	Revision int64                `json:"revision"`
	Rows     []ArtifactCatalogRow `json:"rows"`
	// First starts a new snapshot (discarding any half-delivered one) and
	// Final commits it. A single-chunk snapshot sets both.
	First bool `json:"first,omitempty"`
	Final bool `json:"final,omitempty"`
	// Withdraw removes this node's coverage instead of replacing it. A node
	// whose inventory cannot be represented — over the per-node cap — must
	// say so: the aggregator skips a node it believes it covers, so leaving
	// the old coverage in place advertises an inventory the node no longer
	// has and nothing ever asks it again.
	Withdraw bool `json:"withdraw,omitempty"`
}

func artifactCatalogKindKey(kind string) string { return strings.TrimSpace(kind) }

// MaxArtifactCatalogRowsPerNode is the publisher-side cap on one node's whole
// inventory of a kind. A node over it does not publish at all: it stays
// uncovered and the aggregator keeps asking it, which is slower but never
// wrong.
func MaxArtifactCatalogRowsPerNode() int { return maxArtifactCatalogRowsPerNode }

// WithdrawArtifactCatalogCoverage builds the publication that removes this
// node's coverage of a kind.
func WithdrawArtifactCatalogCoverage(kind, nodeID string, epoch, revision int64) ArtifactCatalogSnapshot {
	return ArtifactCatalogSnapshot{
		Kind:     strings.TrimSpace(kind),
		NodeID:   strings.TrimSpace(nodeID),
		Epoch:    epoch,
		Revision: revision,
		First:    true,
		Final:    true,
		Withdraw: true,
	}
}

// ChunkArtifactCatalogSnapshot splits an inventory into commands that fit the
// apply transport. The sequence is always non-empty: an EMPTY inventory is a
// real statement ("this node holds nothing of this kind"), and losing it is
// what keeps a tenant's list asking every worker forever.
func ChunkArtifactCatalogSnapshot(kind, nodeID string, epoch, revision int64, rows []ArtifactCatalogRow) []ArtifactCatalogSnapshot {
	base := ArtifactCatalogSnapshot{
		Kind:     strings.TrimSpace(kind),
		NodeID:   strings.TrimSpace(nodeID),
		Epoch:    epoch,
		Revision: revision,
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

// ArtifactCatalogEpochRequest asks the authority for one publisher token.
// The node is NOT a body field: the server fills it from the authenticated
// peer identity, so a node can only ever be issued its own.
type ArtifactCatalogEpochRequest struct {
	Kind string `json:"kind"`
	// Holder identifies the requesting process. A retry from the same holder
	// is answered with the token it already has rather than a new one.
	Holder string `json:"holder"`
}

// ArtifactCatalogEpochResponse carries exactly the issued token.
type ArtifactCatalogEpochResponse struct {
	Epoch int64 `json:"epoch"`
}

// AllocateArtifactCatalogEpoch issues this process its fencing token through
// the replicated log.
//
// Why an allocation and not a read: reading the committed epoch and locally
// choosing "one more" claims nothing. Two processes for the same node — a
// restart overlapping its predecessor, or a node rejoining while its old
// process drains — both read the same value, both pick the same successor,
// and the catalogue can no longer order them: whichever has the higher
// REVISION wins, which is the opposite of what the token is for. Allocating
// through the log makes every token distinct and monotonic.
func (c *Cluster) AllocateArtifactCatalogEpoch(ctx context.Context, kind, nodeID, holder string) (int64, error) {
	if c == nil || c.raft == nil || c.raft.raft == nil {
		return 0, fmt.Errorf("cluster: node holds no placement state")
	}
	kind = artifactCatalogKindKey(kind)
	nodeID = strings.TrimSpace(nodeID)
	holder = strings.TrimSpace(holder)
	if kind == "" || nodeID == "" || holder == "" {
		return 0, fmt.Errorf("cluster: artifact catalogue epoch allocation requires kind, node and holder")
	}
	if c.raft.raft.State() != raft.Leader {
		// Only the leader can allocate, and a token has to reach the caller,
		// which the generic forwarded apply cannot carry back.
		return c.forwardArtifactCatalogEpochToLeader(ctx, kind, nodeID, holder)
	}
	payload, err := encodeCommand(command{
		Op: opAllocateArtifactEpoch, ArtifactKind: kind, NodeID: nodeID, ArtifactHolder: holder,
	})
	if err != nil {
		return 0, fmt.Errorf("cluster: encode command: %w", err)
	}
	result, err := c.applyEncodedLocalResult(ctx, payload)
	if err != nil {
		return 0, err
	}
	issued, ok := result.(artifactEpochApplyResult)
	if !ok || issued.Epoch <= 0 {
		return 0, fmt.Errorf("cluster: artifact catalogue epoch allocation returned no token")
	}
	return issued.Epoch, nil
}

// forwardArtifactCatalogEpochToLeader posts the allocation to the leader and
// reads back the issued token. The forwarding node authenticates as itself,
// which is the same identity the leader would bind the token to.
func (c *Cluster) forwardArtifactCatalogEpochToLeader(ctx context.Context, kind, nodeID, holder string) (int64, error) {
	if nodeID != c.nodeID {
		// A peer's allocation can only be served by the leader; telling the
		// peer to retry sends it to one.
		return 0, ErrNotLeader
	}
	leader := c.Leader()
	if leader == "" {
		return 0, ErrNotLeader
	}
	if c.currentInternalClient() == nil || c.gossip == nil {
		return 0, ErrPeerInternalURLRequired
	}
	peerInternal := c.gossip.peerInternalURL(leader)
	if peerInternal == "" {
		return 0, ErrPeerInternalURLRequired
	}
	reqCtx, cancel := context.WithTimeout(ctx, controlPlaneRequestTimeout)
	defer cancel()
	body, err := json.Marshal(ArtifactCatalogEpochRequest{Kind: kind, Holder: holder})
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost,
		strings.TrimRight(peerInternal, "/")+PublicInternalArtifactCatalogEpochPath, bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("cluster: build artifact catalogue epoch allocation: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	SetPeerNodeIDHeader(req, c.nodeID)
	if c.patToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.patToken)
	}
	resp, err := c.ClientForPeer(leader).Do(req)
	if err != nil {
		return 0, fmt.Errorf("cluster: artifact catalogue epoch allocation: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		if resp.StatusCode == http.StatusServiceUnavailable {
			return 0, ErrNotLeader
		}
		return 0, fmt.Errorf("cluster: artifact catalogue epoch allocation: status %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	var out ArtifactCatalogEpochResponse
	if err := decodeControlPlaneJSON(resp.Body, &out); err != nil {
		return 0, fmt.Errorf("cluster: decode artifact catalogue epoch allocation: %w", err)
	}
	if out.Epoch <= 0 {
		return 0, fmt.Errorf("cluster: artifact catalogue epoch allocation returned no token")
	}
	return out.Epoch, nil
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

// AllocateArtifactCatalogEpoch asks the control plane to issue THIS node's
// fencing token. The server fills the node from the authenticated peer
// identity, so a node can only ever be issued its own.
//
// It deliberately does not go through the catalogue page: a publisher needs
// one number, and the page answers with every publisher's coverage (tens of
// kilobytes at fleet scale) after scanning every node's inventory under the
// FSM read lock.
func (a *Agent) AllocateArtifactCatalogEpoch(ctx context.Context, kind, _ string, holder string) (int64, error) {
	if a == nil {
		return 0, fmt.Errorf("cluster: agent is not configured")
	}
	reqCtx, cancel := context.WithTimeout(ctx, controlPlaneRequestTimeout)
	defer cancel()
	var resp ArtifactCatalogEpochResponse
	if err := a.doControlPlaneJSON(reqCtx, http.MethodPost,
		PublicInternalArtifactCatalogEpochPath, PublicInternalArtifactCatalogEpochPath,
		ArtifactCatalogEpochRequest{Kind: artifactCatalogKindKey(kind), Holder: strings.TrimSpace(holder)}, &resp); err != nil {
		return 0, fmt.Errorf("cluster: allocate artifact catalogue epoch: %w", err)
	}
	if resp.Epoch <= 0 {
		return 0, fmt.Errorf("cluster: artifact catalogue epoch allocation returned no token")
	}
	return resp.Epoch, nil
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
		Op:                 opPublishArtifactCatalog,
		ArtifactWithdraw:   chunk.Withdraw,
		ArtifactKind:       strings.TrimSpace(chunk.Kind),
		NodeID:             strings.TrimSpace(chunk.NodeID),
		ArtifactEpoch:      chunk.Epoch,
		ArtifactRevision:   chunk.Revision,
		ArtifactRows:       chunk.Rows,
		ArtifactChunkFirst: chunk.First,
		ArtifactChunkFinal: chunk.Final,
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
	if chunk.Epoch <= 0 {
		return fmt.Errorf("cluster: artifact catalogue publish requires a publisher epoch")
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
	Epoch    int64
	Revision int64
	// Withdrawn marks a node that has no coverage: it either could not
	// represent its inventory, or its storage was attested destroyed. The
	// entry is kept because its epoch is the watermark that fences a
	// publication still in flight from the process that is gone.
	Withdrawn bool
	// Rows is (tenant, id) -> row. The id alone is NOT unique: JS bundle ids
	// are content digests, so two tenants uploading identical content hold
	// the same id on one worker, and keying by id let the second erase the
	// first while the catalogue still claimed to cover both.
	Rows map[string]ArtifactCatalogRow
}

// artifactCatalogRowKey identifies a row inside one node's inventory.
func artifactCatalogRowKey(tenant, id string) string {
	return strings.TrimSpace(tenant) + "\x00" + strings.TrimSpace(id)
}

// artifactCatalogIssuedEpoch is a token the authority handed to one process.
// Holder is the process identity it was issued to, which is what makes a
// retried allocation idempotent instead of burning a fresh epoch per attempt.
type artifactCatalogIssuedEpoch struct {
	Epoch  int64
	Holder string
}

// artifactCatalogSnapshotState is how one kind's catalogue is serialized into
// a raft snapshot: all three parts, because all three are replicated state.
// Issued has to survive a restore or a restored leader would re-issue tokens
// it has already handed out, and two live processes would publish under the
// same epoch.
type artifactCatalogSnapshotState struct {
	Committed map[string]artifactCatalogNodeState
	Pending   map[string]artifactCatalogNodeState
	Issued    map[string]artifactCatalogIssuedEpoch
}

func cloneArtifactCatalogNodes(in map[string]artifactCatalogNodeState) map[string]artifactCatalogNodeState {
	out := make(map[string]artifactCatalogNodeState, len(in))
	for nodeID, entry := range in {
		rows := make(map[string]ArtifactCatalogRow, len(entry.Rows))
		for key, row := range entry.Rows {
			rows[key] = row
		}
		out[nodeID] = artifactCatalogNodeState{
			Epoch: entry.Epoch, Revision: entry.Revision, Withdrawn: entry.Withdrawn, Rows: rows,
		}
	}
	return out
}

// withdrawArtifactCatalogCoverageLocked drops a node's rows and coverage for
// every kind and RAISES its epoch watermark past anything that process could
// still have in flight, so a delayed publication cannot re-add a node whose
// storage an operator attested destroyed. A node that comes back asks the
// authority for the next epoch and publishes normally. Caller holds f.mu.
func (f *placementFSM) withdrawArtifactCatalogCoverageLocked(nodeID string) {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return
	}
	for _, state := range f.artifactCatalog {
		if state == nil {
			continue
		}
		entry, committed := state.Committed[nodeID]
		pending, building := state.Pending[nodeID]
		issued, tokened := state.Issued[nodeID]
		if !committed && !building && !tokened {
			continue
		}
		epoch, revision := entry.Epoch, entry.Revision
		if building && (pending.Epoch > epoch || (pending.Epoch == epoch && pending.Revision > revision)) {
			epoch, revision = pending.Epoch, pending.Revision
		}
		// A token that was ISSUED but not yet published under is the most
		// dangerous of the three: the process holding it has published
		// nothing, so neither Committed nor Pending records it, and a
		// watermark raised only past those would let that process republish
		// the destroyed node's inventory after the attestation.
		if tokened && issued.Epoch > epoch {
			epoch, revision = issued.Epoch, 0
		}
		_ = revision
		state.Committed[nodeID] = artifactCatalogNodeState{
			// One past the highest epoch this node has used: every request
			// from the retired process, whatever its revision, is now older
			// than the watermark.
			Epoch:     epoch + 1,
			Revision:  0,
			Withdrawn: true,
			Rows:      map[string]ArtifactCatalogRow{},
		}
		delete(state.Pending, nodeID)
		// The ledger is cleared, not raised: a node that comes back asks for
		// a fresh token, and the allocation counts from the withdrawn
		// committed watermark, which is already past everything it held.
		delete(state.Issued, nodeID)
	}
}

// artifactCatalogKindState separates the committed snapshot from a
// half-delivered one. Coverage is only ever claimed for a committed snapshot,
// so a publish interrupted between chunks leaves the previous answer standing
// rather than a truncated one.
type artifactCatalogKindState struct {
	Committed map[string]artifactCatalogNodeState
	Pending   map[string]artifactCatalogNodeState
	// Issued is the token ledger: (node) -> the epoch last handed out and to
	// which process. It is the high-water mark a new allocation counts from,
	// so a token issued to a process that never published still orders every
	// later one after it.
	Issued map[string]artifactCatalogIssuedEpoch
}

func cloneArtifactCatalogIssued(in map[string]artifactCatalogIssuedEpoch) map[string]artifactCatalogIssuedEpoch {
	out := make(map[string]artifactCatalogIssuedEpoch, len(in))
	for nodeID, issued := range in {
		out[nodeID] = issued
	}
	return out
}

// supersedes reports whether an incoming publication is newer than what is
// held, ordered by (epoch, revision). A LOWER epoch is a superseded process:
// its requests are refused however high their revision, which is what stops a
// delayed request from a replaced process taking ownership back.
func (s artifactCatalogNodeState) supersedes(epoch, revision int64) bool {
	if s.Epoch != epoch {
		return epoch > s.Epoch
	}
	return revision > s.Revision
}

func (f *placementFSM) artifactCatalogPublisherEpoch(kind, nodeID string) int64 {
	f.mu.RLock()
	defer f.mu.RUnlock()
	state := f.artifactCatalog[artifactCatalogKindKey(kind)]
	if state == nil {
		return 0
	}
	epoch := state.Committed[strings.TrimSpace(nodeID)].Epoch
	// A half-delivered publication has already claimed its epoch.
	if pending := state.Pending[strings.TrimSpace(nodeID)].Epoch; pending > epoch {
		epoch = pending
	}
	return epoch
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
	if state == nil {
		return page
	}
	if len(state.Committed) == 0 {
		if forNode := strings.TrimSpace(req.ForNodeID); forNode != "" {
			page.PublisherEpoch = state.Pending[forNode].Epoch
		}
		return page
	}

	nodeIDs := make([]string, 0, len(state.Committed))
	for nodeID, entry := range state.Committed {
		if entry.Withdrawn {
			// No rows and no coverage: the aggregator asks this node again.
			continue
		}
		nodeIDs = append(nodeIDs, nodeID)
	}
	sort.Strings(nodeIDs)
	// Coverage is a property of the KIND: a node that published an inventory
	// holding nothing for this tenant has still answered for it. It is
	// therefore complete on the first page, independent of the cursor.
	page.Publishers = nodeIDs
	if forNode := strings.TrimSpace(req.ForNodeID); forNode != "" {
		page.PublisherEpoch = state.Committed[forNode].Epoch
		if pending := state.Pending[forNode].Epoch; pending > page.PublisherEpoch {
			page.PublisherEpoch = pending
		}
	}

	// The walk is ordered by (node, id) so the cursor is a single comparable
	// string and a page boundary never loses or repeats a row.
	budget := artifactCatalogPageByteBudget
	lastCursor := ""
	for _, nodeID := range nodeIDs {
		entry := state.Committed[nodeID]
		// Within one tenant an id IS unique, so the walk position stays
		// (node, id) even though the inventory is keyed by (tenant, id).
		ids := make([]string, 0, len(entry.Rows))
		for _, row := range entry.Rows {
			if strings.TrimSpace(row.Tenant) != tenant {
				continue
			}
			ids = append(ids, row.ID)
		}
		sort.Strings(ids)
		for _, id := range ids {
			cursor := artifactCatalogCursor(nodeID, id)
			if req.PageToken != "" && cursor <= req.PageToken {
				continue
			}
			row := entry.Rows[artifactCatalogRowKey(tenant, id)]
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

// clearPendingForPublication drops a half-assembled snapshot on behalf of a
// publication that is being REFUSED or replayed — but only when the assembly
// belongs to that same publication or an older one.
//
// Pending is keyed by node, and an older publisher's late chunk is exactly
// the case where the assembly under that key belongs to somebody else: the
// replacement process that already took a higher epoch. Dropping it
// unconditionally cancelled the replacement's snapshot, and its final chunk
// then landed on nothing ("has no pending snapshot"). Refusing an old request
// must not be a write.
func clearPendingForPublication(state *artifactCatalogKindState, nodeID string, epoch, revision int64) {
	if state == nil || state.Pending == nil {
		return
	}
	pending, ok := state.Pending[nodeID]
	if !ok {
		return
	}
	if pending.Epoch > epoch || (pending.Epoch == epoch && pending.Revision > revision) {
		return
	}
	delete(state.Pending, nodeID)
}
