package cluster

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/hashicorp/raft"
)

// A publish REPLACES the publisher's slice, so deletes propagate by omission,
// and two nodes holding the same artifact both stay publishers while the
// reader dedupes by id.
func TestArtifactCatalogPublishReplacesOnlyThePublishersSlice(t *testing.T) {
	c, cleanup := newTestCluster(t, "srv-catalog", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	ctx := context.Background()

	if err := publishWholeCatalog(ctx, c, ArtifactKindTemplate, "worker-a", "inc-a", 1, catalogRows("", "tpl-1", "tpl-2")); err != nil {
		t.Fatalf("publish worker-a: %v", err)
	}
	if err := publishWholeCatalog(ctx, c, ArtifactKindTemplate, "worker-b", "inc-b", 1, catalogRows("", "tpl-2", "tpl-3")); err != nil {
		t.Fatalf("publish worker-b: %v", err)
	}

	page, err := c.ArtifactCatalog(ctx, ArtifactCatalogRequest{Kind: ArtifactKindTemplate})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	// The catalogue reports rows per (node, id): two nodes holding the same
	// artifact is the replication fact it exists to record, and the list
	// aggregator dedupes by its own key. Collapsing here would also break the
	// (node, id) cursor, which cannot carry "ids already seen".
	if len(page.Rows) != 4 {
		t.Fatalf("rows = %d, want one per (node, artifact)", len(page.Rows))
	}
	distinct := map[string]struct{}{}
	for _, row := range page.Rows {
		distinct[row.ID] = struct{}{}
	}
	if len(distinct) != 3 {
		t.Fatalf("distinct artifacts = %d, want 3", len(distinct))
	}
	if len(page.Publishers) != 2 {
		t.Fatalf("publishers = %v, want both nodes", page.Publishers)
	}

	// worker-a deletes tpl-1 by republishing what is left.
	if err := publishWholeCatalog(ctx, c, ArtifactKindTemplate, "worker-a", "inc-a", 2, catalogRows("", "tpl-2")); err != nil {
		t.Fatalf("republish worker-a: %v", err)
	}
	page, err = c.ArtifactCatalog(ctx, ArtifactCatalogRequest{Kind: ArtifactKindTemplate})
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]struct{}{}
	for _, row := range page.Rows {
		ids[row.ID] = struct{}{}
	}
	if _, gone := ids["tpl-1"]; gone {
		t.Fatal("the republished node still advertises the artifact it dropped")
	}
	if _, kept := ids["tpl-3"]; !kept {
		t.Fatal("a republish by one node dropped another node's rows")
	}
}

// Tenants must not read each other's catalogue: the key carries the tenant,
// and bundle ids are content digests.
func TestArtifactCatalogIsTenantScoped(t *testing.T) {
	c, cleanup := newTestCluster(t, "srv-catalog-tenant", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	ctx := context.Background()

	row := ArtifactCatalogRow{ID: "sha256-aaa", Tenant: "tenant-a", Payload: []byte(`{"digest":"aaa"}`)}
	if err := publishWholeCatalog(ctx, c, ArtifactKindJSBundle, "worker-a", "inc-a", 1, []ArtifactCatalogRow{row}); err != nil {
		t.Fatal(err)
	}

	mine, err := c.ArtifactCatalog(ctx, ArtifactCatalogRequest{Kind: ArtifactKindJSBundle, Tenant: "tenant-a"})
	if err != nil || len(mine.Rows) != 1 {
		t.Fatalf("tenant-a rows = %+v err=%v", mine.Rows, err)
	}
	other, err := c.ArtifactCatalog(ctx, ArtifactCatalogRequest{Kind: ArtifactKindJSBundle, Tenant: "tenant-b"})
	if err != nil {
		t.Fatal(err)
	}
	if len(other.Rows) != 0 {
		t.Fatalf("tenant-b sees %+v; a tenant's catalogue must not disclose another's digests", other.Rows)
	}
	// Coverage is per KIND, so the publisher answers for a tenant it holds
	// nothing for — that is what stops an empty tenant's list sweeping the
	// fleet forever.
	if len(other.Publishers) != 1 || other.Publishers[0] != "worker-a" {
		t.Fatalf("tenant-b publishers = %v, want the node that published an inventory without its rows", other.Publishers)
	}
}

// catalogRows builds tenant-scoped rows for a test publication.
func catalogRows(tenant string, ids ...string) []ArtifactCatalogRow {
	out := make([]ArtifactCatalogRow, 0, len(ids))
	for _, id := range ids {
		payload, _ := json.Marshal(map[string]string{"id": id})
		out = append(out, ArtifactCatalogRow{ID: id, Tenant: tenant, Payload: payload})
	}
	return out
}

// publishWholeCatalog sends an inventory as the chunk sequence a publisher
// would.
func publishWholeCatalog(ctx context.Context, c *Cluster, kind, nodeID, incarnation string, revision int64, rows []ArtifactCatalogRow) error {
	// Tests name a process with a string; the wire carries the authority's
	// fencing token, so map each distinct name to a distinct epoch.
	epoch := int64(1)
	if n, err := strconv.Atoi(strings.TrimPrefix(incarnation, "inc-")); err == nil {
		epoch = int64(n)
	} else if incarnation != "" {
		epoch = int64(len(incarnation))
	}
	for _, chunk := range ChunkArtifactCatalogSnapshot(kind, nodeID, epoch, revision, rows) {
		if err := c.PublishArtifactCatalog(ctx, chunk); err != nil {
			return err
		}
	}
	return nil
}

// Publishes are validated before they reach the log, and the chunk caps are
// aligned with what the apply transport actually accepts: a whole inventory
// of ordinary rows is far larger than one command may carry.
func TestArtifactCatalogPublishIsBounded(t *testing.T) {
	c, cleanup := newTestCluster(t, "srv-catalog-bounds", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	ctx := context.Background()

	valid := ArtifactCatalogSnapshot{Kind: ArtifactKindTemplate, NodeID: "worker", Epoch: 1, Revision: 1, First: true, Final: true}

	bad := valid
	bad.Kind = "not-a-kind"
	if err := c.PublishArtifactCatalog(ctx, bad); err == nil {
		t.Fatal("unknown catalogue kind accepted")
	}
	bad = valid
	bad.NodeID = ""
	if err := c.PublishArtifactCatalog(ctx, bad); err == nil {
		t.Fatal("publish without a node id accepted")
	}
	bad = valid
	bad.Epoch = 0
	if err := c.PublishArtifactCatalog(ctx, bad); err == nil {
		t.Fatal("publish without a publisher epoch accepted")
	}
	bad = valid
	bad.Revision = 0
	if err := c.PublishArtifactCatalog(ctx, bad); err == nil {
		t.Fatal("publish without a revision accepted")
	}
	bad = valid
	bad.Rows = make([]ArtifactCatalogRow, MaxArtifactCatalogChunkRows+1)
	for i := range bad.Rows {
		bad.Rows[i] = ArtifactCatalogRow{ID: fmt.Sprintf("r-%d", i)}
	}
	if err := c.PublishArtifactCatalog(ctx, bad); err == nil {
		t.Fatalf("a chunk of %d rows was accepted", len(bad.Rows))
	}
	bad = valid
	bad.Rows = []ArtifactCatalogRow{{ID: "fat", Payload: make([]byte, maxArtifactCatalogRowBytes+1)}}
	if err := c.PublishArtifactCatalog(ctx, bad); err == nil {
		t.Fatal("an oversized row was accepted")
	}
}

// The catalogue must survive log compaction, or a restarted leader would send
// every list back to the fleet-wide sweep.
func TestArtifactCatalogSurvivesSnapshotRestore(t *testing.T) {
	fsm := newPlacementFSM()
	seedCommittedCatalog(fsm, ArtifactKindJSBundle, "worker-a", 1, 1,
		ArtifactCatalogRow{ID: "sha256-aaa", Tenant: "tenant-a", Payload: []byte(`{"digest":"aaa"}`)})

	snap, err := fsm.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	sink := &fakeSnapshotSink{Buffer: &bytes.Buffer{}}
	if err := snap.Persist(sink); err != nil {
		t.Fatalf("persist: %v", err)
	}
	restored := newPlacementFSM()
	if err := restored.Restore(io.NopCloser(sink.Buffer)); err != nil {
		t.Fatalf("restore: %v", err)
	}
	page := restored.artifactCatalogPage(ArtifactCatalogRequest{Kind: ArtifactKindJSBundle, Tenant: "tenant-a"})
	if len(page.Rows) != 1 || page.Rows[0].ID != "sha256-aaa" || len(page.Publishers) != 1 {
		t.Fatalf("restored catalogue = %+v", page)
	}
}

// A worker holds no FSM, so both sides of the catalogue are RPCs. The write
// rides the same leader-forwarded apply path as every other agent write; the
// read must refuse a non-authoritative answer rather than report a tenant's
// artifacts as absent.
func TestAgentArtifactCatalogRoundTrip(t *testing.T) {
	var published []ArtifactCatalogSnapshot
	var lastRead ArtifactCatalogRequest
	authoritative := true
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case PublicInternalApplyPath, InternalAPIPath:
			body, _ := io.ReadAll(r.Body)
			cmd, err := decodeCommand(body)
			if err != nil {
				t.Errorf("decode forwarded command: %v", err)
				return
			}
			published = append(published, ArtifactCatalogSnapshot{
				Kind: cmd.ArtifactKind, NodeID: cmd.NodeID, Epoch: cmd.ArtifactEpoch,
				Revision: cmd.ArtifactRevision, Rows: cmd.ArtifactRows,
				First: cmd.ArtifactChunkFirst, Final: cmd.ArtifactChunkFinal,
			})
			w.WriteHeader(http.StatusNoContent)
		case PublicInternalArtifactCatalogPath:
			if err := json.NewDecoder(r.Body).Decode(&lastRead); err != nil {
				t.Errorf("decode read request: %v", err)
				return
			}
			_ = json.NewEncoder(w).Encode(ArtifactCatalogPage{
				Rows:          []ArtifactCatalogRow{{ID: "sha256-aaa", Payload: []byte(`{}`)}},
				Publishers:    []string{"worker-self"},
				Authoritative: authoritative,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	ctx := context.Background()

	rows := []ArtifactCatalogRow{{ID: "sha256-aaa", Tenant: "tenant-a", Payload: []byte(`{}`)}}
	for _, chunk := range ChunkArtifactCatalogSnapshot(ArtifactKindJSBundle, "worker-self", 7, 7, rows) {
		if err := agent.PublishArtifactCatalog(ctx, chunk); err != nil {
			t.Fatalf("PublishArtifactCatalog: %v", err)
		}
	}
	if len(published) != 1 || published[0].Kind != ArtifactKindJSBundle || published[0].NodeID != "worker-self" {
		t.Fatalf("forwarded publish = %+v", published)
	}
	if published[0].Epoch != 7 || published[0].Revision != 7 || !published[0].First || !published[0].Final {
		t.Fatalf("forwarded publish lost its version or its chunk framing: %+v", published[0])
	}
	if len(published[0].Rows) != 1 || published[0].Rows[0].Tenant != "tenant-a" {
		t.Fatalf("forwarded rows = %+v; tenancy rides the row so coverage can answer for an empty tenant", published[0].Rows)
	}
	bogus := ArtifactCatalogSnapshot{Kind: "bogus", NodeID: "worker-self", Epoch: 1, Revision: 1, First: true, Final: true}
	if err := agent.PublishArtifactCatalog(ctx, bogus); err == nil {
		t.Fatal("an unknown catalogue kind was forwarded to the control plane")
	}

	page, err := agent.ArtifactCatalog(ctx, ArtifactCatalogRequest{Kind: ArtifactKindJSBundle, Tenant: "tenant-a"})
	if err != nil {
		t.Fatalf("ArtifactCatalog: %v", err)
	}
	if len(page.Rows) != 1 || len(page.Publishers) != 1 {
		t.Fatalf("page = %+v", page)
	}
	if lastRead.Tenant != "tenant-a" {
		t.Fatalf("read request tenant = %q; a worker must ask for its caller's tenant only", lastRead.Tenant)
	}

	authoritative = false
	if _, err := agent.ArtifactCatalog(ctx, ArtifactCatalogRequest{Kind: ArtifactKindJSBundle, Tenant: "tenant-a"}); err == nil {
		t.Fatal("a non-authoritative catalogue answer was accepted; the caller would report a tenant's bundles as absent")
	}
}

// The peer-facing read is what a worker calls; it must carry the publishers
// so the aggregator knows which nodes it still has to ask.
func TestArtifactCatalogForPeerCarriesPublishers(t *testing.T) {
	fsm := newPlacementFSM()
	seedCommittedCatalog(fsm, ArtifactKindTemplate, "worker-a", 1, 1, ArtifactCatalogRow{ID: "tpl-1", Payload: []byte(`{}`)})
	c := &Cluster{fsm: fsm}

	page := c.ArtifactCatalogForPeer(ArtifactCatalogRequest{Kind: ArtifactKindTemplate})
	if !page.Authoritative || len(page.Rows) != 1 || len(page.Publishers) != 1 || page.Publishers[0] != "worker-a" {
		t.Fatalf("peer page = %+v", page)
	}
	var none *Cluster
	if page := none.ArtifactCatalogForPeer(ArtifactCatalogRequest{Kind: ArtifactKindTemplate}); page.Authoritative {
		t.Fatal("a node with no placement state claimed an authoritative catalogue")
	}
}

// The catalogue is answered over the same response ceiling as a placement
// page, and it grows with the fleet's artifacts. Publishers that do not fit
// are left out WHOLE, so the aggregator keeps asking them rather than
// believing a partial slice is their whole inventory.
// seedCommittedCatalog installs a committed snapshot directly, for tests that
// are about the read side rather than the publish protocol.
func seedCommittedCatalog(fsm *placementFSM, kind, nodeID string, epoch, revision int64, rows ...ArtifactCatalogRow) {
	state := fsm.artifactCatalog[artifactCatalogKindKey(kind)]
	if state == nil {
		state = &artifactCatalogKindState{
			Committed: map[string]artifactCatalogNodeState{},
			Pending:   map[string]artifactCatalogNodeState{},
		}
		fsm.artifactCatalog[artifactCatalogKindKey(kind)] = state
	}
	byKey := make(map[string]ArtifactCatalogRow, len(rows))
	for _, row := range rows {
		byKey[artifactCatalogRowKey(row.Tenant, row.ID)] = row
	}
	state.Committed[nodeID] = artifactCatalogNodeState{Epoch: epoch, Revision: revision, Rows: byKey}
}

// The catalogue is answered over the same response ceiling as a placement
// page, and it grows with the fleet's artifacts. A single response budget
// with the remainder dropped sent most of a large fleet back to the peer
// sweep even though the FSM already held its metadata — so the read is paged,
// and the cursor carries what a page cannot.
func TestArtifactCatalogReadIsPagedNotTruncated(t *testing.T) {
	fsm := newPlacementFSM()
	const (
		nodes        = 32
		rowsPerNode  = 64
		expectedRows = nodes * rowsPerNode
	)
	for i := range nodes {
		rows := make([]ArtifactCatalogRow, 0, rowsPerNode)
		for j := range rowsPerNode {
			rows = append(rows, ArtifactCatalogRow{
				ID:      fmt.Sprintf("tpl-%02d-%02d", i, j),
				Payload: make([]byte, maxArtifactCatalogRowBytes),
			})
		}
		seedCommittedCatalog(fsm, ArtifactKindTemplate, fmt.Sprintf("worker-%02d", i), 1, 1, rows...)
	}

	seen := map[string]struct{}{}
	token := ""
	pages := 0
	for {
		page := fsm.artifactCatalogPage(ArtifactCatalogRequest{Kind: ArtifactKindTemplate, PageToken: token})
		pages++
		if len(page.Publishers) != nodes {
			t.Fatalf("page %d lists %d publishers, want all %d; coverage is a property of the kind, not of the page",
				pages, len(page.Publishers), nodes)
		}
		payload, err := json.Marshal(page)
		if err != nil {
			t.Fatalf("marshal page: %v", err)
		}
		if len(payload) > maxControlPlaneJSONResponseBytes {
			t.Fatalf("page %d encodes to %d bytes, past the %d ceiling", pages, len(payload), maxControlPlaneJSONResponseBytes)
		}
		for _, row := range page.Rows {
			if _, dup := seen[row.ID]; dup {
				t.Fatalf("row %s was returned twice across pages", row.ID)
			}
			seen[row.ID] = struct{}{}
		}
		if page.NextPageToken == "" || page.NextPageToken == token {
			break
		}
		token = page.NextPageToken
		if pages > 64 {
			t.Fatal("the walk did not terminate")
		}
	}
	if pages < 2 {
		t.Fatal("the fixture no longer needs more than one page")
	}
	if len(seen) != expectedRows {
		t.Fatalf("the paged walk returned %d of %d rows; a truncated read sends the rest back to the peer sweep", len(seen), expectedRows)
	}
}

// The FSM validates every new command before it mutates state: a replayed or
// forged entry must be refused deterministically on every replica, not
// applied on some and rejected on others.
func TestReplicatedRegistryCommandValidation(t *testing.T) {
	fsm := newPlacementFSM()
	apply := func(cmd command) error {
		raw, err := encodeCommand(cmd)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		resp := fsm.Apply(&raft.Log{Data: raw})
		if err, ok := resp.(error); ok {
			return err
		}
		return nil
	}

	publish := func(cmd command) command {
		cmd.Op = opPublishArtifactCatalog
		if cmd.ArtifactEpoch == 0 {
			cmd.ArtifactEpoch = 1
		}
		if cmd.ArtifactRevision == 0 {
			cmd.ArtifactRevision = 1
		}
		cmd.ArtifactChunkFirst, cmd.ArtifactChunkFinal = true, true
		return cmd
	}

	if err := apply(publish(command{NodeID: "worker-a"})); err == nil {
		t.Fatal("a publish with no kind was applied")
	}
	if err := apply(publish(command{ArtifactKind: ArtifactKindTemplate})); err == nil {
		t.Fatal("a publish with no node id was applied")
	}
	if err := apply(publish(command{ArtifactKind: ArtifactKindTemplate, NodeID: "worker-a", ArtifactEpoch: -1})); err == nil {
		t.Fatal("a publish with no publisher epoch was applied")
	}
	over := make([]ArtifactCatalogRow, MaxArtifactCatalogChunkRows+1)
	for i := range over {
		over[i] = ArtifactCatalogRow{ID: fmt.Sprintf("r-%d", i)}
	}
	if err := apply(publish(command{ArtifactKind: ArtifactKindTemplate, NodeID: "worker-a", ArtifactRows: over})); err == nil {
		t.Fatalf("a chunk of %d rows was applied", len(over))
	}
	// Rows that are individually unusable are dropped, not the whole publish.
	if err := apply(publish(command{ArtifactKind: ArtifactKindTemplate, NodeID: "worker-a", ArtifactRows: []ArtifactCatalogRow{
		{ID: " ", Payload: []byte(`{}`)},
		{ID: "fat", Payload: make([]byte, maxArtifactCatalogRowBytes+1)},
		{ID: "good", Payload: []byte(`{}`)},
	}})); err != nil {
		t.Fatalf("publish with unusable rows: %v", err)
	}
	page := fsm.artifactCatalogPage(ArtifactCatalogRequest{Kind: ArtifactKindTemplate})
	if len(page.Rows) != 1 || page.Rows[0].ID != "good" {
		t.Fatalf("catalogue = %+v, want only the usable row", page.Rows)
	}

	if err := apply(command{Op: opRetireNodeStorage}); err == nil {
		t.Fatal("an attestation with no node id was applied")
	}
	if err := apply(command{Op: opRetireNodeStorage, NodeID: "node-gone"}); err == nil {
		t.Fatal("an attestation with no record was applied")
	}
	if err := apply(command{Op: opRevokeNodeStorage}); err == nil {
		t.Fatal("a revoke with no node id was applied")
	}
	// Revoking something that was never attested is a no-op, not an error.
	if err := apply(command{Op: opRevokeNodeStorage, NodeID: "never-attested"}); err != nil {
		t.Fatalf("revoke of an absent attestation: %v", err)
	}

	for _, id := range []string{"node-b", "node-a"} {
		if err := apply(command{Op: opRetireNodeStorage, NodeID: id, StorageRetirement: &NodeStorageRetirement{NodeID: id, AttestedUnixNano: 5}}); err != nil {
			t.Fatalf("attest %s: %v", id, err)
		}
	}
	got := fsm.nodeStorageRetirementsSnapshot()
	if len(got) != 2 || got[0].NodeID != "node-a" || got[1].NodeID != "node-b" {
		t.Fatalf("snapshot = %+v, want a stable order", got)
	}
}

// A single row larger than the whole page budget cannot be delivered at all.
// It is named rather than silently dropped, and the walk still progresses.
func TestPlacementPageNamesAnUndeliverableRow(t *testing.T) {
	fsm := newPlacementFSM()
	// Big enough that the row alone cannot fit the page budget. Validation
	// caps custom domains long before this, which is why the branch is
	// defensive — but a row that cannot be delivered must still be named
	// rather than silently dropped from a caller's view.
	hosts := make([]string, 0, 200_000)
	for i := range 200_000 {
		hosts = append(hosts, fmt.Sprintf("h%d.%s.example.com", i, strings.Repeat("a", 63)))
	}
	huge := Placement{SandboxID: "sb-000000", OwnerNodeID: "worker", CustomHostnames: hosts}
	if encodedPlacementSize(huge) <= placementPageByteBudget {
		t.Fatal("the fixture row fits the budget; it no longer models an undeliverable record")
	}
	for i := range 40 {
		// The oversized row sorts first; ordinary rows follow it.
		p := Placement{SandboxID: fmt.Sprintf("sb-%06d", i+1), OwnerNodeID: "worker"}
		fsm.placements[p.SandboxID] = p
		fsm.placementIDs.ReplaceOrInsert(p.SandboxID)
	}
	fsm.placements[huge.SandboxID] = huge
	fsm.placementIDs.ReplaceOrInsert(huge.SandboxID)

	// Shrink the effective budget by asking for one row at a time: the first
	// page holds only the oversized row, so it cannot be delivered.
	page := fsm.placementPage(PlacementPageRequest{Limit: 1})
	if len(page.SkippedSandboxIDs) == 0 {
		t.Fatalf("an undeliverable row was not named; callers read its absence as deletion (page=%d rows)", len(page.Placements))
	}
	if page.SkippedSandboxIDs[0] != huge.SandboxID {
		t.Fatalf("skipped = %v, want the undeliverable row named", page.SkippedSandboxIDs)
	}
	if page.NextPageToken == "" {
		t.Fatal("the walk cannot progress past an undeliverable row")
	}
}

// A snapshot is delivered in chunks because one node's inventory is allowed
// to be far larger than a raft command: 4,096 ordinary rows encode to ~1.6 MB
// against a 1 MiB apply cap, so publishing it whole was refused and the node
// kept serving whatever it had published before.
func TestArtifactCatalogChunksFitTheApplyTransport(t *testing.T) {
	// Ordinary bundle metadata, not maximum-sized or malformed rows: a
	// content digest, its module ref, a name, an entrypoint and a size.
	rows := make([]ArtifactCatalogRow, 0, maxArtifactCatalogRowsPerNode)
	for i := range maxArtifactCatalogRowsPerNode {
		digest := fmt.Sprintf("%064x", i)
		payload, err := json.Marshal(models.JSBundle{
			Digest:     digest,
			ModuleRef:  "sha256:" + digest,
			Name:       fmt.Sprintf("handler-%04d", i),
			MainModule: "index.js",
			SizeBytes:  int64(4096 + i),
		})
		if err != nil {
			t.Fatalf("encode bundle %d: %v", i, err)
		}
		rows = append(rows, ArtifactCatalogRow{ID: digest, Tenant: "tenant-a", Payload: payload})
	}

	// The shape the previous implementation sent: one command carrying the
	// whole inventory. It is ordinary metadata, not maximum-sized rows.
	whole, err := encodeCommand(artifactCatalogCommand(ArtifactCatalogSnapshot{
		Kind: ArtifactKindJSBundle, NodeID: "worker-a", Epoch: 1, Revision: 1,
		Rows: rows, First: true, Final: true,
	}))
	if err != nil {
		t.Fatalf("encode whole inventory: %v", err)
	}
	if len(whole) <= maxInternalApplyBytes {
		t.Fatalf("the fixture inventory encodes to %d bytes, inside the %d apply cap; it no longer models the case",
			len(whole), maxInternalApplyBytes)
	}

	chunks := ChunkArtifactCatalogSnapshot(ArtifactKindJSBundle, "worker-a", 1, 3, rows)
	if len(chunks) < 2 {
		t.Fatal("the fixture no longer needs chunking")
	}
	if !chunks[0].First || chunks[0].Final {
		t.Fatalf("first chunk framing = %+v", chunks[0])
	}
	if last := chunks[len(chunks)-1]; !last.Final || last.First {
		t.Fatalf("last chunk framing = %+v", last)
	}
	seen := 0
	for i, chunk := range chunks {
		encoded, encErr := encodeCommand(artifactCatalogCommand(chunk))
		if encErr != nil {
			t.Fatalf("encode chunk %d: %v", i, encErr)
		}
		// maxInternalApplyBytes is what the apply handler and the internal
		// listener enforce; a command over it never reaches the FSM.
		if len(encoded) > maxInternalApplyBytes {
			t.Fatalf("chunk %d encodes to %d bytes, over the %d apply cap", i, len(encoded), maxInternalApplyBytes)
		}
		if err := validateArtifactCatalogChunk(chunk); err != nil {
			t.Fatalf("chunk %d failed its own validation: %v", i, err)
		}
		seen += len(chunk.Rows)
	}
	if seen != len(rows) {
		t.Fatalf("chunking carried %d of %d rows", seen, len(rows))
	}
}

// An inventory that is empty is still a statement — "this node holds nothing
// of this kind" — and losing it is what keeps a tenant with no artifacts
// anywhere asking every compatible worker on every cold list.
func TestArtifactCatalogPublishesAnEmptyInventory(t *testing.T) {
	c, cleanup := newTestCluster(t, "srv-empty-catalog", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	ctx := context.Background()

	chunks := ChunkArtifactCatalogSnapshot(ArtifactKindJSBundle, "worker-empty", 1, 1, nil)
	if len(chunks) != 1 || !chunks[0].First || !chunks[0].Final {
		t.Fatalf("an empty inventory must still be one framed publication: %+v", chunks)
	}
	if err := c.PublishArtifactCatalog(ctx, chunks[0]); err != nil {
		t.Fatalf("publish empty inventory: %v", err)
	}

	page, err := c.ArtifactCatalog(ctx, ArtifactCatalogRequest{Kind: ArtifactKindJSBundle, Tenant: "tenant-with-nothing"})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Rows) != 0 {
		t.Fatalf("rows = %+v, want none", page.Rows)
	}
	if len(page.Publishers) != 1 || page.Publishers[0] != "worker-empty" {
		t.Fatalf("publishers = %v; a node that published an empty inventory has answered for every tenant", page.Publishers)
	}
}

// Two publications can reach the log in the opposite order to the one their
// inventories were read in. The older one must not win, and the publisher
// must be told so rather than believing it is published.
func TestArtifactCatalogFencesOutOfOrderPublications(t *testing.T) {
	c, cleanup := newTestCluster(t, "srv-catalog-order", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	ctx := context.Background()

	if err := publishAtEpoch(ctx, c, ArtifactKindTemplate, "worker-a", 1, 2, catalogRows("", "tpl-new")); err != nil {
		t.Fatal(err)
	}
	// The older read lands afterwards.
	err := publishAtEpoch(ctx, c, ArtifactKindTemplate, "worker-a", 1, 1, catalogRows("", "tpl-old"))
	if !strings.Contains(fmt.Sprint(err), "superseded") {
		t.Fatalf("a late older publication returned %v; the publisher would mark itself clean", err)
	}
	page, err := c.ArtifactCatalog(ctx, ArtifactCatalogRequest{Kind: ArtifactKindTemplate})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Rows) != 1 || page.Rows[0].ID != "tpl-new" {
		t.Fatalf("catalogue = %+v; a late older publication overwrote newer state", page.Rows)
	}

	// The node restarts: it takes the next epoch from the authority and its
	// revisions start again, which must still outrank everything before it.
	epoch, err := c.AllocateArtifactCatalogEpoch(ctx, ArtifactKindTemplate, "worker-a", "restarted-process")
	if err != nil {
		t.Fatal(err)
	}
	if err := publishAtEpoch(ctx, c, ArtifactKindTemplate, "worker-a", epoch, 1, catalogRows("", "tpl-after-restart")); err != nil {
		t.Fatal(err)
	}
	page, err = c.ArtifactCatalog(ctx, ArtifactCatalogRequest{Kind: ArtifactKindTemplate})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Rows) != 1 || page.Rows[0].ID != "tpl-after-restart" {
		t.Fatalf("catalogue = %+v; a restarted publisher was fenced by its dead process's revisions", page.Rows)
	}
}

// A snapshot interrupted between chunks must leave the previous committed
// answer standing: committing what arrived would advertise half an inventory
// as a node's whole one, and the aggregator stops asking a node it covers.
func TestArtifactCatalogDoesNotCommitAHalfDeliveredSnapshot(t *testing.T) {
	c, cleanup := newTestCluster(t, "srv-catalog-partial", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	ctx := context.Background()

	if err := publishWholeCatalog(ctx, c, ArtifactKindTemplate, "worker-a", "inc-1", 1, catalogRows("", "tpl-a", "tpl-b")); err != nil {
		t.Fatal(err)
	}
	// A new snapshot starts but never finishes.
	partial := ArtifactCatalogSnapshot{
		Kind: ArtifactKindTemplate, NodeID: "worker-a", Epoch: 1, Revision: 2,
		Rows: catalogRows("", "tpl-c"), First: true,
	}
	if err := c.PublishArtifactCatalog(ctx, partial); err != nil {
		t.Fatal(err)
	}

	page, err := c.ArtifactCatalog(ctx, ArtifactCatalogRequest{Kind: ArtifactKindTemplate})
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]struct{}{}
	for _, row := range page.Rows {
		ids[row.ID] = struct{}{}
	}
	if len(ids) != 2 {
		t.Fatalf("catalogue = %v; a half-delivered snapshot became the node's advertised inventory", ids)
	}
	if _, leaked := ids["tpl-c"]; leaked {
		t.Fatal("an uncommitted chunk is visible to readers")
	}

	// Finishing the sequence commits it as a whole.
	final := partial
	final.First, final.Final = false, true
	final.Rows = catalogRows("", "tpl-d")
	if err := c.PublishArtifactCatalog(ctx, final); err != nil {
		t.Fatal(err)
	}
	page, err = c.ArtifactCatalog(ctx, ArtifactCatalogRequest{Kind: ArtifactKindTemplate})
	if err != nil {
		t.Fatal(err)
	}
	ids = map[string]struct{}{}
	for _, row := range page.Rows {
		ids[row.ID] = struct{}{}
	}
	if len(ids) != 2 {
		t.Fatalf("committed catalogue = %v, want exactly the new snapshot's rows", ids)
	}
	if _, ok := ids["tpl-c"]; !ok {
		t.Fatalf("committed catalogue = %v, missing the snapshot's first chunk", ids)
	}
	if _, ok := ids["tpl-d"]; !ok {
		t.Fatalf("committed catalogue = %v, missing the snapshot's final chunk", ids)
	}
}

// A continuation chunk with nothing to attach to — its snapshot was never
// started here, or a newer one replaced it — is dropped rather than folded
// into whatever is pending. Committing it would publish a mix of two
// inventories as one node's current state.
func TestArtifactCatalogDropsOrphanedChunks(t *testing.T) {
	fsm := newPlacementFSM()
	applyResult := func(chunk ArtifactCatalogSnapshot) error {
		t.Helper()
		raw, err := encodeCommand(artifactCatalogCommand(chunk))
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		if resp := fsm.Apply(&raft.Log{Data: raw}); resp != nil {
			if err, ok := resp.(error); ok {
				return err
			}
		}
		return nil
	}
	apply := func(chunk ArtifactCatalogSnapshot) {
		t.Helper()
		if err := applyResult(chunk); err != nil {
			t.Fatalf("apply: %v", err)
		}
	}

	// A continuation whose snapshot was never started must not be
	// acknowledged: success would tell the publisher its revision is
	// published and stop it retrying.
	if err := applyResult(ArtifactCatalogSnapshot{
		Kind: ArtifactKindTemplate, NodeID: "worker-a", Epoch: 1, Revision: 1,
		Rows: catalogRows("", "orphan"), Final: true,
	}); err == nil {
		t.Fatal("a continuation chunk with no pending snapshot was acknowledged as published")
	}
	if page := fsm.artifactCatalogPage(ArtifactCatalogRequest{Kind: ArtifactKindTemplate}); len(page.Rows) != 0 {
		t.Fatalf("an orphaned chunk was committed: %+v", page.Rows)
	}

	// A snapshot starts, then a NEWER one starts before the first finishes:
	// the stale continuation must not join the new pending snapshot.
	apply(ArtifactCatalogSnapshot{
		Kind: ArtifactKindTemplate, NodeID: "worker-a", Epoch: 1, Revision: 2,
		Rows: catalogRows("", "old-first"), First: true,
	})
	apply(ArtifactCatalogSnapshot{
		Kind: ArtifactKindTemplate, NodeID: "worker-a", Epoch: 1, Revision: 3,
		Rows: catalogRows("", "new-first"), First: true,
	})
	// The superseded publication's final chunk is refused, not acknowledged:
	// none of its inventory is committed, so telling its publisher otherwise
	// would leave the node advertising an inventory it never published.
	if err := applyResult(ArtifactCatalogSnapshot{
		Kind: ArtifactKindTemplate, NodeID: "worker-a", Epoch: 1, Revision: 2,
		Rows: catalogRows("", "old-final"), Final: true,
	}); err == nil {
		t.Fatal("a superseded publication's final chunk was acknowledged as published")
	}
	if page := fsm.artifactCatalogPage(ArtifactCatalogRequest{Kind: ArtifactKindTemplate}); len(page.Rows) != 0 {
		t.Fatalf("a superseded snapshot's final chunk committed: %+v", page.Rows)
	}

	// The current snapshot still completes normally.
	apply(ArtifactCatalogSnapshot{
		Kind: ArtifactKindTemplate, NodeID: "worker-a", Epoch: 1, Revision: 3,
		Rows: catalogRows("", "new-final"), Final: true,
	})
	page := fsm.artifactCatalogPage(ArtifactCatalogRequest{Kind: ArtifactKindTemplate})
	ids := map[string]struct{}{}
	for _, row := range page.Rows {
		ids[row.ID] = struct{}{}
	}
	if len(ids) != 2 {
		t.Fatalf("committed = %v, want exactly the current snapshot's two chunks", ids)
	}
	if _, ok := ids["old-first"]; ok {
		t.Fatalf("committed = %v; a superseded snapshot's rows leaked into the current one", ids)
	}
}

// The chunk byte cap is what keeps a command inside the apply transport even
// when its row COUNT is legal.
func TestArtifactCatalogChunkByteCapIsEnforced(t *testing.T) {
	rows := make([]ArtifactCatalogRow, 0, 64)
	for i := range 64 {
		rows = append(rows, ArtifactCatalogRow{ID: fmt.Sprintf("r-%02d", i), Payload: make([]byte, maxArtifactCatalogRowBytes)})
	}
	chunk := ArtifactCatalogSnapshot{
		Kind: ArtifactKindTemplate, NodeID: "worker-a", Epoch: 1, Revision: 1,
		Rows: rows, First: true, Final: true,
	}
	if len(chunk.Rows) > MaxArtifactCatalogChunkRows {
		t.Fatal("the fixture is over the row cap, so it would be refused for the wrong reason")
	}
	if err := validateArtifactCatalogChunk(chunk); err == nil {
		t.Fatal("a chunk inside the row cap but over the byte cap was accepted; it would be refused by the apply transport instead")
	}
	// The chunker never produces one.
	for _, produced := range ChunkArtifactCatalogSnapshot(ArtifactKindTemplate, "worker-a", 1, 1, rows) {
		if err := validateArtifactCatalogChunk(produced); err != nil {
			t.Fatalf("the chunker produced an invalid chunk: %v", err)
		}
	}
}

// JS bundle ids are CONTENT digests, so two tenants uploading identical
// content legitimately hold the same id on one worker. Keying the inventory
// by id alone let the second row erase the first while the catalogue kept
// claiming the worker covered both tenants — so the aggregator never asked it
// for the row it had dropped.
func TestArtifactCatalogKeepsIdenticalDigestsForDifferentTenants(t *testing.T) {
	c, cleanup := newTestCluster(t, "srv-digest-collision", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	ctx := context.Background()

	const digest = "sha256-identical-content"
	rows := []ArtifactCatalogRow{
		{ID: digest, Tenant: "tenant-a", Payload: []byte(`{"digest":"identical","tenant":"a"}`)},
		{ID: digest, Tenant: "tenant-b", Payload: []byte(`{"digest":"identical","tenant":"b"}`)},
	}
	if err := publishWholeCatalog(ctx, c, ArtifactKindJSBundle, "worker-a", "inc-1", 1, rows); err != nil {
		t.Fatal(err)
	}

	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		page, err := c.ArtifactCatalog(ctx, ArtifactCatalogRequest{Kind: ArtifactKindJSBundle, Tenant: tenant})
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Rows) != 1 {
			t.Fatalf("%s reads %d rows, want its own copy of the shared digest", tenant, len(page.Rows))
		}
		if len(page.Publishers) != 1 {
			t.Fatalf("%s publishers = %v", tenant, page.Publishers)
		}
	}
}

// A raft snapshot taken BETWEEN chunks must replay the log suffix to the same
// state as a replica that never restored it. Persisting only the committed
// snapshots meant the restored replica silently dropped the publication while
// the others committed it — and the publisher was told it succeeded.
func TestArtifactCatalogSnapshotBetweenChunksReplaysIdentically(t *testing.T) {
	apply := func(fsm *placementFSM, chunk ArtifactCatalogSnapshot) {
		t.Helper()
		raw, err := encodeCommand(artifactCatalogCommand(chunk))
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		if resp := fsm.Apply(&raft.Log{Data: raw}); resp != nil {
			if err, ok := resp.(error); ok {
				t.Fatalf("apply: %v", err)
			}
		}
	}
	seed := func(fsm *placementFSM) {
		for _, chunk := range ChunkArtifactCatalogSnapshot(ArtifactKindTemplate, "worker-a", 1, 1, catalogRows("", "tpl-old")) {
			apply(fsm, chunk)
		}
	}

	uninterrupted := newPlacementFSM()
	seed(uninterrupted)
	interrupted := newPlacementFSM()
	seed(interrupted)

	first := ArtifactCatalogSnapshot{
		Kind: ArtifactKindTemplate, NodeID: "worker-a", Epoch: 1, Revision: 2,
		Rows: catalogRows("", "tpl-new-1"), First: true,
	}
	final := ArtifactCatalogSnapshot{
		Kind: ArtifactKindTemplate, NodeID: "worker-a", Epoch: 1, Revision: 2,
		Rows: catalogRows("", "tpl-new-2"), Final: true,
	}
	apply(uninterrupted, first)
	apply(interrupted, first)

	// The interrupted replica snapshots here — between the chunks — and is
	// restored from it, then replays the same final command.
	snap, err := interrupted.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	sink := &fakeSnapshotSink{Buffer: &bytes.Buffer{}}
	if err := snap.Persist(sink); err != nil {
		t.Fatalf("persist: %v", err)
	}
	restored := newPlacementFSM()
	if err := restored.Restore(io.NopCloser(sink.Buffer)); err != nil {
		t.Fatalf("restore: %v", err)
	}
	apply(uninterrupted, final)
	apply(restored, final)

	want := map[string]struct{}{}
	for _, row := range uninterrupted.artifactCatalogPage(ArtifactCatalogRequest{Kind: ArtifactKindTemplate}).Rows {
		want[row.ID] = struct{}{}
	}
	got := map[string]struct{}{}
	for _, row := range restored.artifactCatalogPage(ArtifactCatalogRequest{Kind: ArtifactKindTemplate}).Rows {
		got[row.ID] = struct{}{}
	}
	if len(want) != 2 {
		t.Fatalf("the uninterrupted replica holds %v; the fixture no longer models a two-chunk publication", want)
	}
	if len(got) != len(want) {
		t.Fatalf("restored replica holds %v, the uninterrupted one holds %v; a snapshot between chunks diverged permanently", got, want)
	}
	for id := range want {
		if _, ok := got[id]; !ok {
			t.Fatalf("restored replica is missing %s", id)
		}
	}
}

// A UUID identifies a process but does not ORDER processes: treating any
// different identifier as newer let a request delayed in transport from a
// process that has already been replaced take ownership back and republish
// its obsolete inventory. The new process has marked itself clean, so nothing
// corrects it.
func TestArtifactCatalogFencesASupersededPublisher(t *testing.T) {
	c, cleanup := newTestCluster(t, "srv-fencing", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	ctx := context.Background()

	// The old process publishes, then dies.
	oldEpoch, err := c.AllocateArtifactCatalogEpoch(ctx, ArtifactKindTemplate, "worker-a", "old-process")
	if err != nil {
		t.Fatal(err)
	}
	if err := publishAtEpoch(ctx, c, ArtifactKindTemplate, "worker-a", oldEpoch, 8, catalogRows("", "tpl-deleted")); err != nil {
		t.Fatal(err)
	}

	// The new process asks the authority for its fencing token and publishes.
	newEpoch, err := c.AllocateArtifactCatalogEpoch(ctx, ArtifactKindTemplate, "worker-a", "new-process")
	if err != nil {
		t.Fatal(err)
	}
	if newEpoch <= oldEpoch {
		t.Fatalf("the authority handed out epoch %d after %d; a restart must be able to supersede", newEpoch, oldEpoch)
	}
	if err := publishAtEpoch(ctx, c, ArtifactKindTemplate, "worker-a", newEpoch, 1, catalogRows("", "tpl-current")); err != nil {
		t.Fatal(err)
	}

	// A request from the dead process, delayed in transport, arrives now —
	// with a HIGHER revision than the new process has reached.
	err = publishAtEpoch(ctx, c, ArtifactKindTemplate, "worker-a", oldEpoch, 9, catalogRows("", "tpl-deleted"))
	if err == nil {
		t.Fatal("a superseded process's delayed publication was accepted")
	}

	page, err := c.ArtifactCatalog(ctx, ArtifactCatalogRequest{Kind: ArtifactKindTemplate})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Rows) != 1 || page.Rows[0].ID != "tpl-current" {
		t.Fatalf("catalogue = %+v; a superseded process republished its obsolete inventory", page.Rows)
	}
}

func publishAtEpoch(ctx context.Context, c *Cluster, kind, nodeID string, epoch, revision int64, rows []ArtifactCatalogRow) error {
	for _, chunk := range ChunkArtifactCatalogSnapshot(kind, nodeID, epoch, revision, rows) {
		if err := c.PublishArtifactCatalog(ctx, chunk); err != nil {
			return err
		}
	}
	return nil
}

// A node that is permanently gone can never publish the corrective empty
// inventory, so its rows and its coverage would outlive it forever — the
// aggregator keeps skipping a machine that no longer exists and keeps
// merging its artifacts into every list. The operator's terminal attestation
// is the boundary that removes them.
func TestStorageRetirementRemovesTheNodesCatalogueMetadata(t *testing.T) {
	c, cleanup := newTestCluster(t, "srv-catalog-retire", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	ctx := context.Background()

	if err := publishAtEpoch(ctx, c, ArtifactKindTemplate, "worker-gone", 3, 1, catalogRows("", "tpl-on-dead-node")); err != nil {
		t.Fatal(err)
	}
	if err := publishAtEpoch(ctx, c, ArtifactKindTemplate, "worker-live", 1, 1, catalogRows("", "tpl-on-live-node")); err != nil {
		t.Fatal(err)
	}

	if err := c.RetireNodeStorage(ctx, "worker-gone", "operator", "disk destroyed", time.Now()); err != nil {
		t.Fatalf("RetireNodeStorage: %v", err)
	}

	page, err := c.ArtifactCatalog(ctx, ArtifactCatalogRequest{Kind: ArtifactKindTemplate})
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range page.Rows {
		if row.ID == "tpl-on-dead-node" {
			t.Fatal("a destroyed node's artifacts are still advertised")
		}
	}
	if slices.Contains(page.Publishers, "worker-gone") {
		t.Fatal("a destroyed node is still claimed as covering the catalogue, so the aggregator keeps skipping it")
	}
	if !slices.Contains(page.Publishers, "worker-live") {
		t.Fatal("retiring one node dropped another node's coverage")
	}

	// It survives compaction: the removal is state, not a read-time filter.
	snap, err := c.fsm.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	sink := &fakeSnapshotSink{Buffer: &bytes.Buffer{}}
	if err := snap.Persist(sink); err != nil {
		t.Fatal(err)
	}
	restored := newPlacementFSM()
	if err := restored.Restore(io.NopCloser(sink.Buffer)); err != nil {
		t.Fatal(err)
	}
	restoredPage := restored.artifactCatalogPage(ArtifactCatalogRequest{Kind: ArtifactKindTemplate})
	if slices.Contains(restoredPage.Publishers, "worker-gone") {
		t.Fatal("the destroyed node's coverage came back through the snapshot")
	}

	// A request still in flight from the destroyed node must not re-add it.
	if err := publishAtEpoch(ctx, c, ArtifactKindTemplate, "worker-gone", 3, 2, catalogRows("", "tpl-on-dead-node")); err == nil {
		t.Fatal("a delayed publication from a retired node was accepted")
	}

	// If the attestation was wrong and the node comes back, it publishes
	// again under a fresh token.
	epoch, err := c.AllocateArtifactCatalogEpoch(ctx, ArtifactKindTemplate, "worker-gone", "returning-process")
	if err != nil {
		t.Fatal(err)
	}
	if err := publishAtEpoch(ctx, c, ArtifactKindTemplate, "worker-gone", epoch, 1, catalogRows("", "tpl-back")); err != nil {
		t.Fatalf("a returning node could not republish: %v", err)
	}
	page, _ = c.ArtifactCatalog(ctx, ArtifactCatalogRequest{Kind: ArtifactKindTemplate})
	if !slices.Contains(page.Publishers, "worker-gone") {
		t.Fatal("a node that came back and republished is still uncovered")
	}
}

// Token allocation is a raft write, so a non-leader forwards it, a nil
// cluster refuses it, and the agent asks the control plane over its own
// endpoint.
func TestArtifactCatalogEpochAllocationEdges(t *testing.T) {
	ctx := context.Background()

	var none *Cluster
	if _, err := none.AllocateArtifactCatalogEpoch(ctx, ArtifactKindTemplate, "worker-a", "p"); err == nil {
		t.Fatal("a nil cluster issued a token")
	}

	c, cleanup := newTestCluster(t, "srv-epoch-edges", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	for _, tc := range []struct{ name, kind, node, holder string }{
		{"no kind", "", "worker-a", "p"},
		{"no node", ArtifactKindTemplate, "", "p"},
		{"no holder", ArtifactKindTemplate, "worker-a", ""},
	} {
		if _, err := c.AllocateArtifactCatalogEpoch(ctx, tc.kind, tc.node, tc.holder); err == nil {
			t.Fatalf("%s: allocation succeeded", tc.name)
		}
	}

	// Distinct kinds keep distinct ledgers: a template token must not
	// consume a JS-bundle one.
	tpl, err := c.AllocateArtifactCatalogEpoch(ctx, ArtifactKindTemplate, "worker-a", "p")
	if err != nil {
		t.Fatal(err)
	}
	js, err := c.AllocateArtifactCatalogEpoch(ctx, ArtifactKindJSBundle, "worker-a", "p")
	if err != nil {
		t.Fatal(err)
	}
	if tpl != 1 || js != 1 {
		t.Fatalf("template=%d js-bundle=%d; the two catalogues share a ledger", tpl, js)
	}

	// A follower cannot allocate: it forwards, and says so when no leader is
	// reachable.
	follower := &Cluster{nodeID: "srv-follower", raft: c.raft}
	if _, err := follower.forwardArtifactCatalogEpochToLeader(ctx, ArtifactKindTemplate, "some-other-node", "p"); !errors.Is(err, ErrNotLeader) {
		t.Fatalf("a peer's allocation on a non-leader returned %v, want ErrNotLeader", err)
	}

	var noAgent *Agent
	if _, err := noAgent.AllocateArtifactCatalogEpoch(ctx, ArtifactKindTemplate, "n", "p"); err == nil {
		t.Fatal("a nil agent issued a token")
	}
	refusing := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(ArtifactCatalogEpochResponse{Epoch: 0})
	}))
	if _, err := refusing.AllocateArtifactCatalogEpoch(ctx, ArtifactKindTemplate, "worker-self", "p"); err == nil {
		t.Fatal("an empty allocation response was treated as a token")
	}
}

// A voluntary withdrawal removes rows and coverage without raising the epoch,
// so the same publisher can keep going once its inventory fits again.
func TestArtifactCatalogVoluntaryWithdrawalKeepsThePublishersEpoch(t *testing.T) {
	c, cleanup := newTestCluster(t, "srv-withdraw", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	ctx := context.Background()

	if err := publishAtEpoch(ctx, c, ArtifactKindTemplate, "worker-a", 2, 1, catalogRows("", "tpl-a")); err != nil {
		t.Fatal(err)
	}
	if err := c.PublishArtifactCatalog(ctx, WithdrawArtifactCatalogCoverage(ArtifactKindTemplate, "worker-a", 2, 2)); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	page, err := c.ArtifactCatalog(ctx, ArtifactCatalogRequest{Kind: ArtifactKindTemplate})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Rows) != 0 || len(page.Publishers) != 0 {
		t.Fatalf("after withdrawal page = %+v, want no rows and no coverage", page)
	}

	// The same publisher continues under its own epoch.
	if err := publishAtEpoch(ctx, c, ArtifactKindTemplate, "worker-a", 2, 3, catalogRows("", "tpl-b")); err != nil {
		t.Fatalf("republish after withdrawal: %v", err)
	}
	page, _ = c.ArtifactCatalog(ctx, ArtifactCatalogRequest{Kind: ArtifactKindTemplate})
	if len(page.Rows) != 1 || len(page.Publishers) != 1 {
		t.Fatalf("page after republish = %+v", page)
	}
}

// Guards on the catalogue's read and withdrawal helpers: an unknown kind, an
// unknown node, and a pending publication that is ahead of the committed one.
func TestArtifactCatalogReadGuards(t *testing.T) {
	fsm := newPlacementFSM()

	// A kind nobody has published reads as an authoritative empty answer,
	// including its epoch question.
	page := fsm.artifactCatalogPage(ArtifactCatalogRequest{Kind: ArtifactKindTemplate, ForNodeID: "worker-a"})
	if !page.Authoritative || len(page.Rows) != 0 || page.PublisherEpoch != 0 {
		t.Fatalf("unpublished kind = %+v", page)
	}

	// A kind whose only state is a half-delivered publication still answers
	// the epoch question, so the publisher does not reuse a claimed token.
	seedCommittedCatalog(fsm, ArtifactKindJSBundle, "worker-a", 2, 1, ArtifactCatalogRow{ID: "b", Tenant: "t", Payload: []byte(`{}`)})
	state := fsm.artifactCatalog[artifactCatalogKindKey(ArtifactKindJSBundle)]
	state.Pending["worker-a"] = artifactCatalogNodeState{Epoch: 6, Revision: 1, Rows: map[string]ArtifactCatalogRow{}}
	page = fsm.artifactCatalogPage(ArtifactCatalogRequest{Kind: ArtifactKindJSBundle, Tenant: "t", ForNodeID: "worker-a"})
	if page.PublisherEpoch != 6 {
		t.Fatalf("publisher epoch = %d, want the pending publication's 6", page.PublisherEpoch)
	}

	// Withdrawing a node nobody knows is a no-op, and so is withdrawing with
	// a blank id.
	fsm.mu.Lock()
	fsm.withdrawArtifactCatalogCoverageLocked("")
	fsm.withdrawArtifactCatalogCoverageLocked("never-seen")
	fsm.mu.Unlock()
	page = fsm.artifactCatalogPage(ArtifactCatalogRequest{Kind: ArtifactKindJSBundle, Tenant: "t"})
	if len(page.Publishers) != 1 {
		t.Fatalf("withdrawing an unknown node changed coverage: %+v", page.Publishers)
	}

	// Retiring a node whose PENDING publication is ahead raises the watermark
	// past it, not past the older committed one.
	fsm.mu.Lock()
	fsm.withdrawArtifactCatalogCoverageLocked("worker-a")
	fsm.mu.Unlock()
	if got := fsm.artifactCatalogPublisherEpoch(ArtifactKindJSBundle, "worker-a"); got != 7 {
		t.Fatalf("watermark = %d, want one past the pending epoch 6", got)
	}
}

// Fairness bookkeeping: the attempt clock is per peer, retires with the
// membership, and is inert on a nil cache.
func TestCapacityAttemptClockBookkeeping(t *testing.T) {
	c := newCapacityLeaseCache("server", nil, 5*time.Second, nil)
	now := time.Now()

	if got := c.attemptedAt("never"); !got.IsZero() {
		t.Fatalf("an unattempted peer reported %v; it must sort first", got)
	}
	c.recordAttempt("peer-a", now)
	c.recordAttempt("", now)
	if got := c.attemptedAt("peer-a"); !got.Equal(now) {
		t.Fatalf("attempt clock = %v, want %v", got, now)
	}

	// A peer gossip no longer knows about takes its bookkeeping with it.
	c.set("peer-a", step3FatCapacity(), now)
	c.retain(map[string]struct{}{"server": {}})
	if got := c.attemptedAt("peer-a"); !got.IsZero() {
		t.Fatal("a retired peer kept its attempt clock")
	}

	var none *capacityLeaseCache
	none.recordAttempt("peer", now)
	if got := none.attemptedAt("peer"); !got.IsZero() {
		t.Fatal("a nil cache answered an attempt lookup")
	}
}

// Ordering was checked against the COMMITTED state only, so a delayed first
// chunk from an older epoch could still look newer than what was committed
// and reset a newer publication that was mid-assembly. The newer final chunk
// then found a mismatched pending snapshot and returned success anyway — so
// its publisher marked itself clean while none of its inventory was ever
// committed, and the delayed old publication became the catalogue's answer.
func TestArtifactCatalogOrdersAgainstPendingAsWellAsCommitted(t *testing.T) {
	fsm := newPlacementFSM()
	applyResult := func(chunk ArtifactCatalogSnapshot) error {
		t.Helper()
		raw, err := encodeCommand(artifactCatalogCommand(chunk))
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		if resp := fsm.Apply(&raft.Log{Data: raw}); resp != nil {
			if err, ok := resp.(error); ok {
				return err
			}
		}
		return nil
	}
	chunk := func(epoch, revision int64, id string, first, final bool) ArtifactCatalogSnapshot {
		return ArtifactCatalogSnapshot{
			Kind: ArtifactKindTemplate, NodeID: "worker-a", Epoch: epoch, Revision: revision,
			Rows: catalogRows("", id), First: first, Final: final,
		}
	}

	// Committed (epoch 1, revision 1).
	if err := applyResult(chunk(1, 1, "tpl-committed", true, true)); err != nil {
		t.Fatal(err)
	}
	// The current process starts (2,1).
	if err := applyResult(chunk(2, 1, "tpl-new-first", true, false)); err != nil {
		t.Fatal(err)
	}
	// A delayed first chunk from the OLD epoch arrives: newer than what is
	// committed, older than what is being assembled.
	if err := applyResult(chunk(1, 2, "tpl-delayed-first", true, false)); err == nil {
		t.Fatal("a delayed older publication reset a newer pending one")
	}
	// The current process finishes. It must not be told it succeeded unless
	// its inventory is actually committed.
	if err := applyResult(chunk(2, 1, "tpl-new-final", false, true)); err != nil {
		t.Fatalf("the current publication was refused: %v", err)
	}

	page := fsm.artifactCatalogPage(ArtifactCatalogRequest{Kind: ArtifactKindTemplate})
	ids := map[string]struct{}{}
	for _, row := range page.Rows {
		ids[row.ID] = struct{}{}
	}
	if _, ok := ids["tpl-delayed-first"]; ok {
		t.Fatalf("catalogue = %v; the delayed old publication won", ids)
	}
	if _, ok := ids["tpl-new-final"]; !ok {
		t.Fatalf("catalogue = %v; the current publication was acknowledged but not committed", ids)
	}
}

// A final chunk whose snapshot is gone must not be acknowledged — unless the
// exact same revision is already committed, which is an ordinary replay after
// a lost acknowledgement and is idempotent.
func TestArtifactCatalogAcknowledgesOnlyCommittedRevisions(t *testing.T) {
	fsm := newPlacementFSM()
	applyResult := func(chunk ArtifactCatalogSnapshot) error {
		t.Helper()
		raw, err := encodeCommand(artifactCatalogCommand(chunk))
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		if resp := fsm.Apply(&raft.Log{Data: raw}); resp != nil {
			if err, ok := resp.(error); ok {
				return err
			}
		}
		return nil
	}
	full := ArtifactCatalogSnapshot{
		Kind: ArtifactKindTemplate, NodeID: "worker-a", Epoch: 1, Revision: 5,
		Rows: catalogRows("", "tpl-a"), First: true, Final: true,
	}
	if err := applyResult(full); err != nil {
		t.Fatal(err)
	}
	// Replay of the same publication after a lost acknowledgement: the state
	// it asked for is already in place, so it is a success, not a conflict.
	if err := applyResult(full); err != nil {
		t.Fatalf("replaying an already-committed publication returned %v; the publisher would retry forever", err)
	}
	page := fsm.artifactCatalogPage(ArtifactCatalogRequest{Kind: ArtifactKindTemplate})
	if len(page.Rows) != 1 || page.Rows[0].ID != "tpl-a" {
		t.Fatalf("catalogue = %+v after a replay", page.Rows)
	}
}

// Reading the current epoch and locally choosing "one more" claims nothing:
// two processes that read before either has published choose the SAME epoch,
// and the survivor's revisions then lose to the predecessor's higher ones.
// An epoch has to be ALLOCATED by the authority.
func TestArtifactCatalogEpochAllocationIsAtomic(t *testing.T) {
	c, cleanup := newTestCluster(t, "srv-epoch-alloc", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	ctx := context.Background()

	first, err := c.AllocateArtifactCatalogEpoch(ctx, ArtifactKindTemplate, "worker-a", "process-1")
	if err != nil {
		t.Fatal(err)
	}
	second, err := c.AllocateArtifactCatalogEpoch(ctx, ArtifactKindTemplate, "worker-a", "process-2")
	if err != nil {
		t.Fatal(err)
	}
	if second <= first {
		t.Fatalf("two processes were issued %d and %d; neither publication had landed, so a read-and-increment gives both the same token", first, second)
	}

	// The predecessor's delayed publication cannot outrank the successor's,
	// however high its revision.
	if err := publishAtEpoch(ctx, c, ArtifactKindTemplate, "worker-a", second, 1, catalogRows("", "tpl-current")); err != nil {
		t.Fatal(err)
	}
	if err := publishAtEpoch(ctx, c, ArtifactKindTemplate, "worker-a", first, 99, catalogRows("", "tpl-stale")); err == nil {
		t.Fatal("a delayed publication from the predecessor was accepted")
	}

	// A retry from the SAME process gets the same token back rather than
	// burning a new one.
	again, err := c.AllocateArtifactCatalogEpoch(ctx, ArtifactKindTemplate, "worker-a", "process-2")
	if err != nil || again != second {
		t.Fatalf("retry allocated %d, want the same %d", again, second)
	}
}

// Retirement must fence epochs that were ISSUED but never published, or a
// process that took a token before the attestation can still republish the
// destroyed node's artifacts afterwards.
func TestStorageRetirementFencesIssuedButUnpublishedEpochs(t *testing.T) {
	c, cleanup := newTestCluster(t, "srv-epoch-retire", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	ctx := context.Background()

	if err := publishAtEpoch(ctx, c, ArtifactKindTemplate, "worker-gone", 1, 1, catalogRows("", "tpl-old")); err != nil {
		t.Fatal(err)
	}
	// The doomed process takes a token and has not published under it yet.
	issued, err := c.AllocateArtifactCatalogEpoch(ctx, ArtifactKindTemplate, "worker-gone", "doomed-process")
	if err != nil {
		t.Fatal(err)
	}

	if err := c.RetireNodeStorage(ctx, "worker-gone", "operator", "disk destroyed", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := publishAtEpoch(ctx, c, ArtifactKindTemplate, "worker-gone", issued, 1, catalogRows("", "tpl-resurrected")); err == nil {
		t.Fatal("a publication under a token issued before the attestation was accepted; the destroyed node's artifacts came back")
	}
	page, err := c.ArtifactCatalog(ctx, ArtifactCatalogRequest{Kind: ArtifactKindTemplate})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Rows) != 0 || len(page.Publishers) != 0 {
		t.Fatalf("catalogue = %+v after retirement", page)
	}
}

// The publisher path must not drag fleet-wide coverage or scan unrelated
// inventories: it needs one node's token, nothing else.
func TestArtifactCatalogEpochAllocationDoesNotReturnTheFleet(t *testing.T) {
	var lastPath string
	var body []byte
	agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastPath = r.URL.Path
		body, _ = io.ReadAll(r.Body)
		_ = json.NewEncoder(w).Encode(ArtifactCatalogEpochResponse{Epoch: 4})
	}))

	epoch, err := agent.AllocateArtifactCatalogEpoch(context.Background(), ArtifactKindTemplate, "worker-self", "process-1")
	if err != nil || epoch != 4 {
		t.Fatalf("epoch = %d err=%v", epoch, err)
	}
	if lastPath != PublicInternalArtifactCatalogEpochPath {
		t.Fatalf("asked %q; the token lookup must not go through the catalogue page", lastPath)
	}
	var req ArtifactCatalogEpochRequest
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("decode request: %v", err)
	}
	if req.Kind != ArtifactKindTemplate || req.Holder != "process-1" {
		t.Fatalf("request = %+v", req)
	}
}

// A publisher on a worker reaches the catalogue over HTTP. If the supersede
// verdict arrives as an untyped 500, errors.Is is false, the publisher never
// retires its refused token, and it retries forever under an epoch the
// authority has moved past — its coverage stops tracking its inventory for
// the life of the process. The identity has to survive BOTH apply listeners
// and BOTH forwarding clients.
func TestSupersededVerdictSurvivesTheApplyBoundary(t *testing.T) {
	superseded := fmt.Errorf("%w: template/worker-a epoch 1 revision 2", ErrArtifactCatalogSuperseded)

	t.Run("agent over the public apply endpoint", func(t *testing.T) {
		agent := newAgentControlPlaneHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// What the v1 handler writes for this verdict.
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"error":"` + superseded.Error() + `"}`))
		}))
		err := agent.PublishArtifactCatalog(context.Background(), ArtifactCatalogSnapshot{
			Kind: ArtifactKindTemplate, NodeID: "worker-a", Epoch: 1, Revision: 2,
			Rows: catalogRows("", "tpl-1"), First: true, Final: true,
		})
		if !errors.Is(err, ErrArtifactCatalogSuperseded) {
			t.Fatalf("agent publish returned %v; the publisher cannot tell it must re-seed its token", err)
		}
	})

	t.Run("server over the internal apply listener", func(t *testing.T) {
		// The listener classifies, the forwarding client inverts: run the
		// real round trip rather than asserting on either half alone.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if retryAfter := ApplyErrorRetryAfterSeconds(superseded); retryAfter > 0 {
				w.Header().Set("Retry-After", fmt.Sprint(retryAfter))
			}
			http.Error(w, superseded.Error(), ApplyErrorStatus(superseded))
		}))
		defer srv.Close()
		resp, err := srv.Client().Post(srv.URL+InternalAPIPath, "application/octet-stream", bytes.NewReader([]byte("payload")))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		if err := forwardApplyStatus(resp.StatusCode, strings.TrimSpace(string(body))); !errors.Is(err, ErrArtifactCatalogSuperseded) {
			t.Fatalf("leader-forward returned %v; a forwarding server cannot tell it must re-seed", err)
		}
	})
}

// Both listeners have to CLASSIFY the verdict, not just carry a message: a
// generic 500 is indistinguishable from a transient apply failure, which the
// publisher is right to retry unchanged.
func TestApplyListenersClassifyTheSupersededVerdict(t *testing.T) {
	superseded := fmt.Errorf("%w: template/worker-a", ErrArtifactCatalogSuperseded)
	if got := ApplyErrorStatus(superseded); got != http.StatusConflict {
		t.Fatalf("internal listener answered %d, want %d so the verdict is distinguishable from a transient failure", got, http.StatusConflict)
	}
	if got := ApplyErrorStatus(errors.New("disk full")); got != http.StatusInternalServerError {
		t.Fatalf("an ordinary apply failure answered %d", got)
	}
}

// A replay of an already-committed publication is answered as success — but
// it must not take the REPLACEMENT publisher's half-assembled snapshot with
// it. Pending is keyed by node, so deleting it unconditionally cancels an
// assembly that belongs to a newer epoch, and the newer publisher's final
// chunk then lands on nothing.
func TestArtifactCatalogReplayDoesNotCancelNewerAssembly(t *testing.T) {
	c, cleanup := newTestCluster(t, "srv-replay-pending", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	ctx := context.Background()

	first, err := c.AllocateArtifactCatalogEpoch(ctx, ArtifactKindTemplate, "worker-a", "process-1")
	if err != nil {
		t.Fatal(err)
	}
	committed := ArtifactCatalogSnapshot{
		Kind: ArtifactKindTemplate, NodeID: "worker-a", Epoch: first, Revision: 1,
		Rows: catalogRows("", "tpl-old"), First: true, Final: true,
	}
	if err := c.PublishArtifactCatalog(ctx, committed); err != nil {
		t.Fatal(err)
	}

	// The replacement process takes a token and starts publishing.
	second, err := c.AllocateArtifactCatalogEpoch(ctx, ArtifactKindTemplate, "worker-a", "process-2")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.PublishArtifactCatalog(ctx, ArtifactCatalogSnapshot{
		Kind: ArtifactKindTemplate, NodeID: "worker-a", Epoch: second, Revision: 1,
		Rows: catalogRows("", "tpl-new-a"), First: true,
	}); err != nil {
		t.Fatal(err)
	}

	// The predecessor's final chunk is redelivered after a lost ACK.
	if err := c.PublishArtifactCatalog(ctx, committed); err != nil {
		t.Fatalf("replay of a committed publication was refused: %v", err)
	}

	// The replacement finishes.
	if err := c.PublishArtifactCatalog(ctx, ArtifactCatalogSnapshot{
		Kind: ArtifactKindTemplate, NodeID: "worker-a", Epoch: second, Revision: 1,
		Rows: catalogRows("", "tpl-new-b"), Final: true,
	}); err != nil {
		t.Fatalf("the newer publisher's final chunk failed after an older replay: %v", err)
	}
	page, err := c.ArtifactCatalog(ctx, ArtifactCatalogRequest{Kind: ArtifactKindTemplate})
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, len(page.Rows))
	for _, row := range page.Rows {
		ids = append(ids, row.ID)
	}
	slices.Sort(ids)
	if !slices.Equal(ids, []string{"tpl-new-a", "tpl-new-b"}) {
		t.Fatalf("catalogue = %v; an older replay cancelled the newer assembly and left the stale inventory standing", ids)
	}
}

// The same applies to a REFUSED older publication: rejecting it must not
// disturb a newer snapshot being assembled for the same node.
func TestArtifactCatalogStaleRejectionDoesNotCancelNewerAssembly(t *testing.T) {
	c, cleanup := newTestCluster(t, "srv-reject-pending", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	ctx := context.Background()

	if err := publishAtEpoch(ctx, c, ArtifactKindTemplate, "worker-a", 5, 3, catalogRows("", "tpl-old")); err != nil {
		t.Fatal(err)
	}
	if err := c.PublishArtifactCatalog(ctx, ArtifactCatalogSnapshot{
		Kind: ArtifactKindTemplate, NodeID: "worker-a", Epoch: 6, Revision: 1,
		Rows: catalogRows("", "tpl-new-a"), First: true,
	}); err != nil {
		t.Fatal(err)
	}
	// An older publisher's chunk arrives late and is correctly refused.
	if err := c.PublishArtifactCatalog(ctx, ArtifactCatalogSnapshot{
		Kind: ArtifactKindTemplate, NodeID: "worker-a", Epoch: 5, Revision: 1,
		Rows: catalogRows("", "tpl-stale"), First: true, Final: true,
	}); err == nil {
		t.Fatal("a superseded publication was accepted")
	}
	if err := c.PublishArtifactCatalog(ctx, ArtifactCatalogSnapshot{
		Kind: ArtifactKindTemplate, NodeID: "worker-a", Epoch: 6, Revision: 1,
		Rows: catalogRows("", "tpl-new-b"), Final: true,
	}); err != nil {
		t.Fatalf("the newer publisher's final chunk failed after an older one was refused: %v", err)
	}
}
