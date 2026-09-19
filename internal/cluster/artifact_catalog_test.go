package cluster

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
	for _, chunk := range ChunkArtifactCatalogSnapshot(kind, nodeID, incarnation, revision, rows) {
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

	valid := ArtifactCatalogSnapshot{Kind: ArtifactKindTemplate, NodeID: "worker", Incarnation: "inc", Revision: 1, First: true, Final: true}

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
	bad.Incarnation = ""
	if err := c.PublishArtifactCatalog(ctx, bad); err == nil {
		t.Fatal("publish without a publisher incarnation accepted")
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
	seedCommittedCatalog(fsm, ArtifactKindJSBundle, "worker-a", "inc-a", 1,
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
				Kind: cmd.ArtifactKind, NodeID: cmd.NodeID, Incarnation: cmd.ArtifactIncarnation,
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
	for _, chunk := range ChunkArtifactCatalogSnapshot(ArtifactKindJSBundle, "worker-self", "inc-1", 7, rows) {
		if err := agent.PublishArtifactCatalog(ctx, chunk); err != nil {
			t.Fatalf("PublishArtifactCatalog: %v", err)
		}
	}
	if len(published) != 1 || published[0].Kind != ArtifactKindJSBundle || published[0].NodeID != "worker-self" {
		t.Fatalf("forwarded publish = %+v", published)
	}
	if published[0].Incarnation != "inc-1" || published[0].Revision != 7 || !published[0].First || !published[0].Final {
		t.Fatalf("forwarded publish lost its version or its chunk framing: %+v", published[0])
	}
	if len(published[0].Rows) != 1 || published[0].Rows[0].Tenant != "tenant-a" {
		t.Fatalf("forwarded rows = %+v; tenancy rides the row so coverage can answer for an empty tenant", published[0].Rows)
	}
	bogus := ArtifactCatalogSnapshot{Kind: "bogus", NodeID: "worker-self", Incarnation: "inc-1", Revision: 1, First: true, Final: true}
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
	seedCommittedCatalog(fsm, ArtifactKindTemplate, "worker-a", "inc-a", 1, ArtifactCatalogRow{ID: "tpl-1", Payload: []byte(`{}`)})
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
func seedCommittedCatalog(fsm *placementFSM, kind, nodeID, incarnation string, revision int64, rows ...ArtifactCatalogRow) {
	state := fsm.artifactCatalog[artifactCatalogKindKey(kind)]
	if state == nil {
		state = &artifactCatalogKindState{
			Committed: map[string]artifactCatalogNodeState{},
			Pending:   map[string]artifactCatalogNodeState{},
		}
		fsm.artifactCatalog[artifactCatalogKindKey(kind)] = state
	}
	byID := make(map[string]ArtifactCatalogRow, len(rows))
	for _, row := range rows {
		byID[row.ID] = row
	}
	state.Committed[nodeID] = artifactCatalogNodeState{Incarnation: incarnation, Revision: revision, Rows: byID}
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
		seedCommittedCatalog(fsm, ArtifactKindTemplate, fmt.Sprintf("worker-%02d", i), "inc", 1, rows...)
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
		if cmd.ArtifactIncarnation == "" {
			cmd.ArtifactIncarnation = "inc-a"
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
	if err := apply(publish(command{ArtifactKind: ArtifactKindTemplate, NodeID: "worker-a", ArtifactIncarnation: " "})); err == nil {
		t.Fatal("a publish with no publisher incarnation was applied")
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
		Kind: ArtifactKindJSBundle, NodeID: "worker-a", Incarnation: "inc-a", Revision: 1,
		Rows: rows, First: true, Final: true,
	}))
	if err != nil {
		t.Fatalf("encode whole inventory: %v", err)
	}
	if len(whole) <= maxInternalApplyBytes {
		t.Fatalf("the fixture inventory encodes to %d bytes, inside the %d apply cap; it no longer models the case",
			len(whole), maxInternalApplyBytes)
	}

	chunks := ChunkArtifactCatalogSnapshot(ArtifactKindJSBundle, "worker-a", "inc-a", 3, rows)
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

	chunks := ChunkArtifactCatalogSnapshot(ArtifactKindJSBundle, "worker-empty", "inc-a", 1, nil)
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
// inventories were read in. The older one must not win, and a publisher that
// restarts must not be fenced out by the revisions its previous process left
// behind.
func TestArtifactCatalogFencesOutOfOrderAndRestartedPublishers(t *testing.T) {
	c, cleanup := newTestCluster(t, "srv-catalog-order", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	ctx := context.Background()

	if err := publishWholeCatalog(ctx, c, ArtifactKindTemplate, "worker-a", "inc-1", 2, catalogRows("", "tpl-new")); err != nil {
		t.Fatal(err)
	}
	// The older read lands afterwards.
	if err := publishWholeCatalog(ctx, c, ArtifactKindTemplate, "worker-a", "inc-1", 1, catalogRows("", "tpl-old")); err != nil {
		t.Fatal(err)
	}
	page, err := c.ArtifactCatalog(ctx, ArtifactCatalogRequest{Kind: ArtifactKindTemplate})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Rows) != 1 || page.Rows[0].ID != "tpl-new" {
		t.Fatalf("catalogue = %+v; a late older publication overwrote newer state", page.Rows)
	}

	// The node restarts: its revisions begin again at 1, and that publication
	// is newer than anything its previous process left.
	if err := publishWholeCatalog(ctx, c, ArtifactKindTemplate, "worker-a", "inc-2", 1, catalogRows("", "tpl-after-restart")); err != nil {
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
		Kind: ArtifactKindTemplate, NodeID: "worker-a", Incarnation: "inc-1", Revision: 2,
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
