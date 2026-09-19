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

	rows := func(ids ...string) []ArtifactCatalogRow {
		out := make([]ArtifactCatalogRow, 0, len(ids))
		for _, id := range ids {
			payload, _ := json.Marshal(map[string]string{"id": id})
			out = append(out, ArtifactCatalogRow{ID: id, Payload: payload})
		}
		return out
	}

	if err := c.PublishArtifactCatalog(ctx, ArtifactKindTemplate, "", "worker-a", rows("tpl-1", "tpl-2")); err != nil {
		t.Fatalf("publish worker-a: %v", err)
	}
	if err := c.PublishArtifactCatalog(ctx, ArtifactKindTemplate, "", "worker-b", rows("tpl-2", "tpl-3")); err != nil {
		t.Fatalf("publish worker-b: %v", err)
	}

	page, err := c.ArtifactCatalog(ctx, ArtifactKindTemplate, "")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(page.Rows) != 3 {
		t.Fatalf("rows = %d, want 3 deduped across both publishers", len(page.Rows))
	}
	if len(page.Publishers) != 2 {
		t.Fatalf("publishers = %v, want both nodes", page.Publishers)
	}

	// worker-a deletes tpl-1 by republishing what is left.
	if err := c.PublishArtifactCatalog(ctx, ArtifactKindTemplate, "", "worker-a", rows("tpl-2")); err != nil {
		t.Fatalf("republish worker-a: %v", err)
	}
	page, err = c.ArtifactCatalog(ctx, ArtifactKindTemplate, "")
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, len(page.Rows))
	for _, row := range page.Rows {
		ids = append(ids, row.ID)
	}
	if len(ids) != 2 || ids[0] != "tpl-2" || ids[1] != "tpl-3" {
		t.Fatalf("rows = %v; a republish must replace only the publisher's own slice", ids)
	}
}

// Tenants must not read each other's catalogue: the key carries the tenant,
// and bundle ids are content digests.
func TestArtifactCatalogIsTenantScoped(t *testing.T) {
	c, cleanup := newTestCluster(t, "srv-catalog-tenant", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	ctx := context.Background()

	row := ArtifactCatalogRow{ID: "sha256-aaa", Payload: []byte(`{"digest":"aaa"}`)}
	if err := c.PublishArtifactCatalog(ctx, ArtifactKindJSBundle, "tenant-a", "worker-a", []ArtifactCatalogRow{row}); err != nil {
		t.Fatal(err)
	}

	mine, err := c.ArtifactCatalog(ctx, ArtifactKindJSBundle, "tenant-a")
	if err != nil || len(mine.Rows) != 1 {
		t.Fatalf("tenant-a rows = %+v err=%v", mine.Rows, err)
	}
	other, err := c.ArtifactCatalog(ctx, ArtifactKindJSBundle, "tenant-b")
	if err != nil {
		t.Fatal(err)
	}
	if len(other.Rows) != 0 || len(other.Publishers) != 0 {
		t.Fatalf("tenant-b sees %+v; a tenant's catalogue must not disclose another's digests", other)
	}
}

// Publishes are validated before they reach the log: an unknown kind, a
// missing publisher, an oversized slice or an oversized row are refused.
func TestArtifactCatalogPublishIsBounded(t *testing.T) {
	c, cleanup := newTestCluster(t, "srv-catalog-bounds", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	ctx := context.Background()

	if err := c.PublishArtifactCatalog(ctx, "not-a-kind", "", "worker", nil); err == nil {
		t.Fatal("unknown catalogue kind accepted")
	}
	if err := c.PublishArtifactCatalog(ctx, ArtifactKindTemplate, "", "", nil); err == nil {
		t.Fatal("publish without a node id accepted")
	}
	oversize := make([]ArtifactCatalogRow, maxArtifactCatalogRowsPerNode+1)
	for i := range oversize {
		oversize[i] = ArtifactCatalogRow{ID: "x"}
	}
	if err := c.PublishArtifactCatalog(ctx, ArtifactKindTemplate, "", "worker", oversize); err == nil {
		t.Fatalf("a publish of %d rows was accepted", len(oversize))
	}
	fat := []ArtifactCatalogRow{{ID: "fat", Payload: make([]byte, maxArtifactCatalogRowBytes+1)}}
	if err := c.PublishArtifactCatalog(ctx, ArtifactKindTemplate, "", "worker", fat); err == nil {
		t.Fatal("an oversized row was accepted")
	}
}

// The catalogue must survive log compaction, or a restarted leader would send
// every list back to the fleet-wide sweep.
func TestArtifactCatalogSurvivesSnapshotRestore(t *testing.T) {
	fsm := newPlacementFSM()
	key := artifactCatalogKey(ArtifactKindJSBundle, "tenant-a")
	fsm.artifactCatalog[key] = map[string]artifactCatalogEntry{
		"worker-a": {Rows: map[string]ArtifactCatalogRow{"sha256-aaa": {ID: "sha256-aaa", Payload: []byte(`{"digest":"aaa"}`)}}},
	}

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
	page := restored.artifactCatalogPage(ArtifactKindJSBundle, "tenant-a")
	if len(page.Rows) != 1 || page.Rows[0].ID != "sha256-aaa" || len(page.Publishers) != 1 {
		t.Fatalf("restored catalogue = %+v", page)
	}
}

// A worker holds no FSM, so both sides of the catalogue are RPCs. The write
// rides the same leader-forwarded apply path as every other agent write; the
// read must refuse a non-authoritative answer rather than report a tenant's
// artifacts as absent.
func TestAgentArtifactCatalogRoundTrip(t *testing.T) {
	var published []ArtifactCatalogPublishRequest
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
			published = append(published, ArtifactCatalogPublishRequest{
				Kind: cmd.ArtifactKind, Tenant: cmd.ArtifactTenant, NodeID: cmd.NodeID, Rows: cmd.ArtifactRows,
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

	rows := []ArtifactCatalogRow{{ID: "sha256-aaa", Payload: []byte(`{}`)}}
	if err := agent.PublishArtifactCatalog(ctx, ArtifactKindJSBundle, "tenant-a", "worker-self", rows); err != nil {
		t.Fatalf("PublishArtifactCatalog: %v", err)
	}
	if len(published) != 1 || published[0].Kind != ArtifactKindJSBundle || published[0].Tenant != "tenant-a" || published[0].NodeID != "worker-self" {
		t.Fatalf("forwarded publish = %+v", published)
	}
	if err := agent.PublishArtifactCatalog(ctx, "bogus", "", "worker-self", nil); err == nil {
		t.Fatal("an unknown catalogue kind was forwarded to the control plane")
	}

	page, err := agent.ArtifactCatalog(ctx, ArtifactKindJSBundle, "tenant-a")
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
	if _, err := agent.ArtifactCatalog(ctx, ArtifactKindJSBundle, "tenant-a"); err == nil {
		t.Fatal("a non-authoritative catalogue answer was accepted; the caller would report a tenant's bundles as absent")
	}
}

// The peer-facing read is what a worker calls; it must carry the publishers
// so the aggregator knows which nodes it still has to ask.
func TestArtifactCatalogForPeerCarriesPublishers(t *testing.T) {
	fsm := newPlacementFSM()
	fsm.artifactCatalog[artifactCatalogKey(ArtifactKindTemplate, "")] = map[string]artifactCatalogEntry{
		"worker-a": {Rows: map[string]ArtifactCatalogRow{"tpl-1": {ID: "tpl-1", Payload: []byte(`{}`)}}},
	}
	c := &Cluster{fsm: fsm}

	page := c.ArtifactCatalogForPeer(ArtifactKindTemplate, "")
	if !page.Authoritative || len(page.Rows) != 1 || len(page.Publishers) != 1 || page.Publishers[0] != "worker-a" {
		t.Fatalf("peer page = %+v", page)
	}
	var none *Cluster
	if page := none.ArtifactCatalogForPeer(ArtifactKindTemplate, ""); page.Authoritative {
		t.Fatal("a node with no placement state claimed an authoritative catalogue")
	}
}

// The catalogue is answered over the same response ceiling as a placement
// page, and it grows with the fleet's artifacts. Publishers that do not fit
// are left out WHOLE, so the aggregator keeps asking them rather than
// believing a partial slice is their whole inventory.
func TestArtifactCatalogPageIsBoundedByBytes(t *testing.T) {
	fsm := newPlacementFSM()
	key := artifactCatalogKey(ArtifactKindTemplate, "")
	byNode := map[string]artifactCatalogEntry{}
	// Each node publishes ~1 MiB, so the budget runs out well before the last.
	for i := range 32 {
		rows := map[string]ArtifactCatalogRow{}
		for j := range 64 {
			id := fmt.Sprintf("tpl-%02d-%02d", i, j)
			rows[id] = ArtifactCatalogRow{ID: id, Payload: make([]byte, maxArtifactCatalogRowBytes)}
		}
		byNode[fmt.Sprintf("worker-%02d", i)] = artifactCatalogEntry{Rows: rows}
	}
	fsm.artifactCatalog[key] = byNode

	page := fsm.artifactCatalogPage(ArtifactKindTemplate, "")
	if !page.Truncated {
		t.Fatal("the fixture no longer exceeds the page budget")
	}
	if len(page.Publishers) == 0 || len(page.Publishers) == len(byNode) {
		t.Fatalf("publishers = %d of %d; a truncated answer must list the nodes it fully covered and no others",
			len(page.Publishers), len(byNode))
	}
	payload, err := json.Marshal(page)
	if err != nil {
		t.Fatalf("marshal page: %v", err)
	}
	if len(payload) > maxControlPlaneJSONResponseBytes {
		t.Fatalf("catalogue page encodes to %d bytes, past the %d ceiling", len(payload), maxControlPlaneJSONResponseBytes)
	}
	// Every listed publisher's rows must all be present, or the aggregator
	// would stop asking a node whose inventory it only half received.
	have := map[string]struct{}{}
	for _, row := range page.Rows {
		have[row.ID] = struct{}{}
	}
	for _, nodeID := range page.Publishers {
		for id := range byNode[nodeID].Rows {
			if _, ok := have[id]; !ok {
				t.Fatalf("publisher %s is listed but row %s is missing", nodeID, id)
			}
		}
	}
}

// Every entry point refuses input that would make the catalogue meaningless,
// and a node that holds no state says so instead of answering empty.
func TestArtifactCatalogEntryPointGuards(t *testing.T) {
	ctx := context.Background()
	var noCluster *Cluster
	var noAgent *Agent

	if err := noCluster.PublishArtifactCatalog(ctx, ArtifactKindTemplate, "", "n", nil); err == nil {
		t.Fatal("publish on a nil cluster was accepted")
	}
	if _, err := noCluster.ArtifactCatalog(ctx, ArtifactKindTemplate, ""); err == nil {
		t.Fatal("read on a nil cluster was accepted")
	}
	if _, err := (&Cluster{}).ArtifactCatalog(ctx, ArtifactKindTemplate, ""); err == nil {
		t.Fatal("read on a cluster with no FSM was accepted")
	}
	if err := noAgent.PublishArtifactCatalog(ctx, ArtifactKindTemplate, "", "n", nil); err == nil {
		t.Fatal("publish on a nil agent was accepted")
	}
	if _, err := noAgent.ArtifactCatalog(ctx, ArtifactKindTemplate, ""); err == nil {
		t.Fatal("read on a nil agent was accepted")
	}

	var noFSM *placementFSM
	_ = noFSM
	empty := newPlacementFSM().artifactCatalogPage(ArtifactKindTemplate, "unknown-tenant")
	if !empty.Authoritative || len(empty.Rows) != 0 || empty.Truncated {
		t.Fatalf("empty catalogue page = %+v; nothing published is an authoritative empty answer", empty)
	}
}

// The same guards for the retirement registry.
func TestNodeStorageRetirementEntryPointGuards(t *testing.T) {
	ctx := context.Background()
	var noCluster *Cluster
	var noAgent *Agent
	now := time.Now()

	if err := noCluster.RetireNodeStorage(ctx, "n", "op", "", now); err == nil {
		t.Fatal("attestation on a nil cluster was accepted")
	}
	if err := (&Cluster{}).RetireNodeStorage(ctx, "", "op", "", now); err == nil {
		t.Fatal("attestation with no node id was accepted")
	}
	if err := noCluster.RevokeNodeStorageRetirement(ctx, "n"); err == nil {
		t.Fatal("revoke on a nil cluster was accepted")
	}
	if err := (&Cluster{}).RevokeNodeStorageRetirement(ctx, " "); err == nil {
		t.Fatal("revoke with no node id was accepted")
	}
	if _, err := noCluster.NodeStorageRetirements(ctx); err == nil {
		t.Fatal("read on a nil cluster was accepted")
	}
	if _, err := (&Cluster{}).NodeStorageRetirements(ctx); err == nil {
		t.Fatal("read on a cluster with no FSM was accepted")
	}
	if err := noAgent.RetireNodeStorage(ctx, "n", "op", "", now); err == nil {
		t.Fatal("attestation on a nil agent was accepted")
	}
	if err := noAgent.RevokeNodeStorageRetirement(ctx, "n"); err == nil {
		t.Fatal("revoke on a nil agent was accepted")
	}
	if _, err := noAgent.NodeStorageRetirements(ctx); err == nil {
		t.Fatal("read on a nil agent was accepted")
	}

	// A zero attestation time is unusable as a fence.
	if got := (NodeStorageRetirement{}).AttestedAt(); !got.IsZero() {
		t.Fatalf("zero attestation carried a time: %v", got)
	}
	if got := (NodeStorageRetirement{AttestedUnix: 1700000000}).AttestedAt(); got.Unix() != 1700000000 {
		t.Fatalf("attested at %v", got)
	}
	var noneCluster *Cluster
	if page := noneCluster.NodeStorageRetirementsForPeer(); page.Authoritative {
		t.Fatal("a nil cluster claimed an authoritative retirement set")
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

	if err := apply(command{Op: opPublishArtifactCatalog, NodeID: "worker-a"}); err == nil {
		t.Fatal("a publish with no kind was applied")
	}
	if err := apply(command{Op: opPublishArtifactCatalog, ArtifactKind: ArtifactKindTemplate}); err == nil {
		t.Fatal("a publish with no node id was applied")
	}
	over := make([]ArtifactCatalogRow, maxArtifactCatalogRowsPerNode+1)
	for i := range over {
		over[i] = ArtifactCatalogRow{ID: "x"}
	}
	if err := apply(command{Op: opPublishArtifactCatalog, ArtifactKind: ArtifactKindTemplate, NodeID: "worker-a", ArtifactRows: over}); err == nil {
		t.Fatal("an oversized publish was applied")
	}
	// Rows that are individually unusable are dropped, not the whole publish.
	if err := apply(command{Op: opPublishArtifactCatalog, ArtifactKind: ArtifactKindTemplate, NodeID: "worker-a", ArtifactRows: []ArtifactCatalogRow{
		{ID: " ", Payload: []byte(`{}`)},
		{ID: "fat", Payload: make([]byte, maxArtifactCatalogRowBytes+1)},
		{ID: "good", Payload: []byte(`{}`)},
	}}); err != nil {
		t.Fatalf("publish with unusable rows: %v", err)
	}
	page := fsm.artifactCatalogPage(ArtifactKindTemplate, "")
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
		if err := apply(command{Op: opRetireNodeStorage, NodeID: id, StorageRetirement: &NodeStorageRetirement{NodeID: id, AttestedUnix: 5}}); err != nil {
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
