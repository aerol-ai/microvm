package cluster

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"
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
