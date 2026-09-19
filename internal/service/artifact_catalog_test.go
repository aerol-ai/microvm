package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/jsbundle"
	"github.com/aerol-ai/microvm/pkg/models"
)

// catalogCluster records the chunk sequences a node publishes and serves back
// the last committed snapshot, standing in for the replicated FSM.
type catalogCluster struct {
	*cluster.Noop
	mu        sync.Mutex
	chunks    []cluster.ArtifactCatalogSnapshot
	snapshots int
	committed map[string]map[string]cluster.ArtifactCatalogRow // kind -> id -> row
	failing   bool                                             // refuse every publish
	readErr   error
}

func newCatalogCluster(self string) *catalogCluster {
	return &catalogCluster{
		Noop:      cluster.NewNoop(self, "http://"+self, ""),
		committed: map[string]map[string]cluster.ArtifactCatalogRow{},
	}
}

func (c *catalogCluster) PublishArtifactCatalog(_ context.Context, chunk cluster.ArtifactCatalogSnapshot) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failing {
		return errors.New("control plane unavailable")
	}
	c.chunks = append(c.chunks, chunk)
	if chunk.First {
		c.committed[chunk.Kind+"\x00pending"] = map[string]cluster.ArtifactCatalogRow{}
	}
	pending := c.committed[chunk.Kind+"\x00pending"]
	if pending == nil {
		pending = map[string]cluster.ArtifactCatalogRow{}
		c.committed[chunk.Kind+"\x00pending"] = pending
	}
	for _, row := range chunk.Rows {
		pending[row.ID] = row
	}
	if chunk.Final {
		c.committed[chunk.Kind] = pending
		delete(c.committed, chunk.Kind+"\x00pending")
		c.snapshots++
	}
	return nil
}

func (c *catalogCluster) ArtifactCatalog(_ context.Context, req cluster.ArtifactCatalogRequest) (cluster.ArtifactCatalogPage, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.readErr != nil {
		return cluster.ArtifactCatalogPage{}, c.readErr
	}
	page := cluster.ArtifactCatalogPage{Authoritative: true}
	for id, row := range c.committed[req.Kind] {
		if row.Tenant != req.Tenant {
			continue
		}
		page.Rows = append(page.Rows, c.committed[req.Kind][id])
	}
	if c.snapshots > 0 {
		page.Publishers = []string{c.SelfNodeID()}
	}
	return page, nil
}

func (c *catalogCluster) publishedSnapshots() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.snapshots
}

func (c *catalogCluster) rowIDs(kind string) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, 0, len(c.committed[kind]))
	for id := range c.committed[kind] {
		out = append(out, id)
	}
	return out
}

func newCatalogService(t *testing.T) (*Service, *catalogCluster) {
	t.Helper()
	st := openSealTestStore(t)
	cl := newCatalogCluster("worker-a")
	svc := &Service{cfg: config.Config{EnableCluster: true}, store: st, cluster: cl}
	return svc, cl
}

// Publication was wired to a handful of call sites, so a create, a build
// finishing or a GC sweep left the catalogue advertising an inventory the
// node no longer had — and the aggregator skips a node it already covers, so
// nothing asked it again. Every inventory mutation marks the kind dirty and
// the reconciler publishes the inventory as it is now.
func TestTemplateInventoryMutationsReachTheCatalogue(t *testing.T) {
	svc, cl := newCatalogService(t)
	ctx := context.Background()

	// Create.
	if err := svc.createTemplateRow(ctx, &models.Template{ID: "tpl-1", Image: "alpine", Status: models.TemplateStatusPending}); err != nil {
		t.Fatal(err)
	}
	svc.ReconcileArtifactCatalog(ctx)
	if got := cl.rowIDs(cluster.ArtifactKindTemplate); len(got) != 1 || got[0] != "tpl-1" {
		t.Fatalf("catalogue after create = %v, want the new template", got)
	}

	// Build status change: the row the catalogue advertises now says ready.
	if err := svc.setTemplateStatus(ctx, "tpl-1", models.TemplateStatusReady, "/rootfs.ext4", "", 1234); err != nil {
		t.Fatal(err)
	}
	svc.ReconcileArtifactCatalog(ctx)
	rows := cl.rowIDs(cluster.ArtifactKindTemplate)
	if len(rows) != 1 {
		t.Fatalf("catalogue = %v", rows)
	}
	cl.mu.Lock()
	payload := cl.committed[cluster.ArtifactKindTemplate]["tpl-1"].Payload
	cl.mu.Unlock()
	var published models.Template
	if err := json.Unmarshal(payload, &published); err != nil {
		t.Fatalf("decode published row: %v", err)
	}
	if published.Status != models.TemplateStatusReady {
		t.Fatalf("published status = %q; a build completing never reached the catalogue", published.Status)
	}

	// GC deletion.
	if err := svc.deleteTemplateRow(ctx, "tpl-1"); err != nil {
		t.Fatal(err)
	}
	svc.ReconcileArtifactCatalog(ctx)
	if got := cl.rowIDs(cluster.ArtifactKindTemplate); len(got) != 0 {
		t.Fatalf("catalogue after deletion = %v; the node still advertises an artifact it does not have", got)
	}
}

// An unchanged inventory must not re-enter the raft log on every tick.
func TestArtifactCatalogReconcileIsIdleWhenNothingChanged(t *testing.T) {
	svc, cl := newCatalogService(t)
	ctx := context.Background()

	svc.ReconcileArtifactCatalog(ctx)
	first := cl.publishedSnapshots()
	if first == 0 {
		t.Fatal("boot published nothing; an empty inventory is the answer that stops the fleet sweep")
	}
	svc.ReconcileArtifactCatalog(ctx)
	svc.ReconcileArtifactCatalog(ctx)
	if got := cl.publishedSnapshots(); got != first {
		t.Fatalf("published %d snapshots for an unchanged inventory, want %d", got, first)
	}
}

// A failed publication must be retried, not logged and forgotten: the node is
// already covered by its previous snapshot, so the aggregator will not ask it
// and nothing else would notice the inventory had moved on.
func TestArtifactCatalogPublishRetriesUntilItSucceeds(t *testing.T) {
	svc, cl := newCatalogService(t)
	ctx := context.Background()

	svc.ReconcileArtifactCatalog(ctx)
	committed := cl.publishedSnapshots()

	// The next publication cannot reach the control plane.
	cl.mu.Lock()
	cl.failing = true
	cl.mu.Unlock()
	if err := svc.createTemplateRow(ctx, &models.Template{ID: "tpl-late", Image: "alpine", Status: models.TemplateStatusReady}); err != nil {
		t.Fatal(err)
	}
	svc.ReconcileArtifactCatalog(ctx)
	if got := cl.publishedSnapshots(); got != committed {
		t.Fatalf("a failed publication committed a snapshot anyway (%d)", got)
	}

	// Transport recovers: the next pass publishes the inventory as it is now.
	cl.mu.Lock()
	cl.failing = false
	cl.mu.Unlock()
	svc.ReconcileArtifactCatalog(ctx)
	if got := cl.rowIDs(cluster.ArtifactKindTemplate); len(got) != 1 || got[0] != "tpl-late" {
		t.Fatalf("catalogue after recovery = %v; the failed publication was never retried", got)
	}
}

// A publication that succeeds while the inventory moves on must not mark the
// node clean: the catalogue would then advertise the older snapshot with
// nothing scheduled to correct it.
func TestArtifactCatalogRepublishesWhenTheInventoryMovedMidPublish(t *testing.T) {
	svc, cl := newCatalogService(t)
	ctx := context.Background()
	svc.ReconcileArtifactCatalog(ctx)

	if err := svc.createTemplateRow(ctx, &models.Template{ID: "tpl-1", Image: "alpine", Status: models.TemplateStatusReady}); err != nil {
		t.Fatal(err)
	}
	// The mutation lands while the publication of the previous inventory is
	// in flight — modelled by marking dirty again before the commit.
	revision, needed := svc.artifactCatalog.begin(cluster.ArtifactKindTemplate)
	if !needed {
		t.Fatal("the fixture no longer has anything to publish")
	}
	svc.MarkArtifactCatalogDirty(cluster.ArtifactKindTemplate)
	svc.artifactCatalog.commit(cluster.ArtifactKindTemplate, revision)

	if _, needed := svc.artifactCatalog.begin(cluster.ArtifactKindTemplate); !needed {
		t.Fatal("the node marked itself clean although its inventory moved while the publication was in flight")
	}
	svc.ReconcileArtifactCatalog(ctx)
	if got := cl.rowIDs(cluster.ArtifactKindTemplate); len(got) != 1 {
		t.Fatalf("catalogue = %v, want the current inventory", got)
	}
}

// A worker with no bundles for a tenant still answers for it: the publication
// covers the KIND, so an empty tenant does not send every list back to the
// fleet.
func TestJSBundleCatalogueCoversTenantsWithNothing(t *testing.T) {
	svc, _ := newCatalogService(t)
	bundleStore, err := jsbundle.NewStore(jsbundle.StoreConfig{Dir: filepath.Join(t.TempDir(), "bundles")})
	if err != nil {
		t.Fatal(err)
	}
	svc.SetIsolateBundleStore(bundleStore)
	svc.cfg.EnableIsolate = true
	ctx := context.Background()

	svc.ReconcileArtifactCatalog(ctx)
	page, ok := svc.ClusterArtifactCatalog(ctx, cluster.ArtifactCatalogRequest{
		Kind:   cluster.ArtifactKindJSBundle,
		Tenant: "tenant-with-nothing",
	})
	if !ok {
		t.Fatal("catalogue read failed")
	}
	if len(page.Rows) != 0 {
		t.Fatalf("rows = %+v, want none", page.Rows)
	}
	if len(page.Publishers) != 1 {
		t.Fatalf("publishers = %v; a node that published an empty inventory has answered for this tenant", page.Publishers)
	}

	// An upload for one tenant is published with its tenancy on the row.
	tenantCtx := controlplane.ContextWithAccess(ctx, controlplane.Access{
		Identity: controlplane.Identity{OwnerRef: "tenant-a"},
	})
	created, err := svc.CreateJSBundle(tenantCtx, models.CreateJSBundleRequest{Name: "hook", Source: jsBundleSrc})
	if err != nil {
		t.Fatal(err)
	}
	svc.ReconcileArtifactCatalog(ctx)
	mine, ok := svc.ClusterArtifactCatalog(ctx, cluster.ArtifactCatalogRequest{
		Kind:   cluster.ArtifactKindJSBundle,
		Tenant: "tenant-a",
	})
	if !ok || len(mine.Rows) != 1 || mine.Rows[0].ID != created.Digest {
		t.Fatalf("tenant-a catalogue = %+v ok=%v", mine.Rows, ok)
	}
	other, _ := svc.ClusterArtifactCatalog(ctx, cluster.ArtifactCatalogRequest{
		Kind:   cluster.ArtifactKindJSBundle,
		Tenant: "tenant-b",
	})
	if len(other.Rows) != 0 {
		t.Fatalf("tenant-b sees %+v; the catalogue must not disclose another tenant's digests", other.Rows)
	}
}

// Standalone mode has no control plane to publish to, and a failed read must
// not look like an empty catalogue: the caller falls back to the peer sweep.
func TestClusterArtifactCatalogFallsBackWhenUnavailable(t *testing.T) {
	st := openSealTestStore(t)
	standalone := &Service{cfg: config.Config{}, store: st}
	req := cluster.ArtifactCatalogRequest{Kind: cluster.ArtifactKindTemplate}
	if _, ok := standalone.ClusterArtifactCatalog(context.Background(), req); ok {
		t.Fatal("standalone mode reported a cluster catalogue")
	}
	standalone.ReconcileArtifactCatalog(context.Background())

	cl := newCatalogCluster("worker-a")
	cl.readErr = context.DeadlineExceeded
	clustered := &Service{cfg: config.Config{EnableCluster: true}, store: st, cluster: cl}
	if _, ok := clustered.ClusterArtifactCatalog(context.Background(), req); ok {
		t.Fatal("an unreachable control plane reported a usable catalogue; the sweep must still run")
	}

	// A Noop cluster publishes nothing and reads nothing.
	noop := &Service{cfg: config.Config{EnableCluster: true}, store: st, cluster: cluster.NewNoop("node-a", "http://node-a", "")}
	noop.ReconcileArtifactCatalog(context.Background())
	if _, ok := noop.ClusterArtifactCatalog(context.Background(), req); ok {
		t.Fatal("a Noop cluster reported a catalogue")
	}
}

// An inventory that cannot be read is not an empty one: publishing an empty
// snapshot would tell the aggregator this node holds nothing.
func TestArtifactCatalogPublishSkipsWhenTheLocalListFails(t *testing.T) {
	svc, cl := newCatalogService(t)
	ctx := context.Background()

	if err := svc.createTemplateRow(ctx, &models.Template{ID: "tpl-1", Image: "alpine", Status: models.TemplateStatusReady}); err != nil {
		t.Fatal(err)
	}
	if err := svc.store.Close(); err != nil {
		t.Fatal(err)
	}
	svc.ReconcileArtifactCatalog(ctx)
	for _, chunk := range cl.chunks {
		if chunk.Kind == cluster.ArtifactKindTemplate {
			t.Fatal("published a template snapshot from a store that could not be read")
		}
	}
}

// An inventory larger than the catalogue's per-node cap is not published at
// all: the node stays uncovered and the aggregator keeps asking it, which is
// slower but never advertises a truncated inventory as a whole one.
func TestArtifactCatalogSkipsAnOversizedInventory(t *testing.T) {
	svc, cl := newCatalogService(t)
	ctx := context.Background()

	for i := range cluster.MaxArtifactCatalogRowsPerNode() + 1 {
		if err := svc.store.CreateTemplate(ctx, &models.Template{
			ID: fmt.Sprintf("tpl-%05d", i), Image: "alpine", Status: models.TemplateStatusReady,
		}); err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}
	svc.MarkArtifactCatalogDirty(cluster.ArtifactKindTemplate)
	svc.ReconcileArtifactCatalog(ctx)

	for _, chunk := range cl.chunks {
		if chunk.Kind == cluster.ArtifactKindTemplate && len(chunk.Rows) > 0 {
			t.Fatal("an inventory over the per-node cap was published anyway")
		}
	}
}

// Rows the catalogue cannot represent are skipped without taking the rest of
// the inventory with them.
func TestArtifactCatalogSkipsUnusableRows(t *testing.T) {
	svc, cl := newCatalogService(t)
	ctx := context.Background()

	if err := svc.store.CreateTemplate(ctx, &models.Template{ID: "tpl-good", Image: "alpine", Status: models.TemplateStatusReady}); err != nil {
		t.Fatal(err)
	}
	svc.MarkArtifactCatalogDirty(cluster.ArtifactKindTemplate)
	svc.ReconcileArtifactCatalog(ctx)
	if got := cl.rowIDs(cluster.ArtifactKindTemplate); len(got) != 1 || got[0] != "tpl-good" {
		t.Fatalf("catalogue = %v, want the usable row", got)
	}

	// A nil / blank-id row never reaches the wire.
	rows, ok := svc.localArtifactRows(ctx, cluster.ArtifactKindTemplate)
	if !ok {
		t.Fatal("local inventory read failed")
	}
	for _, row := range rows {
		if row.ID == "" {
			t.Fatal("a row without an id was built for publication")
		}
	}
	if _, ok := svc.localArtifactRows(ctx, "not-a-kind"); ok {
		t.Fatal("an unknown kind reported a usable inventory")
	}
}

// A node with no bundle store publishes an empty bundle inventory rather than
// nothing: "this node holds no bundles" is what stops every tenant's list
// asking it again.
func TestArtifactCatalogPublishesEmptyBundleInventoryWithoutAStore(t *testing.T) {
	svc, cl := newCatalogService(t)
	ctx := context.Background()
	svc.ReconcileArtifactCatalog(ctx)

	published := false
	for _, chunk := range cl.chunks {
		if chunk.Kind == cluster.ArtifactKindJSBundle && chunk.Final {
			published = true
		}
	}
	if !published {
		t.Fatal("a node without a bundle store published no bundle inventory at all")
	}
}
