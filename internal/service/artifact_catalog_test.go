package service

import (
	"context"
	"encoding/json"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
)

// catalogCluster records what a node publishes and serves it back, standing
// in for the replicated FSM catalogue.
type catalogCluster struct {
	*cluster.Noop
	mu        sync.Mutex
	publishes int
	rows      map[string][]cluster.ArtifactCatalogRow
	readErr   error
}

func newCatalogCluster(self string) *catalogCluster {
	return &catalogCluster{Noop: cluster.NewNoop(self, "http://"+self, ""), rows: map[string][]cluster.ArtifactCatalogRow{}}
}

func (c *catalogCluster) PublishArtifactCatalog(_ context.Context, kind, tenant, nodeID string, rows []cluster.ArtifactCatalogRow) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.publishes++
	c.rows[kind+"\x00"+tenant+"\x00"+nodeID] = rows
	return nil
}

func (c *catalogCluster) ArtifactCatalog(_ context.Context, kind, tenant string) (cluster.ArtifactCatalogPage, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.readErr != nil {
		return cluster.ArtifactCatalogPage{}, c.readErr
	}
	page := cluster.ArtifactCatalogPage{Authoritative: true}
	for key, rows := range c.rows {
		if key[:len(kind)] != kind {
			continue
		}
		page.Rows = append(page.Rows, rows...)
	}
	return page, nil
}

func (c *catalogCluster) publishCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.publishes
}

// The catalogue only replaces the fleet-wide sweep if nodes actually publish
// — and publishing must not become a Raft write per list request.
func TestTemplateCatalogPublishIsDebouncedByInventory(t *testing.T) {
	st := openSealTestStore(t)
	cl := newCatalogCluster("worker-a")
	svc := &Service{cfg: config.Config{EnableCluster: true}, store: st, cluster: cl}
	ctx := context.Background()

	if err := st.CreateTemplate(ctx, &models.Template{ID: "tpl-1", Image: "alpine", Status: models.TemplateStatusReady}); err != nil {
		t.Fatalf("seed template: %v", err)
	}
	svc.PublishTemplateCatalog(ctx)
	if got := cl.publishCount(); got != 1 {
		t.Fatalf("publishes = %d, want 1", got)
	}
	// An unchanged inventory must not re-enter the log.
	svc.PublishTemplateCatalog(ctx)
	svc.PublishTemplateCatalog(ctx)
	if got := cl.publishCount(); got != 1 {
		t.Fatalf("publishes = %d after two no-op calls; an unchanged inventory must write nothing", got)
	}
	// A change republishes.
	if err := st.CreateTemplate(ctx, &models.Template{ID: "tpl-2", Image: "alpine", Status: models.TemplateStatusReady}); err != nil {
		t.Fatal(err)
	}
	svc.PublishTemplateCatalog(ctx)
	if got := cl.publishCount(); got != 2 {
		t.Fatalf("publishes = %d, want the changed inventory republished", got)
	}

	page, ok := svc.ClusterArtifactCatalog(ctx, cluster.ArtifactKindTemplate, "")
	if !ok || len(page.Rows) != 2 {
		t.Fatalf("catalogue read ok=%v rows=%d, want both templates", ok, len(page.Rows))
	}
	var decoded models.Template
	if err := json.Unmarshal(page.Rows[0].Payload, &decoded); err != nil {
		t.Fatalf("catalogue row is not a template: %v", err)
	}
	if decoded.ID == "" {
		t.Fatal("catalogue row lost the template metadata the list has to return")
	}
}

// Standalone mode has no control plane to publish to, and a failed read must
// not look like an empty catalogue: the caller falls back to the peer sweep.
func TestClusterArtifactCatalogFallsBackWhenUnavailable(t *testing.T) {
	st := openSealTestStore(t)
	standalone := &Service{cfg: config.Config{}, store: st}
	if _, ok := standalone.ClusterArtifactCatalog(context.Background(), cluster.ArtifactKindTemplate, ""); ok {
		t.Fatal("standalone mode reported a cluster catalogue")
	}

	cl := newCatalogCluster("worker-a")
	cl.readErr = context.DeadlineExceeded
	clustered := &Service{cfg: config.Config{EnableCluster: true}, store: st, cluster: cl}
	if _, ok := clustered.ClusterArtifactCatalog(context.Background(), cluster.ArtifactKindTemplate, ""); ok {
		t.Fatal("an unreachable control plane reported a usable catalogue; the sweep must still run")
	}
}

// A failed publish must not be remembered as published, or the node stays
// invisible to the catalogue until its inventory happens to change again.
func TestArtifactCatalogPublishRetriesAfterFailure(t *testing.T) {
	st := openSealTestStore(t)
	cl := &failingCatalogCluster{catalogCluster: newCatalogCluster("worker-a"), fail: true}
	svc := &Service{cfg: config.Config{EnableCluster: true}, store: st, cluster: cl}
	ctx := context.Background()

	if err := st.CreateTemplate(ctx, &models.Template{ID: "tpl-1", Image: "alpine", Status: models.TemplateStatusReady}); err != nil {
		t.Fatal(err)
	}
	svc.PublishTemplateCatalog(ctx)
	if got := cl.publishCount(); got != 1 {
		t.Fatalf("attempts = %d, want the first publish attempted", got)
	}

	cl.mu.Lock()
	cl.fail = false
	cl.mu.Unlock()
	svc.PublishTemplateCatalog(ctx)
	if got := cl.publishCount(); got != 2 {
		t.Fatalf("attempts = %d; a failed publish was remembered as published, so the node never re-registers", got)
	}
}

type failingCatalogCluster struct {
	*catalogCluster
	fail bool
}

func (c *failingCatalogCluster) PublishArtifactCatalog(ctx context.Context, kind, tenant, nodeID string, rows []cluster.ArtifactCatalogRow) error {
	c.mu.Lock()
	failing := c.fail
	c.mu.Unlock()
	if failing {
		c.mu.Lock()
		c.publishes++
		c.mu.Unlock()
		return context.DeadlineExceeded
	}
	return c.catalogCluster.PublishArtifactCatalog(ctx, kind, tenant, nodeID, rows)
}
