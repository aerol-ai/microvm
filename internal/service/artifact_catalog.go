package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"sync"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Publishing this node's artifact metadata into the replicated catalogue.
//
// Listing templates or JS bundles across a cluster used to ask every
// runtime-capable worker. The catalogue replaces that with a control-plane
// read (see internal/cluster/artifact_catalog.go); this file is the writer
// side: whenever the local inventory for one (kind, tenant) changes, the node
// republishes its slice of it.
//
// Publishing is best effort and debounced by a fingerprint of the local rows:
// a Raft write per list request would trade a fan-out for a write storm, and
// nothing here is on a create path.

// artifactCatalogPublisher is the cluster capability this needs. Both the
// server-role Cluster (local apply) and the worker/ingress Agent (forwarded
// apply) provide it; Noop does not, which keeps standalone mode inert.
type artifactCatalogPublisher interface {
	PublishArtifactCatalog(ctx context.Context, kind, tenant, nodeID string, rows []cluster.ArtifactCatalogRow) error
}

// artifactCatalogReader is the read side, used by the API aggregator.
type artifactCatalogReader interface {
	ArtifactCatalog(ctx context.Context, kind, tenant string) (cluster.ArtifactCatalogPage, error)
}

// publishedArtifactFingerprints remembers what this process last published
// for each (kind, tenant), so an unchanged inventory costs nothing.
type publishedArtifactFingerprints struct {
	mu   sync.Mutex
	seen map[string]string
}

func (p *publishedArtifactFingerprints) changed(key, fingerprint string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.seen == nil {
		p.seen = make(map[string]string)
	}
	if p.seen[key] == fingerprint {
		return false
	}
	p.seen[key] = fingerprint
	return true
}

func (p *publishedArtifactFingerprints) forget(key string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.seen, key)
}

// ClusterArtifactCatalog reads the replicated catalogue for (kind, tenant).
// Returns ok=false when this node is not clustered or the control plane could
// not answer — the caller then falls back to asking peers directly, which is
// the pre-catalogue behavior and never reports an artifact as absent.
func (s *Service) ClusterArtifactCatalog(ctx context.Context, kind, tenant string) (cluster.ArtifactCatalogPage, bool) {
	if s == nil || !s.cfg.EnableCluster {
		return cluster.ArtifactCatalogPage{}, false
	}
	c := s.Cluster()
	if c == nil {
		return cluster.ArtifactCatalogPage{}, false
	}
	reader, ok := c.(artifactCatalogReader)
	if !ok {
		return cluster.ArtifactCatalogPage{}, false
	}
	page, err := reader.ArtifactCatalog(ctx, kind, tenant)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("cluster: artifact catalogue read failed; falling back to the peer sweep",
				"kind", kind, "err", err)
		}
		return cluster.ArtifactCatalogPage{}, false
	}
	return page, true
}

// PublishTemplateCatalog republishes this node's template metadata. Templates
// are not tenant-scoped, so they live under the empty tenant.
func (s *Service) PublishTemplateCatalog(ctx context.Context) {
	if s == nil || s.store == nil {
		return
	}
	if _, _, ok := s.artifactCatalogPublisher(); !ok {
		return
	}
	templates, err := s.store.ListTemplates(ctx)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("cluster: template catalogue publish skipped; local list failed", "err", err)
		}
		return
	}
	s.PublishTemplateCatalogRows(ctx, templates)
}

// PublishTemplateCatalogRows is PublishTemplateCatalog for a caller that
// already holds the rows. The list handlers use it to self-heal: a node whose
// inventory predates the catalogue (or whose publish failed) registers itself
// the first time anyone reads its list — including the sweep that is still
// asking it directly. Debounced by a fingerprint, so a steady inventory
// writes nothing, and reading the table twice per list would be exactly the
// hidden cost this change exists to remove.
func (s *Service) PublishTemplateCatalogRows(ctx context.Context, templates []*models.Template) {
	publisher, nodeID, ok := s.artifactCatalogPublisher()
	if !ok {
		return
	}
	rows := make([]cluster.ArtifactCatalogRow, 0, len(templates))
	for _, tpl := range templates {
		if tpl == nil || strings.TrimSpace(tpl.ID) == "" {
			continue
		}
		payload, err := json.Marshal(tpl)
		if err != nil {
			continue
		}
		rows = append(rows, cluster.ArtifactCatalogRow{ID: tpl.ID, Payload: payload})
	}
	s.publishArtifactRows(ctx, publisher, cluster.ArtifactKindTemplate, "", nodeID, rows)
}

// PublishJSBundleCatalog republishes this node's bundle metadata for one
// tenant. Bundles ARE tenant-scoped, and the catalogue key keeps them that
// way: a tenant's list never reads another tenant's rows.
func (s *Service) PublishJSBundleCatalog(ctx context.Context, tenant string) {
	if s == nil || s.isolateBundles == nil {
		return
	}
	publisher, nodeID, ok := s.artifactCatalogPublisher()
	if !ok {
		return
	}
	bundles, err := s.listJSBundlesForTenant(tenant)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("cluster: js-bundle catalogue publish skipped; local list failed", "err", err)
		}
		return
	}
	rows := make([]cluster.ArtifactCatalogRow, 0, len(bundles))
	for _, b := range bundles {
		if b == nil || strings.TrimSpace(b.Digest) == "" {
			continue
		}
		payload, err := json.Marshal(b)
		if err != nil {
			continue
		}
		rows = append(rows, cluster.ArtifactCatalogRow{ID: b.Digest, Payload: payload})
	}
	s.publishArtifactRows(ctx, publisher, cluster.ArtifactKindJSBundle, tenant, nodeID, rows)
}

func (s *Service) publishArtifactRows(ctx context.Context, publisher artifactCatalogPublisher, kind, tenant, nodeID string, rows []cluster.ArtifactCatalogRow) {
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	key := kind + "\x00" + tenant
	fingerprint := artifactRowsFingerprint(rows)
	if !s.artifactCatalogPublished.changed(key, fingerprint) {
		return
	}
	if err := publisher.PublishArtifactCatalog(ctx, kind, tenant, nodeID, rows); err != nil {
		// Drop the fingerprint so the next attempt retries rather than
		// believing this slice is published.
		s.artifactCatalogPublished.forget(key)
		if s.logger != nil {
			s.logger.Warn("cluster: artifact catalogue publish failed; peers will keep being asked directly",
				"kind", kind, "rows", len(rows), "err", err)
		}
	}
}

// artifactRowsFingerprint hashes the published slice so an unchanged
// inventory does not re-enter the Raft log.
func artifactRowsFingerprint(rows []cluster.ArtifactCatalogRow) string {
	h := sha256.New()
	for _, row := range rows {
		h.Write([]byte(row.ID))
		h.Write([]byte{0})
		h.Write(row.Payload)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (s *Service) artifactCatalogPublisher() (artifactCatalogPublisher, string, bool) {
	if s == nil || !s.cfg.EnableCluster {
		return nil, "", false
	}
	c := s.Cluster()
	if c == nil {
		return nil, "", false
	}
	nodeID := strings.TrimSpace(c.SelfNodeID())
	if nodeID == "" {
		return nil, "", false
	}
	publisher, ok := c.(artifactCatalogPublisher)
	if !ok {
		return nil, "", false
	}
	return publisher, nodeID, true
}
