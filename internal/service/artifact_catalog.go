package service

import (
	"context"
	"encoding/json"
	"errors"
	"expvar"
	"strconv"
	"strings"
	"sync"

	"github.com/google/uuid"

	"github.com/aerol-ai/microvm/internal/cluster"
)

// Publishing this node's artifact metadata into the replicated catalogue.
//
// Listing templates or JS bundles across a cluster used to ask every
// runtime-capable worker. The catalogue replaces that with a control-plane
// read (see internal/cluster/artifact_catalog.go); this file is the writer
// side, and it is a RECONCILER rather than a side effect:
//
//   - Every inventory mutation marks the kind dirty. Wiring publication to a
//     handful of call sites meant a create, a build completing or a GC sweep
//     left the catalogue advertising an inventory the node no longer had —
//     and because the aggregator skips a node it already covers, nothing
//     asked the node again to find out.
//   - The reconciler publishes the CURRENT local inventory under a revision,
//     in chunks the apply transport accepts, and only records success after
//     the whole snapshot commits. An older publication that lands late is
//     fenced by the FSM, and the node stays dirty until a publish of the
//     inventory as it is now succeeds.
//   - It runs on the maintenance tick and at boot, so a failed publish is
//     retried rather than logged and forgotten.
//
// An empty inventory is published too: "this node holds nothing of this kind"
// is the answer that keeps a tenant with no artifacts anywhere from sending
// every list back to the whole fleet.

// artifactCatalogCoverageWithdrawn counts inventories this node could not
// represent. A non-zero value means its artifacts are being listed by the
// peer sweep rather than the catalogue.
var artifactCatalogCoverageWithdrawn = expvar.NewInt("aerolvm_artifact_catalogue_coverage_withdrawn_total")

// artifactCatalogPublisher is the cluster capability this needs. Both the
// server-role Cluster (local apply) and the worker/ingress Agent (forwarded
// apply) provide it; Noop does not, which keeps standalone mode inert.
type artifactCatalogPublisher interface {
	PublishArtifactCatalog(ctx context.Context, chunk cluster.ArtifactCatalogSnapshot) error
}

// artifactCatalogReader is the read side, used by the API aggregator.
type artifactCatalogReader interface {
	ArtifactCatalog(ctx context.Context, req cluster.ArtifactCatalogRequest) (cluster.ArtifactCatalogPage, error)
}

// artifactCatalogState tracks, per kind, what the local inventory has reached
// and what the catalogue has accepted. dirty is set by every mutation and
// cleared only by a publication of a revision that is still current.
type artifactCatalogState struct {
	mu        sync.Mutex
	epoch     map[string]int64
	revision  map[string]int64
	published map[string]int64
	// holder is this process's identity, generated once, and holderGen
	// distinguishes one ALLOCATION ATTEMPT from the next. The authority hands
	// the same token back to the same (holder, generation), which is what
	// makes a retry after a lost response idempotent; retiring a refused
	// token bumps the generation so the next attempt is issued a fresh one
	// rather than the number that was just refused.
	holder    string
	holderGen map[string]int64
}

// publisherEpoch returns the fencing token this process publishes under, or 0
// when it has not been issued yet. The token comes from the AUTHORITY (the
// catalogue's committed epoch plus one), not from the process, so a request
// still in flight from a replaced process is refused however high its
// revision.
func (s *artifactCatalogState) publisherEpoch(kind string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.epoch[kind]
}

// seedEpoch records the token the authority issued. It never goes backwards
// within a process.
func (s *artifactCatalogState) seedEpoch(kind string, epoch int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.epoch == nil {
		s.epoch = make(map[string]int64)
	}
	if epoch > s.epoch[kind] {
		s.epoch[kind] = epoch
		// A new epoch restarts the revision sequence, and nothing published
		// under the old one counts as published.
		if s.revision == nil {
			s.revision = make(map[string]int64)
		}
		s.revision[kind] = 1
		delete(s.published, kind)
	}
}

// retireEpoch drops the token after the authority refuses it, so the next
// pass asks for a fresh one.
func (s *artifactCatalogState) retireEpoch(kind string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.epoch, kind)
	delete(s.published, kind)
	// The next allocation for THIS kind must be a new token: re-asking under
	// the same identity would be answered with the one the authority just
	// refused. The other kind's generation is untouched, so its own retry
	// stays idempotent.
	if s.holderGen == nil {
		s.holderGen = make(map[string]int64)
	}
	s.holderGen[kind]++
}

// markDirty bumps the kind's revision and returns it.
func (s *artifactCatalogState) markDirty(kind string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.revision == nil {
		s.revision = make(map[string]int64)
	}
	s.revision[kind]++
	return s.revision[kind]
}

// begin returns the revision a publication should carry, and whether one is
// needed at all.
func (s *artifactCatalogState) begin(kind string) (int64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.revision == nil {
		s.revision = make(map[string]int64)
	}
	if s.revision[kind] == 0 {
		// Nothing has marked this kind yet — boot is the first mark.
		s.revision[kind] = 1
	}
	current := s.revision[kind]
	if s.published[kind] == current {
		return 0, false
	}
	return current, true
}

// commit records a successful publication. It is ignored when the inventory
// moved on while the publication was in flight, so the reconciler publishes
// again rather than believing the newer state is out there.
func (s *artifactCatalogState) commit(kind string, revision int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.revision[kind] != revision {
		return
	}
	if s.published == nil {
		s.published = make(map[string]int64)
	}
	s.published[kind] = revision
}

// MarkArtifactCatalogDirty records that this node's inventory of a kind
// changed. It is deliberately cheap — no I/O, no Raft — so every mutation can
// call it; the reconciler does the publishing.
func (s *Service) MarkArtifactCatalogDirty(kind string) {
	if s == nil {
		return
	}
	s.artifactCatalog.markDirty(kind)
}

// ReconcileArtifactCatalog republishes any kind whose local inventory has
// moved since its last accepted publication. Called from the maintenance tick
// and at boot.
func (s *Service) ReconcileArtifactCatalog(ctx context.Context) {
	if s == nil {
		return
	}
	publisher, nodeID, ok := s.artifactCatalogPublisher()
	if !ok {
		return
	}
	s.reconcileArtifactKind(ctx, publisher, nodeID, cluster.ArtifactKindTemplate)
	s.reconcileArtifactKind(ctx, publisher, nodeID, cluster.ArtifactKindJSBundle)
}

func (s *Service) reconcileArtifactKind(ctx context.Context, publisher artifactCatalogPublisher, nodeID, kind string) {
	epoch, ok := s.ensurePublisherEpoch(ctx, kind, nodeID)
	if !ok {
		// No fencing token: publishing without one is how a replaced process
		// takes ownership back. Stay dirty and ask again next pass.
		return
	}
	revision, needed := s.artifactCatalog.begin(kind)
	if !needed {
		return
	}
	rows, ok := s.localArtifactRows(ctx, kind)
	if !ok {
		// The local inventory could not be read. Publishing an empty snapshot
		// would tell the aggregator this node holds nothing; staying dirty
		// retries instead.
		return
	}
	if len(rows) > cluster.MaxArtifactCatalogRowsPerNode() {
		// "Peers will keep being asked" is only true for a node nobody has
		// covered yet. A node already in the catalogue would keep its last
		// inventory advertised and keep being SKIPPED, so an inventory that
		// cannot be represented has to withdraw the coverage explicitly.
		if s.logger != nil {
			s.logger.Warn("cluster: artifact inventory exceeds the catalogue cap; withdrawing coverage so peers are asked directly",
				"kind", kind, "rows", len(rows), "cap", cluster.MaxArtifactCatalogRowsPerNode())
		}
		if err := publisher.PublishArtifactCatalog(ctx, cluster.WithdrawArtifactCatalogCoverage(kind, nodeID, epoch, revision)); err != nil {
			if errors.Is(err, cluster.ErrArtifactCatalogSuperseded) {
				s.artifactCatalog.retireEpoch(kind)
			}
			if s.logger != nil {
				s.logger.Warn("cluster: artifact catalogue coverage withdrawal failed; retrying on the next maintenance pass",
					"kind", kind, "err", err)
			}
			return
		}
		artifactCatalogCoverageWithdrawn.Add(1)
		s.artifactCatalog.commit(kind, revision)
		return
	}
	for _, chunk := range cluster.ChunkArtifactCatalogSnapshot(kind, nodeID, epoch, revision, rows) {
		if err := publisher.PublishArtifactCatalog(ctx, chunk); err != nil {
			if errors.Is(err, cluster.ErrArtifactCatalogSuperseded) {
				// Another process owns this node's catalogue entry, or our
				// token is stale. Drop it and ask the authority again rather
				// than retrying under an epoch it has moved past.
				s.artifactCatalog.retireEpoch(kind)
			}
			// The kind stays dirty, so the next tick starts the snapshot
			// again from its first chunk. A half-delivered snapshot is never
			// committed, so the catalogue keeps serving the previous one.
			if s.logger != nil {
				s.logger.Warn("cluster: artifact catalogue publish failed; retrying on the next maintenance pass",
					"kind", kind, "epoch", epoch, "revision", revision, "err", err)
			}
			return
		}
	}
	s.artifactCatalog.commit(kind, revision)
}

// ensurePublisherEpoch obtains this process's fencing token for a kind,
// asking the authority once and reusing it afterwards.
//
// The token is ALLOCATED, not read-and-incremented: two processes for the
// same node that each read the committed epoch pick the same successor, and
// the catalogue can then no longer order them. artifactCatalogHolder is this
// process's identity, which makes a retried allocation return the token
// already issued instead of burning a fresh one per attempt.
func (s *Service) ensurePublisherEpoch(ctx context.Context, kind, nodeID string) (int64, bool) {
	if epoch := s.artifactCatalog.publisherEpoch(kind); epoch > 0 {
		return epoch, true
	}
	c := s.Cluster()
	allocator, ok := c.(interface {
		AllocateArtifactCatalogEpoch(ctx context.Context, kind, nodeID, holder string) (int64, error)
	})
	if !ok {
		return 0, false
	}
	issued, err := allocator.AllocateArtifactCatalogEpoch(ctx, kind, nodeID, s.artifactCatalogHolder(kind))
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("cluster: artifact catalogue publisher epoch allocation failed; publication deferred",
				"kind", kind, "err", err)
		}
		return 0, false
	}
	s.artifactCatalog.seedEpoch(kind, issued)
	return s.artifactCatalog.publisherEpoch(kind), true
}

// artifactCatalogHolder is this process's identity for one kind's token
// allocation: stable for the life of the process, distinct from any
// predecessor's, and advanced when a token is refused.
func (s *Service) artifactCatalogHolder(kind string) string {
	s.artifactCatalog.mu.Lock()
	defer s.artifactCatalog.mu.Unlock()
	if s.artifactCatalog.holder == "" {
		s.artifactCatalog.holder = uuid.NewString()
	}
	return s.artifactCatalog.holder + "/" + kind + "/" + strconv.FormatInt(s.artifactCatalog.holderGen[kind], 10)
}

// localArtifactRows builds this node's rows for one kind. ok=false means the
// inventory could not be read, which is not the same as an empty one.
func (s *Service) localArtifactRows(ctx context.Context, kind string) ([]cluster.ArtifactCatalogRow, bool) {
	switch kind {
	case cluster.ArtifactKindTemplate:
		if s.store == nil {
			return nil, false
		}
		templates, err := s.store.ListTemplates(ctx)
		if err != nil {
			if s.logger != nil {
				s.logger.Warn("cluster: template catalogue publish skipped; local list failed", "err", err)
			}
			return nil, false
		}
		rows := make([]cluster.ArtifactCatalogRow, 0, len(templates))
		for _, tpl := range templates {
			if tpl == nil || strings.TrimSpace(tpl.ID) == "" {
				continue
			}
			payload, err := encodeArtifactRow(tpl)
			if err != nil {
				continue
			}
			// Templates are not tenant-scoped; they publish under the empty
			// tenant so every tenant's list reads them.
			rows = append(rows, cluster.ArtifactCatalogRow{ID: tpl.ID, Payload: payload})
		}
		return rows, true
	case cluster.ArtifactKindJSBundle:
		if s.isolateBundles == nil {
			// No bundle store on this node: an empty inventory is the honest
			// answer, and publishing it is what stops every bundle list
			// asking this node again.
			return nil, true
		}
		owners := s.isolateBundles.Tenants()
		rows := make([]cluster.ArtifactCatalogRow, 0, len(owners))
		for _, owner := range owners {
			bundles, err := s.listJSBundlesForTenant(owner)
			if err != nil {
				return nil, false
			}
			for _, b := range bundles {
				if b == nil || strings.TrimSpace(b.Digest) == "" {
					continue
				}
				payload, err := encodeArtifactRow(b)
				if err != nil {
					continue
				}
				rows = append(rows, cluster.ArtifactCatalogRow{ID: b.Digest, Tenant: owner, Payload: payload})
			}
		}
		return rows, true
	}
	return nil, false
}

// ClusterArtifactCatalog reads one page of the replicated catalogue.
// Returns ok=false when this node is not clustered or the control plane could
// not answer — the caller then falls back to asking peers directly, which is
// the pre-catalogue behavior and never reports an artifact as absent.
func (s *Service) ClusterArtifactCatalog(ctx context.Context, req cluster.ArtifactCatalogRequest) (cluster.ArtifactCatalogPage, bool) {
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
	page, err := reader.ArtifactCatalog(ctx, req)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("cluster: artifact catalogue read failed; falling back to the peer sweep",
				"kind", req.Kind, "err", err)
		}
		return cluster.ArtifactCatalogPage{}, false
	}
	return page, true
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

// encodeArtifactRow serializes one row's metadata. Kept in one place so both
// kinds stay on the same wire shape the API layer decodes.
func encodeArtifactRow(v any) ([]byte, error) {
	return json.Marshal(v)
}
