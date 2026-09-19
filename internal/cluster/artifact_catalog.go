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
// are. A node publishes the rows it holds for one (kind, tenant); the
// aggregator answers from the catalogue and only asks peers that have not
// published — a set that shrinks to zero as a rolling upgrade completes, and
// is the honest answer for a node whose inventory nobody knows.
//
// What is NOT done here, deliberately: publishing bundle digests into gossip.
// Gossip reaches every node in the fleet, and a node-wide digest list would
// let any peer infer the existence and byte-equality of another tenant's
// code. The Raft FSM is server-tier-only state that already holds every
// tenant's placements, so the catalogue adds no disclosure surface.

const (
	// ArtifactKindTemplate / ArtifactKindJSBundle name the two catalogues.
	// Templates are not tenant-scoped (ListTemplates returns the node's
	// rows), so they publish under the empty tenant.
	ArtifactKindTemplate = "template"
	ArtifactKindJSBundle = "js-bundle"

	// maxArtifactCatalogRowsPerNode bounds one node's published slice. A node
	// over the cap simply does not publish: it stays a non-publisher, the
	// aggregator keeps asking it directly, and the answer stays correct.
	maxArtifactCatalogRowsPerNode = 4096
	// maxArtifactCatalogRowBytes bounds one row. Rows are small metadata
	// (id, name, status, sizes); anything larger is a bug or an attack.
	maxArtifactCatalogRowBytes = 16 << 10
)

// ArtifactCatalogRow is one artifact's metadata as its holder serialized it.
// The FSM does not interpret Payload — the API layer owns the wire type — so
// adding a field to models.Template cannot require an FSM change.
type ArtifactCatalogRow struct {
	ID      string `json:"id"`
	Payload []byte `json:"payload"`
}

// ArtifactCatalogPage is what a reader gets back.
type ArtifactCatalogPage struct {
	Rows []ArtifactCatalogRow `json:"rows"`
	// Publishers are the nodes whose inventory this catalogue already
	// covers. The aggregator asks everyone else, so an unpublished node is
	// never silently dropped from a list.
	Publishers []string `json:"publishers"`
	// Authoritative distinguishes "nothing published yet" from "could not
	// ask". A non-authoritative answer must fall back to the fan-out.
	Authoritative bool `json:"authoritative,omitempty"`
}

// ArtifactCatalogRequest is the agent-facing read.
type ArtifactCatalogRequest struct {
	Kind   string `json:"kind"`
	Tenant string `json:"tenant,omitempty"`
}

// ArtifactCatalogPublishRequest is the agent-facing write.
type ArtifactCatalogPublishRequest struct {
	Kind   string               `json:"kind"`
	Tenant string               `json:"tenant,omitempty"`
	NodeID string               `json:"node_id"`
	Rows   []ArtifactCatalogRow `json:"rows"`
}

func artifactCatalogKey(kind, tenant string) string {
	return strings.TrimSpace(kind) + "\x00" + strings.TrimSpace(tenant)
}

// PublishArtifactCatalog replaces this node's slice of one catalogue.
func (c *Cluster) PublishArtifactCatalog(ctx context.Context, kind, tenant, nodeID string, rows []ArtifactCatalogRow) error {
	if c == nil {
		return fmt.Errorf("cluster: PublishArtifactCatalog requires a cluster")
	}
	if err := validateArtifactCatalogPublish(kind, nodeID, rows); err != nil {
		return err
	}
	return c.applyCommand(ctx, command{
		Op:             opPublishArtifactCatalog,
		ArtifactKind:   strings.TrimSpace(kind),
		ArtifactTenant: strings.TrimSpace(tenant),
		NodeID:         strings.TrimSpace(nodeID),
		ArtifactRows:   rows,
	})
}

// ArtifactCatalog reads one catalogue from the local FSM.
func (c *Cluster) ArtifactCatalog(_ context.Context, kind, tenant string) (ArtifactCatalogPage, error) {
	if c == nil || c.fsm == nil {
		return ArtifactCatalogPage{}, fmt.Errorf("cluster: node holds no placement state")
	}
	return c.fsm.artifactCatalogPage(kind, tenant), nil
}

// ArtifactCatalogForPeer answers the agent-facing read.
func (c *Cluster) ArtifactCatalogForPeer(kind, tenant string) ArtifactCatalogPage {
	if c == nil || c.fsm == nil {
		return ArtifactCatalogPage{}
	}
	return c.fsm.artifactCatalogPage(kind, tenant)
}

// PublishArtifactCatalog forwards the publish to the control plane.
func (a *Agent) PublishArtifactCatalog(ctx context.Context, kind, tenant, nodeID string, rows []ArtifactCatalogRow) error {
	if a == nil {
		return fmt.Errorf("cluster: PublishArtifactCatalog requires an agent")
	}
	if err := validateArtifactCatalogPublish(kind, nodeID, rows); err != nil {
		return err
	}
	return a.applyCommand(ctx, command{
		Op:             opPublishArtifactCatalog,
		ArtifactKind:   strings.TrimSpace(kind),
		ArtifactTenant: strings.TrimSpace(tenant),
		NodeID:         strings.TrimSpace(nodeID),
		ArtifactRows:   rows,
	})
}

// ArtifactCatalog reads the catalogue from the server tier. An unreachable
// control plane is an error: the caller falls back to the fan-out rather than
// reporting a tenant's artifacts as absent.
func (a *Agent) ArtifactCatalog(ctx context.Context, kind, tenant string) (ArtifactCatalogPage, error) {
	if a == nil {
		return ArtifactCatalogPage{}, fmt.Errorf("cluster: agent is not configured")
	}
	reqCtx, cancel := context.WithTimeout(ctx, controlPlaneRequestTimeout)
	defer cancel()
	var resp ArtifactCatalogPage
	body := ArtifactCatalogRequest{Kind: strings.TrimSpace(kind), Tenant: strings.TrimSpace(tenant)}
	if err := a.doControlPlaneJSON(reqCtx, http.MethodPost, PublicInternalArtifactCatalogPath, PublicInternalArtifactCatalogPath, body, &resp); err != nil {
		return ArtifactCatalogPage{}, fmt.Errorf("cluster: read artifact catalogue: %w", err)
	}
	if !resp.Authoritative {
		return ArtifactCatalogPage{}, fmt.Errorf("cluster: artifact catalogue read was not authoritative")
	}
	return resp, nil
}

func validateArtifactCatalogPublish(kind, nodeID string, rows []ArtifactCatalogRow) error {
	switch strings.TrimSpace(kind) {
	case ArtifactKindTemplate, ArtifactKindJSBundle:
	default:
		return fmt.Errorf("cluster: unknown artifact catalogue kind %q", kind)
	}
	if strings.TrimSpace(nodeID) == "" {
		return fmt.Errorf("cluster: artifact catalogue publish requires a node id")
	}
	if len(rows) > maxArtifactCatalogRowsPerNode {
		return fmt.Errorf("cluster: artifact catalogue publish of %d rows exceeds %d", len(rows), maxArtifactCatalogRowsPerNode)
	}
	for _, row := range rows {
		if strings.TrimSpace(row.ID) == "" {
			return fmt.Errorf("cluster: artifact catalogue row requires an id")
		}
		if len(row.Payload) > maxArtifactCatalogRowBytes {
			return fmt.Errorf("cluster: artifact catalogue row %q is %d bytes, over the %d cap", row.ID, len(row.Payload), maxArtifactCatalogRowBytes)
		}
	}
	return nil
}

// artifactCatalogEntry is one node's published slice of one catalogue.
type artifactCatalogEntry struct {
	Rows map[string]ArtifactCatalogRow
}

func (f *placementFSM) artifactCatalogPage(kind, tenant string) ArtifactCatalogPage {
	f.mu.RLock()
	defer f.mu.RUnlock()
	byNode := f.artifactCatalog[artifactCatalogKey(kind, tenant)]
	page := ArtifactCatalogPage{Authoritative: true}
	if len(byNode) == 0 {
		return page
	}
	seen := make(map[string]struct{})
	publishers := make([]string, 0, len(byNode))
	for nodeID, entry := range byNode {
		publishers = append(publishers, nodeID)
		for id, row := range entry.Rows {
			if _, dup := seen[id]; dup {
				continue
			}
			seen[id] = struct{}{}
			page.Rows = append(page.Rows, row)
		}
	}
	sort.Strings(publishers)
	sort.Slice(page.Rows, func(i, j int) bool { return page.Rows[i].ID < page.Rows[j].ID })
	page.Publishers = publishers
	return page
}
