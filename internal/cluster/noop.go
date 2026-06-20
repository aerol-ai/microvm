package cluster

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Noop is the single-node-mode Client implementation. Every method behaves as
// if this node owns every sandbox and is the only cluster member. Used when
// cfg.EnableCluster is false so callsites can be unconditional.
type Noop struct {
	nodeID     string
	apiURL     string
	publicHost string

	// In-memory platform-volume metadata so the single-node Client is a correct
	// standalone store (useful in tests and any clustering-off code path that
	// happens to route through the cluster seam). Real deployments with
	// EnableCluster=false use the SQLite store directly; this just keeps the
	// interface honest rather than silently dropping writes.
	volMu    sync.Mutex
	volumes  map[string]models.Volume // key: tenant\x00id
	volNames map[string]string        // key: tenant\x00name -> id
}

// NewNoop returns a single-node Client. nodeID and apiURL are reported back
// for observability but never actually used for routing. publicHost is the
// operator-configured public ingress address (config.EffectivePublicHost)
// that IngressTargets reports as the single-member target. Empty when the
// daemon runs in IP-only mode (no SB_PUBLIC_HOST / SB_DOMAIN), which also
// means custom domains are disabled.
func NewNoop(nodeID, apiURL, publicHost string) *Noop {
	if nodeID == "" {
		nodeID = "standalone"
	}
	return &Noop{nodeID: nodeID, apiURL: apiURL, publicHost: publicHost}
}

func (n *Noop) SelfNodeID() string { return n.nodeID }
func (n *Noop) SelfAPIURL() string { return n.apiURL }

func (n *Noop) OwnerOf(sandboxID string) (OwnerInfo, error) {
	return OwnerInfo{NodeID: n.nodeID, APIURL: n.apiURL, IsSelf: true}, nil
}

func (n *Noop) OwnerOfName(name string) (string, OwnerInfo, error) {
	return "", OwnerInfo{}, ErrUnknownSandbox
}

func (n *Noop) SelectPlacement(req capacity.Request) (PlacementTarget, error) {
	return PlacementTarget{NodeID: n.nodeID, APIURL: n.apiURL, IsSelf: true}, nil
}

func (n *Noop) RecordPlacement(ctx context.Context, sandboxID string, spec *models.CreateSandboxRequest, secrets PlacementSecrets) error {
	return nil
}
func (n *Noop) ClaimOrphan(ctx context.Context, sandboxID string, spec *models.CreateSandboxRequest, secrets PlacementSecrets) error {
	return nil
}
func (n *Noop) UpsertSpec(ctx context.Context, sandboxID string, spec *models.CreateSandboxRequest, secrets PlacementSecrets) error {
	return nil
}
func (n *Noop) SpecOf(sandboxID string) *models.CreateSandboxRequest { return nil }
func (n *Noop) SecretsOf(sandboxID string) PlacementSecrets          { return PlacementSecrets{} }
func (n *Noop) SealedSecretsOf(sandboxID string) []byte              { return nil }
func (n *Noop) AddExposedPort(ctx context.Context, sandboxID string, port int, route ExposedPortRoute) error {
	return nil
}
func (n *Noop) RemoveExposedPort(ctx context.Context, sandboxID string, port int) error { return nil }
func (n *Noop) ExposedPortsOf(sandboxID string) map[int]ExposedPortRoute                { return nil }
func (n *Noop) AddCustomDomain(ctx context.Context, sandboxID, hostname string) error {
	return nil
}
func (n *Noop) RemoveCustomDomain(ctx context.Context, sandboxID, hostname string) error {
	return nil
}
func (n *Noop) CustomDomainsOf(sandboxID string) []string                   { return nil }
func (n *Noop) ResolveCustomDomain(hostname string) (string, bool)          { return "", false }
func (n *Noop) DeletePlacement(ctx context.Context, sandboxID string) error { return nil }
func (n *Noop) ReserveOnTarget(ctx context.Context, sandboxID string, target PlacementTarget, redacted *models.CreateSandboxRequest, secrets PlacementSecrets, ttl time.Duration) error {
	return nil
}
func (n *Noop) CancelReservation(ctx context.Context, sandboxID string) error { return nil }
func (n *Noop) SetNodeDrainState(ctx context.Context, nodeID string, drained bool) error {
	return nil
}
func (n *Noop) ReassignPlacement(ctx context.Context, sandboxID string, target PlacementTarget) error {
	return nil
}

func (n *Noop) VolumeUpsert(_ context.Context, v models.Volume, maxPerTenant int) (models.Volume, bool, error) {
	tenant := strings.TrimSpace(v.Tenant)
	name := strings.TrimSpace(v.Name)
	if tenant == "" || name == "" || strings.TrimSpace(v.ID) == "" {
		return models.Volume{}, false, ErrUnknownVolume
	}
	n.volMu.Lock()
	defer n.volMu.Unlock()
	if n.volumes == nil {
		n.volumes = make(map[string]models.Volume)
		n.volNames = make(map[string]string)
	}
	if id, ok := n.volNames[volumeNameKey(tenant, name)]; ok {
		return n.volumes[volumeKey(tenant, id)], false, nil
	}
	if maxPerTenant > 0 {
		count := 0
		for k := range n.volumes {
			if strings.HasPrefix(k, tenant+"\x00") {
				count++
			}
		}
		if count >= maxPerTenant {
			return models.Volume{}, false, ErrVolumeQuotaExceeded
		}
	}
	if v.CreatedAt.IsZero() {
		v.CreatedAt = time.Now().UTC()
	}
	n.volumes[volumeKey(tenant, v.ID)] = v
	n.volNames[volumeNameKey(tenant, name)] = v.ID
	return v, true, nil
}

func (n *Noop) VolumeDelete(_ context.Context, tenant, id string) error {
	tenant = strings.TrimSpace(tenant)
	id = strings.TrimSpace(id)
	n.volMu.Lock()
	defer n.volMu.Unlock()
	row, ok := n.volumes[volumeKey(tenant, id)]
	if !ok {
		return ErrUnknownVolume
	}
	delete(n.volumes, volumeKey(tenant, id))
	delete(n.volNames, volumeNameKey(tenant, row.Name))
	return nil
}

func (n *Noop) VolumeByID(_ context.Context, tenant, id string) (models.Volume, error) {
	n.volMu.Lock()
	defer n.volMu.Unlock()
	v, ok := n.volumes[volumeKey(strings.TrimSpace(tenant), strings.TrimSpace(id))]
	if !ok {
		return models.Volume{}, ErrUnknownVolume
	}
	return v, nil
}

func (n *Noop) VolumeByName(_ context.Context, tenant, name string) (models.Volume, error) {
	tenant = strings.TrimSpace(tenant)
	n.volMu.Lock()
	defer n.volMu.Unlock()
	id, ok := n.volNames[volumeNameKey(tenant, strings.TrimSpace(name))]
	if !ok {
		return models.Volume{}, ErrUnknownVolume
	}
	return n.volumes[volumeKey(tenant, id)], nil
}

func (n *Noop) VolumesForTenant(_ context.Context, tenant string) ([]models.Volume, error) {
	prefix := strings.TrimSpace(tenant) + "\x00"
	n.volMu.Lock()
	defer n.volMu.Unlock()
	out := []models.Volume{}
	for k, v := range n.volumes {
		if strings.HasPrefix(k, prefix) {
			out = append(out, v)
		}
	}
	return out, nil
}

func (n *Noop) VolumeExistsForSource(_ context.Context, source string) (bool, error) {
	source = strings.TrimSpace(source)
	n.volMu.Lock()
	defer n.volMu.Unlock()
	for _, v := range n.volumes {
		if v.Source == source {
			return true, nil
		}
	}
	return false, nil
}
func (n *Noop) RemoveMember(ctx context.Context, nodeID string, force bool) error {
	return ErrUnknownMember
}
func (n *Noop) IsNodeDrained(nodeID string) bool                       { return false }
func (n *Noop) ApplyEncoded(ctx context.Context, payload []byte) error { return nil }

func (n *Noop) AssertOwnership(ctx context.Context, local []LocalSandboxState) error { return nil }

func (n *Noop) ForwardHTTP(target Endpoint, w http.ResponseWriter, r *http.Request) {
	// Should never be called in single-node mode (OwnerOf always reports
	// IsSelf=true). If it is, surface the bug rather than silently 200.
	http.Error(w, "cluster: forwarding requested in single-node mode", http.StatusInternalServerError)
}

// AttachInternalHandler is a no-op for single-node mode — there's no mTLS
// listener to wire into, so nothing to do.
func (n *Noop) AttachInternalHandler(h http.Handler) {}

func (n *Noop) Members() []Member {
	return []Member{{NodeID: n.nodeID, APIURL: n.apiURL, PublicHost: n.publicHost, Alive: true}}
}

// IngressTargets reports the single-node deployment's public address as the
// DNS target. Empty publicHost (IP-only mode) returns the Unknown source so
// the service layer can surface a clean 412 rather than fake records.
func (n *Noop) IngressTargets() models.IngressTarget {
	if n.publicHost == "" {
		return models.IngressTarget{Source: models.IngressTargetSourceUnknown}
	}
	return composeIngressTarget([]string{n.publicHost})
}

func (n *Noop) Placements() []Placement { return nil }

func (n *Noop) PlacementsForShards(PlacementShardFilter) []Placement { return nil }

func (n *Noop) PlacementPage(PlacementPageRequest) PlacementPageResponse {
	return PlacementPageResponse{}
}

// PlacementOf has no record in single-node mode — there's no FSM. Returns
// the zero Placement and false so callers fall back to the local sandbox row.
func (n *Noop) PlacementOf(sandboxID string) (Placement, bool) { return Placement{}, false }

// PlacementVersion always returns 0 in single-node mode — there's no FSM and
// no need to wake an ingress reconciler that isn't running.
func (n *Noop) PlacementVersion() uint64 { return 0 }

// SubscribePlacement returns nil in single-node mode. Selecting on a nil
// channel never proceeds, so an ingress reconciler that select{}s on this
// channel + a slow ticker just behaves as if the cluster never has
// placement events — which is exactly the truth.
func (n *Noop) SubscribePlacement(ctx context.Context) <-chan struct{} { return nil }

func (n *Noop) Leader() string { return n.nodeID }

func (n *Noop) Close() error { return nil }
