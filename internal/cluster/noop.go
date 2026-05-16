package cluster

import (
	"context"
	"net/http"
	"time"

	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Noop is the single-node-mode Client implementation. Every method behaves as
// if this node owns every sandbox and is the only cluster member. Used when
// cfg.EnableCluster is false so callsites can be unconditional.
type Noop struct {
	nodeID string
	apiURL string
}

// NewNoop returns a single-node Client. nodeID and apiURL are reported back
// for observability but never actually used for routing.
func NewNoop(nodeID, apiURL string) *Noop {
	if nodeID == "" {
		nodeID = "standalone"
	}
	return &Noop{nodeID: nodeID, apiURL: apiURL}
}

func (n *Noop) SelfNodeID() string { return n.nodeID }
func (n *Noop) SelfAPIURL() string { return n.apiURL }

func (n *Noop) OwnerOf(sandboxID string) (OwnerInfo, error) {
	return OwnerInfo{NodeID: n.nodeID, APIURL: n.apiURL, IsSelf: true}, nil
}

func (n *Noop) SelectPlacement(req capacity.Request) (PlacementTarget, error) {
	return PlacementTarget{NodeID: n.nodeID, APIURL: n.apiURL, IsSelf: true}, nil
}

func (n *Noop) RecordPlacement(ctx context.Context, sandboxID string, spec *models.CreateSandboxRequest, sealedSecrets []byte) error {
	return nil
}
func (n *Noop) UpsertSpec(ctx context.Context, sandboxID string, spec *models.CreateSandboxRequest, sealedSecrets []byte) error {
	return nil
}
func (n *Noop) SpecOf(sandboxID string) *models.CreateSandboxRequest { return nil }
func (n *Noop) SealedSecretsOf(sandboxID string) []byte              { return nil }
func (n *Noop) AddExposedPort(ctx context.Context, sandboxID string, port int, route ExposedPortRoute) error {
	return nil
}
func (n *Noop) RemoveExposedPort(ctx context.Context, sandboxID string, port int) error { return nil }
func (n *Noop) ExposedPortsOf(sandboxID string) map[int]ExposedPortRoute                { return nil }
func (n *Noop) DeletePlacement(ctx context.Context, sandboxID string) error             { return nil }
func (n *Noop) ReserveOnTarget(ctx context.Context, sandboxID string, target PlacementTarget, redacted *models.CreateSandboxRequest, sealedSecrets []byte, ttl time.Duration) error {
	return nil
}
func (n *Noop) CancelReservation(ctx context.Context, sandboxID string) error { return nil }
func (n *Noop) SetNodeDrainState(ctx context.Context, nodeID string, drained bool) error {
	return nil
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
	return []Member{{NodeID: n.nodeID, APIURL: n.apiURL, Alive: true}}
}

func (n *Noop) Placements() []Placement { return nil }

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
