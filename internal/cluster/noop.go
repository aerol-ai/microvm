package cluster

import (
	"context"
	"net/http"

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

func (n *Noop) RecordPlacement(ctx context.Context, sandboxID string, spec *models.CreateSandboxRequest) error {
	return nil
}
func (n *Noop) UpsertSpec(ctx context.Context, sandboxID string, spec *models.CreateSandboxRequest) error {
	return nil
}
func (n *Noop) SpecOf(sandboxID string) *models.CreateSandboxRequest { return nil }
func (n *Noop) AddExposedPort(ctx context.Context, sandboxID string, port int, protocol string) error {
	return nil
}
func (n *Noop) RemoveExposedPort(ctx context.Context, sandboxID string, port int) error { return nil }
func (n *Noop) ExposedPortsOf(sandboxID string) map[int]string                          { return nil }
func (n *Noop) DeletePlacement(ctx context.Context, sandboxID string) error             { return nil }
func (n *Noop) ApplyEncoded(ctx context.Context, payload []byte) error                  { return nil }

func (n *Noop) AssertOwnership(ctx context.Context, local []LocalSandboxState) error { return nil }

func (n *Noop) ForwardHTTP(peerAPIURL string, w http.ResponseWriter, r *http.Request) {
	// Should never be called in single-node mode (OwnerOf always reports
	// IsSelf=true). If it is, surface the bug rather than silently 200.
	http.Error(w, "cluster: forwarding requested in single-node mode", http.StatusInternalServerError)
}

func (n *Noop) Members() []Member {
	return []Member{{NodeID: n.nodeID, APIURL: n.apiURL, Alive: true}}
}

func (n *Noop) Leader() string { return n.nodeID }

func (n *Noop) Close() error { return nil }
