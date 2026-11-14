package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
)

// ErrNotReady wraps every reason Ready gives for a node that should not get
// traffic yet. Its text is the reason a readiness probe sees.
var ErrNotReady = errors.New("not ready")

// Ready says whether to send this node traffic (/ready; Kubernetes v2 plan
// C1, the first plan's decision D8). Health says the process is up; a node
// cut off from the control plane is up, and answered /health with 200, so
// load balancers kept sending it requests that failed (TODOS.md, "A
// partitioned node keeps serving").
//
// A single node is its own control plane, so Ready is Health. In cluster
// mode it also needs this node to be part of the control plane (a server
// still in the raft configuration) and to have had proof of a working one
// within ReadyLeaderGrace: the raft leader, a follower that heard from it,
// or an agent whose control-plane calls succeed (cluster.ControlPlaneContact).
// The grace sits above a normal election, so one does not take every node
// out of rotation at once.
func (s *Service) Ready(ctx context.Context) error {
	if _, err := s.Health(ctx); err != nil {
		return fmt.Errorf("%w: %v", ErrNotReady, err)
	}
	if !s.ClusterEnabled() {
		return nil
	}
	r, ok := s.Cluster().(cluster.ControlPlaneContactReporter)
	if !ok {
		return nil
	}
	contact := r.ControlPlaneContact(ctx)
	if !contact.Member {
		return fmt.Errorf("%w: this server is not in the control plane's raft configuration", ErrNotReady)
	}
	grace := s.cfg.ReadyLeaderGrace
	if grace <= 0 {
		grace = config.DefaultReadyLeaderGrace
	}
	if contact.Last.IsZero() {
		return fmt.Errorf("%w: no contact with the control plane yet", ErrNotReady)
	}
	if since := time.Since(contact.Last); since > grace {
		return fmt.Errorf("%w: no contact with the control plane for %s (more than %s)", ErrNotReady, since.Round(time.Second), grace)
	}
	return nil
}
