package daemon

import (
	"context"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
)

// clusterShutdownBudget bounds the cluster's part of a graceful stop: a
// leadership hand-off (cluster.leaderHandoffTimeout) plus the restart notice.
// It runs before the listeners drain, so it comes out of the same
// termination grace; Kubernetes' default 30 s covers both.
const clusterShutdownBudget = 15 * time.Second

// prepareClusterShutdown runs the cluster client's shutdown step (C8). It
// does nothing outside cluster mode, where no client exists.
func prepareClusterShutdown(p cluster.ShutdownPreparer) {
	if p == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), clusterShutdownBudget)
	defer cancel()
	p.PrepareShutdown(ctx)
}
