package daemon

import (
	"context"
	"fmt"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
)

// oneWayFinalizer is the store's half of finalize in a cluster: run the
// one-way migrations, and list what is still pending.
type oneWayFinalizer interface {
	oneWayMigrator
	PendingOneWayMigrations(ctx context.Context) ([]int, error)
}

// attachOneWayMigrator hands the cluster client this node's finalize step
// (plans/kubectl-style-cluster-ops.md §6.5): once the leader commits a new
// active version, the rollout's finalize step calls it on every node, and
// features that need the new schema turn on per node only after it ran. A
// database with nothing pending is finished from the start. A client
// without the hook (Noop) is left alone.
func attachOneWayMigrator(ctx context.Context, c cluster.Client, db oneWayFinalizer) {
	target, ok := c.(interface {
		AttachOneWayMigrator(cluster.OneWayMigrator, bool)
	})
	if !ok {
		return
	}
	pending, err := db.PendingOneWayMigrations(ctx)
	target.AttachOneWayMigrator(db.RunOneWayMigrations, err == nil && len(pending) == 0)
}

// oneWayMigrator is the store's finalize-gated migration step
// (store.Store.RunOneWayMigrations).
type oneWayMigrator interface {
	RunOneWayMigrations(ctx context.Context) error
}

// runStandaloneOneWayMigrations runs the store's one-way schema migrations
// at boot when cluster mode is off. Open runs only n1Safe migrations, so the
// previous release can still read the database until finalize
// (plans/kubectl-style-cluster-ops.md §6.5, CEO D16). A single node has no
// rollout to finalize: rolling it back means restoring the backup the
// upgrader takes before the swap, so its one-way steps run at once. In a
// cluster the rollout's finalize step calls RunOneWayMigrations instead,
// after the leader commits the new active version.
func runStandaloneOneWayMigrations(ctx context.Context, cfg config.Config, db oneWayMigrator) error {
	if cfg.EnableCluster {
		return nil
	}
	if err := db.RunOneWayMigrations(ctx); err != nil {
		return fmt.Errorf("run one-way schema migrations: %w", err)
	}
	return nil
}
