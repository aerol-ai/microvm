package daemon

import (
	"context"
	"fmt"

	"github.com/aerol-ai/microvm/internal/config"
)

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
