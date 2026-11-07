package config

import (
	"fmt"
	"os"

	"github.com/aerol-ai/microvm/pkg/models"
)

// loadNodeLabelsConfig reads SB_NODE_ZONE and SB_NODE_LABELS. A malformed
// label fails the boot: a node whose labels silently dropped a typo would be
// unmatchable by the rules written for it, and creates would get 409s nobody
// can explain. Single-node mode reads them too, so a rule means the same
// thing with or without a cluster (plans/placement-rules.md P1.6).
func (cfg *Config) loadNodeLabelsConfig() error {
	labels, err := models.ParseNodeLabels(os.Getenv("SB_NODE_LABELS"), os.Getenv("SB_NODE_ZONE"))
	if err != nil {
		return fmt.Errorf("SB_NODE_LABELS / SB_NODE_ZONE: %w", err)
	}
	cfg.NodeLabels = labels
	return nil
}
