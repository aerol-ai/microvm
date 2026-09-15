package service

import (
	"context"
	"io"

	"github.com/aerol-ai/microvm/internal/cluster"
)

type wave30AuthCluster struct {
	*cluster.Noop
	err        error
	placements map[string]cluster.Placement
	deleteErr  error
	deleted    []string
}

func (c *wave30AuthCluster) AuthoritativePlacementsByIDs(_ context.Context, ids []string) (map[string]cluster.Placement, error) {
	if c.err != nil {
		return nil, c.err
	}
	return c.PlacementsByIDs(ids), nil
}

func (c *wave30AuthCluster) PlacementsByIDs(ids []string) map[string]cluster.Placement {
	if c.err != nil {
		return nil
	}
	out := make(map[string]cluster.Placement, len(ids))
	for _, id := range ids {
		if p, ok := c.placements[id]; ok {
			out[id] = p
		}
	}
	return out
}

func (c *wave30AuthCluster) DeletePlacementExact(_ context.Context, sandboxID, _, _ string) error {
	c.deleted = append(c.deleted, sandboxID)
	return c.deleteErr
}

func (c *wave30AuthCluster) BeginDeletePlacementExact(_ context.Context, sandboxID, _, _ string) error {
	c.deleted = append(c.deleted, "begin:"+sandboxID)
	return c.deleteErr
}

func (c *wave30AuthCluster) Placements() []cluster.Placement {
	out := make([]cluster.Placement, 0, len(c.placements))
	for _, p := range c.placements {
		out = append(out, p)
	}
	return out
}

// Silence unused import if io only used via errReader path elsewhere.
// Silence unused import if io only used via errReader path elsewhere.
var _ = io.EOF
