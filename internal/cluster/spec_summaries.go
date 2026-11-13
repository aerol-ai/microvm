package cluster

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"

	"github.com/aerol-ai/microvm/pkg/models"
)

// Spec summaries (plans/kubernetes-v2-architecture.md §16, C17). The
// agent-sandbox API shows each sandbox's image, runtime and size, which the
// hot placement row leaves out (the spec rides the recovery payload). A
// gateway reads a page's worth in one call instead of one point read per
// sandbox. A summary never carries env values, mounts or registry
// credentials: only what a Kubernetes reader is shown.

// PublicInternalSpecSummariesPath answers a batch from a server's FSM.
const PublicInternalSpecSummariesPath = "/v1/cluster/internal/placements/spec-summaries"

// MaxSpecSummaryBatch bounds one call.
const MaxSpecSummaryBatch = 500

// ErrBadSpecSummaryBatch is an empty or oversized batch.
var ErrBadSpecSummaryBatch = errors.New("cluster: a spec-summary batch holds 1 to 500 ids")

// SpecSummary is what the API shows of a sandbox's spec, at the placement
// Version it was read from (a cache keyed by it stays right across a stop,
// which does not move the version).
type SpecSummary struct {
	Image    string   `json:"image,omitempty"`
	Runtime  string   `json:"runtime,omitempty"`
	CPU      float64  `json:"cpu,omitempty"`
	MemoryMB int      `json:"memory_mb,omitempty"`
	Command  []string `json:"command,omitempty"`
	// Tags are shown as the object's labels; a claim's tags mark it as one.
	Tags    map[string]string `json:"tags,omitempty"`
	Version uint64            `json:"version"`
}

// SpecSummariesRequest names the sandboxes.
type SpecSummariesRequest struct {
	IDs []string `json:"ids"`
}

// SpecSummariesResponse has a summary for each id with a spec.
type SpecSummariesResponse struct {
	Summaries map[string]SpecSummary `json:"summaries"`
}

// SpecSummaryReader is implemented by Cluster (its own FSM) and Agent (the
// server tier).
type SpecSummaryReader interface {
	SpecSummaries(ctx context.Context, ids []string) (map[string]SpecSummary, error)
}

func summarizeSpec(spec *models.CreateSandboxRequest, version uint64) SpecSummary {
	return SpecSummary{Image: spec.Image, Runtime: spec.Runtime, CPU: spec.CPU, MemoryMB: spec.MemoryMB,
		Command: slices.Clone(spec.ContainerCommand), Tags: maps.Clone(spec.Tags), Version: version}
}

func validSpecSummaryBatch(ids []string) error {
	if len(ids) == 0 || len(ids) > MaxSpecSummaryBatch {
		return fmt.Errorf("%w, not %d", ErrBadSpecSummaryBatch, len(ids))
	}
	return nil
}

// SpecSummaries reads the summaries from this server's FSM.
func (c *Cluster) SpecSummaries(_ context.Context, ids []string) (map[string]SpecSummary, error) {
	if c == nil || c.fsm == nil {
		return nil, fmt.Errorf("cluster: node holds no placement state")
	}
	if err := validSpecSummaryBatch(ids); err != nil {
		return nil, err
	}
	out := make(map[string]SpecSummary, len(ids))
	for _, id := range ids {
		if p, ok := c.fsm.get(id); ok && p.Spec != nil {
			out[id] = summarizeSpec(p.Spec, p.Version)
		}
	}
	return out, nil
}

// SpecSummaries reads the summaries from the server tier.
func (a *Agent) SpecSummaries(ctx context.Context, ids []string) (map[string]SpecSummary, error) {
	if a == nil {
		return nil, fmt.Errorf("cluster: agent is not configured")
	}
	if err := validSpecSummaryBatch(ids); err != nil {
		return nil, err
	}
	reqCtx, cancel := context.WithTimeout(ctx, controlPlaneRequestTimeout)
	defer cancel()
	var out SpecSummariesResponse
	if err := a.doControlPlaneJSON(reqCtx, http.MethodPost, PublicInternalSpecSummariesPath, PublicInternalSpecSummariesPath, SpecSummariesRequest{IDs: ids}, &out); err != nil {
		return nil, fmt.Errorf("cluster: spec summaries: %w", err)
	}
	return out.Summaries, nil
}
