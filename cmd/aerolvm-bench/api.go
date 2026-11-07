package main

import (
	"context"
	"errors"
	"strings"

	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// runTagKey tags every sandbox a run makes with the run's id, so cleanup can
// find the ones whose create answer never arrived.
const runTagKey = "aerolvm-bench-run"

// sandboxAPI is what the benchmark needs from AerolVM; sdkAPI is the real
// one, tests fake it.
type sandboxAPI interface {
	Create(ctx context.Context, opts sdktypes.CreateSandboxOptions) (created, error)
	// Destroy deletes a sandbox; one already gone is not an error.
	Destroy(ctx context.Context, id string) error
	// ListRun returns the ids of the sandboxes tagged with runID.
	ListRun(ctx context.Context, runID string) ([]string, error)
}

type created struct {
	ID     string
	Status string
}

type sdkAPI struct {
	// creates is sent once: a create the server refuses (429, 503) counts
	// as a failure, so the numbers show the server's own answers instead
	// of hiding a refusal inside a slower create.
	creates *microvm.Client
	// cleanup keeps the SDK's retries: deleting what the run made matters
	// more than how fast it goes.
	cleanup *microvm.Client
}

func newSDKAPI(apiURL, token string) (sandboxAPI, error) {
	noRetries := -1
	creates, err := microvm.NewClientWithConfig(&sdktypes.MicroVMConfig{
		APIUrl: apiURL, PATToken: token, Retry: &sdktypes.RetryConfig{MaxRetries: &noRetries},
	})
	if err != nil {
		return nil, err
	}
	cleanup, err := microvm.NewClientWithConfig(&sdktypes.MicroVMConfig{APIUrl: apiURL, PATToken: token})
	if err != nil {
		return nil, err
	}
	return &sdkAPI{creates: creates, cleanup: cleanup}, nil
}

func (a *sdkAPI) Create(ctx context.Context, opts sdktypes.CreateSandboxOptions) (created, error) {
	sb, err := a.creates.Create(ctx, opts)
	if err != nil {
		return created{}, err
	}
	return created{ID: sb.ID, Status: string(sb.Status)}, nil
}

func (a *sdkAPI) Destroy(ctx context.Context, id string) error {
	if err := a.cleanup.Destroy(ctx, id); err != nil && !errors.Is(err, microvm.ErrNotFound) {
		return err
	}
	return nil
}

func (a *sdkAPI) ListRun(ctx context.Context, runID string) ([]string, error) {
	items, err := a.cleanup.List(ctx, microvm.WithTags(map[string]string{runTagKey: runID}))
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, sb := range items {
		// Trust the row, not the filter: a server that ignored the tag
		// filter would list every sandbox, and this list feeds deletes.
		if sb.Tags[runTagKey] == runID && strings.HasPrefix(sb.Name, sandboxNamePrefix(runID)) {
			ids = append(ids, sb.ID)
		}
	}
	return ids, nil
}

// sandboxNamePrefix starts the name of every sandbox of run runID.
func sandboxNamePrefix(runID string) string { return "bench-" + runID + "-" }
