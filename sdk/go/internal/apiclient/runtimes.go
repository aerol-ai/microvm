package apiclient

import (
	"context"
	"net/http"

	"github.com/aerol-ai/microvm/pkg/models"
)

// ListRuntimes reads every runtime a create accepts, what each can do, and
// whether this deployment offers it now (GET /v1/runtimes). It is a read,
// so it keeps the default retry tier. Nodes is set only for fleet admins:
// the server leaves it out for everyone else.
func (c *Client) ListRuntimes(ctx context.Context) ([]models.RuntimeListEntry, error) {
	var response models.ListRuntimesResponse
	if err := c.doJSON(ctx, http.MethodGet, c.versioned("/runtimes"), nil, &response); err != nil {
		return nil, err
	}
	if response.Runtimes == nil {
		return []models.RuntimeListEntry{}, nil
	}
	return response.Runtimes, nil
}
