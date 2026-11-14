package apiclient

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/aerol-ai/microvm/pkg/models"
)

// Warm pools (plans/agent-sandbox-feature-parity.md W1). Each call is a
// PUT, GET or DELETE of one entry, so every one is safe to retry and keeps
// the default retry tier.

// warmPoolPath keeps an image's slashes as path separators and escapes each
// segment, so ghcr.io/acme/agent:1 reaches the server as written and no
// proxy has an encoded slash to rewrite.
func (c *Client) warmPoolPath(image string) string {
	segments := strings.Split(image, "/")
	for i, s := range segments {
		segments[i] = url.PathEscape(s)
	}
	return c.versioned("/warm-pools/" + strings.Join(segments, "/"))
}

// PutWarmPool creates or replaces an image's warm-pool entry.
func (c *Client) PutWarmPool(ctx context.Context, image string, request models.WarmPoolRequest) (models.WarmPool, error) {
	var response models.WarmPool
	err := c.doJSON(ctx, http.MethodPut, c.warmPoolPath(image), request, &response)
	return response, err
}

// GetWarmPool reads an image's warm-pool entry with its status.
func (c *Client) GetWarmPool(ctx context.Context, image string) (models.WarmPool, error) {
	var response models.WarmPool
	err := c.doJSON(ctx, http.MethodGet, c.warmPoolPath(image), nil, &response)
	return response, err
}

// ListWarmPools reads every warm-pool entry, by image, with its status.
func (c *Client) ListWarmPools(ctx context.Context) ([]models.WarmPool, error) {
	var response models.WarmPoolList
	if err := c.doJSON(ctx, http.MethodGet, c.versioned("/warm-pools"), nil, &response); err != nil {
		return nil, err
	}
	if response.Pools == nil {
		return []models.WarmPool{}, nil
	}
	return response.Pools, nil
}

// DeleteWarmPool removes an image's warm-pool entry.
func (c *Client) DeleteWarmPool(ctx context.Context, image string) error {
	return c.doJSON(ctx, http.MethodDelete, c.warmPoolPath(image), nil, nil)
}
