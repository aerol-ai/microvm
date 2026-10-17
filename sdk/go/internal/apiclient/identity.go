package apiclient

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/aerol-ai/microvm/pkg/models"
)

// Identity calls (plans/identity-and-access.md §5.2 and §5.4). The server
// designs each one for retry: whoami and list are reads, a create that
// loses its reply and is re-sent gets 409 for the name it already took,
// and a repeated revoke is another 204.

// WhoAmI returns the caller's own resolved principal, role, team and
// credential expiry (GET /v1/whoami).
func (c *Client) WhoAmI(ctx context.Context) (models.WhoAmI, error) {
	var out models.WhoAmI
	err := c.doJSON(ctx, http.MethodGet, c.versioned("/whoami"), nil, &out)
	return out, err
}

// CreateAPIToken mints a scoped API token (POST /v1/tokens). The returned
// Token is the secret, shown this once: the server keeps only its hash. A
// 409 means the name is taken, possibly by an earlier attempt of this same
// call whose reply was lost; that secret cannot be recovered, so revoke the
// token and create it again.
func (c *Client) CreateAPIToken(ctx context.Context, req models.CreateAPITokenRequest) (models.CreatedAPIToken, error) {
	var out models.CreatedAPIToken
	err := c.doJSON(ctx, http.MethodPost, c.versioned("/tokens"), req, &out)
	return out, err
}

// ListAPITokens lists the API tokens (GET /v1/tokens), expired ones
// included until the server's sweep removes them. Never a secret.
func (c *Client) ListAPITokens(ctx context.Context) (models.APITokenList, error) {
	var out models.APITokenList
	if err := c.doJSON(ctx, http.MethodGet, c.versioned("/tokens"), nil, &out); err != nil {
		return models.APITokenList{}, err
	}
	if out.Tokens == nil {
		out.Tokens = []models.APIToken{}
	}
	return out, nil
}

// RevokeAPIToken deletes a token by id (DELETE /v1/tokens/{id}). A token
// that is already gone is not an error.
func (c *Client) RevokeAPIToken(ctx context.Context, id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return errors.New("token id is required")
	}
	return c.doJSON(ctx, http.MethodDelete, c.versioned("/tokens/"+url.PathEscape(id)), nil, nil)
}
