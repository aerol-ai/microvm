package microvm

import (
	"context"

	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// PutIdentityRole puts a role tag on a team's cloud identity allow list, or
// changes its minimum caller role ("runner" or "admin"). Admin only. The
// same call twice changes nothing, so it is safe to retry. Sandboxes are
// created with a tag through CreateSandboxOptions.Identity.
func (c *Client) PutIdentityRole(ctx context.Context, tag string, opts sdktypes.IdentityRoleOptions) (sdktypes.IdentityRole, error) {
	return c.inner.PutIdentityRole(ctx, tag, opts)
}

// ListIdentityRoles reads one page of a team's cloud identity allow list.
// Admin only.
func (c *Client) ListIdentityRoles(ctx context.Context, opts sdktypes.ListIdentityRolesOptions) (sdktypes.IdentityRoleList, error) {
	return c.inner.ListIdentityRoles(ctx, opts)
}

// DeleteIdentityRole takes a role tag off a team's allow list (team "" is
// the operator namespace). Admin only. Sandboxes that use it keep their
// current token (at most one hour) and get no new one. Deleting a tag that
// is already gone succeeds.
func (c *Client) DeleteIdentityRole(ctx context.Context, tag, team string) error {
	return c.inner.DeleteIdentityRole(ctx, tag, team)
}
