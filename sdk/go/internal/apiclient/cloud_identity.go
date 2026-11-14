package apiclient

import (
	"context"
	"net/http"
	"net/url"
	"strconv"

	"github.com/aerol-ai/microvm/pkg/models"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// Cloud identity role tags (plans/sandbox-cloud-identity.md D1.5): each
// team's allow list of the tags a sandbox may claim. Admin only. Every call
// is idempotent on the server (a repeated PUT changes nothing, a repeated
// DELETE is another 204), so all three retry on the safe tier.

func (c *Client) identityRolePath(tag, team string) string {
	path := c.versionPrefix + "/identity/roles/" + url.PathEscape(tag)
	if team != "" {
		path += "?" + url.Values{"team": {team}}.Encode()
	}
	return path
}

// PutIdentityRole puts a tag on a team's allow list, or changes its minimum
// caller role.
func (c *Client) PutIdentityRole(ctx context.Context, tag string, opts sdktypes.IdentityRoleOptions) (models.IdentityRole, error) {
	var out models.IdentityRole
	err := c.doJSON(ctx, http.MethodPut, c.identityRolePath(tag, opts.Team), models.IdentityRoleRequest{MinRole: opts.MinRole}, &out)
	return out, err
}

// ListIdentityRoles reads one page of a team's allow list.
func (c *Client) ListIdentityRoles(ctx context.Context, opts sdktypes.ListIdentityRolesOptions) (models.IdentityRoleList, error) {
	values := make(url.Values)
	if opts.Team != "" {
		values.Set("team", opts.Team)
	}
	if opts.Cursor != "" {
		values.Set("cursor", opts.Cursor)
	}
	if opts.Limit > 0 {
		values.Set("limit", strconv.Itoa(opts.Limit))
	}
	path := c.versionPrefix + "/identity/roles"
	if len(values) > 0 {
		path += "?" + values.Encode()
	}
	var out models.IdentityRoleList
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &out); err != nil {
		return models.IdentityRoleList{}, err
	}
	if out.Roles == nil {
		out.Roles = []models.IdentityRole{}
	}
	return out, nil
}

// DeleteIdentityRole takes a tag off a team's allow list.
func (c *Client) DeleteIdentityRole(ctx context.Context, tag, team string) error {
	return c.doJSON(ctx, http.MethodDelete, c.identityRolePath(tag, team), nil, nil)
}
