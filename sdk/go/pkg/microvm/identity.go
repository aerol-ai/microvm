package microvm

import (
	"context"
	"os"
	"strings"

	apiclient "github.com/aerol-ai/microvm/sdk/go/internal/apiclient"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// HeaderTeam is the header the client sends its team in (MicroVMConfig.Team
// or SB_TEAM) on every request.
const HeaderTeam = apiclient.HeaderTeam

// WhoAmI returns who the server says the caller is: its principal, role,
// team and when the credential expires. Every valid credential may call it.
func (c *Client) WhoAmI(ctx context.Context) (sdktypes.WhoAmI, error) {
	return c.inner.WhoAmI(ctx)
}

// Tokens manages scoped API tokens (avm_…) for services and CI. Creating
// and revoking needs an admin credential; listing needs an auditor or an
// admin.
func (c *Client) Tokens() *Tokens {
	return &Tokens{client: c}
}

// Tokens is the API token surface of a Client; get one from Client.Tokens.
type Tokens struct {
	client *Client
}

// Create mints a token. The result's Token field is the secret, returned
// this once and never again, so store it before discarding the result. A
// 409 (errors.Is(err, ErrConflict)) means the name is taken, possibly by an
// earlier attempt whose reply was lost; that secret cannot be recovered, so
// revoke the token and create it again.
func (t *Tokens) Create(ctx context.Context, opts sdktypes.CreateAPITokenOptions) (sdktypes.CreatedAPIToken, error) {
	return t.client.inner.CreateAPIToken(ctx, opts)
}

// List returns every token, expired ones included (Expired is true) until
// the server removes them 30 days after expiry. It never returns a secret.
func (t *Tokens) List(ctx context.Context) (sdktypes.APITokenList, error) {
	return t.client.inner.ListAPITokens(ctx)
}

// Revoke deletes the token with this id (tok_…). Revoking a token that is
// already gone succeeds, so a retried revoke is safe.
func (t *Tokens) Revoke(ctx context.Context, id string) error {
	return t.client.inner.RevokeAPIToken(ctx, id)
}

// firstEnv returns the first of names set to a non-blank value, trimmed.
func firstEnv(names ...string) string {
	for _, name := range names {
		if value := strings.TrimSpace(os.Getenv(name)); value != "" {
			return value
		}
	}
	return ""
}
