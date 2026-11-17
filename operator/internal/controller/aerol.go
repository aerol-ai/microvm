package controller

import (
	"context"

	"github.com/aerol-ai/microvm/operator/internal/aerolapi"
	"github.com/aerol-ai/microvm/pkg/upgradewire"
)

// AerolAPI is the part of the admin API the controllers use; tests fake
// it. *aerolapi.Client implements it.
type AerolAPI interface {
	Ready(ctx context.Context) bool
	Adopt(ctx context.Context) error
	MintJoinToken(ctx context.Context, role, ttl, createdBy string) (aerolapi.JoinToken, error)
	GetNode(ctx context.Context, id string) (aerolapi.Node, error)
	Members(ctx context.Context) ([]aerolapi.Node, error)
	Cordon(ctx context.Context, id string) error
	Uncordon(ctx context.Context, id string) error
	Evacuate(ctx context.Context, id string, req aerolapi.EvacuateRequest) (aerolapi.EvacuateResult, error)
	Gone(ctx context.Context, id string) error
	DeleteNode(ctx context.Context, id string, force bool) error
	Rollout(ctx context.Context) (*upgradewire.Rollout, error)
	ApplyImages(ctx context.Context, version string, req upgradewire.ApplyRequest) (*upgradewire.Rollout, error)
	Rollback(ctx context.Context) error
	// The operator's own admin API token (operator_token.go).
	CreateToken(ctx context.Context, name, role, team, expiresIn string) (aerolapi.CreatedAPIToken, error)
	ListTokens(ctx context.Context) ([]aerolapi.APIToken, error)
	RevokeToken(ctx context.Context, id string) error
	WhoAmI(ctx context.Context) error
}

var _ AerolAPI = (*aerolapi.Client)(nil)

// Credentials is what the operator calls one cluster's servers with: Token,
// and Fallback once if a server answers Token with 401 (apiCredentials).
type Credentials struct {
	Token    string
	Fallback string
}

// APIFactory makes the admin API client for one cluster, from its API
// Service URL and credentials.
type APIFactory func(baseURL string, cred Credentials) AerolAPI

// DefaultAPIFactory is the real client.
func DefaultAPIFactory(baseURL string, cred Credentials) AerolAPI {
	c := aerolapi.New(baseURL, cred.Token)
	c.Fallback = cred.Fallback
	return c
}
