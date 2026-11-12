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
}

var _ AerolAPI = (*aerolapi.Client)(nil)

// APIFactory makes the admin API client for one cluster, from its API
// Service URL and admin token.
type APIFactory func(baseURL, token string) AerolAPI

// DefaultAPIFactory is the real client.
func DefaultAPIFactory(baseURL, token string) AerolAPI { return aerolapi.New(baseURL, token) }
