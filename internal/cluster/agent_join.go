package cluster

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// Join tokens asked of a worker or ingress node: it holds no Raft state, so
// it sends the operator route on to the server tier, which forwards to the
// leader (join.go). The caller's principal rides in the body; a server
// honours it only from a node principal over mTLS (pkg/api/v1).

// JoinTokenManager creates, lists and revokes join tokens. Implemented by
// Cluster and Agent; not part of Client (Noop has no cluster to join).
type JoinTokenManager interface {
	CreateJoinToken(ctx context.Context, req JoinTokenCreateRequest) (JoinTokenCreated, error)
	ListJoinTokens(ctx context.Context) (JoinTokenList, error)
	RevokeJoinToken(ctx context.Context, id string) error
}

// CreateJoinToken asks the server tier.
func (a *Agent) CreateJoinToken(ctx context.Context, req JoinTokenCreateRequest) (JoinTokenCreated, error) {
	var out JoinTokenCreated
	err := a.doControlPlaneJSON(ctx, http.MethodPost, PublicJoinTokensPath, PublicJoinTokensPath, req, &out)
	return out, agentJoinError(err)
}

// ListJoinTokens asks the server tier.
func (a *Agent) ListJoinTokens(ctx context.Context) (JoinTokenList, error) {
	var out JoinTokenList
	err := a.doControlPlaneJSON(ctx, http.MethodGet, PublicJoinTokensPath, PublicJoinTokensPath, nil, &out)
	return out, agentJoinError(err)
}

// RevokeJoinToken asks the server tier.
func (a *Agent) RevokeJoinToken(ctx context.Context, id string) error {
	id = strings.TrimSpace(id)
	if !ValidJoinTokenID(id) {
		return ErrJoinBadRequest
	}
	path := PublicJoinTokensPath + "/" + url.PathEscape(id)
	return agentJoinError(a.doControlPlaneJSON(ctx, http.MethodDelete, path, path, nil, nil))
}

// agentJoinError restores a server's join refusal so the worker's own route
// answers the same status.
func agentJoinError(err error) error {
	var se statusError
	if err == nil || !errors.As(err, &se) {
		return err
	}
	return peerJoinError(se.status, se.message)
}
