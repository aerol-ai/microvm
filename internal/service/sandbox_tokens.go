package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/identitywire"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/sandboxtoken"
)

// Sandbox tokens (plans/agent-sandbox-feature-parity.md §5.9, A1). The
// threat model is in pkg/sandboxtoken's package comment. The service issues
// them on the sandbox's owner node (the route is owner-forwarded, so the
// sandbox row and its owner are read where they live) and verifies them on
// any node with no store read: the key is derived from the server key ring
// every node already holds.

var (
	// ErrSandboxTokenInvalid is a 400: the request asked for a token the
	// server will not issue (no or too long a lifetime, a bad scope).
	ErrSandboxTokenInvalid = errors.New("invalid sandbox token request")
	// ErrSandboxTokensUnavailable is a 503: this node has no server key to
	// sign with (none configured, or a key-store revoke dropped it).
	ErrSandboxTokensUnavailable = errors.New("sandbox tokens are unavailable: this server has no server key loaded")
)

// sandboxTokenNow is the clock tokens are issued and checked with; tests
// replace it.
var sandboxTokenNow = time.Now

// sandboxTokenMaxTTL is the configured cap, or the default when a Service
// was built without Load (tests).
func (s *Service) sandboxTokenMaxTTL() time.Duration {
	if s.cfg.SandboxTokenMaxTTL > 0 {
		return s.cfg.SandboxTokenMaxTTL
	}
	return 24 * time.Hour
}

// IssueSandboxToken signs a token for sandboxID with the scope req asks
// for. The caller must see the sandbox (owner scope); the route already
// required sandbox.exec, the most a token grants. Not idempotent by nature:
// every call mints a new token with a new id, and nothing is stored, so a
// retried call leaks nothing but a second short-lived token the caller
// never received.
func (s *Service) IssueSandboxToken(ctx context.Context, sandboxID string, req models.CreateSandboxTokenRequest) (models.SandboxToken, error) {
	ttl, err := s.sandboxTokenTTL(req.ExpiresIn)
	if err != nil {
		return models.SandboxToken{}, err
	}
	if req.Port < 0 || req.Port > 65535 {
		return models.SandboxToken{}, fmt.Errorf("%w: port must be between 1 and 65535", ErrSandboxTokenInvalid)
	}
	if err := sandboxtoken.ValidatePathPrefix(req.PathPrefix); err != nil {
		return models.SandboxToken{}, fmt.Errorf("%w: %v", ErrSandboxTokenInvalid, err)
	}
	methods, err := sandboxtoken.NormalizeMethods(req.Methods)
	if err != nil {
		return models.SandboxToken{}, fmt.Errorf("%w: %v", ErrSandboxTokenInvalid, err)
	}
	sandbox, err := s.scopedGet(ctx, sandboxID)
	if err != nil {
		return models.SandboxToken{}, err
	}
	if sandbox.Status == models.SandboxStatusDestroyed {
		return models.SandboxToken{}, fmt.Errorf("%w: sandbox %s", store.ErrNotFound, sandboxID)
	}
	if s.cipher == nil {
		return models.SandboxToken{}, ErrSandboxTokensUnavailable
	}
	id, err := sandboxtoken.NewTokenID()
	if err != nil {
		return models.SandboxToken{}, err
	}
	now := sandboxTokenNow()
	raw, claims, err := sandboxtoken.Sign(s.cipher, sandboxtoken.Claims{
		TokenID:    id,
		SandboxID:  sandbox.ID,
		Owner:      sandbox.OwnerRef,
		Port:       req.Port,
		PathPrefix: req.PathPrefix,
		Methods:    methods,
		IssuedAt:   now.Unix(),
		ExpiresAt:  now.Add(ttl).Unix(),
	})
	if err != nil {
		// A revoked key, never a token: the error names no claim.
		return models.SandboxToken{}, fmt.Errorf("%w: %w", ErrSandboxTokensUnavailable, err)
	}
	if s.logger != nil {
		// The id, never the token: the token is a bearer credential.
		s.logger.Info("sandbox token issued", "sandbox_id", claims.SandboxID, "token_id", claims.TokenID,
			"key_id", claims.KeyID, "port", claims.Port, "path_prefix", claims.PathPrefix,
			"methods", strings.Join(claims.Methods, ","), "expires_at", claims.Expiry())
	}
	return models.SandboxToken{
		Token:      raw,
		TokenID:    claims.TokenID,
		SandboxID:  claims.SandboxID,
		Port:       claims.Port,
		PathPrefix: claims.PathPrefix,
		Methods:    claims.Methods,
		ExpiresAt:  claims.Expiry(),
	}, nil
}

// sandboxTokenTTL parses expires_in and applies the cap.
func (s *Service) sandboxTokenTTL(raw string) (time.Duration, error) {
	if strings.TrimSpace(raw) == "" {
		return 0, fmt.Errorf("%w: expires_in is required (for example \"15m\" or \"2h\")", ErrSandboxTokenInvalid)
	}
	ttl, err := identitywire.ParseTokenTTL(raw)
	if err != nil {
		return 0, fmt.Errorf("%w: expires_in %q is not a positive lifetime; give one like 15m or 2h", ErrSandboxTokenInvalid, raw)
	}
	if ttl < time.Second {
		return 0, fmt.Errorf("%w: expires_in must be at least 1s", ErrSandboxTokenInvalid)
	}
	if max := s.sandboxTokenMaxTTL(); ttl > max {
		return 0, fmt.Errorf("%w: expires_in is longer than this server allows (%s, SB_SANDBOX_TOKEN_MAX_TTL)", ErrSandboxTokenInvalid, max)
	}
	return ttl, nil
}

// VerifySandboxToken checks a token's signature, claims and validity window
// with no store read. It does not check the scope against a request: the
// caller does that with Claims.Allows, because only it knows the request.
// The error is one of pkg/sandboxtoken's sentinels and never holds the token.
func (s *Service) VerifySandboxToken(raw string) (sandboxtoken.Claims, error) {
	if s == nil || s.cipher == nil {
		// No key: nothing can verify, so a token reads as a bad signature,
		// never as a reason to let the request through.
		return sandboxtoken.Claims{}, sandboxtoken.ErrInvalidSignature
	}
	return sandboxtoken.Verify(s.cipher, raw, sandboxTokenNow(), s.sandboxTokenMaxTTL())
}
