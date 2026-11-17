package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
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
// every node already holds. A revoke is a not-before second on the owner's
// row, checked where a token request already reads that row: enforceOwner
// for the toolbox, PortAccess for a gated port.

var (
	// ErrSandboxTokenInvalid is a 400: the request asked for a token the
	// server will not issue (no or too long a lifetime, a bad scope).
	ErrSandboxTokenInvalid = errors.New("invalid sandbox token request")
	// ErrSandboxTokensUnavailable is a 503: this node has no server key to
	// sign with (none configured, or a key-store revoke dropped it).
	ErrSandboxTokensUnavailable = errors.New("sandbox tokens are unavailable: this server has no server key loaded")
	// ErrSandboxTokenRevoked is a 401: a good token used on its sandbox's
	// toolbox after that sandbox's tokens were revoked. The words match
	// the public-port gate's refusal for the same token.
	ErrSandboxTokenRevoked = errors.New("sandbox token refused: revoked")
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
	// A token issued in the same second as a revoke is lifted to the
	// revoke's not-before, so the revoke refuses only the tokens before it.
	now := sandboxtoken.IssueTime(sandboxTokenNow(), sandbox.TokensNotBefore)
	raw, claims, err := s.signSandboxToken(ctx, sandboxtoken.Claims{
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

// RevokeSandboxTokens refuses every token issued for sandboxID so far: it
// moves the sandbox's tokens_not_before to the next second and returns it.
// A token issued after the call works (IssueSandboxToken lifts one issued
// in the same second up to the not-before). The route is owner-forwarded
// and needs sandbox.exec, the same as issuing; a sandbox token cannot call
// it (the edge holds a token to the toolbox).
//
// Idempotent in effect: the store keeps the larger not-before, so a retry
// or a second call refuses the same tokens plus any issued in between, and
// never brings one back. Nothing else changes: no route, no other row, no
// cluster state, so there is nothing to roll back. The cost of the check
// it arms is no extra read: the toolbox route reads this row on the owner
// already (enforceOwner), and a gated port reads it with its gate
// (PortAccess), whose warm-cache entry is dropped here.
func (s *Service) RevokeSandboxTokens(ctx context.Context, sandboxID string) (models.RevokeSandboxTokensResponse, error) {
	sandbox, err := s.scopedGet(ctx, sandboxID)
	if err != nil {
		return models.RevokeSandboxTokensResponse{}, err
	}
	if sandbox.Status == models.SandboxStatusDestroyed {
		return models.RevokeSandboxTokensResponse{}, fmt.Errorf("%w: sandbox %s", store.ErrNotFound, sandboxID)
	}
	notBefore, err := s.store.RevokeSandboxTokens(ctx, sandbox.ID, sandboxtoken.NotBeforeAt(sandboxTokenNow()))
	if err != nil {
		return models.RevokeSandboxTokensResponse{}, err
	}
	// After the write: a PortAccess that read the row before it can no
	// longer cache that read (warmGen moved), and the next one reads the
	// new not-before.
	s.invalidateWarm(sandbox.ID)
	at := time.Unix(notBefore, 0).UTC()
	if s.logger != nil {
		s.logger.Info("sandbox tokens revoked", "sandbox_id", sandbox.ID, "tokens_not_before", at)
	}
	return models.RevokeSandboxTokensResponse{SandboxID: sandbox.ID, TokensNotBefore: at}, nil
}

// raiseTokensNotBeforeToTakeover refuses, on a sandbox row this node kept
// from an earlier ownership, every token issued before the node took the
// placement back. Without it a failback reopens a revoke: the sandbox moves
// to another node, which recreates it (a new row, so a new not-before), the
// user revokes its tokens there, and the placement then returns here, where
// the owner watcher reuses the old row with its old not-before, and the
// revoked tokens work again. ownerSinceUnixNano is the placement's
// OwnerSinceUnixNano (the leader's time for the takeover's raft entry); 0
// means no takeover is known and changes nothing.
//
// The watcher calls this on every tick for every owned sandbox; it writes
// once per takeover, because afterwards the row is no longer older. A
// sandbox that never changed owner is never touched: the FSM leaves the
// first owner at 0, so a create whose row is written before its placement
// is not mistaken for one. The write is the revoke's own MAX, so a retry,
// or a revoke racing it, never moves the not-before back. It refuses the
// tokens issued in the takeover's second too, as a revoke would; one issued
// here after the takeover but before this tick in that second is refused
// with them. Cluster mode off: no placement, so the value is always 0.
func (s *Service) raiseTokensNotBeforeToTakeover(ctx context.Context, row *models.Sandbox, ownerSinceUnixNano int64) error {
	if ownerSinceUnixNano <= 0 {
		return nil
	}
	notBefore := sandboxtoken.NotBeforeAt(time.Unix(0, ownerSinceUnixNano))
	if row.TokensNotBefore >= notBefore {
		return nil
	}
	stored, err := s.store.RevokeSandboxTokens(ctx, row.ID, notBefore)
	if err != nil {
		return fmt.Errorf("refuse sandbox tokens from before the takeover: %w", err)
	}
	previous := row.TokensNotBefore
	row.TokensNotBefore = stored
	// After the write, as RevokeSandboxTokens does: a gated port's warm
	// entry read before it must not keep the old not-before.
	s.invalidateWarm(row.ID)
	if s.logger != nil {
		s.logger.Info("sandbox tokens from before the owner takeover refused",
			"sandbox_id", row.ID, "owner_since", time.Unix(0, ownerSinceUnixNano).UTC(),
			"previous_tokens_not_before", time.Unix(previous, 0).UTC(), "tokens_not_before", time.Unix(stored, 0).UTC())
	}
	return nil
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
//
// In a cluster whose servers sign (server_signing.go), a token signed with
// a server key ring key counts only if it was issued before they took over;
// a worker that cannot tell when that was takes none.
func (s *Service) VerifySandboxToken(raw string) (sandboxtoken.Claims, error) {
	if s == nil {
		return sandboxtoken.Claims{}, sandboxtoken.ErrInvalidSignature
	}
	// No key at all: nothing can verify, so a token reads as a bad
	// signature, never as a reason to let the request through.
	claims, err := sandboxtoken.Verify(s.sandboxTokenKeys(), raw, sandboxTokenNow(), s.sandboxTokenMaxTTL())
	if err != nil {
		return claims, err
	}
	if !legacyTokenAllowed(s.currentSigningMode(), claims) {
		return sandboxtoken.Claims{}, sandboxtoken.ErrInvalidSignature
	}
	return claims, nil
}

// signSandboxToken signs c with the key this node signs with: the server
// key ring's until servers sign; then a server key, here on a server, or
// by a server for the sandbox's owner (SignSandboxTokenFor).
func (s *Service) signSandboxToken(ctx context.Context, c sandboxtoken.Claims) (string, sandboxtoken.Claims, error) {
	mode := s.currentSigningMode()
	if !mode.known {
		return "", c, fmt.Errorf("%w: the server tier did not say which key signs tokens", ErrSandboxTokensUnavailable)
	}
	if !mode.on {
		return sandboxtoken.Sign(s.cipher, c)
	}
	switch cl := s.Cluster().(type) {
	case serverSigningCluster:
		k, err := s.openServerKeys()
		if err != nil {
			return "", c, err
		}
		if k == nil {
			return "", c, ErrServerSigningOff
		}
		return sandboxtoken.Sign(k, c)
	case signingFeedCluster:
		body, err := json.Marshal(c)
		if err != nil {
			return "", c, err
		}
		resp, err := cl.SignSandboxToken(ctx, cluster.SandboxTokenSignRequest{Claims: body})
		if err != nil {
			return "", c, fmt.Errorf("a server did not sign the token: %w", err)
		}
		// What came back must be a token this node takes, for these claims.
		got, err := s.VerifySandboxToken(resp.Token)
		if err != nil || got.TokenID != c.TokenID || got.SandboxID != c.SandboxID {
			return "", c, fmt.Errorf("a server signed a token this node does not take: %v", err)
		}
		return resp.Token, got, nil
	}
	return "", c, ErrServerSigningOff
}

// SignSandboxTokenFor signs claims a node sent for a sandbox it owns, on a
// server (POST /v1/cluster/internal/sandbox-tokens/sign). The owner checked
// its caller and built the claims from its row, as it always has; this
// checks what the owner cannot be trusted with alone: that the sandbox is
// the sender's (a server may ask for any), that the owner in the claims is
// the sandbox's, and that the lifetime and issue time are ones this server
// would give. It signs with the servers' key, which the owner does not hold.
func (s *Service) SignSandboxTokenFor(ctx context.Context, peerID string, peerIsServer bool, raw []byte) (cluster.SandboxTokenSignResponse, error) {
	k, err := s.openServerKeys()
	if err != nil {
		return cluster.SandboxTokenSignResponse{}, err
	}
	if k == nil {
		return cluster.SandboxTokenSignResponse{}, ErrServerSigningOff
	}
	var c sandboxtoken.Claims
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return cluster.SandboxTokenSignResponse{}, fmt.Errorf("%w: claims: %v", ErrSandboxTokenInvalid, err)
	}
	cl := s.Cluster()
	if cl == nil {
		return cluster.SandboxTokenSignResponse{}, ErrServerSigningOff
	}
	p, ok := cl.PlacementOf(strings.TrimSpace(c.SandboxID))
	if !ok || p.IsDeleting() {
		return cluster.SandboxTokenSignResponse{}, fmt.Errorf("%w: sandbox %s", store.ErrNotFound, c.SandboxID)
	}
	if !peerIsServer && (strings.TrimSpace(peerID) == "" || strings.TrimSpace(p.OwnerNodeID) != strings.TrimSpace(peerID)) {
		return cluster.SandboxTokenSignResponse{}, ErrSignNotOwner
	}
	if c.Owner != strings.TrimSpace(p.OwnerRef) {
		return cluster.SandboxTokenSignResponse{}, fmt.Errorf("%w: the claims name another owner than the sandbox's", ErrSignNotOwner)
	}
	now := sandboxTokenNow()
	iat := time.Unix(c.IssuedAt, 0)
	if iat.After(now.Add(sandboxtoken.ClockSkew)) || iat.Before(now.Add(-sandboxtoken.ClockSkew)) {
		return cluster.SandboxTokenSignResponse{}, fmt.Errorf("%w: issued at %s, not now", ErrSandboxTokenInvalid, iat.UTC())
	}
	if c.ExpiresAt-c.IssuedAt > int64(s.sandboxTokenMaxTTL()/time.Second) {
		return cluster.SandboxTokenSignResponse{}, fmt.Errorf("%w: lives longer than this server allows (SB_SANDBOX_TOKEN_MAX_TTL)", ErrSandboxTokenInvalid)
	}
	token, signed, err := sandboxtoken.Sign(k, c)
	if err != nil {
		return cluster.SandboxTokenSignResponse{}, fmt.Errorf("%w: %v", ErrSandboxTokenInvalid, err)
	}
	if s.logger != nil {
		s.logger.Info("sandbox token signed for its owner", "sandbox_id", signed.SandboxID, "token_id", signed.TokenID,
			"key_id", signed.KeyID, "owner_node", p.OwnerNodeID, "expires_at", signed.Expiry())
	}
	return cluster.SandboxTokenSignResponse{Token: token, KeyID: signed.KeyID}, nil
}
