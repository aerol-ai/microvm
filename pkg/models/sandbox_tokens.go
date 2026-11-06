package models

import "time"

// Sandbox token wire types (plans/agent-sandbox-feature-parity.md §5.9, A1):
// the body and answer of POST /v1/sandboxes/{id}/tokens. The token itself is
// pkg/sandboxtoken.

// CreateSandboxTokenRequest is the body of POST /v1/sandboxes/{id}/tokens.
// Every field but ExpiresIn narrows the token; leaving one out leaves that
// part of the request unrestricted.
type CreateSandboxTokenRequest struct {
	// ExpiresIn is the token's lifetime: a Go duration ("15m", "2h") or a
	// whole number of days ("1d"). Required, and capped by
	// SB_SANDBOX_TOKEN_MAX_TTL.
	ExpiresIn string `json:"expires_in"`
	// Port, when set, makes a token for that port's public URL (a port
	// exposed with visibility "token"). Left out, the token is for the
	// sandbox's toolbox (exec, files, sessions). One token is never both.
	Port int `json:"port,omitempty"`
	// PathPrefix limits the request path: the toolbox path (for example
	// "/files") or the public URL path (for example "/app"). It must be an
	// absolute, clean path; "/files" covers "/files" and "/files/x", not
	// "/files-x".
	PathPrefix string `json:"path_prefix,omitempty"`
	// Methods are the only HTTP methods allowed (GET, HEAD, POST, PUT,
	// PATCH, DELETE, OPTIONS).
	Methods []string `json:"methods,omitempty"`
}

// SandboxToken is the 201 body of POST /v1/sandboxes/{id}/tokens. Token is
// shown in this answer only: the server stores nothing, so a lost token
// cannot be looked up again (issue another).
type SandboxToken struct {
	Token string `json:"token"`
	// TokenID is the token's public id (stk_…): what audit records and
	// logs name instead of the token.
	TokenID    string    `json:"token_id"`
	SandboxID  string    `json:"sandbox_id"`
	Port       int       `json:"port,omitempty"`
	PathPrefix string    `json:"path_prefix,omitempty"`
	Methods    []string  `json:"methods,omitempty"`
	ExpiresAt  time.Time `json:"expires_at"`
}
