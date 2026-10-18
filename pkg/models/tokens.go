package models

import "time"

// Scoped API token wire types (plans/identity-and-access.md §5.4): the
// /v1/tokens bodies, shared by the server, the aerolvm CLI and the SDKs.

// CreateAPITokenRequest is the body of POST /v1/tokens.
type CreateAPITokenRequest struct {
	// Name is 1 to 64 characters of A-Z, a-z, 0-9, '.', '_' and '-',
	// unique among the team's tokens.
	Name string `json:"name"`
	// Role is viewer, runner, auditor or admin.
	Role string `json:"role"`
	// Team is a team name (1 to 63 of a-z, 0-9, '-') or "*" for every
	// team. auditor and admin require "*".
	Team string `json:"team"`
	// ExpiresIn is the lifetime: "90d", "720h" or any Go duration. It is
	// required and capped by SB_TOKEN_MAX_TTL.
	ExpiresIn string `json:"expires_in"`
}

// APIToken is one token as GET /v1/tokens lists it. It never carries the
// secret or its hash.
type APIToken struct {
	// ID is the public id (tok_…): the audit caller id, and what
	// DELETE /v1/tokens/{id} takes.
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Role      string    `json:"role"`
	Team      string    `json:"team"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	// Expired tokens no longer authenticate. They stay listed until the
	// expiry sweep removes them 30 days after they expire.
	Expired bool `json:"expired"`
}

// CreatedAPIToken is the 201 body of POST /v1/tokens: the stored token plus
// its plaintext, which the server shows this once and never stores.
type CreatedAPIToken struct {
	APIToken
	Token string `json:"token"`
}

// APITokenList is the body of GET /v1/tokens.
type APITokenList struct {
	Tokens []APIToken `json:"tokens"`
}
