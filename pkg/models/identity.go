package models

import "time"

// Cloud identity per sandbox (plans/sandbox-cloud-identity.md): the create
// option, what a sandbox shows of it, and the /v1/identity/roles bodies.
// Nothing here is a secret; the token itself never appears in any API.

// IdentityRequest is the create option `identity` (D1.6). RoleTag must be on
// the owner's allow list (/v1/identity/roles) and the caller must hold its
// minimum role. The token's subject is built from the caller's own team and
// RoleTag, never from anything else in the request.
type IdentityRequest struct {
	RoleTag string `json:"role_tag"`
	// Audience is the token's aud; empty means sts.amazonaws.com.
	Audience string `json:"audience,omitempty"`
	// AWSRoleARN, when set, also gives the sandbox AWS_ROLE_ARN and
	// AWS_WEB_IDENTITY_TOKEN_FILE, which every AWS SDK reads.
	AWSRoleARN string `json:"aws_role_arn,omitempty"`
	// AzureClientID and AzureTenantID, set together, give the sandbox the
	// AZURE_* variables the Azure SDKs read for workload identity.
	AzureClientID string `json:"azure_client_id,omitempty"`
	AzureTenantID string `json:"azure_tenant_id,omitempty"`
}

// SandboxIdentity is a sandbox's identity as GET shows it.
type SandboxIdentity struct {
	RoleTag       string `json:"role_tag"`
	Audience      string `json:"audience"`
	Subject       string `json:"subject"`
	AWSRoleARN    string `json:"aws_role_arn,omitempty"`
	AzureClientID string `json:"azure_client_id,omitempty"`
	AzureTenantID string `json:"azure_tenant_id,omitempty"`
	// TokenFile is where the token is inside the sandbox.
	TokenFile string `json:"token_file"`
	// TokenExpiresAt is when the token now in the sandbox expires; absent
	// until the first one arrives.
	TokenExpiresAt *time.Time `json:"token_expires_at,omitempty"`
	// LastError is why the last token push failed; empty after a success.
	LastError string `json:"last_error,omitempty"`
}

// IdentityRole is one role tag on an owner's allow list. MinRole is the
// least caller role (runner or admin) that may create a sandbox with it.
type IdentityRole struct {
	Tag       string    `json:"tag"`
	MinRole   string    `json:"min_role"`
	Team      string    `json:"team,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// IdentityRoleRequest is the body of PUT /v1/identity/roles/{tag}.
type IdentityRoleRequest struct {
	MinRole string `json:"min_role"`
}

// IdentityRoleList is the body of GET /v1/identity/roles.
type IdentityRoleList struct {
	Roles []IdentityRole `json:"roles"`
	// NextCursor, when set, is the cursor for the next page.
	NextCursor string `json:"next_cursor,omitempty"`
}

// IdentityKeyRotation is the body of POST /v1/identity/keys/rotate: the key
// id that now signs and the ones the JWKS still lists. Never key material.
type IdentityKeyRotation struct {
	ActiveKeyID    string   `json:"active_key_id"`
	PublishedKeyID []string `json:"published_key_ids"`
}
