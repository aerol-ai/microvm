package controlplane

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
)

// PrincipalKind names the credential family a caller authenticated with
// (plans/identity-and-access.md §5.1). It is the `kind` of the audit caller
// and of the aerolvm_auth_* metrics, so the values are a wire contract.
type PrincipalKind string

const (
	// PrincipalOperator is the shared operator token (PAT) from outside the
	// cluster, or forwarded by a peer on a user's behalf.
	PrincipalOperator PrincipalKind = "operator"
	// PrincipalToken is a scoped API token (avm_…, task T3).
	PrincipalToken PrincipalKind = "token"
	// PrincipalOIDC is an identity provider's signed token (task T6).
	PrincipalOIDC PrincipalKind = "oidc"
	// PrincipalControlPlane is a caller the managed provider's Validator
	// resolved.
	PrincipalControlPlane PrincipalKind = "controlplane"
	// PrincipalNode is a cluster peer calling with the PAT over mTLS on its
	// own behalf (control calls), not forwarding a user's request.
	PrincipalNode PrincipalKind = "node"
	// PrincipalSystem is a background loop with no request (task T4 names
	// them system:<subsystem> in audit records).
	PrincipalSystem PrincipalKind = "system"
	// PrincipalSandboxKey is an SSH session authenticated by a sandbox's
	// Ed25519 key (task T5).
	PrincipalSandboxKey PrincipalKind = "sandbox_key"
)

// Principal is who made the request. ID is stable and safe for audit records
// and trace attributes ("operator", "node:n3", "controlplane:<external id>",
// later "tok_…" and "oidc:<issuer>:<sub>"). Name is for people and logs only:
// it can change (an email rename) and is never a trace attribute.
type Principal struct {
	Kind PrincipalKind
	ID   string
	Name string
}

// Role is the built-in role a principal holds (§5.3). T1 only carries it;
// T2 turns roles into route permissions.
type Role string

const (
	RoleViewer  Role = "viewer"
	RoleRunner  Role = "runner"
	RoleAuditor Role = "auditor"
	RoleAdmin   Role = "admin"
)

// Valid reports whether r is one of the four built-in roles.
func (r Role) Valid() bool {
	switch r {
	case RoleViewer, RoleRunner, RoleAuditor, RoleAdmin:
		return true
	}
	return false
}

// TeamOwnerPrefix marks an owner ref that names an open-source team. The
// prefix keeps teams out of the managed build's account namespace, so a team
// called "acme" can never collide with a managed account "acme" (§5.1).
const TeamOwnerPrefix = "team:"

// TeamOwnerRef is the owner ref a credential bound to team carries.
func TeamOwnerRef(team string) string { return TeamOwnerPrefix + team }

// FleetTeam is how a fleet-wide binding names its team: every team.
const FleetTeam = "*"

// Team is the team a caller acts for: FleetTeam for an unscoped (fleet)
// caller, the team name for a `team:` owner, and "" for a managed account
// (its owner ref is an account key, not a team).
func (a Access) Team() string {
	if a.Fleet {
		return FleetTeam
	}
	if team, ok := strings.CutPrefix(a.Identity.OwnerRef, TeamOwnerPrefix); ok {
		return team
	}
	return ""
}

// The §5.1 invariant table, one constructor per row, so every authenticator
// builds the same Access for the same credential and a test pins each row.

// OperatorAccess is the PAT on the public listener (and, with Via set by the
// API edge, a PAT request a peer forwarded): fleet-wide, admin, "operator".
// It is exactly today's Access{Operator: true} under its new names.
func OperatorAccess() Access {
	return Access{
		Fleet:     true,
		Role:      RoleAdmin,
		Principal: Principal{Kind: PrincipalOperator, ID: "operator", Name: "operator"},
	}
}

// NodeAccess is the PAT presented by a cluster peer over mTLS on its own
// behalf. It has the operator's powers (as today); only the name differs, so
// audit records say which node acted instead of "operator".
func NodeAccess(nodeID string) Access {
	id := "node:" + nodeID
	return Access{
		Fleet:     true,
		Role:      RoleAdmin,
		Principal: Principal{Kind: PrincipalNode, ID: id, Name: id},
	}
}

// TokenAccess is a scoped API token (avm_…, plans/identity-and-access.md
// §5.4): the token's role, bound to one team or, for team FleetTeam, to
// every team. A team-bound token is fenced to owner team:<team>; a fleet
// token is unscoped and creates sandboxes with owner "", exactly as the PAT
// does. The principal id is the token's public id (tok_…), which is also
// the audit caller id; the name is the token's name, for people only.
func TokenAccess(id, name string, role Role, team string, expiresAt time.Time) Access {
	a := Access{
		Role:      role,
		Principal: Principal{Kind: PrincipalToken, ID: id, Name: SanitizeDisplayName(name)},
		ExpiresAt: expiresAt,
	}
	if team == FleetTeam {
		a.Fleet = true
	} else {
		a.Identity.OwnerRef = TeamOwnerRef(team)
	}
	return a
}

// ErrIdentityStale refuses a named credential this node cannot check
// because its copy of the replicated token list is older than
// SB_IDENTITY_MAX_STALE (§5.4). The API edge answers 503 with Retry-After:
// the credential may be perfectly good, the node just cannot vouch for it.
var ErrIdentityStale = errors.New("controlplane: identity data is stale")

// ErrIdentityNoOwner is returned for a managed identity with an empty
// OwnerRef. Scoped to owner "", it would see every operator-created sandbox
// and snapshot, so a validator answering that is broken and the caller is
// refused rather than failing open (unchanged from before T1).
var ErrIdentityNoOwner = fmt.Errorf("%w: identity has no owner", ErrTokenRejected)

// ErrIdentityRole is returned when a managed provider names a role other than
// viewer or runner. A provider may narrow a caller, never grant fleet powers
// (CEO review finding 1.4), so anything else is refused, not clamped.
var ErrIdentityRole = fmt.Errorf("%w: managed identity role must be viewer or runner", ErrTokenRejected)

// ControlPlaneAccess maps a managed provider's Identity onto Access: scoped
// to its OwnerRef, role Identity.Role or runner when unset, principal
// controlplane:<ExternalID>. runner is today's owner-scoped verb set, so a
// provider that sets no role sees no change (L8).
func ControlPlaneAccess(id Identity) (Access, error) {
	owner := strings.TrimSpace(id.OwnerRef)
	if owner == "" {
		return Access{}, ErrIdentityNoOwner
	}
	role := id.Role
	switch role {
	case "":
		role = RoleRunner
	case RoleViewer, RoleRunner:
	default:
		return Access{}, ErrIdentityRole
	}
	// ExternalID is the provider's stable subject. A provider that leaves it
	// empty still gets a stable, non-empty principal id from the owner.
	subject := strings.TrimSpace(id.ExternalID)
	if subject == "" {
		subject = owner
	}
	name := SanitizeDisplayName(id.Name)
	if name == "" {
		name = subject
	}
	return Access{
		Identity:  id,
		Role:      role,
		Principal: Principal{Kind: PrincipalControlPlane, ID: string(PrincipalControlPlane) + ":" + subject, Name: name},
	}, nil
}

// maxDisplayNameRunes caps a claim- or provider-derived display name before
// it reaches a record, a hint or a report (§5.4, Section 3 finding 3.6).
const maxDisplayNameRunes = 256

// SanitizeDisplayName strips control characters and truncates to 256 runes.
// Display names come from outside (provider identities, token names, JWT
// claims) and end up in logs and audit records, so a newline or terminal
// escape must not survive.
func SanitizeDisplayName(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range strings.TrimSpace(s) {
		if unicode.IsControl(r) {
			continue
		}
		if n == maxDisplayNameRunes {
			break
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}

// RejectReason is the coarse, standard reason a named credential (an avm_
// token or a JWT) was refused (CEO review D17). It is sent to the caller as
// the RFC 6750 error_description and the JSON body's `reason`. It must never
// carry claim values, key ids, which signature check failed, or whether an
// avm_ id exists.
type RejectReason string

const (
	RejectExpired          RejectReason = "expired"
	RejectNotYetValid      RejectReason = "not_yet_valid"
	RejectUnknownIssuer    RejectReason = "unknown_issuer"
	RejectWrongAudience    RejectReason = "wrong_audience"
	RejectTooLongLived     RejectReason = "too_long_lived"
	RejectInvalidSignature RejectReason = "invalid_signature"
	RejectMalformed        RejectReason = "malformed"
	// RejectUnknownOrRevoked covers both an unknown and a revoked avm_ token:
	// telling them apart would disclose whether an id exists.
	RejectUnknownOrRevoked RejectReason = "unknown_or_revoked"
)

// Valid reports whether r is one of the D17 reasons. The API edge sends only
// valid reasons to a caller, so a typo in an authenticator can never leak an
// arbitrary string into a response.
func (r RejectReason) Valid() bool {
	switch r {
	case RejectExpired, RejectNotYetValid, RejectUnknownIssuer, RejectWrongAudience,
		RejectTooLongLived, RejectInvalidSignature, RejectMalformed, RejectUnknownOrRevoked:
		return true
	}
	return false
}

// CredentialError is what an authenticator returns when it recognised a
// named credential (Kind PrincipalToken or PrincipalOIDC) and refused it. The
// API edge turns it into a 401 that names Reason. Any other refusal (the PAT,
// the managed provider, an unrecognised bearer) keeps today's bare 401.
type CredentialError struct {
	Kind   PrincipalKind
	Reason RejectReason
}

func (e *CredentialError) Error() string {
	return fmt.Sprintf("controlplane: %s credential rejected: %s", e.Kind, e.Reason)
}

// Unwrap makes errors.Is(err, ErrTokenRejected) hold for every refusal.
func (e *CredentialError) Unwrap() error { return ErrTokenRejected }

// AsCredentialError returns the CredentialError in err's chain, if any.
func AsCredentialError(err error) (*CredentialError, bool) {
	var ce *CredentialError
	if errors.As(err, &ce) {
		return ce, true
	}
	return nil, false
}
