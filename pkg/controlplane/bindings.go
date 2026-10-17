package controlplane

import (
	"errors"
	"time"
)

// TeamBinding is one role a credential holds: on one team, or on every team
// (FleetTeam). An identity-file binding resolves to one (§5.5), and an OIDC
// token carries every one its claims match, in file order.
type TeamBinding struct {
	Role Role
	Team string
}

// Apply returns a narrowed to binding b: its role, and its team as the owner
// scope (or fleet scope for FleetTeam). Principal, Via, ExpiresAt and
// Bindings are kept, so team selection can apply any of a's bindings.
func (b TeamBinding) Apply(a Access) Access {
	a.Role = b.Role
	if b.Team == FleetTeam {
		a.Fleet = true
		a.Identity.OwnerRef = ""
	} else {
		a.Fleet = false
		a.Identity.OwnerRef = TeamOwnerRef(b.Team)
	}
	return a
}

// OIDCAccess is an identity provider's verified token (§5.5): principal p,
// scoped by its first binding until team selection picks another. bindings
// must not be empty: a token that matched none is refused with a
// NoBindingError, never given an Access.
func OIDCAccess(p Principal, bindings []TeamBinding, expiresAt time.Time) Access {
	a := Access{Principal: p, ExpiresAt: expiresAt, Bindings: bindings}
	if len(bindings) > 0 {
		a = bindings[0].Apply(a)
	}
	return a
}

// ErrIdentityUnavailable refuses a JWT this node cannot check right now: the
// identity file was invalid at boot, or the issuer's signing keys could not
// be fetched (§5.5, §11). The API edge answers 503 with Retry-After. The PAT
// and avm_ tokens are unaffected, since neither needs the provider.
var ErrIdentityUnavailable = errors.New("controlplane: OIDC sign-in is unavailable on this node")

// NoBinding reasons: the `reason` of a v1 "no binding" 403 (design review
// DR8).
const (
	NoBindingReason     = "no_binding"
	GroupOverageReason  = "group_overage"
	noBindingErrMessage = "controlplane: verified OIDC token matched no role binding"
)

// NoBindingError refuses a verified OIDC token whose claims match no
// identity-file binding (§5.5, D9, DR8). Every field is the caller's own:
// the issuer they signed in through (its identity-file name), their display
// name, and the groups their token carried, so they can tell their admin
// what is missing. Overage means the provider left the groups out (Entra
// sends an overage pointer instead above 200 groups); Groups is then empty.
type NoBindingError struct {
	Issuer  string
	Name    string
	Groups  []string
	Overage bool
}

func (e *NoBindingError) Error() string { return noBindingErrMessage }

// Reason is the DR8 reason: group_overage or no_binding.
func (e *NoBindingError) Reason() string {
	if e.Overage {
		return GroupOverageReason
	}
	return NoBindingReason
}

// AsNoBindingError returns the NoBindingError in err's chain, if any.
func AsNoBindingError(err error) (*NoBindingError, bool) {
	var nb *NoBindingError
	if errors.As(err, &nb) {
		return nb, true
	}
	return nil, false
}
