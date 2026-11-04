package identity

import (
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/identitywire"
)

// ExplainClaims reads the claims identity-file bindings match on (the
// username, groups and roles claims, by the names its issuer gives them)
// out of bearer, for `whoami --explain` (CEO review D22, §5.15).
//
// It does not check the signature, and need not: names is the
// Access.ClaimNames this node built for this very bearer on this request,
// so the token was verified moments ago; and the answer goes back to the
// caller who presented the token, so it holds nothing the caller couldn't
// already read. Reading the claims here, on the rare explain call, keeps
// every caller's groups out of the verified-token cache. Names and groups
// are sanitized as the "no binding" 403 sanitizes them.
func ExplainClaims(bearer string, names *controlplane.ClaimNames) *identitywire.ExplainClaims {
	if names == nil {
		return nil
	}
	out := &identitywire.ExplainClaims{Issuer: names.Issuer}
	if len(bearer) > MaxJWTBytes || !looksLikeJWT(bearer) {
		return out
	}
	_, claims, _ := decodeUnverified(bearer)
	if claims == nil {
		return out
	}
	if name, ok := stringClaim(claims.raw[names.Username]); ok {
		out.Username = controlplane.SanitizeDisplayName(name)
	}
	if out.Username == "" {
		out.Username = controlplane.SanitizeDisplayName(claims.sub)
	}
	if groupOverage(claims.raw, names.Groups) {
		// The groups claim of an overage token is not the full list.
		out.GroupOverage = true
	} else {
		groups, _ := stringsClaim(claims.raw[names.Groups])
		out.Groups = sanitizeGroups(groups)
	}
	roles, _ := stringsClaim(claims.raw[names.Roles])
	out.Roles = sanitizeGroups(roles)
	return out
}
