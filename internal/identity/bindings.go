package identity

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"time"

	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// Bindings map a verified token's claims to AerolVM roles (§5.5). Every
// binding of the token's issuer is tried top to bottom and every match is
// kept, deduplicated by role and team: the first is the token's default, and
// X-AerolVM-Team selects among the rest per request (§5.3). The match set,
// never the selected team, is what the verified-token cache stores (eng
// review E7, E8).

// tokenClaims is a token payload, decoded once on the cold path.
type tokenClaims struct {
	iss string
	sub string
	aud []string
	exp time.Time
	nbf time.Time // zero when absent
	iat time.Time // zero when absent
	raw map[string]json.RawMessage
}

var errMalformedClaims = errors.New("identity: malformed token claims")

// parseClaims decodes payload. exp and sub are required, iss must be a
// string, and the registered time claims must be numbers: anything else is
// malformed before any key is touched.
func parseClaims(payload []byte) (*tokenClaims, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil || raw == nil {
		return nil, errMalformedClaims
	}
	c := &tokenClaims{raw: raw}
	var ok bool
	if c.iss, ok = stringClaim(raw["iss"]); !ok || c.iss == "" {
		return nil, errMalformedClaims
	}
	if c.sub, ok = stringClaim(raw["sub"]); !ok || c.sub == "" {
		return nil, errMalformedClaims
	}
	aud, present := raw["aud"]
	if !present {
		return nil, errMalformedClaims
	}
	if c.aud, ok = stringsClaim(aud); !ok {
		return nil, errMalformedClaims
	}
	exp, present := raw["exp"]
	if !present {
		return nil, errMalformedClaims
	}
	if c.exp, ok = timeClaim(exp); !ok {
		return nil, errMalformedClaims
	}
	for name, dst := range map[string]*time.Time{"nbf": &c.nbf, "iat": &c.iat} {
		if v, present := raw[name]; present {
			if *dst, ok = timeClaim(v); !ok {
				return nil, errMalformedClaims
			}
		}
	}
	return c, nil
}

// matchResult is what a token's claims resolve to under one issuer.
type matchResult struct {
	bindings []controlplane.TeamBinding
	// groups is the token's groups claim, kept for the "no binding" 403
	// (the caller's own claims, D9). overage means the provider left the
	// groups out and sent a pointer instead (Entra above 200 groups).
	groups  []string
	overage bool
}

// match resolves c against iss's bindings in file order.
func (iss *Issuer) match(c *tokenClaims) matchResult {
	var res matchResult
	res.groups, _ = stringsClaim(c.raw[iss.GroupsClaim])
	res.overage = groupOverage(c.raw, iss.GroupsClaim)
	if res.overage {
		// An overage token's groups claim, if any, is not the full list:
		// matching or echoing it would mislead.
		res.groups = nil
	}
	var groupSet, roleSet map[string]struct{}
	// Deduplicated by what a binding grants: a later binding for the same
	// role and team adds nothing to select, and the first one is the one
	// `whoami --explain` names.
	type grant struct {
		role controlplane.Role
		team string
	}
	seen := map[grant]struct{}{}
	for _, b := range iss.bindings {
		var hit bool
		switch {
		case b.Group != "":
			if groupSet == nil {
				groupSet = toSet(res.groups)
			}
			_, hit = groupSet[b.Group]
		case b.AppRole != "":
			if roleSet == nil {
				roles, _ := stringsClaim(c.raw[iss.RolesClaim])
				roleSet = toSet(roles)
			}
			_, hit = roleSet[b.AppRole]
		default:
			hit = b.claimsMatch(c.raw)
		}
		if !hit {
			continue
		}
		g := grant{b.Role, b.Team}
		if _, dup := seen[g]; dup {
			continue
		}
		seen[g] = struct{}{}
		res.bindings = append(res.bindings, controlplane.TeamBinding{Role: b.Role, Team: b.Team, Index: b.index, Rule: b.line})
	}
	return res
}

// claimsMatch reports whether every claim the binding names has its value:
// equal for a string, boolean or number claim, contained for a list. A
// binding on email requires email_verified, or anyone who can set an
// unverified email at the provider could claim someone else's binding.
func (b *Binding) claimsMatch(raw map[string]json.RawMessage) bool {
	for _, k := range b.claimKeys {
		if !claimHas(raw[k], b.Claim[k]) {
			return false
		}
		if k == "email" && !claimTrue(raw["email_verified"]) {
			return false
		}
	}
	return true
}

// groupOverage reports Entra's overage pointer: _claim_names names the
// groups claim (it moved to a Graph call L2 rules out), or hasgroups is
// set (the implicit-flow variant).
func groupOverage(raw map[string]json.RawMessage, groupsClaim string) bool {
	if v, ok := raw["_claim_names"]; ok {
		var names map[string]json.RawMessage
		if json.Unmarshal(v, &names) == nil {
			if _, moved := names[groupsClaim]; moved {
				return true
			}
		}
	}
	return claimTrue(raw["hasgroups"])
}

func claimHas(v json.RawMessage, want string) bool {
	if len(v) == 0 {
		return false
	}
	if s, ok := stringClaim(v); ok {
		return s == want
	}
	var list []json.RawMessage
	if json.Unmarshal(v, &list) == nil {
		for _, item := range list {
			if s, ok := stringClaim(item); ok && s == want {
				return true
			}
		}
		return false
	}
	// A boolean or number claim matches its JSON literal ("true", "42").
	var scalar any
	if json.Unmarshal(v, &scalar) != nil {
		return false
	}
	switch scalar.(type) {
	case bool, float64:
		return string(bytes.TrimSpace(v)) == want
	}
	return false
}

func claimTrue(v json.RawMessage) bool {
	var b bool
	if json.Unmarshal(v, &b) == nil {
		return b
	}
	s, ok := stringClaim(v)
	return ok && s == "true"
}

func stringClaim(v json.RawMessage) (string, bool) {
	if len(v) == 0 || v[0] != '"' {
		return "", false
	}
	var s string
	if json.Unmarshal(v, &s) != nil {
		return "", false
	}
	return s, true
}

// stringsClaim reads a claim that is a string or a list of strings; list
// items that are not strings are skipped.
func stringsClaim(v json.RawMessage) ([]string, bool) {
	if len(v) == 0 {
		return nil, false
	}
	if s, ok := stringClaim(v); ok {
		return []string{s}, true
	}
	var list []json.RawMessage
	if json.Unmarshal(v, &list) != nil {
		return nil, false
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		if s, ok := stringClaim(item); ok {
			out = append(out, s)
		}
	}
	return out, true
}

// timeClaim reads a NumericDate (RFC 7519 §2): seconds since the epoch,
// possibly fractional.
func timeClaim(v json.RawMessage) (time.Time, bool) {
	var f float64
	if len(v) == 0 || v[0] == '"' || json.Unmarshal(v, &f) != nil || math.IsNaN(f) || f < 0 || f > 1e11 {
		return time.Time{}, false
	}
	sec, frac := math.Modf(f)
	return time.Unix(int64(sec), int64(frac*1e9)).UTC(), true
}

func toSet(items []string) map[string]struct{} {
	set := make(map[string]struct{}, len(items))
	for _, s := range items {
		set[s] = struct{}{}
	}
	return set
}
