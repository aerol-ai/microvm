package identity

import (
	"crypto/subtle"
	"expvar"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/identitywire"
)

// TokenAuthenticator is the apiToken link of pkg/api's authenticator chain
// (plans/identity-and-access.md §5.2, step 3). It claims every bearer with
// the avm_ prefix, so a mistyped token gets a token refusal reason instead
// of falling through to the managed provider.
//
//	avm_… ─► checksum ── bad ──────────────────────────► 401 malformed (no lookup)
//	        └► lookup (memory) ── stale, route ≠ metrics.read ─► 503 stale
//	           └► SHA-256(secret) vs stored hash ── miss ──────► 401 unknown_or_revoked
//	              └► expiry ── past ─────────────────────────► 401 expired
//	                 └► Access{token principal, role, team}
//
// Every step is local: a checksum, a map read, one SHA-256 of 43 bytes and
// a constant-time compare. A spray of malformed or unknown tokens costs no
// server-tier call (CEO review D21).
type TokenAuthenticator struct {
	lookup TokenLookup
	logger *slog.Logger
	now    func() time.Time
	// lastStaleLog throttles the stale-accept log line to one a minute.
	lastStaleLog atomic.Int64
}

// NewTokenAuthenticator builds the authenticator over lookup.
func NewTokenAuthenticator(lookup TokenLookup, logger *slog.Logger) *TokenAuthenticator {
	return &TokenAuthenticator{lookup: lookup, logger: logger, now: time.Now}
}

// staleAcceptLogInterval bounds the stale-accept log line (D16).
const staleAcceptLogInterval = time.Minute

var (
	// staleAccepts counts requests accepted from a stale mirror under the
	// metrics.read exception (D16): aerolvm_identity_stale_accept_total.
	staleAccepts = expvar.NewInt("aerolvm_identity_stale_accept_total")
	// dummyHash is compared against when an id is unknown, so a miss costs
	// the same hash and compare as a hit: response time never tells a
	// caller whether an id exists.
	dummyHash = make([]byte, 32)
)

// Authenticate decides a bearer. matched is false only for a bearer
// without the avm_ prefix.
func (a *TokenAuthenticator) Authenticate(r *http.Request, bearer string) (controlplane.Access, bool, error) {
	if !identitywire.LooksLikeAPIToken(bearer) {
		return controlplane.Access{}, false, nil
	}
	tok, err := identitywire.ParseAPIToken(bearer)
	if err != nil {
		return controlplane.Access{}, true, refuse(controlplane.RejectMalformed)
	}
	rec, found, fresh := a.lookup.LookupToken(tok.ID)
	staleAccept := false
	if !fresh {
		// A mirror that cannot sync might still hold a revoked token.
		// Only a route that needs nothing but metrics.read is served from
		// it, so worker metrics keep flowing through a server-tier outage;
		// every other permission fails closed (D16).
		if perm, ok := controlplane.RoutePermissionFromContext(r.Context()); !ok || perm != controlplane.PermMetricsRead {
			return controlplane.Access{}, true, controlplane.ErrIdentityStale
		}
		staleAccept = true
	}
	want := dummyHash
	if found {
		want = rec.SecretHash
	}
	got := identitywire.HashAPITokenSecret(tok.Secret)
	if subtle.ConstantTimeCompare(got[:], want) != 1 || !found {
		return controlplane.Access{}, true, refuse(controlplane.RejectUnknownOrRevoked)
	}
	if rec.Expired(a.now()) {
		return controlplane.Access{}, true, refuse(controlplane.RejectExpired)
	}
	if staleAccept {
		a.noteStaleAccept(rec.ID)
	}
	return rec.Access(), true, nil
}

func refuse(reason controlplane.RejectReason) error {
	return &controlplane.CredentialError{Kind: controlplane.PrincipalToken, Reason: reason}
}

// noteStaleAccept counts every stale accept and logs at most one a minute.
func (a *TokenAuthenticator) noteStaleAccept(id string) {
	staleAccepts.Add(1)
	now := a.now().UnixNano()
	last := a.lastStaleLog.Load()
	if last != 0 && time.Duration(now-last) < staleAcceptLogInterval {
		return
	}
	if !a.lastStaleLog.CompareAndSwap(last, now) || a.logger == nil {
		return
	}
	a.logger.Warn("identity: accepted an API token from a stale token mirror for a metrics.read route",
		"token_id", id, "hint", "this node cannot reach the server tier; tokens are refused on every other route until it syncs")
}
