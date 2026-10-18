package api

// One authentication function for every surface (plans/identity-and-access.md
// §5.2, eng review D6). v1, Daytona, MCP, the dashboard's metrics, E2B and
// Runloop all run the same authenticate(); the surfaces differ only in where
// they read the credential and how they word a refusal.
//
//	credential ─► authenticators, in order; the first that matches decides
//	               pat ─► apiToken (T3) ─► [jwt T6] ─► provider
//	           ─► post-match steps: forward attribution, surface rule,
//	               team selection
//	           ─► refusals: reason mapping (401 / 403 / 400) per surface

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	apie2b "github.com/aerol-ai/microvm/pkg/api/e2b"
	"github.com/aerol-ai/microvm/pkg/api/remotemcp"
	"github.com/aerol-ai/microvm/pkg/api/runloop"
	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/identitywire"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Authenticator recognises one credential kind. matched=false means "not
// mine": the next authenticator gets the credential. matched=true decides
// the request: err refuses it, otherwise the Access is the caller. The first
// match wins, so no later authenticator ever sees a credential an earlier one
// claimed. Task T3 (avm_ tokens) and T6 (OIDC) each add one with
// WithCredentialAuthenticator; nothing else changes.
//
// A named-credential authenticator refuses with *controlplane.CredentialError
// to give the caller a D17 reason. Any other error is a bare 401.
type Authenticator interface {
	Authenticate(r *http.Request, bearer string) (controlplane.Access, bool, error)
}

// authLink is one authenticator in the chain plus the `kind` label its
// refusals count under in aerolvm_auth_failures_total.
type authLink struct {
	kind string
	auth Authenticator
}

// Failure-kind labels that are not a principal kind.
const (
	authKindNone    = "none"    // no credential at all
	authKindUnknown = "unknown" // nothing recognised the credential
)

// ServerOption configures NewServer.
type ServerOption func(*serverOptions)

type serverOptions struct {
	credentials []authLink
}

// WithCredentialAuthenticator adds a named-credential authenticator: the avm_
// token mirror (T3, kind controlplane.PrincipalToken) or the OIDC verifier
// (T6, kind controlplane.PrincipalOIDC). They run after the PAT and before the
// managed provider, in the order the options are given.
//
// They run only when SB_IDENTITY_ENABLED=true. With identity off NewServer
// drops them, so a bearer that looks like an avm_ token or a JWT still reaches
// the managed provider exactly as before (L8). The daemon refuses to boot with
// identity on and a non-noop provider Validator, so the two never compete.
func WithCredentialAuthenticator(kind controlplane.PrincipalKind, a Authenticator) ServerOption {
	return func(o *serverOptions) {
		if a != nil {
			o.credentials = append(o.credentials, authLink{kind: string(kind), auth: a})
		}
	}
}

// buildAuthChain orders the authenticators: pat, the named credentials, then
// the managed provider, which is last because it claims every non-empty
// bearer nothing before it recognised.
func buildAuthChain(patToken string, validator controlplane.Validator, credentials []authLink) []authLink {
	providerKind := string(controlplane.PrincipalControlPlane)
	if controlplane.IsNoopValidator(validator) {
		// The open-source build has no provider: a refusal there means
		// "nothing recognised this", not "the control plane said no".
		providerKind = authKindUnknown
	}
	if validator == nil {
		validator = controlplane.Noop().Validator
	}
	links := make([]authLink, 0, len(credentials)+2)
	links = append(links, authLink{kind: string(controlplane.PrincipalOperator), auth: patAuthenticator{token: patToken}})
	links = append(links, credentials...)
	return append(links, authLink{kind: providerKind, auth: providerAuthenticator{validator: validator}})
}

// authLinks returns the chain. A Server built by NewServer has it already; a
// bare &Server{patToken, validator} (unit tests) gets the default chain.
func (s *Server) authLinks() []authLink {
	if s.authChain != nil {
		return s.authChain
	}
	return buildAuthChain(s.patToken, s.validator, nil)
}

// patAuthenticator recognises the operator token (PAT). It never refuses: a
// credential that is not the PAT may be any other kind, so it passes on.
type patAuthenticator struct{ token string }

// matches compares in constant time: the PAT grants fleet-wide access, so a
// byte-wise == would leak the matching prefix length as a timing signal.
func (p patAuthenticator) matches(candidate string) bool {
	return candidate != "" && p.token != "" &&
		subtle.ConstantTimeCompare([]byte(candidate), []byte(p.token)) == 1
}

// Authenticate splits the PAT into its two principals (§5.1). A cluster peer
// that proves itself with its mTLS certificate and is NOT forwarding a user's
// request is acting for itself: node:<peer>. Everyone else, including a peer
// forwarding a user's PAT request, is the operator; forward attribution then
// records the edge node in Via. Both get today's powers; only the name
// differs.
func (p patAuthenticator) Authenticate(r *http.Request, bearer string) (controlplane.Access, bool, error) {
	if !p.matches(bearer) {
		return controlplane.Access{}, false, nil
	}
	if !isForwarded(r) {
		if peer, ok := mtlsPeer(r); ok {
			return controlplane.NodeAccess(peer), true, nil
		}
	}
	return controlplane.OperatorAccess(), true, nil
}

// providerAuthenticator hands every remaining non-empty bearer to the
// control-plane Validator. Under controlplane.Noop() that rejects everything,
// which collapses the chain back to PAT-only, exactly as before this seam.
type providerAuthenticator struct{ validator controlplane.Validator }

func (p providerAuthenticator) Authenticate(r *http.Request, bearer string) (controlplane.Access, bool, error) {
	if bearer == "" {
		return controlplane.Access{}, false, nil
	}
	identity, err := p.validator.Validate(r.Context(), bearer)
	if err != nil {
		return controlplane.Access{}, true, err
	}
	access, err := controlplane.ControlPlaneAccess(identity)
	if err != nil {
		return controlplane.Access{}, true, err
	}
	return access, true, nil
}

// postMatchStep runs after an authenticator accepted the credential, in
// order. Each may refine the Access or refuse the request.
type postMatchStep func(r *http.Request, a controlplane.Access) (controlplane.Access, error)

var postMatchSteps = []postMatchStep{attributeForward, enforceSurface, selectTeam}

// authenticate decides who the request is from. It never reads an identity
// header: the credential, the verified mTLS peer and the request path are the
// only inputs, and the X-Cluster-* markers it reads are themselves accepted
// only from a live mTLS peer (clusterControlHeaderGuard).
func (s *Server) authenticate(r *http.Request, bearer string) (controlplane.Access, *authFailure) {
	if bearer == "" {
		return controlplane.Access{}, &authFailure{status: http.StatusUnauthorized, kind: authKindNone, reason: "missing"}
	}
	for _, link := range s.authLinks() {
		access, matched, err := link.auth.Authenticate(r, bearer)
		if !matched {
			continue
		}
		if err == nil {
			access, err = runPostMatchSteps(r, access)
		}
		if err != nil {
			return controlplane.Access{}, mapAuthFailure(link.kind, err)
		}
		return access, nil
	}
	return controlplane.Access{}, &authFailure{status: http.StatusUnauthorized, kind: authKindUnknown, reason: "rejected"}
}

func runPostMatchSteps(r *http.Request, access controlplane.Access) (controlplane.Access, error) {
	for _, step := range postMatchSteps {
		var err error
		if access, err = step(r, access); err != nil {
			return access, err
		}
	}
	return access, nil
}

// isForwarded reports whether a peer reverse-proxied this request on a
// user's behalf (cluster.ForwardHTTP's Director sets the marker).
func isForwarded(r *http.Request) bool {
	return r.Header.Get(cluster.HeaderForwarded) == "1"
}

// mtlsPeer returns the node id proven by the request's verified mTLS leaf.
// Most requests carry no client certificate; checking that first skips the
// error AuthenticatedPeerNodeID would allocate on every public request.
func mtlsPeer(r *http.Request) (string, bool) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
		return "", false
	}
	peer, err := cluster.AuthenticatedPeerNodeID(r)
	return peer, err == nil
}

// attributeForward records the edge node in Via when a peer forwarded the
// request. The owner node re-authenticates the original credential itself,
// so Via only says which node it came through. The id comes from the
// verified certificate, never from a header.
func attributeForward(r *http.Request, a controlplane.Access) (controlplane.Access, error) {
	if !isForwarded(r) {
		return a, nil
	}
	if peer, ok := mtlsPeer(r); ok {
		a.Via = peer
	}
	return a, nil
}

// headerClusterSurface marks a peer's forward of a remote MCP tool call
// (§5.14). Like every X-Cluster-* header it is honoured only from a live
// mTLS peer.
const headerClusterSurface = "X-Cluster-Surface"

// enforceSurface is the surface rule: an MCP-only credential (an OAuth access
// token for an mcp_audiences audience) is accepted on /mcp and on a forward a
// peer marked as MCP, and refused everywhere else. The marker widens where a
// verified credential is accepted; it never supplies an identity.
func enforceSurface(r *http.Request, a controlplane.Access) (controlplane.Access, error) {
	if !a.MCPOnly {
		return a, nil
	}
	if r.URL.Path == remotemcp.Path {
		return a, nil
	}
	if r.Header.Get(headerClusterSurface) == "mcp" {
		if _, ok := mtlsPeer(r); ok {
			return a, nil
		}
	}
	return a, &controlplane.CredentialError{Kind: a.Principal.Kind, Reason: controlplane.RejectWrongAudience}
}

// HeaderTeam selects which of a credential's teams a request acts for (CEO
// review D13). It is an ordinary header: a reverse-proxied forward keeps it,
// a fan-out request gets it from cluster.StampForward, and the owner node
// applies the same selection offline.
const HeaderTeam = cluster.HeaderTeam

// headerTeamKey is HeaderTeam in Go's canonical form. Header.Get with a
// non-canonical key allocates a canonical copy on every request.
var headerTeamKey = http.CanonicalHeaderKey(HeaderTeam)

var errBadTeamHeader = errors.New("invalid " + HeaderTeam + " header: a team name is 1 to 63 characters of a-z, 0-9 and -")

// teamNotBoundError refuses a team the credential has no binding for. The
// message names only the caller's own role and team (D9).
type teamNotBoundError struct {
	team  string
	role  controlplane.Role
	bound string
}

func (e *teamNotBoundError) Error() string {
	if e.bound == controlplane.FleetTeam {
		return HeaderTeam + ": " + e.team + " is not one of this credential's teams (it holds role " + string(e.role) +
			" on all teams); send no " + HeaderTeam + " header to act on every team"
	}
	return HeaderTeam + ": " + e.team + " is not one of this credential's teams (it holds role " + string(e.role) +
		" on team " + e.bound + "); ask an admin for a binding on team " + e.team
}

// selectTeam is team selection. The header selects among the teams the
// verified credential is already bound to; it never grants one. A credential
// in T1 has exactly one binding, so the header must name it; T6 extends this
// to the several bindings an OIDC token can match. The PAT, node and managed
// callers ignore the header entirely (L8: their behavior is unchanged).
func selectTeam(r *http.Request, a controlplane.Access) (controlplane.Access, error) {
	header := r.Header.Get(headerTeamKey)
	if header == "" {
		return a, nil
	}
	switch a.Principal.Kind {
	case controlplane.PrincipalToken, controlplane.PrincipalOIDC:
	default:
		return a, nil
	}
	team := strings.TrimSpace(header)
	if !identitywire.ValidTeamName(team) {
		return a, errBadTeamHeader
	}
	// A fleet credential's team is "*", which is never a valid team name, so
	// naming a team on it refuses rather than silently narrowing.
	if bound := a.Team(); team != bound {
		return a, &teamNotBoundError{team: team, role: a.Role, bound: bound}
	}
	return a, nil
}

// authFailure is a refused request, after reason mapping.
type authFailure struct {
	status int
	// kind and reason are the aerolvm_auth_failures_total labels.
	kind   string
	reason string
	// invalidToken is set only for a D17 refusal of an avm_ token or a JWT:
	// the 401 then carries it in WWW-Authenticate and the body's `reason`.
	invalidToken controlplane.RejectReason
	// message is the 400/403/503 text. A 401 always uses the surface's own
	// fixed text, so PAT and managed 401 bodies stay byte for byte as before.
	message string
	// retryAfter is the Retry-After seconds of a 503.
	retryAfter int
}

// identityStaleRetryAfter is the Retry-After of a stale-mirror 503: about
// one mirror poll, after which the node may have synced.
const identityStaleRetryAfter = 5

// mapAuthFailure is reason mapping (D17 for 401s, D9 for 403s). Only an avm_
// token or a JWT refusal with a known reason tells the caller why. The PAT,
// the managed provider and an unrecognised bearer keep today's bare 401,
// even if a provider returns a CredentialError.
func mapAuthFailure(linkKind string, err error) *authFailure {
	if ce, ok := controlplane.AsCredentialError(err); ok {
		switch ce.Kind {
		case controlplane.PrincipalToken, controlplane.PrincipalOIDC:
			if ce.Reason.Valid() {
				return &authFailure{status: http.StatusUnauthorized, kind: string(ce.Kind), reason: string(ce.Reason), invalidToken: ce.Reason}
			}
		}
		return &authFailure{status: http.StatusUnauthorized, kind: linkKind, reason: "rejected"}
	}
	var notBound *teamNotBoundError
	switch {
	case errors.Is(err, controlplane.ErrIdentityStale):
		// The token mirror on this node cannot vouch for any token right
		// now (§5.4): the credential may be fine, so 503, not 401.
		return &authFailure{status: http.StatusServiceUnavailable, kind: linkKind, reason: "stale",
			message: "identity data is stale on this node; retry shortly", retryAfter: identityStaleRetryAfter}
	case errors.Is(err, errBadTeamHeader):
		return &authFailure{status: http.StatusBadRequest, kind: linkKind, reason: "bad_team", message: err.Error()}
	case errors.As(err, &notBound):
		return &authFailure{status: http.StatusForbidden, kind: linkKind, reason: "team_not_bound", message: err.Error()}
	case errors.Is(err, controlplane.ErrIdentityNoOwner):
		return &authFailure{status: http.StatusUnauthorized, kind: linkKind, reason: "no_owner"}
	case errors.Is(err, controlplane.ErrIdentityRole):
		return &authFailure{status: http.StatusUnauthorized, kind: linkKind, reason: "bad_role"}
	}
	return &authFailure{status: http.StatusUnauthorized, kind: linkKind, reason: "rejected"}
}

// authSurface is what differs between the API surfaces: where the credential
// is read and how a refusal is worded. Every 401 text below is pinned byte
// for byte by TestUnauthorizedBodiesUnchanged.
type authSurface struct {
	credential   func(s *Server, r *http.Request) string
	unauthorized string
	// write writes status with message; reason is non-empty only for a D17
	// 401 and adds the body's `reason` field.
	write func(w http.ResponseWriter, status int, message, reason string)
}

var (
	v1Surface = authSurface{
		credential:   func(_ *Server, r *http.Request) string { return apihttp.BearerToken(r) },
		unauthorized: "unauthorized",
		write: func(w http.ResponseWriter, status int, message, reason string) {
			if reason == "" {
				apihttp.WriteError(w, status, message)
				return
			}
			apihttp.WriteJSON(w, status, models.ErrorResponse{Error: message, Reason: reason})
		},
	}
	e2bSurface = authSurface{
		credential:   (*Server).e2bCredential,
		unauthorized: "Unauthorized, please check your credentials.",
		write:        apie2b.WriteErrorReason,
	}
	// The Runloop SDKs send `Authorization: Bearer <RUNLOOP_API_KEY>`, the
	// same credential shape v1 takes.
	runloopSurface = authSurface{
		credential:   func(_ *Server, r *http.Request) string { return apihttp.BearerToken(r) },
		unauthorized: "unauthorized: check RUNLOOP_API_KEY",
		write:        runloop.WriteErrorReason,
	}
)

// e2bCredential reads the E2B surface's credential. The E2B SDKs send
// X-API-KEY; other clients send a bearer. A PAT in either header wins, as it
// did before T1; otherwise the bearer is tried before X-API-KEY.
func (s *Server) e2bCredential(r *http.Request) string {
	apiKey := strings.TrimSpace(r.Header.Get("X-API-KEY"))
	if s.isPATToken(apiKey) {
		return apiKey
	}
	if bearer := apihttp.BearerToken(r); bearer != "" {
		return bearer
	}
	return apiKey
}

// isPATToken reports whether candidate is the operator PAT (constant time).
func (s *Server) isPATToken(candidate string) bool {
	return patAuthenticator{token: s.patToken}.matches(candidate)
}

// withAuth is the one auth middleware; the three surfaces below are the
// former requireAuth / requireE2BAuth / requireRunloopAuth, now one function
// plus three error writers (H5).
func (s *Server) withAuth(surface authSurface, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		access, failure := s.authenticate(r, surface.credential(s, r))
		s.observeAuth(r, access, failure)
		if failure != nil {
			writeAuthFailure(w, surface, failure)
			return
		}
		ctx := controlplane.ContextWithAccess(r.Context(), access)
		next.ServeHTTP(w, r.WithContext(withCorrelationID(ctx, r)))
	})
}

// withCorrelationID gives every authenticated request one correlation id
// (plans/identity-and-access.md §5.8, H3): the caller's X-Correlation-ID or
// X-Request-ID; else one already on the context (an in-process remote MCP
// call inside an outer request); else a fresh one. Every record the request
// writes carries it, and cluster.StampForward sends it to each peer the
// request is forwarded or fanned out to, so one call can be followed across
// nodes. Minting costs one 8-byte crypto/rand read per request, no I/O.
func withCorrelationID(ctx context.Context, r *http.Request) context.Context {
	if id := apihttp.CorrelationID(r); id != "" {
		return auditlog.ContextWithCorrelationID(ctx, id)
	}
	if auditlog.CorrelationIDFromContext(ctx) != "" {
		return ctx
	}
	return auditlog.ContextWithCorrelationID(ctx, auditlog.NewCorrelationID())
}

func writeAuthFailure(w http.ResponseWriter, surface authSurface, f *authFailure) {
	if f.retryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(f.retryAfter))
	}
	if f.status != http.StatusUnauthorized {
		surface.write(w, f.status, f.message, "")
		return
	}
	if f.invalidToken != "" {
		// RFC 6750 §3.1. The reason is one of the fixed D17 values, so it
		// needs no quoting beyond the surrounding quotes.
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="`+string(f.invalidToken)+`"`)
	}
	surface.write(w, f.status, surface.unauthorized, string(f.invalidToken))
}

// requireAuth wraps next with authentication for v1, Daytona, remote MCP and
// the metrics endpoints. All API versions share it through Deps.Auth.
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return s.withAuth(v1Surface, next)
}

// requireE2BAuth is authentication with the E2B credential headers and body.
func (s *Server) requireE2BAuth(next http.Handler) http.Handler {
	return s.withAuth(e2bSurface, next)
}

// requireRunloopAuth is authentication with the Runloop error body.
func (s *Server) requireRunloopAuth(next http.Handler) http.Handler {
	return s.withAuth(runloopSurface, next)
}

// authOrigin is the aerolvm_auth_requests_total origin label: "peer" for an
// mTLS cluster peer, "host" for a loopback TCP peer, "public" otherwise.
// Caddy also connects from loopback, so its traffic counts as "host" until
// the PROXY-protocol change (T10, D12) gives sandboxd the real client.
func authOrigin(r *http.Request) string {
	if _, ok := mtlsPeer(r); ok {
		return "peer"
	}
	if addr, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		if addr.Addr().Unmap().IsLoopback() {
			return "host"
		}
		return "public"
	}
	if addr, err := netip.ParseAddr(r.RemoteAddr); err == nil && addr.Unmap().IsLoopback() {
		return "host"
	}
	return "public"
}
