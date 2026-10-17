package api

// One authentication function for every surface (plans/identity-and-access.md
// §5.2, eng review D6). v1, Daytona, MCP, the dashboard's metrics, E2B and
// Runloop all run the same authenticate(); the surfaces differ only in where
// they read the credential and how they word a refusal.
//
//	credential ─► authenticators, in order; the first that matches decides
//	               pat ─► apiToken (T3) ─► jwt (internal/identity) ─► provider
//	           ─► post-match steps: forward attribution, surface rule,
//	               team selection
//	           ─► refusals: reason mapping (401 / 403 / 400 / 503) per surface

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
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
	// authKindMCPHandoff is a remote MCP inner call that reached the edge
	// without the Access hand-off (finding 2.5): a bug, never a caller's
	// mistake.
	authKindMCPHandoff = "mcp_handoff"
)

// noHandoffMessage is the 500 text for that bug. It names no detail: the
// fix is in sandboxd, and the log line and metric tell the operator.
const noHandoffMessage = "internal error: a remote MCP tool call reached the API without its caller"

// ServerOption configures NewServer.
type ServerOption func(*serverOptions)

type serverOptions struct {
	credentials []authLink
	discovery   func() []identitywire.DiscoveryIssuer
	mcpResource func() MCPResource
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
func buildAuthChain(pat patAuthenticator, validator controlplane.Validator, credentials []authLink) []authLink {
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
	links = append(links, authLink{kind: string(controlplane.PrincipalOperator), auth: pat})
	links = append(links, credentials...)
	return append(links, authLink{kind: providerKind, auth: providerAuthenticator{validator: validator}})
}

// authLinks returns the chain. A Server built by NewServer has it already; a
// bare &Server{patToken, validator} (unit tests) gets the default chain.
func (s *Server) authLinks() []authLink {
	if s.authChain != nil {
		return s.authChain
	}
	return buildAuthChain(s.patAuth(), s.validator, nil)
}

// patAuth is the server's PAT authenticator.
func (s *Server) patAuth() patAuthenticator {
	return patAuthenticator{token: s.patToken, previous: s.patTokenPrevious, hostOnly: s.patScopeHost, trustClientIP: s.l4ProxyProtocol}
}

// patAuthenticator recognises the operator token (PAT).
type patAuthenticator struct {
	token string
	// previous is SB_PAT_TOKEN_PREVIOUS: during a rolling rotation the old
	// token keeps working on every node until it is removed (§5.11, H2).
	previous string
	// hostOnly is SB_PAT_SCOPE=host: the PAT is accepted only from a
	// loopback TCP peer and from mTLS cluster peers (CEO review D4).
	hostOnly bool
	// trustClientIP is SB_L4_FALLBACK_PROXY_PROTOCOL: Caddy's
	// X-AerolVM-Client-IP then marks its loopback traffic as public.
	trustClientIP bool
}

// matches compares in constant time: the PAT grants fleet-wide access, so a
// byte-wise == would leak the matching prefix length as a timing signal.
// Both tokens are always compared, so the time taken does not say which
// one matched, or whether a previous token is configured.
func (p patAuthenticator) matches(candidate string) bool {
	if candidate == "" {
		return false
	}
	current := p.token != "" && subtle.ConstantTimeCompare([]byte(candidate), []byte(p.token)) == 1
	previous := p.previous != "" && subtle.ConstantTimeCompare([]byte(candidate), []byte(p.previous)) == 1
	return current || previous
}

// Authenticate splits the PAT into its two principals (§5.1). A cluster peer
// that proves itself with its mTLS certificate and is NOT forwarding a user's
// request is acting for itself: node:<peer>. Everyone else, including a peer
// forwarding a user's PAT request, is the operator; forward attribution then
// records the edge node in Via. Both get today's powers; only the name
// differs.
//
// Under SB_PAT_SCOPE=host it also refuses a PAT from a public origin (the
// public socket, or a TCP peer that is not loopback), and a PAT a peer
// forwarded unless the edge marked it X-Cluster-PAT-Origin: host. A missing
// marker is refused too, so host scope is turned on only once every node
// runs this release (the runbook's order). Under the default scope "any"
// nothing here changes (L8).
func (p patAuthenticator) Authenticate(r *http.Request, bearer string) (controlplane.Access, bool, error) {
	if !p.matches(bearer) {
		return controlplane.Access{}, false, nil
	}
	if p.hostOnly {
		switch requestOrigin(r, p.trustClientIP) {
		case originPublic:
			return controlplane.Access{}, true, errPATScope
		case originPeer:
			if isForwarded(r) && r.Header.Get(cluster.HeaderPATOrigin) != cluster.PATOriginHost {
				return controlplane.Access{}, true, errPATOrigin
			}
		}
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
//
// A remote MCP tool's inner call is decided first, by the Access hand-off
// alone (§5.14): /mcp already authenticated the caller, ran the surface rule
// and selected the team, so none of that runs again, and the bearer the
// call also carries (for forwards) is never looked at here. An inner call
// without the hand-off is a bug, answered 500 (finding 2.5); falling back to
// the bearer would hold an /mcp-only token to /v1's rules.
func (s *Server) authenticate(r *http.Request, bearer string) (controlplane.Access, *authFailure) {
	if access, inner, ok := remotemcp.Handoff(r.Context()); inner {
		if !ok {
			return controlplane.Access{}, &authFailure{status: http.StatusInternalServerError, kind: authKindMCPHandoff,
				reason: "no_handoff", message: noHandoffMessage}
		}
		return access, nil
	}
	if bearer == "" {
		return controlplane.Access{}, &authFailure{status: http.StatusUnauthorized, kind: authKindNone, reason: "missing"}
	}
	for _, link := range s.authLinks() {
		access, matched, err := link.auth.Authenticate(r, bearer)
		if !matched {
			continue
		}
		if err == nil {
			if access, err = runPostMatchSteps(r, access); err != nil {
				// The credential itself was good: a post-match step refused
				// the request (a team it is not bound to). The caller is
				// known, so the refusal can name them (§5.9: a 403 is an api
				// record, not an anonymous auth_denied).
				f := mapAuthFailure(link.kind, err)
				f.caller, f.hasCaller = access, true
				return controlplane.Access{}, f
			}
		}
		if err != nil {
			f := mapAuthFailure(link.kind, err)
			if f.noBinding != nil {
				// A verified token that matched no binding: the caller holds
				// no role but is known, so the 403 is an api record naming
				// them, like the wrong-team 403 above (§5.5, finding 2.3).
				f.caller, f.hasCaller = controlplane.Access{Principal: f.noBinding.Principal}, true
			}
			return controlplane.Access{}, f
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
const headerClusterSurface = cluster.HeaderSurface

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
	if mcpForward(r) {
		return a, nil
	}
	return a, &controlplane.CredentialError{Kind: a.Principal.Kind, Reason: controlplane.RejectWrongAudience}
}

// mcpForward reports whether a live peer forwarded r as a remote MCP tool's
// inner call: cluster.StampForward sets the surface marker and the forwarded
// marker together, and both count only over a verified mTLS connection
// (clusterControlHeaderGuard refuses them from anyone else in cluster mode
// and drops them on a single node).
func mcpForward(r *http.Request) bool {
	if r.Header.Get(headerClusterSurface) != auditlog.SurfaceMCP || !isForwarded(r) {
		return false
	}
	_, ok := mtlsPeer(r)
	return ok
}

// requestSurface is the surface an api or denied record names: the one the
// in-process transport put on the context (an edge's MCP inner call), or
// mcp for a peer's MCP forward, so the owner that runs a forwarded inner
// call records it as the MCP call it is (§5.9).
func requestSurface(r *http.Request) string {
	if surface := auditlog.SurfaceFromContext(r.Context()); surface != "" {
		return surface
	}
	if mcpForward(r) {
		return auditlog.SurfaceMCP
	}
	return ""
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
// message names only the caller's own bindings (D9): what `whoami` and the
// caller's own token already say.
type teamNotBoundError struct {
	team     string
	bindings []controlplane.TeamBinding
}

// maxHintBindings caps how many of the caller's bindings a 403 lists.
const maxHintBindings = 10

func (e *teamNotBoundError) Error() string {
	if len(e.bindings) == 1 && e.bindings[0].Team == controlplane.FleetTeam {
		return HeaderTeam + ": " + e.team + " is not one of this credential's teams (it holds role " + string(e.bindings[0].Role) +
			" on all teams); send no " + HeaderTeam + " header to act on every team"
	}
	holds := make([]string, 0, min(len(e.bindings), maxHintBindings)+1)
	for i, b := range e.bindings {
		if i == maxHintBindings {
			holds = append(holds, "and "+strconv.Itoa(len(e.bindings)-i)+" more")
			break
		}
		holds = append(holds, "role "+string(b.Role)+" on "+teamPhrase(b.Team))
	}
	return HeaderTeam + ": " + e.team + " is not one of this credential's teams (it holds " + strings.Join(holds, ", ") +
		"); ask an admin for a binding on team " + e.team
}

func teamPhrase(team string) string {
	if team == controlplane.FleetTeam {
		return "all teams"
	}
	return "team " + team
}

// selectTeam is team selection (§5.3, D13). The header selects among the
// bindings the verified credential already holds; it never grants one.
// Without the header the first binding stands (Access arrives scoped to
// it). An OIDC token can match several identity-file bindings and selects
// the first whose team the header names; an avm_ token has one binding, so
// the header must name it. Naming a team only a fleet binding covers is
// refused rather than silently narrowed: a fleet binding's team is "*",
// never a team name (design review DR2). The PAT, node and managed callers
// ignore the header entirely (L8: their behavior is unchanged).
//
// Selection runs per request, after any cache: the verified-token cache
// stores the binding set, never the selected team (eng review E7). A
// forwarded request carries the team the edge resolved
// (cluster.StampForward), so the owner node re-applies the same selection
// offline (L2).
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
	bindings := a.Bindings
	if len(bindings) == 0 {
		bindings = []controlplane.TeamBinding{{Role: a.Role, Team: a.Team()}}
	}
	for _, b := range bindings {
		if b.Team == team {
			return b.Apply(a), nil
		}
	}
	return a, &teamNotBoundError{team: team, bindings: bindings}
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
	// hint is that refusal's fixed setting hint (an Entra v1 access token,
	// §5.14), added to the 401 text after the surface's own words.
	hint string
	// message is the 400/403/503 text. A 401 uses the surface's own fixed
	// text, so PAT and managed 401 bodies stay byte for byte as before; the
	// one exception is a PAT refused by SB_PAT_SCOPE=host, which exists only
	// with that opt-in and says to sign in instead.
	message string
	// retryAfter is the Retry-After seconds of a 503.
	retryAfter int
	// caller is the verified credential's Access when a post-match step,
	// not the credential, refused the request; hasCaller says it is set.
	caller    controlplane.Access
	hasCaller bool
	// noBinding is set on a "no binding" 403 for a verified OIDC token: v1
	// adds its fields (reason, issuer, name, groups) to the body (DR8).
	noBinding *controlplane.NoBindingError
}

// identityStaleRetryAfter is the Retry-After of a stale-mirror 503: about
// one mirror poll, after which the node may have synced.
const identityStaleRetryAfter = 5

// identityUnavailableMessage is the 503 text for a JWT this node cannot
// check right now (the identity file is invalid, or the issuer's keys could
// not be fetched). It names no detail: the caller is unauthenticated, and
// the operator has the log line and the metrics.
const identityUnavailableMessage = "sign-in with an identity provider is unavailable on this server right now; retry shortly, or use an API token"

// identityUnavailableRetryAfter is the Retry-After on that 503, in seconds:
// about half the JWKS refetch gap.
const identityUnavailableRetryAfter = 30

// mapAuthFailure is reason mapping (D17 for 401s, D9 for 403s, 503 when this
// node cannot vouch for a named credential right now). Only an avm_ token or
// a JWT refusal with a known reason tells the caller why. The PAT, the
// managed provider and an unrecognised bearer keep today's bare 401, even if
// a provider returns a CredentialError.
func mapAuthFailure(linkKind string, err error) *authFailure {
	if ce, ok := controlplane.AsCredentialError(err); ok {
		switch ce.Kind {
		case controlplane.PrincipalToken, controlplane.PrincipalOIDC:
			if ce.Reason.Valid() {
				return &authFailure{status: http.StatusUnauthorized, kind: string(ce.Kind), reason: string(ce.Reason), invalidToken: ce.Reason, hint: ce.Hint}
			}
		}
		return &authFailure{status: http.StatusUnauthorized, kind: linkKind, reason: "rejected"}
	}
	if nb, ok := controlplane.AsNoBindingError(err); ok {
		return &authFailure{status: http.StatusForbidden, kind: linkKind, reason: nb.Reason(), message: noBindingMessage(nb), noBinding: nb}
	}
	var notBound *teamNotBoundError
	switch {
	case errors.Is(err, controlplane.ErrIdentityStale):
		// The token mirror on this node cannot vouch for any token right
		// now (§5.4): the credential may be fine, so 503, not 401.
		return &authFailure{status: http.StatusServiceUnavailable, kind: linkKind, reason: "stale",
			message: "identity data is stale on this node; retry shortly", retryAfter: identityStaleRetryAfter}
	case errors.Is(err, controlplane.ErrIdentityUnavailable):
		// No good identity file, or the issuer's keys could not be fetched
		// (§5.5, §11): the token may be fine, so 503, not 401.
		return &authFailure{status: http.StatusServiceUnavailable, kind: linkKind, reason: "unavailable",
			message: identityUnavailableMessage, retryAfter: identityUnavailableRetryAfter}
	case errors.Is(err, errPATScope):
		// SB_PAT_SCOPE=host: the one 401 that names what to use instead.
		return &authFailure{status: http.StatusUnauthorized, kind: linkKind, reason: "pat_scope", message: patScopeMessage}
	case errors.Is(err, errPATOrigin):
		return &authFailure{status: http.StatusUnauthorized, kind: linkKind, reason: "pat_origin", message: patScopeMessage}
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
	// writeNoBinding, when set, writes the "no binding" 403 with its
	// structured fields (DR8). Surfaces without it (the E2B and Runloop
	// facades) keep their own body shape and carry the hint in the message.
	writeNoBinding func(w http.ResponseWriter, message string, nb *controlplane.NoBindingError)
	// oauthChallenge marks /mcp: its 401 names the RFC 9728 metadata, so an
	// OAuth connector learns where to sign in (§5.14).
	oauthChallenge bool
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
		writeNoBinding: func(w http.ResponseWriter, message string, nb *controlplane.NoBindingError) {
			apihttp.WriteJSON(w, http.StatusForbidden, models.ErrorResponse{
				Error:  message,
				Reason: nb.Reason(),
				Issuer: nb.Issuer,
				Name:   nb.Name,
				Groups: nb.Groups,
			})
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
	// mcpSurface is v1's, plus the OAuth challenge on a 401.
	mcpSurface = func() authSurface {
		s := v1Surface
		s.oauthChallenge = true
		return s
	}()
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

// isPATToken reports whether candidate is the operator PAT, current or
// previous (constant time).
func (s *Server) isPATToken(candidate string) bool {
	return s.patAuth().matches(candidate)
}

// withAuth is the one auth middleware; the three surfaces below are the
// former requireAuth / requireE2BAuth / requireRunloopAuth, now one function
// plus three error writers (H5).
func (s *Server) withAuth(surface authSurface, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		access, failure := s.authenticate(r, surface.credential(s, r))
		s.observeAuth(r, access, failure)
		if failure != nil {
			challenge := ""
			if surface.oauthChallenge && failure.status == http.StatusUnauthorized {
				challenge = s.mcpChallengeParams()
			}
			writeAuthFailure(w, surface, failure, challenge)
			s.recordAuthFailure(r, failure)
			return
		}
		ctx := controlplane.ContextWithAccess(r.Context(), access)
		switch access.Principal.Kind {
		case controlplane.PrincipalOperator, controlplane.PrincipalNode:
			// Where this node accepted the PAT, for the
			// X-Cluster-PAT-Origin every forward of it carries (§5.11).
			ctx = cluster.ContextWithPATOrigin(ctx, patOrigin(r, s.l4ProxyProtocol))
		}
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

// writeAuthFailure writes f in the surface's shape. challenge, set only for
// a /mcp 401 with an OAuth resource configured, is the RFC 9728 auth-params
// (resource_metadata, scope) the Bearer challenge leads with.
func writeAuthFailure(w http.ResponseWriter, surface authSurface, f *authFailure, challenge string) {
	if f.retryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(f.retryAfter))
	}
	if f.noBinding != nil && surface.writeNoBinding != nil {
		surface.writeNoBinding(w, f.message, f.noBinding)
		return
	}
	if f.status != http.StatusUnauthorized {
		surface.write(w, f.status, f.message, "")
		return
	}
	params := challenge
	if f.invalidToken != "" {
		// RFC 6750 §3.1. The reason is one of the fixed D17 values, so it
		// needs no quoting beyond the surrounding quotes.
		if params != "" {
			params += ", "
		}
		params += `error="invalid_token", error_description="` + string(f.invalidToken) + `"`
	}
	if params != "" {
		// A request with no credential at all gets the challenge without an
		// error code (RFC 6750 §3.1): that is how a connector first learns
		// where to sign in.
		w.Header().Set("WWW-Authenticate", "Bearer "+params)
	}
	message := surface.unauthorized
	if f.message != "" {
		message = f.message
	}
	if f.hint != "" {
		message += " (" + f.hint + ")"
	}
	surface.write(w, f.status, message, string(f.invalidToken))
}

// requireAuth wraps next with authentication for v1, Daytona and the metrics
// endpoints. All API versions share it through Deps.Auth.
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return s.withAuth(v1Surface, next)
}

// requireMCPAuth is v1 authentication for /mcp, whose 401 also carries the
// RFC 9728 challenge when the identity file names an MCP resource (§5.14).
// With identity off, or no mcp.resource, it is requireAuth byte for byte.
func (s *Server) requireMCPAuth(next http.Handler) http.Handler {
	return s.withAuth(mcpSurface, next)
}

// requireE2BAuth is authentication with the E2B credential headers and body.
func (s *Server) requireE2BAuth(next http.Handler) http.Handler {
	return s.withAuth(e2bSurface, next)
}

// requireRunloopAuth is authentication with the Runloop error body.
func (s *Server) requireRunloopAuth(next http.Handler) http.Handler {
	return s.withAuth(runloopSurface, next)
}
