package api

// Sandbox tokens at the API edge (plans/agent-sandbox-feature-parity.md
// §5.9, A1; threat model in pkg/sandboxtoken). The authenticator claims a
// bearer that starts with avmst_ and checks it with no store read; the
// post-match scope step then refuses it on every request but its own
// sandbox's toolbox, inside its path prefix and methods. Both run in the
// one authenticate() every surface shares, so a sandbox token is refused
// on Daytona, E2B, Runloop and /mcp by the same code that lets it through
// on the v1 toolbox, and controlplane.Access.Can grants it sandbox.exec
// only, as a second fence behind the scope step.
//
//	bearer avmst_… ─► verify (signature, expiry, cap) ── bad ──► 401 reason
//	               ─► scope: a v1 toolbox or sessions route? ── no ──► 403
//	               ─► Allows(sandbox id, toolbox path, method) ── no ──► 403 (part)
//	               ─► Access{sandbox_token:stk_…, owner fence, exec only}

import (
	"errors"
	"net/http"

	apiv1 "github.com/aerol-ai/microvm/pkg/api/v1"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/sandboxtoken"
)

// sandboxTokenAuthenticator recognises a sandbox token. It runs right after
// the PAT and before the avm_ and JWT authenticators and the managed
// provider, with identity on or off: the prefix is its own, so no other
// credential reaches it, and an avmst_ bearer never reaches a provider.
type sandboxTokenAuthenticator struct {
	verify func(raw string) (sandboxtoken.Claims, error)
}

func (a sandboxTokenAuthenticator) Authenticate(_ *http.Request, bearer string) (controlplane.Access, bool, error) {
	if !sandboxtoken.IsToken(bearer) {
		return controlplane.Access{}, false, nil
	}
	if a.verify == nil {
		return controlplane.Access{}, true, &controlplane.CredentialError{Kind: controlplane.PrincipalSandboxToken, Reason: controlplane.RejectInvalidSignature}
	}
	claims, err := a.verify(bearer)
	if err != nil {
		return controlplane.Access{}, true, &controlplane.CredentialError{Kind: controlplane.PrincipalSandboxToken, Reason: sandboxTokenReason(err)}
	}
	return controlplane.Access{
		// Fenced to the issuing owner: the service's owner scope then holds
		// the token to that owner's sandboxes even if the scope step below
		// had a hole.
		Identity:     controlplane.Identity{OwnerRef: claims.Owner},
		Principal:    controlplane.Principal{Kind: controlplane.PrincipalSandboxToken, ID: claims.TokenID, Name: claims.TokenID},
		ExpiresAt:    claims.Expiry(),
		SandboxToken: &claims,
	}, true, nil
}

// sandboxTokenReason maps a verify error onto the D17 reason the 401
// carries. Anything unexpected is malformed: a reason, never the error.
func sandboxTokenReason(err error) controlplane.RejectReason {
	switch {
	case errors.Is(err, sandboxtoken.ErrExpired):
		return controlplane.RejectExpired
	case errors.Is(err, sandboxtoken.ErrNotYetValid):
		return controlplane.RejectNotYetValid
	case errors.Is(err, sandboxtoken.ErrTooLongLived):
		return controlplane.RejectTooLongLived
	case errors.Is(err, sandboxtoken.ErrInvalidSignature):
		return controlplane.RejectInvalidSignature
	}
	return controlplane.RejectMalformed
}

// errSandboxTokenRoute refuses a sandbox token on a route that is not its
// sandbox's toolbox (a token can never list, create, delete or mint).
var errSandboxTokenRoute = errors.New("a sandbox token works only on its sandbox's toolbox (/v1/sandboxes/{id}/toolbox and /sessions)")

// The routes a toolbox sandbox token is accepted on, by the ServeMux
// pattern that matched. Comparing the pattern, not the path, means the
// check sees exactly the route the handler will run.
var (
	toolboxRootPattern  = apiv1.PathPrefix + "/sandboxes/{id}/toolbox"
	toolboxPathPattern  = apiv1.PathPrefix + "/sandboxes/{id}/toolbox/{path...}"
	sessionsRootPattern = apiv1.PathPrefix + "/sandboxes/{id}/sessions"
	sessionsPathPattern = apiv1.PathPrefix + "/sandboxes/{id}/sessions/{path...}"
)

// sandboxTokenToolboxPath returns the toolbox path a request will be proxied
// to, computed the way the v1 toolbox and sessions handlers compute it
// (pkg/api/v1/proxy.go), or ok=false for any other route.
func sandboxTokenToolboxPath(r *http.Request) (string, bool) {
	switch r.Pattern {
	case toolboxRootPattern:
		return "/", true
	case toolboxPathPattern:
		return "/" + r.PathValue("path"), true
	case sessionsRootPattern:
		return "/sessions", true
	case sessionsPathPattern:
		return "/sessions/" + r.PathValue("path"), true
	}
	return "", false
}

// enforceSandboxTokenScope is the scope step: a sandbox token is accepted
// only on its sandbox's toolbox, inside its path prefix and methods, and
// only if it is a toolbox token (a port token opens a public URL, A2).
func enforceSandboxTokenScope(r *http.Request, a controlplane.Access) (controlplane.Access, error) {
	if a.Principal.Kind != controlplane.PrincipalSandboxToken {
		return a, nil
	}
	if a.SandboxToken == nil {
		return a, errSandboxTokenRoute
	}
	toolboxPath, ok := sandboxTokenToolboxPath(r)
	if !ok {
		return a, errSandboxTokenRoute
	}
	return a, a.SandboxToken.Allows(sandboxtoken.Request{
		SandboxID: r.PathValue("id"),
		Path:      toolboxPath,
		Method:    r.Method,
	})
}

// scopePart is the fixed word a scope refusal names.
func scopePart(err error) string {
	var se *sandboxtoken.ScopeError
	if errors.As(err, &se) {
		return se.Part
	}
	return "request"
}
