package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Token-gated public ports (plans/agent-sandbox-feature-parity.md §5.9, A2;
// the token is A1's, threat model in pkg/sandboxtoken).
//
// A port exposed with visibility "token" is never published on the direct
// Caddy route that dials the container: its route always takes the shape
// that goes through the sandboxd ingress proxy (the wake route with Caddy
// routes, the router target under SB_INGRESS_PROXY_ROUTING), so every
// public request for it passes pkg/api/ingressproxy, which checks the token
// before it wakes, buffers or proxies anything. The other ways to reach a
// port are closed for a gated one: it is left off toolboxd's /proxy/<port>
// allowlist, a custom domain may not target it, and the raw TCP/TLS, WASM
// and isolate surfaces refuse the option.
//
//	expose(visibility=token) ─► store row "token" ─► route → ingress proxy
//	public request ─► ingress proxy: PortAccess (warm cache or the one row
//	                  read it already made) ─► gated? ─► token or cookie ─►
//	                  verify (no store read) ─► not revoked (the not-before
//	                  PortAccess returned) ─► strip ─► proxy

var (
	// ErrTokenVisibilityInvalid is a 400: an unknown visibility value.
	ErrTokenVisibilityInvalid = errors.New("invalid port visibility")
	// ErrTokenVisibilityUnavailable is a 400: this deployment, runtime or
	// protocol cannot gate a port behind a token.
	ErrTokenVisibilityUnavailable = errors.New("visibility \"token\" is not available here")
	// ErrTokenVisibilityConflict is a 409: a custom domain targets the
	// port, which would be a second, ungated way in.
	ErrTokenVisibilityConflict = errors.New("a custom domain targets this port")
)

// checkTokenVisibility refuses visibility "token" where the gate could not
// hold: anything but an HTTP port, the WASM and isolate runtimes (their
// ports have no ingress-proxy shape yet), a server without a domain (the
// cookie is Secure and host-only, so it needs HTTPS and a host per port),
// a server where the ingress proxy is not listening, and a port a custom
// domain dials directly.
func (s *Service) checkTokenVisibility(sandbox *models.Sandbox, port int, protocol string) error {
	if protocol != models.ExposedPortProtocolHTTP {
		return fmt.Errorf("%w: only http ports can need a token (this one is %s)", ErrTokenVisibilityUnavailable, protocol)
	}
	if s.isWasmSandbox(sandbox) || s.isIsolateSandbox(sandbox) {
		return fmt.Errorf("%w: runtime %s ports cannot need a token yet", ErrTokenVisibilityUnavailable, sandbox.Runtime)
	}
	if s.caddy == nil || !s.caddy.Enabled() || strings.TrimSpace(s.cfg.Domain) == "" {
		return fmt.Errorf("%w: it needs a server with a domain (HTTPS), because the browser cookie it sets is Secure and host-only", ErrTokenVisibilityUnavailable)
	}
	if !s.cfg.EnableServerless && s.routesWrittenToCaddy() {
		return fmt.Errorf("%w: it needs the sandboxd ingress proxy, which runs with SB_ENABLE_SERVERLESS=true (the default) or SB_INGRESS_PROXY_ROUTING", ErrTokenVisibilityUnavailable)
	}
	for _, d := range sandbox.CustomDomains {
		if d.TargetPort == port {
			return fmt.Errorf("%w: %s dials port %d directly; remove it first", ErrTokenVisibilityConflict, d.Hostname, port)
		}
	}
	if !s.tokenPortsClusterReady() {
		return fmt.Errorf("%w: every cluster node must first run a build that keeps a port's token gate through failover; finish upgrading the cluster", ErrTokenVisibilityUnavailable)
	}
	return nil
}

// tokenPortsClusterReady reports whether a port may become token-gated:
// always on a single node; in cluster mode only once every live member
// keeps the gate through failover (cluster.TokenPortGate), since a failover
// through an older build would recreate the port as public.
func (s *Service) tokenPortsClusterReady() bool {
	if s == nil || !s.cfg.EnableCluster {
		return true
	}
	gate, ok := s.Cluster().(cluster.TokenPortGate)
	return ok && gate.TokenPortsAllowed()
}

// setExposure puts exposure into sandbox's in-memory port list, replacing
// the row for the same port, so a route install that reads the list sees
// the visibility this call is storing.
func setExposure(sandbox *models.Sandbox, exposure models.ExposedPort) {
	for i := range sandbox.ExposedPorts {
		if sandbox.ExposedPorts[i].Port == exposure.Port {
			sandbox.ExposedPorts[i] = exposure
			return
		}
	}
	sandbox.ExposedPorts = append(sandbox.ExposedPorts, exposure)
}

// portTokenGated reports whether sandbox's port is exposed with visibility
// "token".
func portTokenGated(sandbox *models.Sandbox, port int) bool {
	if sandbox == nil {
		return false
	}
	for _, p := range sandbox.ExposedPorts {
		if p.Port == port {
			return p.TokenGated()
		}
	}
	return false
}

// exposeGatedHTTPPort stores an HTTP exposure whose gate is being set or
// lifted, then installs its route. Row first: the ingress proxy reads the
// gate from the row, so from this write on every request it serves is
// checked, and the route moving onto it is what closes the direct way in.
// If the route write fails the previous row goes back (or ours is
// removed), so the store never claims a gate the route does not have.
func (s *Service) exposeGatedHTTPPort(ctx context.Context, sandbox *models.Sandbox, exposure models.ExposedPort, previous *models.ExposedPort) error {
	if err := s.store.UpsertPort(ctx, exposure); err != nil {
		return err
	}
	s.invalidateWarm(sandbox.ID)
	if err := s.installHTTPPortRoute(ctx, sandbox, exposure.Port); err != nil {
		var restoreErr error
		if previous != nil {
			restoreErr = s.store.UpsertPort(ctx, *previous)
		} else {
			restoreErr = s.store.DeletePort(ctx, sandbox.ID, exposure.Port)
		}
		s.invalidateWarm(sandbox.ID)
		if restoreErr != nil {
			// The row now disagrees with the route until the caller
			// retries; say so where an operator will see it.
			s.logger.Error("expose_port: could not put the port row back after a failed route write",
				"sandbox_id", sandbox.ID, "port", exposure.Port, "visibility", exposure.Visibility, "error", restoreErr)
		}
		return err
	}
	if s.testAfterHTTPPortInstall != nil {
		s.testAfterHTTPPortInstall()
	}
	return nil
}

// PortAccess is what the ingress proxy needs to know about a sandbox port
// before it does anything else with a request.
type PortAccess struct {
	// Started is IsSandboxStarted's answer: a warm sandbox skips the
	// cold-start body buffering and admission.
	Started bool
	// TokenGated means the port was exposed with visibility "token": the
	// request needs a sandbox token for this port.
	TokenGated bool
	// TokensNotBefore is the sandbox's tokens_not_before: a port token
	// issued before it was revoked (sandboxtoken.Claims.CheckNotBefore).
	TokensNotBefore int64
}

// PortAccess answers IsSandboxStarted, the port's gate and the sandbox's
// token not-before from one read: the warm cache when it holds this
// sandbox's port list, else the sandbox row (which carries its exposed
// ports and the not-before). It adds no store read to the ingress path. An
// entry cached without a port list (warmCacheSet) is never trusted for the
// gate, so a gated port can never read as open from it, and a revoke drops
// the entry (RevokeSandboxTokens), so a revoked token is never let in by a
// not-before cached before it.
func (s *Service) PortAccess(ctx context.Context, id string, port int) (PortAccess, error) {
	if e, ok := s.warmEntryFor(id); ok && e.portsKnown {
		_, gated := e.gated[port]
		return PortAccess{Started: true, TokenGated: gated, TokensNotBefore: e.notBefore}, nil
	}
	warmGen := s.warmGen.Load()
	sb, err := s.scopedGet(ctx, id)
	if err != nil {
		return PortAccess{}, err
	}
	started := sb.Status == models.SandboxStatusStarted
	if started {
		s.warmCacheSetSandbox(sb, warmGen)
	}
	return PortAccess{Started: started, TokenGated: portTokenGated(sb, port), TokensNotBefore: sb.TokensNotBefore}, nil
}

// warmEntry is one warm-cache value: when it expires and, when the setter
// had the row, which of the sandbox's ports are token-gated and the
// sandbox's token not-before.
type warmEntry struct {
	exp        int64
	portsKnown bool
	gated      map[int]struct{}
	notBefore  int64
}

func (s *Service) warmEntryFor(id string) (warmEntry, bool) {
	s.warmCacheMu.RLock()
	e, ok := s.warmCache[id]
	s.warmCacheMu.RUnlock()
	if !ok || time.Now().UnixNano() >= e.exp {
		return warmEntry{}, false
	}
	return e, true
}

// warmCacheSetSandbox caches sb as warm together with its gated ports,
// unless invalidateWarm ran since gen was read (before sb was): then sb may
// predate a stop or a gate change, and caching it would hide that change
// for up to warmCacheTTL. One counter for every sandbox keeps this an
// atomic load; a skipped set costs only the next request a row read.
func (s *Service) warmCacheSetSandbox(sb *models.Sandbox, gen uint64) {
	e := warmEntry{exp: time.Now().Add(warmCacheTTL).UnixNano(), portsKnown: true, notBefore: sb.TokensNotBefore}
	for _, p := range sb.ExposedPorts {
		if p.TokenGated() {
			if e.gated == nil {
				e.gated = make(map[int]struct{}, 1)
			}
			e.gated[p.Port] = struct{}{}
		}
	}
	s.warmCacheMu.Lock()
	defer s.warmCacheMu.Unlock()
	if s.warmGen.Load() != gen {
		return
	}
	if s.warmCache == nil {
		s.warmCache = make(map[string]warmEntry)
	}
	s.warmCache[sb.ID] = e
}

// portLockKey names one sandbox port.
type portLockKey struct {
	id   string
	port int
}

// lockExposedPort serializes expose and unexpose calls on one sandbox port
// and returns the unlock. Without it, opposite calls race. Say a "public"
// and a "token" call arrive together: the rows can land public then token
// while the routes land wake then direct, so the store says "token" and the
// route skips the gate. A retry with no visibility can also read the row
// from before a "token" call and write it back public. Node-local is
// enough: the v1 routes forward every expose and unexpose to the owner.
// Callers on other ports and sandboxes never wait on each other.
func (s *Service) lockExposedPort(id string, port int) func() {
	return s.portLocks.lock(portLockKey{id: id, port: port})
}
