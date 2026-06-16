package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
)

// CustomDomainCacheEvicter is the narrow surface the service needs from the
// ingressproxy TLS-ask handler so that AddCustomDomain can punch a hole in
// the negative cache immediately when a new hostname is attached. Kept as an
// interface (rather than importing pkg/api/ingressproxy directly) because
// ingressproxy already depends on internal/service — pulling the dependency
// the other way would create an import cycle. cmd/sandboxd wires the real
// handler in via AttachCustomDomainCacheEvicter once both packages are built.
type CustomDomainCacheEvicter interface {
	EvictNegativeCache(hostname string)
}

// customDomainState is the optional dependency block holding the negative
// cache evicter. Held behind a mutex so AttachCustomDomainCacheEvicter is
// safe to call after service.New (it is — main.go wires it after building
// both the handler and the service).
type customDomainState struct {
	mu      sync.RWMutex
	evicter CustomDomainCacheEvicter
}

var customDomainsState customDomainState

// AttachCustomDomainCacheEvicter is the wire-up hook called from cmd/sandboxd
// once the TLSAskHandler is built. Passing nil is allowed (and the default) —
// negative-cache eviction is best-effort; the cache entry expires on its own
// TTL and the worst case is a 60s delay before the first ACME ask sees the
// freshly-added hostname.
func (s *Service) AttachCustomDomainCacheEvicter(e CustomDomainCacheEvicter) {
	customDomainsState.mu.Lock()
	customDomainsState.evicter = e
	customDomainsState.mu.Unlock()
}

func evictCustomDomainNegativeCache(hostname string) {
	customDomainsState.mu.RLock()
	e := customDomainsState.evicter
	customDomainsState.mu.RUnlock()
	if e != nil {
		e.EvictNegativeCache(hostname)
	}
}

// sandboxCustomHostnamesList returns just the operator-attached hostnames
// (without per-domain ports) for cluster-FSM replay and similar consumers
// that only care about the ownership binding, not the routing dial target.
func sandboxCustomHostnamesList(sandbox *models.Sandbox) []string {
	if sandbox == nil || len(sandbox.CustomDomains) == 0 {
		return nil
	}
	out := make([]string, 0, len(sandbox.CustomDomains))
	for _, cd := range sandbox.CustomDomains {
		if cd.Hostname != "" {
			out = append(out, cd.Hostname)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// sandboxCustomHostnames extracts the operator-attached public hostnames
// plus their per-domain target ports from a sandbox snapshot, in the shape
// expected by pkg/caddy.UpsertSandboxRoute. Returns nil when the field is
// empty so the route shape stays byte-identical to pre-custom-domains for
// sandboxes that never attached one.
//
// TargetPort=0 propagates as-is — pkg/caddy resolves that to the toolbox
// port at install time, preserving the pre-target-port default behavior for
// rows persisted before the feature shipped.
func sandboxCustomHostnames(sandbox *models.Sandbox) []caddy.CustomHostnameRoute {
	if sandbox == nil || len(sandbox.CustomDomains) == 0 {
		return nil
	}
	out := make([]caddy.CustomHostnameRoute, 0, len(sandbox.CustomDomains))
	for _, cd := range sandbox.CustomDomains {
		// Defense in depth: only the validated, normalized hostname goes
		// into the Caddy matcher. Status (pending_dns / issuing / ready /
		// failed) does not gate routing — Caddy's on-demand TLS handles
		// the cert lifecycle independently. A domain whose DNS hasn't
		// propagated yet simply won't get traffic; once it does, the
		// route is already in place.
		if cd.Hostname == "" {
			continue
		}
		route := caddy.CustomHostnameRoute{Hostname: cd.Hostname, TargetPort: cd.TargetPort}
		if cd.TargetPort > 0 {
			route.MaskRequestHost = strings.TrimSpace(sandbox.MaskRequestHost)
		}
		out = append(out, route)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// validateCreateCustomDomains runs before any expensive create work (admission,
// mounts, docker.Create) so an invalid or unsupported custom-domains payload
// rejects without burning resources. Mutates req.CustomDomains in place with
// the normalized slice so the rest of createSandbox sees canonical hostnames.
//
// Returns ErrCustomDomainNotSupported when custom domains were requested on a
// deployment that can't serve them (feature flag off, or IP mode). That maps
// to 412 at the HTTP layer — distinct from a 400 "your input is malformed",
// because the caller's input may be perfectly valid; the cluster just can't
// honor it. Empty CustomDomains is always fine.
func (s *Service) validateCreateCustomDomains(req *models.CreateSandboxRequest) error {
	if req == nil || len(req.CustomDomains) == 0 {
		return nil
	}
	if !allowPublicTrafficEnabled(req.AllowPublicTraffic) {
		return ErrPublicTrafficDisabled
	}
	if !s.cfg.EnableCustomDomains {
		return ErrCustomDomainNotSupported
	}
	base := strings.TrimSpace(s.cfg.Domain)
	if base == "" {
		// IP-mode deployment: no SB_DOMAIN means no on-demand TLS, and the
		// public URL is path-based instead of vhost-based. A custom hostname
		// has nowhere to live.
		return ErrCustomDomainNotSupported
	}
	normalized, err := models.ValidateCustomDomainList(req.CustomDomains, base)
	if err != nil {
		return err
	}
	req.CustomDomains = normalized
	return nil
}

// ErrCustomDomainNotSupported is re-exported from pkg/models so callers that
// already import internal/service (every handler) don't need a second import
// just to errors.Is against the sentinel. Same pattern other service-layer
// sentinels (ErrSandboxManuallyStopped) follow.
var ErrCustomDomainNotSupported = models.ErrCustomDomainNotSupported

// ErrCustomDomainProtocolConflict — see pkg/models comment.
var ErrCustomDomainProtocolConflict = models.ErrCustomDomainProtocolConflict

// ErrCustomDomainPerSandboxCap — see pkg/models comment.
var ErrCustomDomainPerSandboxCap = models.ErrCustomDomainPerSandboxCap

// ErrCustomDomainPortMismatch surfaces the store-layer port-mismatch sentinel
// under the service-layer sentinel that the API handler already maps to 409.
// See store.ErrCustomDomainPortMismatch for the underlying rule.
var ErrCustomDomainPortMismatch = store.ErrCustomDomainPortMismatch

// recordClusterCustomDomain replicates the (sandbox, hostname) binding into
// the placement FSM so cluster-wide uniqueness, ingress-node TLS-ask lookup,
// and failover replay all see it. Mirrors recordClusterExposedPort.
// cluster.ErrCustomHostnameConflict is mapped to store.ErrCustomDomainConflict
// so the API layer's existing 409 mapping covers both the local PK race and
// the cluster-wide Raft tiebreaker without a second sentinel.
func (s *Service) recordClusterCustomDomain(ctx context.Context, sandboxID, hostname string) error {
	c := s.Cluster()
	if c == nil {
		return nil
	}
	commitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := c.AddCustomDomain(commitCtx, sandboxID, hostname); err != nil {
		if errors.Is(err, cluster.ErrCustomHostnameConflict) {
			return store.ErrCustomDomainConflict
		}
		return fmt.Errorf("cluster: record custom domain: %w", err)
	}
	return nil
}

func (s *Service) removeClusterCustomDomain(ctx context.Context, sandboxID, hostname string) error {
	c := s.Cluster()
	if c == nil {
		return nil
	}
	commitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := c.RemoveCustomDomain(commitCtx, sandboxID, hostname); err != nil {
		return fmt.Errorf("cluster: remove custom domain: %w", err)
	}
	return nil
}

// AddCustomDomain attaches a new public hostname to an existing sandbox. The
// caller is responsible for sandbox-scoped authorization (the API layer); this
// helper validates the hostname against the deployment's base domain, enforces
// the IRON RULE (no coexistence with protocol=tcp/tls exposures), persists the
// row, re-PATCHes the Caddy route to include the new hostname, and rolls back
// the store insert on Caddy failure. On success, the negative cache entry for
// the hostname is punched so the next ACME ask hits the resolver instead of
// being refused for the cached 60s.
//
// targetPort selects the in-container port the hostname routes to. Zero is
// the sentinel meaning "use the toolbox port" (the pre-target-port default,
// preserving existing behavior). Set once at attach time; changing the port
// requires detach + re-add so in-flight traffic can't silently redirect.
//
// Returns:
//   - ErrCustomDomainNotSupported (412) when the deployment doesn't support custom domains.
//   - ErrCustomDomainInvalid (400) when the hostname fails validation.
//   - ErrCustomDomainInvalidTargetPort (400) when targetPort is outside [0, 65535].
//   - ErrCustomDomainProtocolConflict (409) when the sandbox already exposes tcp/tls ports.
//   - ErrCustomDomainPerSandboxCap (409) when the sandbox already holds the cap.
//   - ErrCustomDomainPortMismatch (409) when re-adding an existing hostname with a different port.
//   - store.ErrCustomDomainConflict (409) when the hostname is owned by a different sandbox.
//   - store.ErrNotFound (404) when the sandbox does not exist.
func (s *Service) AddCustomDomain(ctx context.Context, sandboxID, hostname string, targetPort int) error {
	if !s.cfg.EnableCustomDomains || strings.TrimSpace(s.cfg.Domain) == "" {
		return ErrCustomDomainNotSupported
	}
	if err := models.ValidateCustomDomainTargetPort(targetPort); err != nil {
		return err
	}
	canonical, err := models.NormalizeCustomDomain(hostname, s.cfg.Domain)
	if err != nil {
		return err
	}
	sandbox, err := s.scopedGet(ctx, sandboxID)
	if err != nil {
		return err
	}
	if !sandboxAllowsPublicTraffic(sandbox) {
		return ErrPublicTrafficDisabled
	}
	if hasL4Exposure(sandbox) {
		return ErrCustomDomainProtocolConflict
	}
	if s.isWasmSandbox(sandbox) {
		if err := s.validateWasmCustomDomainTargetPort(sandbox, targetPort); err != nil {
			return err
		}
	}
	// Per-sandbox cap is enforced here rather than in the store so the error
	// surfaces with the canonical sentinel; the store would otherwise just
	// insert and the count check would race with concurrent adds. Reads
	// the operator-tunable cap from config (SB_CUSTOM_DOMAINS_MAX_PER_SANDBOX)
	// with the compile-time default as a safety floor when the config wasn't
	// validated (tests, embedded callers).
	maxDomains := s.cfg.CustomDomainsMaxPerSandbox
	if maxDomains <= 0 {
		maxDomains = models.MaxCustomDomainsPerSandbox
	}
	if len(sandbox.CustomDomains) >= maxDomains {
		// Idempotent re-add of an existing hostname must NOT trip the cap —
		// the same row already counts in the slice.
		alreadyHeld := false
		for _, cd := range sandbox.CustomDomains {
			if cd.Hostname == canonical {
				alreadyHeld = true
				break
			}
		}
		if !alreadyHeld {
			return ErrCustomDomainPerSandboxCap
		}
	}

	// Verify DNS ownership (TXT record). The TXT proves zone control and is
	// keyed to the hostname, not the sandbox ID, so users can provision it
	// once and attach the hostname to any sandbox (including a recreated
	// one with a new ID).
	if err := verifyCustomDomainOwnership(ctx, s.dnsResolver, canonical, s.cfg.CustomDomainVerifyPrefix, s.cfg.CustomDomainVerifyValuePrefix); err != nil {
		return err
	}

	if err := s.store.AddCustomDomain(ctx, sandboxID, canonical, targetPort); err != nil {
		return err
	}

	// Cluster-wide uniqueness gate. Without this two owners on different
	// nodes can each accept the same hostname (local SQLite PK is per-node);
	// the FSM is the cross-node tiebreaker. Run BEFORE the Caddy PATCH so a
	// conflict rolls back cheaply — the local row goes away and Caddy was
	// never told about the hostname. Noop returns nil so single-node mode
	// short-circuits.
	if err := s.recordClusterCustomDomain(ctx, sandboxID, canonical); err != nil {
		_ = s.store.RemoveCustomDomain(ctx, sandboxID, canonical)
		return err
	}

	// Re-read so the caddy PATCH sees the full union (existing + new). The
	// store inserts with pending_dns status; Caddy's on-demand TLS does not
	// look at status, only hostname presence, so the new hostname is route-
	// matchable immediately.
	refreshed, err := s.store.Get(ctx, sandboxID)
	if err != nil {
		_ = s.removeClusterCustomDomain(ctx, sandboxID, canonical)
		_ = s.store.RemoveCustomDomain(ctx, sandboxID, canonical)
		return fmt.Errorf("reload sandbox after custom-domain insert: %w", err)
	}
	if err := s.syncSandboxPublicRoute(ctx, refreshed); err != nil {
		// Store first / caddy second with rollback on caddy failure. Same
		// shape as the create path. We deliberately keep the row OUT of the
		// store on a partial failure rather than leaving an orphan row that
		// the reconciler would have to clean up — the caller can simply
		// retry the request.
		_ = s.removeClusterCustomDomain(ctx, sandboxID, canonical)
		_ = s.store.RemoveCustomDomain(ctx, sandboxID, canonical)
		return fmt.Errorf("install caddy route for custom domain %q: %w", canonical, err)
	}
	if err := s.syncWasmCustomDomainRoutes(ctx, refreshed); err != nil {
		_ = s.removeClusterCustomDomain(ctx, sandboxID, canonical)
		_ = s.store.RemoveCustomDomain(ctx, sandboxID, canonical)
		return err
	}
	evictCustomDomainNegativeCache(canonical)
	return nil
}

// RemoveCustomDomain detaches a hostname. Order is store-first then Caddy.
// If the store delete succeeds but the Caddy patch fails, the hostname is
// gone from the store while Caddy may still serve it until the next
// reconcile pass converges routing. Cross-sandbox removal returns
// store.ErrNotFound (the store layer scopes the DELETE to (sandbox,
// hostname)), so a tenant cannot rip a domain out of someone else's route
// by guessing the hostname.
func (s *Service) RemoveCustomDomain(ctx context.Context, sandboxID, hostname string) error {
	// Mirror AddCustomDomain's deployment-capability gate. routes.go documents
	// that disabled-feature / IP-mode deployments surface 412 here too — the
	// route is mounted unconditionally so callers can tell "this cluster does
	// not do custom domains" apart from "the route does not exist".
	if !s.cfg.EnableCustomDomains || strings.TrimSpace(s.cfg.Domain) == "" {
		return ErrCustomDomainNotSupported
	}
	canonical, err := models.NormalizeCustomDomain(hostname, s.cfg.Domain)
	if err != nil {
		return err
	}
	sandbox, err := s.scopedGet(ctx, sandboxID)
	if err != nil {
		return err
	}
	owned := false
	for _, cd := range sandbox.CustomDomains {
		if cd.Hostname == canonical {
			owned = true
			break
		}
	}
	if !owned {
		return store.ErrNotFound
	}
	if err := s.store.RemoveCustomDomain(ctx, sandboxID, canonical); err != nil {
		return err
	}
	// Release the FSM claim so a future AddCustomDomain on a different
	// sandbox is not blocked by a stale hostname binding the local store no
	// longer backs. Idempotent in the cluster command, so a redundant remove
	// from a reconcile pass is safe. Noop is a nil return in single-node.
	if err := s.removeClusterCustomDomain(ctx, sandboxID, canonical); err != nil {
		// Best-effort: log and proceed. The local row is already gone, and a
		// stale FSM binding will be cleaned by the placement-teardown sweep
		// on sandbox destroy or by an operator-initiated reconcile. Surfacing
		// the error here would leave the caller unable to retry cleanly.
		s.logger.Warn("custom-domain cluster release failed; reconcile will retry",
			"sandbox_id", sandboxID, "hostname", canonical, "error", err)
	}
	refreshed, err := s.store.Get(ctx, sandboxID)
	if err != nil {
		return fmt.Errorf("reload sandbox after custom-domain delete: %w", err)
	}
	if err := s.syncSandboxPublicRoute(ctx, refreshed); err != nil {
		// Caddy is the source of truth for routing; if we couldn't refresh the
		// route set, the row is gone from the store but Caddy may still serve
		// the hostname. The next ingress reconcile (or AddCustomDomain
		// re-attaching the same hostname elsewhere) will converge it.
		return fmt.Errorf("update caddy route after custom-domain delete %q: %w", canonical, err)
	}
	if err := s.syncWasmCustomDomainRoutes(ctx, refreshed); err != nil {
		return err
	}
	// UpsertSandboxRoute only writes; it does not GC the per-hostname route
	// for the detached domain. Drop it explicitly so the dial target stops
	// answering immediately rather than waiting on a reconcile sweep.
	if err := s.caddy.DeleteCustomDomainHTTPRoute(ctx, refreshed.ID, canonical); err != nil {
		return fmt.Errorf("delete caddy per-hostname route for %q: %w", canonical, err)
	}
	return nil
}

// ListCustomDomains returns the canonical rows for one sandbox. Empty slice
// (nil) when none are attached. Same deployment-capability gate as
// Add/Remove: disabled-feature or IP-mode returns ErrCustomDomainNotSupported
// (412) rather than an empty list, so callers can distinguish "this sandbox
// has no domains" from "this cluster does not do custom domains".
func (s *Service) ListCustomDomains(ctx context.Context, sandboxID string) ([]models.CustomDomain, error) {
	if !s.cfg.EnableCustomDomains || strings.TrimSpace(s.cfg.Domain) == "" {
		return nil, ErrCustomDomainNotSupported
	}
	if _, err := s.scopedGet(ctx, sandboxID); err != nil {
		return nil, err
	}
	return s.store.ListCustomDomains(ctx, sandboxID)
}

// hasL4Exposure reports whether sandbox has any protocol=tcp/tls exposed port.
// Used by AddCustomDomain to enforce the IRON RULE and (in the future) by the
// expose-port path to reject tcp/tls when a custom domain already exists.
func hasL4Exposure(sandbox *models.Sandbox) bool {
	if sandbox == nil {
		return false
	}
	for _, ep := range sandbox.ExposedPorts {
		switch ep.Protocol {
		case models.ExposedPortProtocolTCP, models.ExposedPortProtocolTLS:
			return true
		}
	}
	return false
}

// hasCustomDomains reports whether sandbox holds any custom-domain row. The
// expose-port path (ExposePort with protocol=tcp/tls) uses this to enforce
// the IRON RULE from the other side.
func hasCustomDomains(sandbox *models.Sandbox) bool {
	return sandbox != nil && len(sandbox.CustomDomains) > 0
}

// persistCustomDomainsOnCreate writes each validated hostname row after the
// caddy route is installed and the sandbox row is persisted. Called from
// createSandbox right after store.Create. On any single failure, every row
// inserted so far in this call is rolled back so the caller's create path
// can unwind cleanly without leaving partial rows.
//
// We deliberately do NOT re-PATCH caddy per hostname here — the initial
// UpsertSandboxRoute already included sandboxCustomHostnames(sandbox) with
// the full set, so the route matcher is in place before this runs.
//
// CreateSandbox does not (yet) accept per-domain target ports — the bulk
// CustomDomains field on the request is still []string and every row is
// persisted with target_port=0 (the toolbox-default sentinel). Callers that
// need a per-domain port use AddCustomDomain post-create.
func (s *Service) persistCustomDomainsOnCreate(ctx context.Context, sandboxID string, hostnames []string) error {
	if len(hostnames) == 0 {
		return nil
	}
	added := make([]string, 0, len(hostnames))
	rollback := func() {
		for _, prev := range added {
			_ = s.removeClusterCustomDomain(ctx, sandboxID, prev)
			_ = s.store.RemoveCustomDomain(ctx, sandboxID, prev)
		}
	}
	for _, h := range hostnames {
		if err := s.store.AddCustomDomain(ctx, sandboxID, h, 0); err != nil {
			rollback()
			if errors.Is(err, store.ErrCustomDomainConflict) {
				return err
			}
			return fmt.Errorf("persist custom domain %q: %w", h, err)
		}
		// Replicate into the FSM before we consider this row added — a
		// cross-node hostname conflict surfaces here, not later on a
		// failover that's too late to roll back the caller's create call.
		if err := s.recordClusterCustomDomain(ctx, sandboxID, h); err != nil {
			_ = s.store.RemoveCustomDomain(ctx, sandboxID, h)
			rollback()
			return err
		}
		added = append(added, h)
	}
	for _, h := range added {
		evictCustomDomainNegativeCache(h)
	}
	return nil
}
