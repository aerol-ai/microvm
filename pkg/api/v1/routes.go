package v1

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/docker"
)

// ImageBuilder is the slice of pkg/docker.Client v1 needs to compile an
// Image-builder graph into a content-addressed local image tag, and
// optionally push the result to a remote registry. Declared as an
// interface so the test harness can stub it without standing up a real
// Docker daemon. PushImage is v1-only — the Daytona facade interface
// deliberately omits it to keep its surface aligned with upstream Daytona.
type ImageBuilder interface {
	BuildImage(ctx context.Context, req docker.BuildImageRequest) error
	ImageExists(ctx context.Context, imageRef string) (bool, error)
	PushImage(ctx context.Context, req docker.PushImageRequest) (string, error)
	// RefreshTag bumps Docker's Metadata.LastTagTime so the built-image
	// janitor doesn't GC a tag that was just handed out from the build
	// cache. Called on the ImageExists==true short-circuit path.
	RefreshTag(ctx context.Context, fullRef string) error
	// RemoveImage rolls back a freshly built tag when the downstream
	// snapshot-register call fails — otherwise the layer leaks because no
	// snapshot row points at it for the built-image janitor to clean up.
	RemoveImage(ctx context.Context, imageRef string) error
}

// BuildConfig mirrors the operator-configured image-build knobs.
type BuildConfig struct {
	ContextEnabled bool
	Timeout        time.Duration
}

// Deps holds the shared dependencies a version package needs from the
// top-level pkg/api router. Keeping these explicit (rather than reaching into
// pkg/api globals) lets future version packages coexist without coupling.
type Deps struct {
	Service *service.Service
	Logger  *slog.Logger
	// Auth wraps each handler with bearer-token auth. The middleware lives in
	// pkg/api so all versions share one auth contract; the version package
	// only decides which routes need it.
	Auth func(http.Handler) http.Handler
	// AuditLimiter rate-limits GET /v1/sandboxes/{id}/audit only (E1b
	// amplification bound). Nil disables limiting (tests).
	AuditLimiter *AuditRateLimiter
	// Builder is optional. When nil, POST /v1/images/build responds 503.
	Builder ImageBuilder
	Build   BuildConfig
	// ContainerEngine is the host engine (docker|containerd). Used for
	// Server-Timing engine tags and BuildKit-absent clear errors.
	ContainerEngine string
}

// RegisterRoutes mounts every v1 route onto mux. Paths are written with the
// PathPrefix already baked in so this file is the single grep target for
// "what does v1 expose?".
func RegisterRoutes(mux *http.ServeMux, d Deps) {
	h := &handlers{deps: d}

	mux.Handle("GET "+PathPrefix+"/capacity", d.Auth(http.HandlerFunc(h.capacity)))
	mux.Handle("POST "+PathPrefix+"/admin/reconcile", withAuthOperator(d, http.HandlerFunc(h.reconcile)))
	mux.Handle("POST "+PathPrefix+"/images/build", d.Auth(http.HandlerFunc(h.clusterBuildImageWrap)))

	// POST /sandboxes is special: placement happens in the wrapper before any
	// local handler runs. The wrapper falls through to createSandbox when this
	// node is the chosen owner.
	mux.Handle("POST "+PathPrefix+"/sandboxes", d.Auth(http.HandlerFunc(h.clusterCreateWrap)))
	// GET /sandboxes is cluster-wide: clusterListWrap fans out to peers and
	// merges with the local list so the "any node accepts any request"
	// invariant covers list, not just per-sandbox routes. Single-node and
	// already-forwarded requests fall through to listSandboxes unchanged.
	mux.Handle("GET "+PathPrefix+"/sandboxes", d.Auth(http.HandlerFunc(h.clusterListWrap)))

	// Per-sandbox routes are wrapped with clusterForwardWrap so that requests
	// addressing a sandbox owned by another node are transparently forwarded
	// to that node. In single-node mode (Noop cluster) the wrapper is a
	// pass-through.
	wrap := h.clusterForwardWrap
	mux.Handle("GET "+PathPrefix+"/sandboxes/{id}", d.Auth(wrap(http.HandlerFunc(h.getSandbox))))
	mux.Handle("POST "+PathPrefix+"/sandboxes/{id}/start", d.Auth(wrap(http.HandlerFunc(h.startSandbox))))
	mux.Handle("POST "+PathPrefix+"/sandboxes/{id}/stop", d.Auth(wrap(http.HandlerFunc(h.stopSandbox))))
	// DELETE goes through clusterForwardWrap (forward to owner if not us)
	// then through clusterDestroyWrap (local destroy + DeletePlacement).
	mux.Handle("DELETE "+PathPrefix+"/sandboxes/{id}", d.Auth(wrap(http.HandlerFunc(h.clusterDestroyWrap))))
	mux.Handle("POST "+PathPrefix+"/sandboxes/{id}/resize", d.Auth(wrap(http.HandlerFunc(h.resizeSandbox))))
	mux.Handle("POST "+PathPrefix+"/sandboxes/{id}/snapshot", d.Auth(wrap(http.HandlerFunc(h.createSnapshot))))
	mux.Handle("PUT "+PathPrefix+"/sandboxes/{id}/lifecycle", d.Auth(wrap(http.HandlerFunc(h.updateLifecycle))))
	mux.Handle("POST "+PathPrefix+"/sandboxes/{id}/ports/{port}", d.Auth(wrap(http.HandlerFunc(h.exposePort))))
	mux.Handle("DELETE "+PathPrefix+"/sandboxes/{id}/ports/{port}", d.Auth(wrap(http.HandlerFunc(h.unexposePort))))
	// Custom domains (plans/custom-domains.md). Gated server-side by
	// SB_ENABLE_CUSTOM_DOMAINS — routes are always mounted (so a request
	// hits a 412 rather than a 404 when the cluster has the feature off)
	// and the service layer returns ErrCustomDomainNotSupported. Wrapped
	// with clusterForwardWrap so a request addressing a remote-owned
	// sandbox follows the same forward path as every other per-sandbox
	// route — the owner is the only node with the row to mutate.
	mux.Handle("POST "+PathPrefix+"/sandboxes/{id}/custom-domains", d.Auth(wrap(http.HandlerFunc(h.addCustomDomain))))
	mux.Handle("GET "+PathPrefix+"/sandboxes/{id}/custom-domains", d.Auth(wrap(http.HandlerFunc(h.listCustomDomains))))
	mux.Handle("DELETE "+PathPrefix+"/sandboxes/{id}/custom-domains/{hostname}", d.Auth(wrap(http.HandlerFunc(h.removeCustomDomain))))
	mux.Handle("GET "+PathPrefix+"/sandboxes/{id}/custom-domains/dns", d.Auth(wrap(http.HandlerFunc(h.customDomainDNS))))
	// Ingress DNS target — not sandbox-scoped. Operator-only: reveals cluster
	// ingress topology to managed tenants otherwise.
	mux.Handle("GET "+PathPrefix+"/ingress/dns", withAuthOperator(d, http.HandlerFunc(h.ingressDNS)))
	mux.Handle("GET "+PathPrefix+"/sandboxes/{id}/mounts", d.Auth(wrap(http.HandlerFunc(h.listMounts))))
	mux.Handle("GET "+PathPrefix+"/sandboxes/{id}/network/usage", d.Auth(wrap(http.HandlerFunc(h.getNetworkUsage))))
	mux.Handle("PATCH "+PathPrefix+"/sandboxes/{id}/network/limits", d.Auth(wrap(http.HandlerFunc(h.updateNetworkLimits))))
	// Secret audit history: local JSONL + live fan-out. NOT clusterForwardWrap —
	// owner-forward would drop pre-failover history (plans/secrets-hardening §E1b).
	mux.Handle("GET "+PathPrefix+"/sandboxes/{id}/audit", d.Auth(withAuditLimit(d, http.HandlerFunc(h.getSandboxAudit))))
	mux.Handle("POST "+PathPrefix+"/snapshots", d.Auth(http.HandlerFunc(h.registerSnapshot)))

	// Firecracker template lifecycle (plans/snapshot-clone-fast-boot.md
	// Phase 2). Templates are per-worker artifacts, so the wrapper routes
	// creates to a Firecracker-capable worker and fans per-id operations to
	// those workers when the caller hits an ingress/server node.
	mux.Handle("POST "+PathPrefix+"/templates", d.Auth(http.HandlerFunc(h.clusterCreateTemplateWrap)))
	mux.Handle("GET "+PathPrefix+"/templates", d.Auth(http.HandlerFunc(h.clusterListTemplatesWrap)))
	mux.Handle("GET "+PathPrefix+"/templates/{id}", d.Auth(h.clusterTemplateItemWrap(http.HandlerFunc(h.getTemplate))))
	mux.Handle("DELETE "+PathPrefix+"/templates/{id}", d.Auth(h.clusterTemplateItemWrap(http.HandlerFunc(h.deleteTemplate))))
	// Operator-triggered snapshot rebuild (Phase 6 follow-up). Idempotent
	// under concurrent retry — see RequestTemplateRebuild for the CAS gate.
	mux.Handle("POST "+PathPrefix+"/templates/{id}/rebuild", d.Auth(h.clusterTemplateItemWrap(http.HandlerFunc(h.rebuildTemplate))))

	// WASM module catalogue (plans/wasm-runtime.md). Per-host like templates.
	mux.Handle("POST "+PathPrefix+"/wasm-modules", d.Auth(http.HandlerFunc(h.createWasmModule)))
	mux.Handle("POST "+PathPrefix+"/wasm-modules/push", d.Auth(http.HandlerFunc(h.pushWasmModule)))
	mux.Handle("GET "+PathPrefix+"/wasm-modules", d.Auth(http.HandlerFunc(h.listWasmModules)))
	mux.Handle("GET "+PathPrefix+"/wasm-modules/{id}", d.Auth(http.HandlerFunc(h.getWasmModule)))
	mux.Handle("DELETE "+PathPrefix+"/wasm-modules/{id}", d.Auth(http.HandlerFunc(h.deleteWasmModule)))

	// JS/TS bundle catalogue (plans/isolate-runtime.md §8) — the isolate
	// runtime's "no image, no registry" upload path. Owner-scoped; per-host.
	// EXPERIMENTAL until the §10.1 demand checkpoint.
	mux.Handle("POST "+PathPrefix+"/js-bundles", d.Auth(http.HandlerFunc(h.createJSBundle)))
	mux.Handle("GET "+PathPrefix+"/js-bundles", d.Auth(http.HandlerFunc(h.listJSBundles)))
	mux.Handle("GET "+PathPrefix+"/js-bundles/{id}", d.Auth(http.HandlerFunc(h.getJSBundle)))
	mux.Handle("DELETE "+PathPrefix+"/js-bundles/{id}", d.Auth(http.HandlerFunc(h.deleteJSBundle)))

	// Explicit session routes are syntactic sugar for the toolbox proxy:
	// /v1/sandboxes/{id}/sessions/... → toolbox /sessions/...
	mux.Handle(PathPrefix+"/sandboxes/{id}/sessions", d.Auth(wrap(http.HandlerFunc(h.sessionsProxy))))
	mux.Handle(PathPrefix+"/sandboxes/{id}/sessions/{path...}", d.Auth(wrap(http.HandlerFunc(h.sessionsProxy))))
	mux.Handle(PathPrefix+"/sandboxes/{id}/toolbox", d.Auth(wrap(http.HandlerFunc(h.toolboxProxy))))
	mux.Handle(PathPrefix+"/sandboxes/{id}/toolbox/{path...}", d.Auth(wrap(http.HandlerFunc(h.toolboxProxy))))

	// Cluster observability + admission controls + peer internals: operator /
	// fleet-PAT only. Managed tenant tokens must not drain nodes, apply Raft
	// commands, or read fleet topology (P0). Peer HTTP uses SB_PAT_TOKEN.
	op := func(next http.Handler) http.Handler { return withAuthOperator(d, next) }
	mux.Handle("GET "+PathPrefix+"/cluster/members", op(http.HandlerFunc(h.clusterMembers)))
	mux.Handle("DELETE "+PathPrefix+"/cluster/members/{id}", op(http.HandlerFunc(h.clusterRemoveMember)))
	mux.Handle("GET "+PathPrefix+"/cluster/leader", op(http.HandlerFunc(h.clusterLeader)))
	mux.Handle("GET "+PathPrefix+"/cluster/placements/{id}", op(http.HandlerFunc(h.clusterPlacement)))
	mux.Handle("GET "+PathPrefix+"/cluster/sandbox-index", op(http.HandlerFunc(h.clusterSandboxIndex)))
	mux.Handle("GET "+PathPrefix+"/cluster/ingress-route/{id}", op(http.HandlerFunc(h.clusterIngressRoute)))
	mux.Handle("POST "+PathPrefix+"/cluster/nodes/{id}/drain", op(http.HandlerFunc(h.clusterDrainNode)))
	mux.Handle("POST "+PathPrefix+"/cluster/nodes/{id}/uncordon", op(http.HandlerFunc(h.clusterUncordonNode)))
	mux.Handle("POST "+cluster.PublicWasmMigratePath, op(http.HandlerFunc(h.clusterWasmMigrate)))
	mux.Handle("GET "+cluster.PublicInternalWasmMigratePath+"{id}/export", op(http.HandlerFunc(h.clusterInternalWasmMigrateExport)))
	mux.Handle("PUT "+cluster.PublicInternalWasmMigratePath+"{id}/import", op(http.HandlerFunc(h.clusterInternalWasmMigrateImport)))
	mux.Handle("POST "+PathPrefix+"/cluster/orphans/{id}/reclaim-local", op(http.HandlerFunc(h.clusterReclaimOrphanLocal)))
	mux.Handle("DELETE "+PathPrefix+"/cluster/orphans/{id}", op(http.HandlerFunc(h.clusterDeleteOrphan)))
	mux.Handle("POST "+cluster.PublicInternalApplyPath, op(http.HandlerFunc(h.clusterInternalApply)))
	mux.Handle("GET "+cluster.PublicInternalPlacementPath+"{id}", op(http.HandlerFunc(h.clusterInternalPlacement)))
	mux.Handle("GET "+cluster.PublicInternalPlacementByNamePath+"{name}", op(http.HandlerFunc(h.clusterInternalPlacementByName)))
	mux.Handle("GET "+cluster.PublicInternalPlacementsPath, op(http.HandlerFunc(h.clusterInternalPlacements)))
	mux.Handle("POST "+cluster.PublicInternalPlacementsQueryPath, op(http.HandlerFunc(h.clusterInternalPlacementsQuery)))
	mux.Handle("POST "+cluster.PublicInternalPlacementsPagePath, op(http.HandlerFunc(h.clusterInternalPlacementsPage)))
	mux.Handle("GET "+cluster.PublicInternalRecoveryPath+"{ref}", op(http.HandlerFunc(h.clusterInternalRecoveryGet)))
	mux.Handle("POST "+cluster.PublicInternalSelectPlacementPath, op(http.HandlerFunc(h.clusterInternalSelectPlacement)))
	mux.Handle("GET "+cluster.PublicInternalVolumePath, op(http.HandlerFunc(h.clusterInternalVolume)))
	mux.Handle("GET "+cluster.PublicInternalDrainStatePath+"{id}", op(http.HandlerFunc(h.clusterInternalDrainState)))
	mux.Handle("POST "+cluster.PublicInternalSecretPath, op(http.HandlerFunc(h.clusterInternalSecretPut)))
	mux.Handle("DELETE "+cluster.PublicInternalSecretPath+"/{sandboxID}", op(http.HandlerFunc(h.clusterInternalSecretDelete)))
	mux.Handle("GET "+cluster.PublicInternalSandboxAuditPath+"{id}/audit", op(http.HandlerFunc(h.clusterInternalSandboxAudit)))
	mux.Handle("GET "+cluster.PublicInternalSandboxAuditPath+"{id}/meta", op(http.HandlerFunc(h.clusterInternalSandboxMeta)))
}

func withAuditLimit(d Deps, next http.Handler) http.Handler {
	if d.AuditLimiter == nil {
		return next
	}
	return d.AuditLimiter.Middleware(next)
}
