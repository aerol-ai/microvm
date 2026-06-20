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
	// Builder is optional. When nil, POST /v1/images/build responds 503.
	Builder ImageBuilder
	Build   BuildConfig
}

// RegisterRoutes mounts every v1 route onto mux. Paths are written with the
// PathPrefix already baked in so this file is the single grep target for
// "what does v1 expose?".
func RegisterRoutes(mux *http.ServeMux, d Deps) {
	h := &handlers{deps: d}

	mux.Handle("GET "+PathPrefix+"/capacity", d.Auth(http.HandlerFunc(h.capacity)))
	mux.Handle("POST "+PathPrefix+"/admin/reconcile", d.Auth(http.HandlerFunc(h.reconcile)))
	mux.Handle("POST "+PathPrefix+"/images/build", d.Auth(http.HandlerFunc(h.buildImage)))

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
	// Ingress DNS target — not sandbox-scoped, so no clusterForwardWrap
	// (any node can answer from its own gossip view). Auth still required:
	// the response reveals cluster ingress topology.
	mux.Handle("GET "+PathPrefix+"/ingress/dns", d.Auth(http.HandlerFunc(h.ingressDNS)))
	mux.Handle("GET "+PathPrefix+"/sandboxes/{id}/mounts", d.Auth(wrap(http.HandlerFunc(h.listMounts))))
	mux.Handle("GET "+PathPrefix+"/sandboxes/{id}/network/usage", d.Auth(wrap(http.HandlerFunc(h.getNetworkUsage))))
	mux.Handle("PATCH "+PathPrefix+"/sandboxes/{id}/network/limits", d.Auth(wrap(http.HandlerFunc(h.updateNetworkLimits))))
	mux.Handle("POST "+PathPrefix+"/snapshots", d.Auth(http.HandlerFunc(h.registerSnapshot)))

	// Firecracker template lifecycle (plans/snapshot-clone-fast-boot.md
	// Phase 2). No clusterForwardWrap — templates are per-host artifacts;
	// cross-node placement awareness is Phase 6 territory.
	mux.Handle("POST "+PathPrefix+"/templates", d.Auth(http.HandlerFunc(h.createTemplate)))
	mux.Handle("GET "+PathPrefix+"/templates", d.Auth(http.HandlerFunc(h.listTemplates)))
	mux.Handle("GET "+PathPrefix+"/templates/{id}", d.Auth(http.HandlerFunc(h.getTemplate)))
	mux.Handle("DELETE "+PathPrefix+"/templates/{id}", d.Auth(http.HandlerFunc(h.deleteTemplate)))
	// Operator-triggered snapshot rebuild (Phase 6 follow-up). Idempotent
	// under concurrent retry — see RequestTemplateRebuild for the CAS
	// gate. No clusterForwardWrap: templates are per-host artifacts and
	// a rebuild only makes sense on the node that owns the rootfs.
	mux.Handle("POST "+PathPrefix+"/templates/{id}/rebuild", d.Auth(http.HandlerFunc(h.rebuildTemplate)))

	// WASM module catalogue (plans/wasm-runtime.md). Per-host like templates.
	mux.Handle("POST "+PathPrefix+"/wasm-modules", d.Auth(http.HandlerFunc(h.createWasmModule)))
	mux.Handle("POST "+PathPrefix+"/wasm-modules/push", d.Auth(http.HandlerFunc(h.pushWasmModule)))
	mux.Handle("GET "+PathPrefix+"/wasm-modules", d.Auth(http.HandlerFunc(h.listWasmModules)))
	mux.Handle("GET "+PathPrefix+"/wasm-modules/{id}", d.Auth(http.HandlerFunc(h.getWasmModule)))
	mux.Handle("DELETE "+PathPrefix+"/wasm-modules/{id}", d.Auth(http.HandlerFunc(h.deleteWasmModule)))

	// Explicit session routes are syntactic sugar for the toolbox proxy:
	// /v1/sandboxes/{id}/sessions/... → toolbox /sessions/...
	mux.Handle(PathPrefix+"/sandboxes/{id}/sessions", d.Auth(wrap(http.HandlerFunc(h.sessionsProxy))))
	mux.Handle(PathPrefix+"/sandboxes/{id}/sessions/{path...}", d.Auth(wrap(http.HandlerFunc(h.sessionsProxy))))
	mux.Handle(PathPrefix+"/sandboxes/{id}/toolbox", d.Auth(wrap(http.HandlerFunc(h.toolboxProxy))))
	mux.Handle(PathPrefix+"/sandboxes/{id}/toolbox/{path...}", d.Auth(wrap(http.HandlerFunc(h.toolboxProxy))))

	// Cluster observability (Phase 1). Read-only; safe to expose alongside
	// the v1 surface without violating the v1 freeze (these are net-new
	// paths, not changes to existing wire format).
	mux.Handle("GET "+PathPrefix+"/cluster/members", d.Auth(http.HandlerFunc(h.clusterMembers)))
	mux.Handle("DELETE "+PathPrefix+"/cluster/members/{id}", d.Auth(http.HandlerFunc(h.clusterRemoveMember)))
	mux.Handle("GET "+PathPrefix+"/cluster/leader", d.Auth(http.HandlerFunc(h.clusterLeader)))
	mux.Handle("GET "+PathPrefix+"/cluster/placements/{id}", d.Auth(http.HandlerFunc(h.clusterPlacement)))
	mux.Handle("GET "+PathPrefix+"/cluster/sandbox-index", d.Auth(http.HandlerFunc(h.clusterSandboxIndex)))
	mux.Handle("GET "+PathPrefix+"/cluster/ingress-route/{id}", d.Auth(http.HandlerFunc(h.clusterIngressRoute)))
	// Drain / uncordon are operator admission controls — they don't move
	// existing work, they just stop SelectPlacement from sending new sandboxes
	// to the node. PATCH-style verbs would also fit but POST keeps the surface
	// consistent with /admin/reconcile (also a leader-side write side effect).
	mux.Handle("POST "+PathPrefix+"/cluster/nodes/{id}/drain", d.Auth(http.HandlerFunc(h.clusterDrainNode)))
	mux.Handle("POST "+PathPrefix+"/cluster/nodes/{id}/uncordon", d.Auth(http.HandlerFunc(h.clusterUncordonNode)))
	mux.Handle("POST "+cluster.PublicWasmMigratePath, d.Auth(http.HandlerFunc(h.clusterWasmMigrate)))
	mux.Handle("GET "+cluster.PublicInternalWasmMigratePath+"{id}/export", d.Auth(http.HandlerFunc(h.clusterInternalWasmMigrateExport)))
	mux.Handle("PUT "+cluster.PublicInternalWasmMigratePath+"{id}/import", d.Auth(http.HandlerFunc(h.clusterInternalWasmMigrateImport)))
	mux.Handle("POST "+PathPrefix+"/cluster/orphans/{id}/reclaim-local", d.Auth(http.HandlerFunc(h.clusterReclaimOrphanLocal)))
	mux.Handle("DELETE "+PathPrefix+"/cluster/orphans/{id}", d.Auth(http.HandlerFunc(h.clusterDeleteOrphan)))
	// Internal endpoint: receives leader-forwarded raft commands from peer
	// nodes that aren't the current leader. Auth-gated by the same PAT as
	// every other route — see clusterInternalApply for the leadership-shift
	// retry contract.
	mux.Handle("POST "+cluster.PublicInternalApplyPath, d.Auth(http.HandlerFunc(h.clusterInternalApply)))
	mux.Handle("GET "+cluster.PublicInternalPlacementPath+"{id}", d.Auth(http.HandlerFunc(h.clusterInternalPlacement)))
	mux.Handle("GET "+cluster.PublicInternalPlacementByNamePath+"{name}", d.Auth(http.HandlerFunc(h.clusterInternalPlacementByName)))
	mux.Handle("GET "+cluster.PublicInternalPlacementsPath, d.Auth(http.HandlerFunc(h.clusterInternalPlacements)))
	mux.Handle("POST "+cluster.PublicInternalPlacementsQueryPath, d.Auth(http.HandlerFunc(h.clusterInternalPlacementsQuery)))
	mux.Handle("POST "+cluster.PublicInternalPlacementsPagePath, d.Auth(http.HandlerFunc(h.clusterInternalPlacementsPage)))
	mux.Handle("PUT "+cluster.PublicInternalRecoveryPath+"{ref}", d.Auth(http.HandlerFunc(h.clusterInternalRecoveryPut)))
	mux.Handle("GET "+cluster.PublicInternalRecoveryPath+"{ref}", d.Auth(http.HandlerFunc(h.clusterInternalRecoveryGet)))
	mux.Handle("POST "+cluster.PublicInternalSelectPlacementPath, d.Auth(http.HandlerFunc(h.clusterInternalSelectPlacement)))
	mux.Handle("GET "+cluster.PublicInternalVolumePath, d.Auth(http.HandlerFunc(h.clusterInternalVolume)))
	mux.Handle("GET "+cluster.PublicInternalDrainStatePath+"{id}", d.Auth(http.HandlerFunc(h.clusterInternalDrainState)))
}
