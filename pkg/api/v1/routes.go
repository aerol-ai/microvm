package v1

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// Deps holds the shared dependencies a version package needs from the
// top-level pkg/api router. Keeping these explicit (rather than reaching into
// pkg/api globals) lets future version packages coexist without coupling.
type Deps struct {
	Service *service.Service
	Logger  *slog.Logger
	// Auth authenticates a request: it attaches the caller's Access or
	// refuses with 401. The middleware lives in pkg/api so all versions share
	// one auth contract. Routes never call it directly: Route composes it
	// with the permission check.
	Auth func(http.Handler) http.Handler
	// Audit is the seam task T5 fills with kind "api" records
	// (apihttp.AuditHook). nil records nothing.
	Audit apihttp.AuditHook
	// AuditLimiter rate-limits GET /v1/sandboxes/{id}/audit only (E1b
	// amplification bound). Nil disables limiting (tests).
	AuditLimiter *AuditRateLimiter
	// ContainerEngine is the host engine (docker|containerd). Used for
	// Server-Timing engine tags and BuildKit-absent clear errors.
	ContainerEngine string
}

// Route returns h behind authenticate → authorize(perm) → audit seam
// (plans/identity-and-access.md §5.3). Every v1 route is registered through
// it; the registry test fails on one that is not.
func (d Deps) Route(perm controlplane.Permission, h http.Handler) http.Handler {
	return d.router().Route(perm, h)
}

// RouteBy is Route for a route whose permission depends on the request.
func (d Deps) RouteBy(tag string, classify func(*http.Request) controlplane.Permission, h http.Handler) http.Handler {
	return d.router().RouteBy(tag, classify, h)
}

func (d Deps) router() apihttp.Router {
	return apihttp.Router{Authenticate: d.Auth, Deny: writeForbidden, Audit: d.Audit}
}

// writeForbidden is the v1 403. A PAT request on a cluster-internal route
// without a peer certificate keeps the exact answer withInternalMTLS gave
// before T2 (L8): the operator holds every permission but cluster.internal,
// and what it lacks is the node's mTLS proof.
func writeForbidden(w http.ResponseWriter, r *http.Request, d apihttp.Denial) {
	if d.Permission == controlplane.PermClusterInternal && d.Access.Principal.Kind == controlplane.PrincipalOperator {
		if _, err := cluster.AuthenticatedPeerNodeID(r); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
	}
	apihttp.WriteForbidden(w, r, d)
}

// Shorthands for the permission table below.
const (
	permRead     = controlplane.PermSandboxRead
	permWrite    = controlplane.PermSandboxWrite
	permExec     = controlplane.PermSandboxExec
	permFleet    = controlplane.PermFleetAdmin
	permInternal = controlplane.PermClusterInternal
)

// RegisterRoutes mounts every v1 route onto mux. Paths are written with the
// PathPrefix already baked in so this file is the single grep target for
// "what does v1 expose, and which permission does each route need?".
func RegisterRoutes(mux apihttp.Mux, d Deps) {
	h := &handlers{deps: d}
	// readOrSecrets: a sandbox read needs sandbox.secrets when it asks for
	// the env (include_env), sandbox.read otherwise.
	readOrSecrets := func(next http.Handler) http.Handler {
		return d.RouteBy(apihttp.ReadOrSecretsTag, apihttp.ReadOrSecrets, next)
	}

	// Who the caller is (identity-and-access §5.2): needs only a valid
	// principal, describes only the caller, never forwarded.
	mux.Handle("GET "+PathPrefix+"/whoami", d.Route(controlplane.PermAuthenticated, http.HandlerFunc(h.whoami)))
	mux.Handle("GET "+PathPrefix+"/capacity", d.Route(permRead, http.HandlerFunc(h.capacity)))
	mux.Handle("POST "+PathPrefix+"/admin/reconcile", d.Route(permFleet, http.HandlerFunc(h.reconcile)))
	mux.Handle("POST "+PathPrefix+"/images/build", d.Route(permWrite, http.HandlerFunc(h.clusterBuildImageWrap)))

	// POST /sandboxes is special: placement happens in the wrapper before any
	// local handler runs. The wrapper falls through to createSandbox when this
	// node is the chosen owner.
	mux.Handle("POST "+PathPrefix+"/sandboxes", d.Route(permWrite, http.HandlerFunc(h.clusterCreateWrap)))
	// GET /sandboxes is cluster-wide: clusterListWrap fans out to peers and
	// merges with the local list so the "any node accepts any request"
	// invariant covers list, not just per-sandbox routes. Single-node and
	// already-forwarded requests fall through to listSandboxes unchanged.
	mux.Handle("GET "+PathPrefix+"/sandboxes", readOrSecrets(http.HandlerFunc(h.clusterListWrap)))

	// Per-sandbox routes are wrapped with clusterForwardWrap so that requests
	// addressing a sandbox owned by another node are transparently forwarded
	// to that node. In single-node mode (Noop cluster) the wrapper is a
	// pass-through. The permission is checked on the edge before forwarding,
	// and again on the owner, which mounts the same handler.
	wrap := h.clusterForwardWrap
	mux.Handle("GET "+PathPrefix+"/sandboxes/{id}", readOrSecrets(wrap(http.HandlerFunc(h.getSandbox))))
	mux.Handle("POST "+PathPrefix+"/sandboxes/{id}/start", d.Route(permWrite, wrap(http.HandlerFunc(h.startSandbox))))
	mux.Handle("POST "+PathPrefix+"/sandboxes/{id}/stop", d.Route(permWrite, wrap(http.HandlerFunc(h.stopSandbox))))
	// DELETE goes through clusterForwardWrap (forward to owner if not us)
	// then through clusterDestroyWrap (local destroy + DeletePlacement).
	mux.Handle("DELETE "+PathPrefix+"/sandboxes/{id}", d.Route(permWrite, wrap(http.HandlerFunc(h.clusterDestroyWrap))))
	mux.Handle("POST "+PathPrefix+"/sandboxes/{id}/resize", d.Route(permWrite, wrap(http.HandlerFunc(h.resizeSandbox))))
	mux.Handle("POST "+PathPrefix+"/sandboxes/{id}/snapshot", d.Route(permWrite, wrap(http.HandlerFunc(h.createSnapshot))))
	mux.Handle("PUT "+PathPrefix+"/sandboxes/{id}/lifecycle", d.Route(permWrite, wrap(http.HandlerFunc(h.updateLifecycle))))
	mux.Handle("POST "+PathPrefix+"/sandboxes/{id}/ports/{port}", d.Route(permWrite, wrap(http.HandlerFunc(h.exposePort))))
	mux.Handle("DELETE "+PathPrefix+"/sandboxes/{id}/ports/{port}", d.Route(permWrite, wrap(http.HandlerFunc(h.unexposePort))))
	// Custom domains (plans/custom-domains.md). Gated server-side by
	// SB_ENABLE_CUSTOM_DOMAINS — routes are always mounted (so a request
	// hits a 412 rather than a 404 when the cluster has the feature off)
	// and the service layer returns ErrCustomDomainNotSupported. Wrapped
	// with clusterForwardWrap so a request addressing a remote-owned
	// sandbox follows the same forward path as every other per-sandbox
	// route — the owner is the only node with the row to mutate.
	mux.Handle("POST "+PathPrefix+"/sandboxes/{id}/custom-domains", d.Route(permWrite, wrap(http.HandlerFunc(h.addCustomDomain))))
	mux.Handle("GET "+PathPrefix+"/sandboxes/{id}/custom-domains", d.Route(permRead, wrap(http.HandlerFunc(h.listCustomDomains))))
	mux.Handle("DELETE "+PathPrefix+"/sandboxes/{id}/custom-domains/{hostname}", d.Route(permWrite, wrap(http.HandlerFunc(h.removeCustomDomain))))
	mux.Handle("GET "+PathPrefix+"/sandboxes/{id}/custom-domains/dns", d.Route(permRead, wrap(http.HandlerFunc(h.customDomainDNS))))
	// Ingress DNS target — not sandbox-scoped. Fleet-admin only: reveals
	// cluster ingress topology to managed tenants otherwise.
	mux.Handle("GET "+PathPrefix+"/ingress/dns", d.Route(permFleet, http.HandlerFunc(h.ingressDNS)))
	mux.Handle("GET "+PathPrefix+"/sandboxes/{id}/mounts", d.Route(permRead, wrap(http.HandlerFunc(h.listMounts))))
	mux.Handle("GET "+PathPrefix+"/sandboxes/{id}/network/usage", d.Route(permRead, wrap(http.HandlerFunc(h.getNetworkUsage))))
	mux.Handle("PATCH "+PathPrefix+"/sandboxes/{id}/network/limits", d.Route(permWrite, wrap(http.HandlerFunc(h.updateNetworkLimits))))
	// Live egress policy (plans/egress-domain-filtering.md §5.8): forwarded
	// to the owner, the only node that can apply it to the running sandbox.
	mux.Handle("PUT "+PathPrefix+"/sandboxes/{id}/network/policy", d.Route(permWrite, wrap(http.HandlerFunc(h.updateNetworkPolicy))))
	// Learn-mode recording (P2-7): the owner holds it, so it is forwarded.
	mux.Handle("GET "+PathPrefix+"/sandboxes/{id}/network/learned", d.Route(permRead, wrap(http.HandlerFunc(h.getNetworkLearned))))
	// Named egress profiles (D21). Not sandbox-scoped, so no owner
	// forwarding; in a cluster the service writes them through Raft.
	mux.Handle("PUT "+PathPrefix+"/egress-profiles/{name}", d.Route(permWrite, http.HandlerFunc(h.putEgressProfile)))
	mux.Handle("GET "+PathPrefix+"/egress-profiles/{name}", d.Route(permRead, http.HandlerFunc(h.getEgressProfile)))
	mux.Handle("DELETE "+PathPrefix+"/egress-profiles/{name}", d.Route(permWrite, http.HandlerFunc(h.deleteEgressProfile)))
	mux.Handle("GET "+PathPrefix+"/egress-profiles", d.Route(permRead, http.HandlerFunc(h.listEgressProfiles)))
	// Pure policy evaluation: no sandbox, no state change, so a read.
	mux.Handle("POST "+PathPrefix+"/network/policy/check", d.Route(permRead, http.HandlerFunc(h.checkNetworkPolicy)))
	// Secret audit history: local JSONL + live fan-out. NOT clusterForwardWrap —
	// owner-forward would drop pre-failover history (plans/secrets-hardening §E1b).
	mux.Handle("GET "+PathPrefix+"/sandboxes/{id}/audit", d.Route(controlplane.PermAuditRead, withAuditLimit(d, http.HandlerFunc(h.getSandboxAudit))))
	// On-demand full-chain verification of this node's audit log. O(file),
	// one at a time per node: page reads verify only the records they
	// return, this is where the whole chain is proven.
	mux.Handle("POST "+PathPrefix+"/audit/verify", d.Route(controlplane.PermAuditVerify, http.HandlerFunc(h.verifySandboxAudit)))
	mux.Handle("POST "+PathPrefix+"/snapshots", d.Route(permWrite, http.HandlerFunc(h.registerSnapshot)))
	// Snapshot catalogue read/delete (I group). The list is node-local and
	// store-paged; get/delete-by-id are wrapped so a cluster request reaches
	// the node holding the image (B6). A v1 snapshot id is its name.
	mux.Handle("GET "+PathPrefix+"/snapshots", d.Route(permRead, http.HandlerFunc(h.listSnapshots)))
	mux.Handle("GET "+PathPrefix+"/snapshots/{id}", d.Route(permRead, h.snapshotForwardWrap(http.HandlerFunc(h.getSnapshot))))
	mux.Handle("DELETE "+PathPrefix+"/snapshots/{id}", d.Route(permWrite, h.snapshotForwardWrap(http.HandlerFunc(h.deleteSnapshot))))

	// Firecracker template lifecycle (plans/snapshot-clone-fast-boot.md
	// Phase 2). Templates are global operator-managed, per-worker artifacts; no
	// tenant owner model exists, so every template route is fleet.admin. The
	// wrapper routes creates to one Firecracker worker, item operations
	// through the leader's all-status worker catalogue, and cluster-wide
	// lists through a coalescing leader aggregate.
	mux.Handle("POST "+PathPrefix+"/templates", d.Route(permFleet, http.HandlerFunc(h.clusterCreateTemplateWrap)))
	mux.Handle("GET "+PathPrefix+"/templates", d.Route(permFleet, http.HandlerFunc(h.clusterListTemplatesWrap)))
	mux.Handle("GET "+PathPrefix+"/templates/{id}", d.Route(permFleet, h.clusterTemplateItemWrap(http.HandlerFunc(h.getTemplate))))
	mux.Handle("DELETE "+PathPrefix+"/templates/{id}", d.Route(permFleet, h.clusterTemplateItemWrap(http.HandlerFunc(h.deleteTemplate))))
	// Operator-triggered snapshot rebuild (Phase 6 follow-up). Idempotent
	// under concurrent retry — see RequestTemplateRebuild for the CAS gate.
	mux.Handle("POST "+PathPrefix+"/templates/{id}/rebuild", d.Route(permFleet, h.clusterTemplateItemWrap(http.HandlerFunc(h.rebuildTemplate))))

	// WASM module catalogue (plans/wasm-runtime.md). Per-host like templates.
	mux.Handle("POST "+PathPrefix+"/wasm-modules", d.Route(permWrite, http.HandlerFunc(h.createWasmModule)))
	mux.Handle("POST "+PathPrefix+"/wasm-modules/push", d.Route(permWrite, http.HandlerFunc(h.pushWasmModule)))
	mux.Handle("GET "+PathPrefix+"/wasm-modules", d.Route(permRead, http.HandlerFunc(h.listWasmModules)))
	mux.Handle("GET "+PathPrefix+"/wasm-modules/{id}", d.Route(permRead, http.HandlerFunc(h.getWasmModule)))
	mux.Handle("DELETE "+PathPrefix+"/wasm-modules/{id}", d.Route(permWrite, http.HandlerFunc(h.deleteWasmModule)))

	// JS/TS bundle catalogue (plans/isolate-runtime.md §8) — the isolate
	// runtime's "no image, no registry" upload path. Owner-scoped; per-host.
	// EXPERIMENTAL until the §10.1 demand checkpoint.
	mux.Handle("POST "+PathPrefix+"/js-bundles", d.Route(permWrite, http.HandlerFunc(h.createJSBundle)))
	mux.Handle("GET "+PathPrefix+"/js-bundles", d.Route(permRead, http.HandlerFunc(h.clusterListJSBundlesWrap)))
	mux.Handle("GET "+PathPrefix+"/js-bundles/{id}", d.Route(permRead, http.HandlerFunc(h.getJSBundle)))
	mux.Handle("DELETE "+PathPrefix+"/js-bundles/{id}", d.Route(permWrite, http.HandlerFunc(h.deleteJSBundle)))

	// Explicit session routes are syntactic sugar for the toolbox proxy:
	// /v1/sandboxes/{id}/sessions/... → toolbox /sessions/...
	// The whole toolbox proxy is one permission, sandbox.exec, whatever the
	// sub-path: file reads included, since files can hold secrets.
	mux.Handle(PathPrefix+"/sandboxes/{id}/sessions", d.Route(permExec, wrap(http.HandlerFunc(h.sessionsProxy))))
	mux.Handle(PathPrefix+"/sandboxes/{id}/sessions/{path...}", d.Route(permExec, wrap(http.HandlerFunc(h.sessionsProxy))))
	mux.Handle(PathPrefix+"/sandboxes/{id}/toolbox", d.Route(permExec, wrap(http.HandlerFunc(h.toolboxProxy))))
	mux.Handle(PathPrefix+"/sandboxes/{id}/toolbox/{path...}", d.Route(permExec, wrap(http.HandlerFunc(h.toolboxProxy))))

	// Cluster observability + admission controls: fleet.admin. Managed
	// tenant tokens must not drain nodes or read fleet topology (P0).
	// Peer internals are cluster.internal, which only a node: principal
	// holds (a peer's SB_PAT_TOKEN over mTLS, on its own behalf), and
	// withInternalMTLS still requires that peer to be a live member.
	op := func(next http.Handler) http.Handler { return d.Route(permFleet, next) }
	internalOp := func(next http.Handler) http.Handler {
		return d.Route(permInternal, withInternalMTLS(d, next))
	}
	mux.Handle("GET "+PathPrefix+"/cluster/members", op(http.HandlerFunc(h.clusterMembers)))
	mux.Handle("DELETE "+PathPrefix+"/cluster/members/{id}", op(http.HandlerFunc(h.clusterRemoveMember)))
	mux.Handle("GET "+PathPrefix+"/cluster/leader", op(http.HandlerFunc(h.clusterLeader)))
	mux.Handle("GET "+PathPrefix+"/cluster/placements/{id}", op(http.HandlerFunc(h.clusterPlacement)))
	// Fleet-admin only, like every other /cluster route: the recipient set
	// names which nodes hold a tenant's sealed secret, which is fleet
	// topology a tenant token must not read.
	// clusterForwardWrap, not bare op(): SecretHoldersForSandbox reads the
	// LOCAL store, and on a cluster the sandbox row lives on the owner. Served
	// by any other node the read answered 404 "sandbox not found" for a
	// sandbox that plainly existed — which is what the live S2 run hit, on
	// every HA case at once, because they all wait on this endpoint. The
	// wrapper is a pass-through under a Noop cluster, so single-node is
	// unaffected.
	mux.Handle("GET "+PathPrefix+"/cluster/sandboxes/{id}/secret-holders", op(wrap(http.HandlerFunc(h.clusterSecretHolders))))
	mux.Handle("GET "+PathPrefix+"/cluster/sandbox-index", op(http.HandlerFunc(h.clusterSandboxIndex)))
	mux.Handle("GET "+PathPrefix+"/cluster/ingress-route/{id}", op(http.HandlerFunc(h.clusterIngressRoute)))
	mux.Handle("POST "+PathPrefix+"/cluster/nodes/{id}/drain", op(http.HandlerFunc(h.clusterDrainNode)))
	mux.Handle("POST "+PathPrefix+"/cluster/nodes/{id}/uncordon", op(http.HandlerFunc(h.clusterUncordonNode)))
	mux.Handle("POST "+PathPrefix+"/cluster/nodes/{id}/storage-retired", op(http.HandlerFunc(h.clusterRetireNodeStorage)))
	mux.Handle("DELETE "+PathPrefix+"/cluster/nodes/{id}/storage-retired", op(http.HandlerFunc(h.clusterRevokeNodeStorageRetirement)))
	mux.Handle("GET "+PathPrefix+"/cluster/storage-retirements", op(http.HandlerFunc(h.clusterListNodeStorageRetirements)))
	mux.Handle("POST "+cluster.PublicWasmMigratePath, op(http.HandlerFunc(h.clusterWasmMigrate)))
	mux.Handle("GET "+cluster.PublicInternalWasmMigratePath+"{id}/export", internalOp(http.HandlerFunc(h.clusterInternalWasmMigrateExport)))
	mux.Handle("PUT "+cluster.PublicInternalWasmMigratePath+"{id}/import", internalOp(http.HandlerFunc(h.clusterInternalWasmMigrateImport)))
	mux.Handle("POST "+PathPrefix+"/cluster/orphans/{id}/reclaim-local", op(http.HandlerFunc(h.clusterReclaimOrphanLocal)))
	mux.Handle("DELETE "+PathPrefix+"/cluster/orphans/{id}", op(http.HandlerFunc(h.clusterDeleteOrphan)))
	mux.Handle("POST "+cluster.PublicInternalApplyPath, internalOp(http.HandlerFunc(h.clusterInternalApply)))
	mux.Handle("GET "+cluster.PublicInternalPlacementPath+"{id}", internalOp(http.HandlerFunc(h.clusterInternalPlacement)))
	mux.Handle("GET "+cluster.PublicInternalPlacementByNamePath+"{name}", internalOp(http.HandlerFunc(h.clusterInternalPlacementByName)))
	mux.Handle("GET "+cluster.PublicInternalPlacementsPath, internalOp(http.HandlerFunc(h.clusterInternalPlacements)))
	mux.Handle("POST "+cluster.PublicInternalPlacementsQueryPath, internalOp(http.HandlerFunc(h.clusterInternalPlacementsQuery)))
	mux.Handle("POST "+cluster.PublicInternalPlacementsPagePath, internalOp(http.HandlerFunc(h.clusterInternalPlacementsPage)))
	mux.Handle("GET "+cluster.PublicInternalPlacementChangesPath, internalOp(http.HandlerFunc(h.clusterInternalPlacementChanges)))
	mux.Handle("POST "+cluster.PublicInternalPlacementsByIDsPath, internalOp(http.HandlerFunc(h.clusterInternalPlacementsByIDs)))
	mux.Handle("POST "+cluster.PublicInternalOwnedRecoveryPath, internalOp(http.HandlerFunc(h.clusterInternalOwnedRecovery)))
	mux.Handle("POST "+cluster.PublicInternalReassignStuckPath, internalOp(http.HandlerFunc(h.clusterInternalReassignStuck)))
	mux.Handle("GET "+cluster.PublicInternalNodeStorageRetirementsPath, internalOp(http.HandlerFunc(h.clusterInternalNodeStorageRetirements)))
	mux.Handle("POST "+cluster.PublicInternalArtifactCatalogPath, internalOp(http.HandlerFunc(h.clusterInternalArtifactCatalog)))
	mux.Handle("POST "+cluster.PublicInternalArtifactCatalogEpochPath, internalOp(http.HandlerFunc(h.clusterInternalArtifactCatalogEpoch)))
	mux.Handle("POST "+cluster.PublicInternalEgressProfileWritePath, internalOp(http.HandlerFunc(h.clusterInternalEgressProfileWrite)))
	mux.Handle("POST "+cluster.PublicInternalEgressProfileReadPath, internalOp(http.HandlerFunc(h.clusterInternalEgressProfileRead)))
	mux.Handle("GET "+cluster.PublicInternalAuditACLPath+"{id}", internalOp(http.HandlerFunc(h.clusterInternalAuditACL)))
	mux.Handle("GET "+cluster.PublicInternalRecoveryPath+"{ref}", internalOp(http.HandlerFunc(h.clusterInternalRecoveryGet)))
	mux.Handle("POST "+cluster.PublicInternalSelectPlacementPath, internalOp(http.HandlerFunc(h.clusterInternalSelectPlacement)))
	mux.Handle("GET "+cluster.PublicInternalVolumePath, internalOp(http.HandlerFunc(h.clusterInternalVolume)))
	mux.Handle("GET "+cluster.PublicInternalSnapshotNodePath, internalOp(http.HandlerFunc(h.clusterInternalSnapshotNode)))
	mux.Handle("GET "+cluster.PublicInternalDrainStatePath+"{id}", internalOp(http.HandlerFunc(h.clusterInternalDrainState)))
	mux.Handle("GET "+cluster.PublicInternalDrainedNodesPath, internalOp(http.HandlerFunc(h.clusterInternalDrainedNodes)))
	mux.Handle("GET "+cluster.PublicInternalStorageObligationsPath, internalOp(http.HandlerFunc(h.clusterInternalStorageObligations)))
	mux.Handle("POST "+cluster.PublicInternalSecretPath, internalOp(http.HandlerFunc(h.clusterInternalSecretPut)))
	mux.Handle("HEAD "+cluster.PublicInternalSecretPath+"/{sandboxID}", internalOp(http.HandlerFunc(h.clusterInternalSecretHead)))
	mux.Handle("DELETE "+cluster.PublicInternalSecretPath+"/{sandboxID}", internalOp(http.HandlerFunc(h.clusterInternalSecretDelete)))
	mux.Handle("GET "+cluster.PublicInternalSandboxAuditPath+"{id}/audit", internalOp(withAuditPeerLimit(d, http.HandlerFunc(h.clusterInternalSandboxAudit))))
}

const clusterPeerNodeIDHeader = cluster.PeerNodeIDHeader

func withInternalMTLS(d Deps, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peerID, err := cluster.AuthenticatedPeerNodeID(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		if !peerMemberAlive(d, peerID) {
			cluster.RecordMTLSUnknownPeer()
			http.Error(w, "cluster peer not in membership", http.StatusForbidden)
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), clusterPeerNodeIDContextKey{}, peerID))
		next.ServeHTTP(w, r)
	})
}

// peerMemberAlive reports whether peerID is an Alive gossip member. A valid
// CA-signed certificate is not sufficient after a node has been removed from
// membership, and an unavailable membership source must fail closed.
func peerMemberAlive(d Deps, peerID string) bool {
	if d.Service == nil || peerID == "" {
		return false
	}
	c := d.Service.Cluster()
	if c == nil {
		return false
	}
	return cluster.IsLivePeer(c, peerID)
}

type clusterPeerNodeIDContextKey struct{}

func withAuditLimit(d Deps, next http.Handler) http.Handler {
	if d.AuditLimiter == nil {
		return next
	}
	return d.AuditLimiter.Middleware(next)
}

func withAuditPeerLimit(d Deps, next http.Handler) http.Handler {
	if d.AuditLimiter == nil {
		return next
	}
	return d.AuditLimiter.PeerMiddleware(next)
}
