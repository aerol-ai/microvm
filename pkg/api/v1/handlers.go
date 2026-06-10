package v1

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/models"
)

// handlers carries Deps so each handler method has access to the service,
// logger, and shared response helpers without threading them through every
// signature. Handlers are intentionally thin — wire decode → service call →
// wire encode — so the version boundary stays at this layer.
type handlers struct {
	deps Deps
}

func (h *handlers) reconcile(w http.ResponseWriter, r *http.Request) {
	if err := h.deps.Service.Reconcile(r.Context()); err != nil {
		h.deps.Logger.Warn("reconcile failed", "error", err)
		apihttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (h *handlers) capacity(w http.ResponseWriter, r *http.Request) {
	apihttp.WriteJSON(w, http.StatusOK, h.deps.Service.Capacity())
}

func (h *handlers) createSandbox(w http.ResponseWriter, r *http.Request) {
	var req models.CreateSandboxRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	response, err := h.deps.Service.CreateSandbox(r.Context(), req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			apihttp.WriteError(w, http.StatusGatewayTimeout, "sandbox create exceeded timeout")
			return
		}
		if errors.Is(err, context.Canceled) {
			// Client disconnected mid-create; 503 avoids confusing client-disconnect
			// events with validation errors in monitoring dashboards.
			apihttp.WriteError(w, http.StatusServiceUnavailable, "sandbox create cancelled")
			return
		}
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusCreated, response)
}

func (h *handlers) listSandboxes(w http.ResponseWriter, r *http.Request) {
	sandboxes, err := h.deps.Service.ListSandboxes(r.Context(), parseTagFilter(r))
	if err != nil {
		h.deps.Logger.Warn("list sandboxes failed", "error", err)
		apihttp.WriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, sandboxes)
}

// parseTagFilter pulls every query parameter of the form `tag.<key>=<value>`
// into a flat map. Multiple tag.* params AND together at the service layer.
// Anything else in the query string is ignored. This is the read-path twin of
// CreateSandboxRequest.Tags — an external control plane stamps tags at create
// time and uses the same keys here to scope its list calls. See
// plans/multi-tenancy-via-control-plane.md.
func parseTagFilter(r *http.Request) map[string]string {
	const prefix = "tag."
	q := r.URL.Query()
	var filter map[string]string
	for key, values := range q {
		if !strings.HasPrefix(key, prefix) || len(values) == 0 {
			continue
		}
		name := key[len(prefix):]
		if name == "" {
			continue
		}
		if filter == nil {
			filter = make(map[string]string, 2)
		}
		filter[name] = values[0]
	}
	return filter
}

func (h *handlers) getSandbox(w http.ResponseWriter, r *http.Request) {
	sandbox, err := h.deps.Service.GetSandbox(r.Context(), r.PathValue("id"))
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, sandbox)
}

func (h *handlers) startSandbox(w http.ResponseWriter, r *http.Request) {
	sandbox, err := h.deps.Service.StartSandbox(r.Context(), r.PathValue("id"))
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, sandbox)
}

func (h *handlers) stopSandbox(w http.ResponseWriter, r *http.Request) {
	sandbox, err := h.deps.Service.StopSandbox(r.Context(), r.PathValue("id"))
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, sandbox)
}

func (h *handlers) createSnapshot(w http.ResponseWriter, r *http.Request) {
	var req models.CreateSandboxSnapshotRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	response, err := h.deps.Service.CreateSnapshot(r.Context(), r.PathValue("id"), req)
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusCreated, response)
}

func (h *handlers) resizeSandbox(w http.ResponseWriter, r *http.Request) {
	var req models.ResizeSandboxRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	id := r.PathValue("id")
	sandbox, err := h.deps.Service.ResizeSandbox(r.Context(), id, req)
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	// FSM spec write-through now lives in Service.ResizeSandbox so Daytona and
	// E2B inherit the same contract.
	apihttp.WriteJSON(w, http.StatusOK, sandbox)
}

func (h *handlers) updateLifecycle(w http.ResponseWriter, r *http.Request) {
	var req models.UpdateLifecycleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	id := r.PathValue("id")
	sandbox, err := h.deps.Service.UpdateLifecycle(r.Context(), id, req.Lifecycle)
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	// FSM spec write-through now lives in Service.UpdateLifecycle.
	apihttp.WriteJSON(w, http.StatusOK, sandbox)
}

func (h *handlers) exposePort(w http.ResponseWriter, r *http.Request) {
	port, err := strconv.Atoi(r.PathValue("port"))
	if err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid port")
		return
	}
	// Body is optional — legacy callers POST with no body and get HTTP routing.
	// New callers send {"protocol":"tcp"} or {"protocol":"tls"} to choose a
	// caddy-l4 path. ContentLength == 0 is the unambiguous "no body" signal;
	// we intentionally don't strict-decode an empty stream so old SDKs keep
	// working unchanged.
	var req models.ExposePortRequest
	if r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
	}
	id := r.PathValue("id")
	resp, err := h.deps.Service.ExposePort(r.Context(), id, port, req.Protocol)
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	// Replicate the canonical protocol the service settled on (not the raw
	// request value) so a future failover-recreate uses the same protocol the
	// user is seeing.
	h.replicateAddExposedPort(r.Context(), id, port, cluster.ExposedPortRoute{
		Protocol:  resp.Protocol,
		HostPort:  resp.HostPort,
		PublicURL: resp.PublicURL,
	})
	apihttp.WriteJSON(w, http.StatusOK, resp)
}

func (h *handlers) unexposePort(w http.ResponseWriter, r *http.Request) {
	port, err := strconv.Atoi(r.PathValue("port"))
	if err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid port")
		return
	}
	id := r.PathValue("id")
	if err := h.deps.Service.UnexposePort(r.Context(), id, port); err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	h.replicateRemoveExposedPort(r.Context(), id, port)
	w.WriteHeader(http.StatusNoContent)
}

// addCustomDomain attaches a new operator-provided public hostname to a
// sandbox. Body shape: {"hostname":"api.acme.com","target_port":3333}.
// target_port is optional; omitting it (or sending 0) routes the hostname to
// the toolbox agent, preserving pre-v2 behavior. Status codes follow the
// custom-domain sentinels in pkg/api/apihttp.WriteStoreAwareError:
// 412 = feature disabled / IP mode; 409 = hostname owned by another sandbox,
// IRON RULE violation (tcp/tls coexistence), or target_port mismatch on
// idempotent re-add; 400 = malformed hostname / invalid target_port;
// 404 = sandbox not found.
func (h *handlers) addCustomDomain(w http.ResponseWriter, r *http.Request) {
	var req models.AddCustomDomainRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	id := r.PathValue("id")
	if err := h.deps.Service.AddCustomDomain(r.Context(), id, req.Hostname, req.TargetPort); err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	// Return the full list back so callers don't need a follow-up GET to
	// learn the canonical (lowercased, dot-trimmed) hostname or its initial
	// status. Mirrors the createSandbox response shape.
	domains, err := h.deps.Service.ListCustomDomains(r.Context(), id)
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusCreated, map[string]any{"custom_domains": domains})
}

// removeCustomDomain detaches a hostname from a sandbox. {hostname} in the
// path may be passed in any case — the service layer normalizes before
// comparing. Cross-sandbox removal is rejected with 404 (the store scopes
// the DELETE to (sandbox, hostname)).
func (h *handlers) removeCustomDomain(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	hostname := r.PathValue("hostname")
	if err := h.deps.Service.RemoveCustomDomain(r.Context(), id, hostname); err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// listCustomDomains returns the per-hostname rows attached to a sandbox.
// Same shape the create response embeds in Sandbox.CustomDomains, so an SDK
// can use one decoder for both surfaces.
func (h *handlers) listCustomDomains(w http.ResponseWriter, r *http.Request) {
	domains, err := h.deps.Service.ListCustomDomains(r.Context(), r.PathValue("id"))
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, map[string]any{"custom_domains": domains})
}

// customDomainDNS returns the ready-to-paste DNS records for a sandbox's
// attached custom domains plus the resolved ingress target. SDK consumers
// surface this directly to end users so they don't have to read the
// custom-domains docs to figure out what record to add at their DNS
// provider. Same cluster-forwarding wrap as the other per-sandbox routes:
// owner is the only node that holds the sandbox row.
func (h *handlers) customDomainDNS(w http.ResponseWriter, r *http.Request) {
	resp, err := h.deps.Service.CustomDomainDNS(r.Context(), r.PathValue("id"))
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, resp)
}

// ingressDNS returns the cluster's public ingress address(es) — the value
// users must point custom-domain DNS records at. Read-only and not
// sandbox-scoped; the same target serves every custom domain on the
// cluster. No EnableCustomDomains gate: the underlying data is the
// gossiped public host every node already advertises, and an SDK consumer
// rendering "point your DNS here first" is useful even before they decide
// whether to attach a domain.
func (h *handlers) ingressDNS(w http.ResponseWriter, r *http.Request) {
	apihttp.WriteJSON(w, http.StatusOK, h.deps.Service.IngressDNSTarget())
}

func (h *handlers) listMounts(w http.ResponseWriter, r *http.Request) {
	mounts, err := h.deps.Service.ListMounts(r.Context(), r.PathValue("id"))
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, map[string]any{"mounts": mounts})
}

func (h *handlers) getNetworkUsage(w http.ResponseWriter, r *http.Request) {
	usage, err := h.deps.Service.GetNetworkUsage(r.Context(), r.PathValue("id"))
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, usage)
}

func (h *handlers) updateNetworkLimits(w http.ResponseWriter, r *http.Request) {
	var req models.UpdateNetworkLimitsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	id := r.PathValue("id")
	// Pointer-nil ⇒ "leave alone"; pointer-to-zero ⇒ "set to unlimited".
	// Read the existing limits when only one direction is supplied so the
	// other direction round-trips unchanged.
	current, err := h.deps.Service.GetNetworkUsage(r.Context(), id)
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	in := current.BytesInLimit
	if req.NetworkBytesInLimit != nil {
		in = *req.NetworkBytesInLimit
	}
	out := current.BytesOutLimit
	if req.NetworkBytesOutLimit != nil {
		out = *req.NetworkBytesOutLimit
	}
	usage, err := h.deps.Service.SetNetworkLimits(r.Context(), id, in, out)
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, usage)
}
