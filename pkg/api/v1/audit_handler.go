package v1

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
)

// getSandboxAudit serves GET /v1/sandboxes/{id}/audit with live fan-out.
// Intentionally NOT wrapped in clusterForwardWrap — owner-forward drops
// pre-failover history (plans/secrets-hardening §E1b).
func (h *handlers) getSandboxAudit(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		apihttp.WriteError(w, http.StatusBadRequest, "missing sandbox id")
		return
	}
	opts := parseSecretAuditQuery(r)
	// Authorize via local row or placement-owner OwnerRef metadata so pure
	// ingress nodes do not 404 before fan-out (P1). Incarnation is required
	// for retained ACL matches (one-way format; no any-incarnation fallback).
	if err := h.deps.Service.AuthorizeSandboxAuditAccess(r.Context(), id, opts.IncarnationID); err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	page, err := h.deps.Service.ListSecretAudit(r.Context(), id, opts)
	if err != nil {
		if errors.Is(err, service.ErrSecretAuditIndexIncomplete) {
			apihttp.WriteError(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, page)
}

// clusterInternalSandboxAudit serves the peer-local slice (no fan-out).
func (h *handlers) clusterInternalSandboxAudit(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		// Path is .../sandboxes/{id}/audit — also accept suffix parse for mux variants.
		id = strings.TrimSpace(r.PathValue("sandboxID"))
	}
	if id == "" {
		apihttp.WriteError(w, http.StatusBadRequest, "missing sandbox id")
		return
	}
	opts := parseSecretAuditQuery(r)
	events, next, err := h.deps.Service.ListSecretAuditLocal(r.Context(), id, opts)
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	selfID := ""
	if c := h.deps.Service.Cluster(); c != nil {
		selfID = c.SelfNodeID()
	}
	answered := []string{selfID}
	if selfID == "" {
		answered = []string{"local"}
	}
	apihttp.WriteJSON(w, http.StatusOK, service.SecretAuditPage{
		Events: events,
		Coverage: service.SecretAuditCoverage{
			Answered: answered,
			Missing:  nil,
			Partial:  false,
		},
		NextCursor: next,
	})
}

// clusterInternalSandboxMeta serves OwnerRef for ingress audit authorization.
func (h *handlers) clusterInternalSandboxMeta(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		id = strings.TrimSpace(r.PathValue("sandboxID"))
	}
	if id == "" {
		apihttp.WriteError(w, http.StatusBadRequest, "missing sandbox id")
		return
	}
	ownerRef, ok, err := h.deps.Service.SandboxOwnerRefLocal(r.Context(), id)
	if err != nil {
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}
	if !ok {
		apihttp.WriteError(w, http.StatusNotFound, "sandbox not found")
		return
	}
	apihttp.WriteJSON(w, http.StatusOK, cluster.SandboxOwnerMeta{OwnerRef: ownerRef, Exists: true})
}

func parseSecretAuditQuery(r *http.Request) service.SecretAuditQuery {
	q := service.SecretAuditQuery{
		Cursor:        strings.TrimSpace(r.URL.Query().Get("cursor")),
		Kind:          strings.TrimSpace(r.URL.Query().Get("kind")),
		IncarnationID: strings.TrimSpace(r.URL.Query().Get("incarnation_id")),
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil {
			q.Limit = n
		}
	}
	return q
}

// correlationIDFromRequest prefers X-Correlation-ID, then X-Request-ID.
func correlationIDFromRequest(r *http.Request) string {
	if v := strings.TrimSpace(r.Header.Get("X-Correlation-ID")); v != "" {
		return v
	}
	return strings.TrimSpace(r.Header.Get("X-Request-ID"))
}
