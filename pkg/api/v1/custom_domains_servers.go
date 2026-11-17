package v1

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/api/clustercreate"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Custom hostnames in a cluster are bound by a server, after the caller's
// DNS proof (internal/service custom_domain_bind.go): a worker or gateway
// sends a domain attach, and a create with custom_domains, to a server with
// the caller's own credential, as it does the settings writes
// (server_tier.go). The server binds, then the call goes on to the
// sandbox's owner as before. A call a server already forwarded here is the
// owner's half, and runs here.
//
// Cost on the create path: one forward from the worker or gateway to a
// server, and the server's TXT lookup per hostname (none for an operator
// or admin). The owner does not look the proof up again.

// isForward reports whether a peer forwarded r (X-Cluster-Forwarded, which
// the cluster header guard takes only from a live mTLS peer).
func isForward(r *http.Request) bool {
	return r.Header.Get(cluster.HeaderForwarded) == "1"
}

// sentOnToThisServer reports whether a worker or gateway sent r on to this
// server (cluster.Agent.ForwardToServer): this server is then the call's
// edge, which binds the name and routes the call to the owner, and not the
// owner's half of it, which only a server sends.
func (h *handlers) sentOnToThisServer(r *http.Request) bool {
	if h.deps.Service == nil || !h.deps.Service.BindsCustomDomainsForCallers() {
		return false
	}
	return cluster.SentOnByNonServer(h.deps.Service.Cluster(), r)
}

// attachGoesToServer: a worker's or gateway's domain attach goes to a
// server, unless a server sent it here.
func (h *handlers) attachGoesToServer(r *http.Request) bool {
	return !isForward(r)
}

// createGoesToServer reports whether this worker or gateway sends a create
// to a server: one with custom_domains that no node placed yet.
func (h *handlers) createGoesToServer(r *http.Request, req models.CreateSandboxRequest) bool {
	if h.deps.Service == nil || !h.deps.Service.SendsOperatorCallsToServers() ||
		strings.TrimSpace(r.Header.Get(clustercreate.HeaderTarget)) != "" || isForward(r) {
		return false
	}
	// Once servers sign, a cloud identity in a placement's spec is what a
	// server signs the sandbox's tokens from, so only a server puts one
	// there (cluster peer_proposals.go): a create that asks for one goes
	// to a server too. Only such a create reads the signing mode.
	return len(req.CustomDomains) > 0 || (req.Identity != nil && h.deps.Service.ServerSigningOn())
}

// asEdge returns r as this server's own edge call when a worker or gateway
// sent it on: the forward marker would make this server take it for the
// owner's half, and refuse to send it on to the owner (a loop). The caller
// was authenticated already, with the worker or gateway as the hop.
func (h *handlers) asEdge(r *http.Request) *http.Request {
	if !h.sentOnToThisServer(r) {
		return r
	}
	r = r.Clone(r.Context())
	r.Header.Del(cluster.HeaderForwarded)
	return r
}

// bindCustomDomainFirst is a server's half of a domain attach: it binds the
// hostname for the caller, then serves the call (here, or on the owner).
// If the owner refuses the attach, a name this call bound is released; a
// 5xx leaves it bound (the outcome is unknown, and a retry finds it bound).
func (h *handlers) bindCustomDomainFirst(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		svc := h.deps.Service
		r = h.asEdge(r)
		if svc == nil || !svc.BindsCustomDomainsForCallers() || isForward(r) {
			next.ServeHTTP(w, r)
			return
		}
		raw, err := apihttp.ReadJSONBody(w, r)
		_ = r.Body.Close()
		if err != nil {
			apihttp.WriteError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(raw))
		r.ContentLength = int64(len(raw))
		var req models.AddCustomDomainRequest
		if json.Unmarshal(raw, &req) != nil {
			next.ServeHTTP(w, r) // the handler answers the bad body
			return
		}
		ctx, release, err := svc.BindCustomDomain(r.Context(), r.PathValue("id"), req.Hostname)
		if err != nil {
			apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
			return
		}
		if release == nil {
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		rec := &statusCapture{ResponseWriter: w}
		next.ServeHTTP(rec, r.WithContext(ctx))
		if rec.status >= 400 && rec.status < 500 {
			release()
		}
	})
}

// bindCreateCustomDomains is the create router's AfterReserve on a server,
// for a create with custom_domains: it binds them to the reservation. nil
// otherwise.
func (h *handlers) bindCreateCustomDomains(req models.CreateSandboxRequest) func(http.ResponseWriter, *http.Request, string, string) (*http.Request, bool) {
	if len(req.CustomDomains) == 0 || h.deps.Service == nil || !h.deps.Service.BindsCustomDomainsForCallers() {
		return nil
	}
	return func(w http.ResponseWriter, r *http.Request, sandboxID, incarnationID string) (*http.Request, bool) {
		ctx, err := h.deps.Service.BindCreateCustomDomains(r.Context(), sandboxID, incarnationID, req.CustomDomains)
		if err != nil {
			apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
			return nil, false
		}
		return r.WithContext(ctx), true
	}
}

// statusCapture records the status a handler set with WriteHeader. A
// handler that writes its body without one answers 200, which leaves
// status 0: only a 4xx matters to the caller. The body goes straight to
// the embedded writer; nothing here reads or copies it.
type statusCapture struct {
	http.ResponseWriter
	status int
}

func (c *statusCapture) WriteHeader(code int) {
	if c.status == 0 {
		c.status = code
	}
	c.ResponseWriter.WriteHeader(code)
}

func (c *statusCapture) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
