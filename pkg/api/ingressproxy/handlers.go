package ingressproxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
)

// httpWake serves /__ingress/http/{id}/{port}[/{path...}]. The flow:
//
//  1. Parse id + port + remainder of path.
//  2. If the request has a body and is NOT an Upgrade (WebSocket / etc),
//     buffer it up to MaxBufferBytes — overflow → 413. Cold-start wakes
//     can take up to ~15s and we can't replay a body the client streamed.
//  3. Wake the sandbox via Service.WakeAwarePortTarget. Sentinels
//     (ErrSandboxManuallyStopped → 409, ErrWakeCircuitOpen → 503+Retry-After,
//     store.ErrNotFound → 404) flow through apihttp.WriteStoreAwareError.
//  4. Reverse-proxy to the now-awake container with FlushInterval=-1 for
//     streaming responses. Upgrade headers pass through unchanged.
func (h *handlers) httpWake(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	portStr := r.PathValue("port")
	rest := r.PathValue("path")

	if id == "" || portStr == "" {
		apihttp.WriteError(w, http.StatusBadRequest, "missing sandbox id or port")
		return
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		apihttp.WriteError(w, http.StatusBadRequest, "invalid port")
		return
	}

	// Buffer the request body before initiating wake — we can't replay
	// a client stream after the cold-start delay. Upgrades have no body
	// in the HTTP sense, so skip buffering for them.
	isUpgrade := strings.EqualFold(r.Header.Get("Connection"), "upgrade") ||
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") ||
		r.Header.Get("Upgrade") != ""

	if !isUpgrade && r.Body != nil && r.ContentLength != 0 {
		buf, err := bufferBody(r.Body, h.deps.MaxBufferBytes)
		if err != nil {
			if errors.Is(err, errBodyTooLarge) {
				apihttp.WriteError(w, http.StatusRequestEntityTooLarge,
					"request body exceeds wake buffer cap")
				return
			}
			apihttp.WriteError(w, http.StatusBadRequest, "failed to read request body")
			return
		}
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(buf))
		r.ContentLength = int64(len(buf))
		r.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(buf)), nil
		}
	}

	endpoint, err := h.deps.Resolver.WakeAwarePortTarget(r.Context(), id, port)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			apihttp.WriteError(w, http.StatusNotFound, "sandbox not found")
			return
		}
		// Wake-timeout (context deadline) surfaces as a generic error
		// from StartSandbox — translate to 503+Retry-After:2 per D6
		// so clients retry quickly while the cold start finishes.
		if errors.Is(err, service.ErrWakeCircuitOpen) {
			w.Header().Set("Retry-After", "60")
			apihttp.WriteError(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		if errors.Is(err, service.ErrSandboxManuallyStopped) {
			apihttp.WriteError(w, http.StatusConflict, err.Error())
			return
		}
		// Timeouts / capacity / other transient failures: tell the
		// client to retry shortly.
		w.Header().Set("Retry-After", "2")
		apihttp.WriteStoreAwareError(h.deps.Logger, w, err)
		return
	}

	target, err := url.Parse(endpoint.URL)
	if err != nil {
		apihttp.WriteError(w, http.StatusInternalServerError, "invalid sandbox target")
		return
	}

	// Reconstruct the path the user originally requested. Caddy rewrote
	// it to /__ingress/http/{id}/{port}{path}, so the captured {path}
	// segment is the original path without its leading slash.
	upstreamPath := "/"
	if rest != "" {
		upstreamPath = "/" + rest
	}

	// Activity at request start: bump last_active_at so the lifecycle
	// idle sweep does not stop a sandbox currently serving traffic.
	// Then a 30s ticker keeps it alive for the duration of any
	// long-lived connection (WebSocket, SSE, long-poll). Errors are
	// swallowed — failing to touch should never break the request.
	_ = h.deps.Resolver.TouchSandbox(r.Context(), id)
	tickerCtx, cancelTicker := context.WithCancel(r.Context())
	defer cancelTicker()
	go h.activityTicker(tickerCtx, id)

	// Use Rewrite (not the deprecated Director) so the request is built
	// once with the correct upstream URL. SetXForwarded propagates the
	// caller IP for visibility in upstream logs.
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.URL.Path = upstreamPath
			pr.Out.URL.RawPath = ""
			pr.Out.Host = target.Host
			pr.SetXForwarded()
		},
		// FlushInterval=-1 disables buffering so streaming responses
		// (SSE, chunked, long-poll) reach the client as the sandbox
		// emits them.
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			apihttp.WriteError(w, http.StatusBadGateway, "sandbox unavailable")
		},
	}
	proxy.ServeHTTP(w, r)
}

// activityTicker re-touches the sandbox every activityTickInterval for
// as long as ctx is live. The first touch already fired in httpWake;
// this only handles long-lived streams where a single request can
// outlive a normal idle threshold.
func (h *handlers) activityTicker(ctx context.Context, id string) {
	t := time.NewTicker(activityTickInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = h.deps.Resolver.TouchSandbox(ctx, id)
		}
	}
}
