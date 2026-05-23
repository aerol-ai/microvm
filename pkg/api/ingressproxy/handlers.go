package ingressproxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/capacity"
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
	//
	// Warm-bypass: when the sandbox is already running, WakeAwarePortTarget
	// returns instantly with no cold-start window, so buffering serves no
	// purpose — it would just enforce MaxBufferBytes against normal
	// uploads (turning a 100 MiB POST into a 413) and waste memory on
	// every request. We pay one extra store.Get to decide, which is
	// cheaper than the buffer + allocation. If IsSandboxStarted returns
	// ErrNotFound we surface 404 immediately; other errors fall through
	// to the buffer-and-wake path (the wake helper will surface them
	// with the right status if they recur).
	isUpgrade := strings.EqualFold(r.Header.Get("Connection"), "upgrade") ||
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") ||
		r.Header.Get("Upgrade") != ""

	started, startedErr := h.deps.Resolver.IsSandboxStarted(r.Context(), id)
	if errors.Is(startedErr, store.ErrNotFound) {
		apihttp.WriteError(w, http.StatusNotFound, "sandbox not found")
		return
	}

	if !started && !isUpgrade && r.Body != nil && r.ContentLength != 0 {
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
		writeWakeError(h.deps.Logger, w, id, port, err)
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

// writeWakeError maps a wake failure to the HTTP response the docs
// promise (serverless.mdx). Any error that does not match a known
// sentinel — cold-start timeout (context.DeadlineExceeded from
// wakeStartTimeout), Docker start failures, capacity rejections that
// slip past the cluster check — is a transient failure of the cold
// start, so the fallback is 503 + Retry-After:2 rather than the
// generic 400 WriteStoreAwareError defaults to. A 4xx here would
// confuse clients and load balancers into treating the failure as
// permanent and never retrying.
//
// Order matters: WriteStoreAwareError is the canonical mapper for
// capacity errors (it sets the cluster-aware Retry-After). We delegate
// to it for the recognized error families and only fall through to
// the 503 default for "unknown wake failure".
func writeWakeError(logger *slog.Logger, w http.ResponseWriter, id string, port int, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		apihttp.WriteError(w, http.StatusNotFound, "sandbox not found")
	case errors.Is(err, service.ErrSandboxManuallyStopped):
		apihttp.WriteError(w, http.StatusConflict, err.Error())
	case errors.Is(err, service.ErrWakeCircuitOpen):
		w.Header().Set("Retry-After", "60")
		apihttp.WriteError(w, http.StatusServiceUnavailable, err.Error())
	case errors.Is(err, capacity.ErrCapacityExceeded), errors.Is(err, cluster.ErrCapacityExceeded),
		errors.Is(err, cluster.ErrCreateBackpressure), errors.Is(err, cluster.ErrNoPlacementTarget),
		errors.Is(err, cluster.ErrInvalidTopology):
		apihttp.WriteStoreAwareError(logger, w, err)
	default:
		// Unknown wake failure: cold-start timeout, Docker start error,
		// or anything else surfaced by StartSandbox. All are transient
		// from the client's perspective — retry shortly.
		logger.Warn("wake failed", "sandbox_id", id, "port", port, "error", err)
		w.Header().Set("Retry-After", "2")
		apihttp.WriteError(w, http.StatusServiceUnavailable, "sandbox wake failed")
	}
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
