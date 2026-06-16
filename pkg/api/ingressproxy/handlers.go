package ingressproxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"math/rand"
	"net"
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

// dialUpstream is overridable in tests; in production it is net.Dialer.DialContext.
var dialUpstream = func(ctx context.Context, addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: 2 * time.Second}
	return d.DialContext(ctx, "tcp", addr)
}

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

	// Admission control on the cold-start path only. Warm requests pass
	// straight through — they don't hold a wake slot and behave like a
	// plain reverse proxy. The slot is released as soon as the readiness
	// probe finishes (or fails); we do NOT keep it across the proxy hop,
	// since at that point the sandbox is indistinguishable from a warm
	// backend and shouldn't count against the wake-window budget.
	var releasePending func()
	if !started {
		release, admitErr := h.state.acquirePending(id)
		if admitErr != nil {
			h.deps.Logger.Warn("wake admission rejected",
				"sandbox_id", id, "port", port, "reason", admitErr.Error())
			w.Header().Set("Retry-After", "2")
			apihttp.WriteError(w, http.StatusServiceUnavailable, admitErr.Error())
			return
		}
		releasePending = release
		// Failsafe — if any branch below forgets to release, defer
		// catches it on return. The closure is idempotent.
		defer func() {
			if releasePending != nil {
				releasePending()
			}
		}()
	}

	if !started && !isUpgrade && r.Body != nil && r.ContentLength != 0 {
		// Reserve from the global byte budget BEFORE buffering, so a
		// flood of concurrent cold POSTs can't pin >cap bytes. The
		// per-request cap (MaxBufferBytes) still applies; this is the
		// cross-request cap. Use the declared ContentLength as the
		// reservation when known; fall back to MaxBufferBytes when
		// unknown (-1) since that's the upper bound bufferBody can
		// produce.
		reserve := r.ContentLength
		if reserve < 0 || reserve > h.deps.MaxBufferBytes {
			reserve = h.deps.MaxBufferBytes
		}
		releaseBuf, budgetErr := h.state.acquireBuffer(reserve)
		if budgetErr != nil {
			h.deps.Logger.Warn("wake buffer budget rejected",
				"sandbox_id", id, "port", port,
				"requested_bytes", reserve, "reason", budgetErr.Error())
			w.Header().Set("Retry-After", "2")
			apihttp.WriteError(w, http.StatusServiceUnavailable, budgetErr.Error())
			return
		}
		// Hold the budget until the handler returns; the proxy reads
		// from the in-memory buffer during ServeHTTP, so releasing
		// earlier would let the global counter undershoot the real
		// memory footprint.
		defer releaseBuf()

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

	// Post-wake readiness probe. WakeAwarePortTarget returns as soon as
	// Docker reports the container running, but the user's process inside
	// (npm dev server, gunicorn, etc.) typically takes another moment to
	// bind to its listening port. Without this hold the reverse proxy
	// connects too early, gets ECONNREFUSED, and the client sees 502.
	// We hold the caller's connection until the upstream accepts a TCP
	// connection or the readiness budget is exhausted.
	//
	// Single-flighted per (sandbox, port): 10k concurrent waiters
	// produce one probe loop, not 10k. Skipped when the sandbox was
	// already started at preflight — a warm upstream is by definition
	// already listening.
	if !started {
		readyTimeout := h.deps.UpstreamReadyTimeout
		if readyTimeout <= 0 {
			readyTimeout = defaultUpstreamReadyTimeout
		}
		probeErr := h.state.probeOnce(r.Context(), id, port, readyTimeout,
			func(probeCtx context.Context, budget time.Duration) error {
				return waitForUpstreamReady(probeCtx, target.Host, budget)
			})
		if probeErr != nil {
			h.deps.Logger.Warn("upstream not ready after wake",
				"sandbox_id", id, "port", port, "error", probeErr)
			w.Header().Set("Retry-After", "2")
			apihttp.WriteError(w, http.StatusServiceUnavailable, "sandbox upstream not ready")
			return
		}
	}

	// Release the pending slot now: probe is done, sandbox is warm,
	// the rest of the request is just a reverse proxy hop. Setting
	// the local handle to nil prevents the defer from double-releasing.
	if releasePending != nil {
		releasePending()
		releasePending = nil
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
	// For long-lived connections (WebSocket, SSE, long-poll) we keep
	// touching every activityTickInterval. Short requests that finish
	// before the first interval pay only a timer-heap entry — no
	// goroutine is spawned. Errors are swallowed; failing to touch
	// should never break the request.
	_ = h.deps.Resolver.TouchSandbox(r.Context(), id)
	h.scheduleActivityTouch(r.Context(), id)

	// Use Rewrite (not the deprecated Director) so the request is built
	// once with the correct upstream URL. SetXForwarded propagates the
	// caller IP for visibility in upstream logs.
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.URL.Path = upstreamPath
			pr.Out.URL.RawPath = ""
			// maskRequestHost (E2B network.maskRequestHost): rewrite the
			// upstream Host so frameworks that validate it (Vite, Django,
			// webpack-dev-server) accept the request. This is the wake-path
			// enforcement point — the direct Caddy route can't reach here
			// because we overwrite Host below. Empty mask keeps today's
			// behavior (the container sees its own IP:port as Host).
			if endpoint.MaskRequestHost != "" {
				pr.Out.Host = endpoint.MaskRequestHost
			} else {
				pr.Out.Host = target.Host
			}
			pr.SetXForwarded()
		},
		// FlushInterval=-1 disables buffering so streaming responses
		// (SSE, chunked, long-poll) reach the client as the sandbox
		// emits them.
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			// Reached when the upstream resets / closes mid-request, or
			// when a warm-bypass request raced an in-progress shutdown.
			// Either way the failure is transient from the caller's view
			// — surface 503 + Retry-After so clients and load balancers
			// retry rather than treating it as a permanent gateway fault.
			h.deps.Logger.Warn("proxy to sandbox upstream failed",
				"sandbox_id", id, "port", port, "error", err)
			w.Header().Set("Retry-After", "2")
			apihttp.WriteError(w, http.StatusServiceUnavailable, "sandbox upstream unavailable")
		},
	}
	proxy.ServeHTTP(w, r)
}

// waitForUpstreamReady polls addr (host:port) with TCP dials until it
// accepts a connection, the caller's context is cancelled, or the
// overall budget elapses. Returns nil as soon as a connection succeeds
// (closed immediately). Returns the last dial error on budget timeout.
//
// Backoff starts at 100ms (with up to 50ms jitter to spread SYN bursts
// when many waiters converge on the same upstream simultaneously) and
// doubles to a 1s cap. A typical framework-process boot (Node, Python)
// takes 1-5 seconds, so the first few retries are tight; the cap
// prevents busy-looping once the boot drags into the multi-second
// range.
//
// Retries on any dial error except caller cancellation / deadline.
// Docker bridge networks during container start can briefly emit
// EHOSTUNREACH, ENETUNREACH, or ECONNRESET in addition to the usual
// ECONNREFUSED — narrowing the retry to only ECONNREFUSED would
// surface those races to the client as immediate failures.
func waitForUpstreamReady(ctx context.Context, addr string, budget time.Duration) error {
	deadline := time.Now().Add(budget)
	probeCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	// Per-call jitter on the very first delay (0-50 ms) so 10k waiters
	// released by a single wake don't all dial at exactly t+100ms.
	// Uses the global math/rand source — concurrent-safe since Go 1.20.
	delay := 100*time.Millisecond + time.Duration(rand.Int63n(int64(50*time.Millisecond)))
	const maxDelay = 1 * time.Second
	var lastErr error
	for {
		if err := probeCtx.Err(); err != nil {
			if lastErr != nil {
				return lastErr
			}
			return err
		}
		conn, err := dialUpstream(probeCtx, addr)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		// Caller cancellation / deadline are terminal — don't keep
		// dialling against a dead caller. Everything else (connection
		// refused, host unreachable, reset by peer) is treated as the
		// "container is up but service not bound yet" signal.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		lastErr = err
		select {
		case <-probeCtx.Done():
			return lastErr
		case <-time.After(delay):
		}
		if delay < maxDelay {
			delay *= 2
			if delay > maxDelay {
				delay = maxDelay
			}
		}
	}
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

// scheduleActivityTouch arms a self-rearming timer that re-touches the
// sandbox every activityTickInterval while ctx is alive. The first
// touch already fired in httpWake; this only handles long-lived streams
// where a single request can outlive a normal idle threshold.
//
// Using time.AfterFunc instead of a long-lived goroutine + ticker means
// sub-interval requests (the common case) cost only a single timer-heap
// entry. AfterFunc runs each callback in a fresh, short-lived goroutine
// so idle requests carry no goroutine at all. ctx cancellation is
// observed at the next tick — one stray AfterFunc invocation may run
// after the request completes, but it short-circuits on ctx.Err().
func (h *handlers) scheduleActivityTouch(ctx context.Context, id string) {
	var fire func()
	fire = func() {
		if ctx.Err() != nil {
			return
		}
		_ = h.deps.Resolver.TouchSandbox(ctx, id)
		if ctx.Err() != nil {
			return
		}
		time.AfterFunc(activityTickInterval, fire)
	}
	time.AfterFunc(activityTickInterval, fire)
}
