// Package remotemcp serves the AerolVM MCP tools over Streamable HTTP at
// /mcp on sandboxd (plans/mcp-server-and-agent-cli.md §5.7, Phase 2b). It is
// off unless SB_MCP_ENABLED=true, authenticates with the API's bearer token,
// and is pinned-only: every request names one sandbox in ?sandbox=.
//
// The endpoint is stateless (no Mcp-Session-Id), so any node can serve any
// request behind any load balancer and nothing touches cluster state. Each
// request builds an agentmcp server whose tools reach the API in-process
// with the caller's own token (see inProcessTransport).
package remotemcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.opentelemetry.io/otel/attribute"
	"golang.org/x/time/rate"

	"github.com/aerol-ai/microvm/internal/agentmcp"
	"github.com/aerol-ai/microvm/internal/agenttools"
	"github.com/aerol-ai/microvm/internal/observability"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// Path is where the endpoint is mounted: not under /v1, because MCP
// versions itself.
const Path = "/mcp"

// inProcessBaseURL is the URL the in-process SDK client is given. The
// transport never dials it; it only has to parse.
const inProcessBaseURL = "http://sandboxd.in-process"

// Config configures the endpoint.
type Config struct {
	// AllowedOrigins lists browser origins that may call /mcp. A request
	// with any other Origin is refused (DNS rebinding); MCP clients that
	// aren't browsers send no Origin and are unaffected.
	AllowedOrigins []string
	// AllowedHosts, when set, lists the Host values /mcp answers to.
	AllowedHosts []string
	// RateLimit is the per-token request rate (req/s); the burst is twice
	// that. Zero disables the limit.
	RateLimit float64
	Version   string
	Logger    *slog.Logger
}

// Handler is the /mcp endpoint.
type Handler struct {
	cfg     Config
	api     func() http.Handler
	sdk     *mcp.StreamableHTTPHandler
	limiter *tokenLimiter
}

type optionsKey struct{}

// New builds the endpoint. api returns sandboxd's root API handler; it is
// a func because /mcp is mounted on that same handler.
func New(cfg Config, api func() http.Handler) *Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	h := &Handler{cfg: cfg, api: api, limiter: newTokenLimiter(cfg.RateLimit)}
	h.sdk = mcp.NewStreamableHTTPHandler(h.serverFor, &mcp.StreamableHTTPOptions{
		Stateless:    true,
		JSONResponse: true,
		Logger:       cfg.Logger,
		// The SDK's own rebinding guard 403s any request that arrives on a
		// loopback socket with a non-loopback Host. Behind Caddy that is
		// every request: Caddy dials 127.0.0.1:21212 with Host set to the
		// API domain. The guard exists for unauthenticated local servers;
		// Wrap already does the real defence (Origin before auth, bearer
		// token, optional Host pinning).
		DisableLocalhostProtection: true,
	})
	return h
}

// Wrap returns the endpoint wrapped around the API's auth middleware, in
// order: Origin/Host check (before auth, so a rebinding page learns
// nothing), bearer auth, per-token rate limit, query options, then MCP.
func (h *Handler) Wrap(auth func(http.Handler) http.Handler) http.Handler {
	authed := auth(http.HandlerFunc(h.serveAuthed))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" && !slices.Contains(h.cfg.AllowedOrigins, origin) {
			recordRequest("forbidden_origin")
			apihttp.WriteError(w, http.StatusForbidden, "origin not allowed")
			return
		}
		if len(h.cfg.AllowedHosts) > 0 && !slices.Contains(h.cfg.AllowedHosts, hostOnly(r.Host)) {
			recordRequest("forbidden_host")
			apihttp.WriteError(w, http.StatusForbidden, "host not allowed")
			return
		}
		sw := &statusWriter{ResponseWriter: w}
		authed.ServeHTTP(sw, r)
		if sw.status == http.StatusUnauthorized {
			recordRequest("unauthorized")
		}
	})
}

func (h *Handler) serveAuthed(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	if !h.limiter.allow(token) {
		recordRequest("rate_limited")
		w.Header().Set("Retry-After", "1")
		apihttp.WriteError(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}
	if r.Method == http.MethodPost {
		opts, err := agentmcp.ParseQuery(r.URL.Query())
		if err != nil {
			recordRequest("bad_request")
			apihttp.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), optionsKey{}, opts))
	}
	recordRequest("accepted")
	h.sdk.ServeHTTP(w, r)
}

// serverFor builds the MCP server for one stateless request.
func (h *Handler) serverFor(r *http.Request) *mcp.Server {
	opts, ok := r.Context().Value(optionsKey{}).(agentmcp.Options)
	if !ok {
		return nil // the SDK answers 400
	}
	tools, err := agenttools.New(agenttools.Config{
		APIURL:     inProcessBaseURL,
		Token:      bearerToken(r),
		Source:     agenttools.SourceMCP,
		HTTPClient: &http.Client{Transport: &inProcessTransport{handler: h.api(), remoteAddr: r.RemoteAddr}},
	})
	if err != nil {
		return nil
	}
	server, err := agentmcp.New(tools, opts, h.cfg.Version, agentmcp.WithInstrument(h.instrument(r.Context())))
	if err != nil {
		return nil
	}
	return server.MCP()
}

// instrument records each tool call (CEO review CF6): a counter by tool and
// outcome, latency, one log line and one span, with tool, sandbox_id,
// owner_ref, outcome and duration. Arguments and outputs are never recorded:
// they can hold file contents and secrets.
func (h *Handler) instrument(reqCtx context.Context) agentmcp.Instrument {
	ownerRef := ""
	if access, ok := controlplane.AccessFromContext(reqCtx); ok && !access.Operator {
		ownerRef = access.Identity.OwnerRef
	}
	return func(ctx context.Context, tool string) (context.Context, func(string, error)) {
		start := time.Now()
		ctx, span := observability.StartSpan(ctx, "mcp.tool_call", attribute.String("mcp.tool", tool))
		return ctx, func(sandboxID string, err error) {
			outcome, code := classify(err)
			duration := time.Since(start)
			recordToolCall(tool, outcome, duration)
			span.SetAttributes(
				attribute.String("sandbox_id", sandboxID),
				attribute.String("owner_ref", ownerRef),
				attribute.String("mcp.outcome", outcome),
				attribute.Int64("duration_ms", duration.Milliseconds()),
			)
			observability.EndSpan(span, spanError(outcome, err))
			attrs := []any{"tool", tool, "sandbox_id", sandboxID, "owner_ref", ownerRef, "outcome", outcome, "duration_ms", duration.Milliseconds()}
			if code != "" {
				attrs = append(attrs, "code", code)
			}
			h.cfg.Logger.Info("mcp tool call", attrs...)
		}
	}
}

// classify maps a tool error onto the outcome label. api_error is the
// platform failing (5xx, unreachable, timeouts) and is what the error-rate
// alert watches; tool_error is a call the model can fix (not found, bad
// argument, edit conflict) and is normal agent behaviour.
func classify(err error) (outcome, code string) {
	if err == nil {
		return "ok", ""
	}
	e := agenttools.Classify(err)
	switch {
	case e.Code == agenttools.CodeUnauthorized || e.Code == agenttools.CodeForbidden:
		return "unauthorized", e.Code
	case e.HTTPStatus >= 500 && e.Code != agenttools.CodeUnsupportedRuntime,
		e.Code == agenttools.CodeUnavailable, e.Code == agenttools.CodeUnreachable,
		e.Code == agenttools.CodeInternal, e.Code == agenttools.CodeTimeout:
		return "api_error", e.Code
	}
	return "tool_error", e.Code
}

// spanError marks only platform failures as span errors.
func spanError(outcome string, err error) error {
	if outcome == "api_error" {
		return err
	}
	return nil
}

func bearerToken(r *http.Request) string {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(auth) > 7 && strings.EqualFold(auth[:7], "bearer ") {
		return strings.TrimSpace(auth[7:])
	}
	return ""
}

func hostOnly(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// tokenLimiter rate-limits per token. Tokens are keyed by their SHA-256 so
// no credential is held in memory beyond the request; idle buckets are
// dropped once the map grows.
type tokenLimiter struct {
	rate    rate.Limit
	burst   int
	mu      sync.Mutex
	buckets map[string]*tokenBucket
}

type tokenBucket struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

const maxTokenBuckets = 10000

func newTokenLimiter(perSecond float64) *tokenLimiter {
	if perSecond <= 0 {
		return nil
	}
	return &tokenLimiter{rate: rate.Limit(perSecond), burst: max(1, int(2*perSecond)), buckets: map[string]*tokenBucket{}}
}

func (l *tokenLimiter) allow(token string) bool {
	if l == nil {
		return true
	}
	sum := sha256.Sum256([]byte(token))
	key := hex.EncodeToString(sum[:])
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= maxTokenBuckets {
			l.evictIdleLocked(now)
		}
		b = &tokenBucket{limiter: rate.NewLimiter(l.rate, l.burst)}
		l.buckets[key] = b
	}
	b.lastSeen = now
	return b.limiter.AllowN(now, 1)
}

// evictIdleLocked drops buckets idle long enough to have refilled: a fresh
// bucket would behave the same.
func (l *tokenLimiter) evictIdleLocked(now time.Time) {
	refill := time.Duration(float64(l.burst)/float64(l.rate)*float64(time.Second)) + time.Second
	for k, b := range l.buckets {
		if now.Sub(b.lastSeen) > refill {
			delete(l.buckets, k)
		}
	}
}
