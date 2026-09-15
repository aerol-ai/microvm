package api

import (
	"bufio"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	apie2b "github.com/aerol-ai/microvm/pkg/api/e2b"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	oteltrace "go.opentelemetry.io/otel/trace"
)

const clusterControlHeaderPrefix = "X-Cluster-"

// clusterControlHeaderGuard makes every internal routing marker a consequence
// of node-authenticated transport, never a credential supplied by a public API
// caller. This single guard covers v1 and all compatibility facades, including
// create-target, fan-out loop, peer-node, and artifact-replication headers.
func (s *Server) clusterControlHeaderGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.clusterEnabled || !hasClusterControlHeader(r.Header) {
			next.ServeHTTP(w, r)
			return
		}
		peerID, err := cluster.AuthenticatedPeerNodeID(r)
		if err != nil {
			apihttp.WriteError(w, http.StatusForbidden, err.Error())
			return
		}
		if s.service == nil || !cluster.IsLivePeer(s.service.Cluster(), peerID) {
			cluster.RecordMTLSUnknownPeer()
			apihttp.WriteError(w, http.StatusForbidden, "cluster peer not in membership")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func hasClusterControlHeader(header http.Header) bool {
	for name := range header {
		if strings.HasPrefix(http.CanonicalHeaderKey(name), clusterControlHeaderPrefix) {
			return true
		}
	}
	return false
}

// extractBearerToken returns the caller's bearer token from either:
//  1. the Authorization header, or
//  2. the WebSocket Sec-WebSocket-Protocol header in the form
//     `sandbox.bearer, <token>` (browsers cannot set Authorization on a
//     WebSocket handshake, so subprotocol smuggling is the standard pattern).
func extractBearerToken(r *http.Request) string {
	const prefix = "Bearer "
	authorization := r.Header.Get("Authorization")
	if strings.HasPrefix(authorization, prefix) {
		return strings.TrimPrefix(authorization, prefix)
	}

	for _, raw := range r.Header.Values("Sec-WebSocket-Protocol") {
		for _, part := range strings.Split(raw, ",") {
			candidate := strings.TrimSpace(part)
			if candidate == "" || candidate == "sandbox.bearer" {
				continue
			}
			return candidate
		}
	}
	return ""
}

// isPATToken compares a caller credential against the operator PAT in
// constant time — the PAT grants fleet-wide access, so a byte-wise `==`
// would leak match-prefix length as a timing side channel.
func (s *Server) isPATToken(candidate string) bool {
	return candidate != "" &&
		subtle.ConstantTimeCompare([]byte(candidate), []byte(s.patToken)) == 1
}

// requireAuth wraps next with bearer-token authentication. All API versions
// share this middleware via the Deps.Auth callback in their RegisterRoutes —
// there is no per-version auth.
//
// Two paths:
//   - The PAT authenticates as operator: full, unscoped (fleet-wide) access,
//     exactly as before this seam existed.
//   - Any other bearer token is handed to the control-plane validator. On
//     success the resolved Identity is attached as a non-operator Access, so the
//     service layer scopes the request to that owner. Under controlplane.Noop()
//     the validator rejects every non-PAT token, so this collapses back to
//     PAT-only behavior.
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := extractBearerToken(r)
		if s.isPATToken(token) {
			next.ServeHTTP(w, s.withOperatorAccess(r))
			return
		}
		if r2, ok := s.authenticateUserToken(r, token); ok {
			next.ServeHTTP(w, r2)
			return
		}
		apihttp.WriteError(w, http.StatusUnauthorized, "unauthorized")
	})
}

func (s *Server) requireE2BAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := extractBearerToken(r)
		apiKey := strings.TrimSpace(r.Header.Get("X-API-KEY"))
		if s.isPATToken(apiKey) || s.isPATToken(token) {
			next.ServeHTTP(w, s.withOperatorAccess(r))
			return
		}
		// The E2B facade also accepts the API key via X-API-KEY; try whichever
		// non-PAT credential was supplied as a user token.
		candidate := token
		if candidate == "" {
			candidate = apiKey
		}
		if r2, ok := s.authenticateUserToken(r, candidate); ok {
			next.ServeHTTP(w, r2)
			return
		}
		apie2b.WriteError(w, http.StatusUnauthorized, "Unauthorized, please check your credentials.")
	})
}

// withOperatorAccess stamps the PAT/operator marker onto the request context so
// the service layer bypasses owner scoping.
func (s *Server) withOperatorAccess(r *http.Request) *http.Request {
	return r.WithContext(controlplane.ContextWithAccess(r.Context(), controlplane.Access{Operator: true}))
}

// authenticateUserToken validates a non-PAT token via the control plane. On
// success it returns the request carrying a non-operator Access (owner-scoped);
// on rejection (including every token under the no-op validator) it returns
// ok=false and the caller writes 401. An empty token is never validated.
func (s *Server) authenticateUserToken(r *http.Request, token string) (*http.Request, bool) {
	if token == "" {
		return nil, false
	}
	identity, err := s.validator.Validate(r.Context(), token)
	if err != nil {
		return nil, false
	}
	access := controlplane.Access{Identity: identity}
	return r.WithContext(controlplane.ContextWithAccess(r.Context(), access)), true
}

func loggingMiddleware(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
		ctx, span := otel.Tracer("github.com/aerol-ai/microvm/pkg/api").Start(ctx, r.Method+" "+r.URL.Path,
			oteltrace.WithSpanKind(oteltrace.SpanKindServer),
			oteltrace.WithAttributes(
				attribute.String("http.request.method", r.Method),
				attribute.String("url.path", r.URL.Path),
				attribute.String("network.protocol.name", r.Proto),
			),
		)
		defer span.End()
		r = r.WithContext(ctx)
		// Wrap the writer so we can record the status code and whether the
		// connection was hijacked (i.e. WebSocket upgrade succeeded). The
		// wrapper proxies http.Hijacker / http.Flusher so the toolbox proxy
		// can still upgrade through this middleware.
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		duration := time.Since(start)
		status := rec.statusCode()
		if r.Pattern != "" {
			route := strings.TrimPrefix(r.Pattern, r.Method+" ")
			span.SetName(r.Method + " " + route)
			span.SetAttributes(attribute.String("http.route", route))
		}
		span.SetAttributes(
			attribute.Int("http.response.status_code", status),
			attribute.Int64("http.server.duration_ms", duration.Milliseconds()),
		)
		if rec.hijacked {
			span.SetAttributes(attribute.Bool("aerolvm.http.hijacked", true))
		}
		if status >= http.StatusInternalServerError {
			span.SetStatus(codes.Error, http.StatusText(status))
		}
		fields := []any{
			"method", r.Method,
			"path", r.URL.Path,
			"duration", duration,
			"status", status,
		}
		if rec.hijacked {
			fields = append(fields, "hijacked", true)
		}
		if upgrade := r.Header.Get("Upgrade"); upgrade != "" {
			fields = append(fields, "upgrade", upgrade)
		}
		logger.Info("request complete", fields...)
	})
}

// statusRecorder records the status the handler wrote (default 200, mirroring
// net/http) and whether the connection was hijacked. The Hijack/Flush passthrough
// is the load-bearing bit for WebSocket upgrades — the reverse proxy in the
// v1 toolbox handler needs the underlying ResponseWriter to satisfy
// http.Hijacker, and a wrapper that doesn't forward Hijack would silently break
// every WS request flowing through this middleware.
type statusRecorder struct {
	http.ResponseWriter
	status   int
	wrote    bool
	hijacked bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wrote {
		s.status = code
		s.wrote = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.wrote {
		s.status = http.StatusOK
		s.wrote = true
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := s.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("response writer does not implement http.Hijacker")
	}
	conn, rw, err := hj.Hijack()
	if err == nil {
		s.hijacked = true
	}
	return conn, rw, err
}

func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *statusRecorder) statusCode() int {
	if s.hijacked {
		return http.StatusSwitchingProtocols
	}
	if !s.wrote {
		return http.StatusOK
	}
	return s.status
}

// writeJSON / writeError forward to apihttp so the unversioned /health
// handler in server.go can use the same response shape as v1 handlers
// without importing apihttp directly.
func writeJSON(w http.ResponseWriter, status int, value any) {
	apihttp.WriteJSON(w, status, value)
}
func writeError(w http.ResponseWriter, status int, message string) {
	apihttp.WriteError(w, status, message)
}

// writeStoreAwareError preserves the *Server method shape so the existing
// capacity_error_test.go keeps compiling unchanged. New callers should use
// apihttp.WriteStoreAwareError directly.
func (s *Server) writeStoreAwareError(w http.ResponseWriter, err error) {
	apihttp.WriteStoreAwareError(s.logger, w, err)
}
