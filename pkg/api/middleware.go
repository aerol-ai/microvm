package api

import (
	"bufio"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/api/apihttp"
)

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

// requireAuth wraps next with PAT bearer-token authentication. All API
// versions share this middleware via the Deps.Auth callback in their
// RegisterRoutes — there is no per-version auth.
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if extractBearerToken(r) == s.patToken {
			next.ServeHTTP(w, r)
			return
		}
		apihttp.WriteError(w, http.StatusUnauthorized, "unauthorized")
	})
}

func loggingMiddleware(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		// Wrap the writer so we can record the status code and whether the
		// connection was hijacked (i.e. WebSocket upgrade succeeded). The
		// wrapper proxies http.Hijacker / http.Flusher so the toolbox proxy
		// can still upgrade through this middleware.
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		fields := []any{
			"method", r.Method,
			"path", r.URL.Path,
			"duration", time.Since(start),
			"status", rec.statusCode(),
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
