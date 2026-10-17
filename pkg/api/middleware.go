package api

import (
	"bufio"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
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
// A single node has no peers to send them, so it drops them: otherwise a
// caller could pick its own sandbox id through the create-target pair.
func (s *Server) clusterControlHeaderGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !hasClusterControlHeader(r.Header) {
			next.ServeHTTP(w, r)
			return
		}
		if !s.clusterEnabled {
			for name := range r.Header {
				if strings.HasPrefix(http.CanonicalHeaderKey(name), clusterControlHeaderPrefix) {
					r.Header.Del(name)
				}
			}
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
