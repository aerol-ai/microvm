package main

import (
	"log/slog"
	"net/http"
	"strings"
)

// Trace context from sandboxd (plans/agent-sandbox-feature-parity.md §5.9,
// A3). Every toolbox call sandboxd proxies carries the W3C traceparent of
// its API span (or the caller's, when sandboxd's tracing is off), so one
// line here ties a toolbox request to the API call and the trace behind it.
// toolboxd has no trace exporter of its own, and this adds none: a log line
// carrying the ids is what an operator can join on.

// traceparentHeader is the W3C Trace Context request header.
const traceparentHeader = "Traceparent"

// parseTraceparent reads a version-00 W3C traceparent
// ("00-<32 hex trace id>-<16 hex parent id>-<2 hex flags>"). ok is false for
// anything else, including the all-zero ids the spec calls invalid, so a
// malformed header never reaches the log.
func parseTraceparent(h string) (traceID, parentID string, ok bool) {
	parts := strings.Split(strings.TrimSpace(h), "-")
	if len(parts) != 4 || parts[0] != "00" {
		return "", "", false
	}
	traceID, parentID, flags := parts[1], parts[2], parts[3]
	if len(traceID) != 32 || len(parentID) != 16 || len(flags) != 2 ||
		!lowerHex(traceID) || !lowerHex(parentID) || !lowerHex(flags) ||
		strings.Trim(traceID, "0") == "" || strings.Trim(parentID, "0") == "" {
		return "", "", false
	}
	return traceID, parentID, true
}

func lowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// withTraceLog logs one line per request that carries a valid traceparent:
// method, path, trace id and parent span id, at the start of the request.
// Logging at the start keeps the response writer unwrapped, so WebSocket
// upgrades and streamed exec output pass through untouched, and a
// long-lived session is visible while it runs. Requests without trace
// context (the host's readiness polls) log nothing, as before. The query
// string is never logged: it can name files and carry command options.
func withTraceLog(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if traceID, parentID, ok := parseTraceparent(r.Header.Get(traceparentHeader)); ok && logger != nil {
			logger.Info("toolbox request", "method", r.Method, "path", r.URL.Path, "trace_id", traceID, "parent_span_id", parentID)
		}
		next.ServeHTTP(w, r)
	})
}
