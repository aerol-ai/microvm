package apihttp

import (
	"net/http"
	"strings"
)

// CorrelationID returns the caller's correlation id: X-Correlation-ID, else
// X-Request-ID, else "". A forwarded request carries the edge's id in
// X-Correlation-ID (cluster.StampForward), so the owner node reads the same
// id the edge recorded.
func CorrelationID(r *http.Request) string {
	if r == nil {
		return ""
	}
	if v := strings.TrimSpace(r.Header.Get("X-Correlation-ID")); v != "" {
		return v
	}
	return strings.TrimSpace(r.Header.Get("X-Request-ID"))
}
