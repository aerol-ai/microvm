package caddy

import (
	"expvar"
	"net/http"
	"time"
)

// Caddy admin metrics. The hot path is the ingress reconciler at 10K-sandbox
// scale doing 2K-route writes per tick — operators need to see admin latency
// (the dominant tick-time contributor) and error rate (the canary for "Caddy
// is about to fall behind") without bolting on a metrics library. expvar lands
// these at /debug/vars; a prom-exporter-for-expvar can scrape them.
//
// Naming mirrors aerolvm_ingress_* in internal/service/ingress_metrics.go so
// an operator dashboard can correlate "admin latency went up" with "reconcile
// nanos went up" on the same prefix.
var (
	caddyAdminCallsTotal  = expvar.NewInt("aerolvm_caddy_admin_calls_total")
	caddyAdminErrorsTotal = expvar.NewInt("aerolvm_caddy_admin_errors_total")
	// caddyAdminLastNanos is the wall-clock duration of the most recent admin
	// call. Gauge rather than histogram for the same reason ingress_metrics
	// uses a gauge: no histogram dependency, percentiles via prom-exporter
	// downstream if the operator wants them.
	caddyAdminLastNanos = expvar.NewInt("aerolvm_caddy_admin_last_nanos")
)

// instrumentingTransport wraps an http.RoundTripper to record per-call
// duration and error counters. Installed at construction time so every
// caddy.Client method is metric'd uniformly without per-call-site changes
// (there are 8+ httpClient.Do call sites in client.go alone).
//
// Why not just record around each sendJSON? Several admin paths (Ping,
// DeleteTCPServer, deleteRoute) bypass sendJSON and use httpClient.Do
// directly. A transport-level wrapper captures everything, including any
// future helper added without remembering to add the metric.
type instrumentingTransport struct {
	inner http.RoundTripper
}

func (t *instrumentingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	start := time.Now()
	resp, err := t.inner.RoundTrip(req)
	caddyAdminCallsTotal.Add(1)
	caddyAdminLastNanos.Set(time.Since(start).Nanoseconds())
	// Transport-level errors are connection failures (Caddy down, refused,
	// timeout). HTTP 4xx/5xx returned from Caddy come back via resp.StatusCode
	// and are NOT errors here — the caller decides whether they're errors
	// (e.g. 404 on DELETE is success, 404 on UPSERT triggers an insert path).
	if err != nil {
		caddyAdminErrorsTotal.Add(1)
	}
	return resp, err
}

// wrapTransport installs the instrumenting wrapper around base. Returns base
// directly when base is nil — http.Client falls back to http.DefaultTransport
// in that case, which we'd lose if we wrapped nil — but in practice
// caddy.New always supplies a real client. Kept for safety.
func wrapTransport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &instrumentingTransport{inner: base}
}
