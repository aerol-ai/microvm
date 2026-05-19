package caddy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestInstrumentingTransportCountsCalls pins the load-bearing claim: every
// admin call (regardless of response code) increments the calls counter and
// updates the last-nanos gauge. Without that, operator dashboards can't tell
// the difference between "Caddy admin is wedged" (no recent calls) and
// "everything is fine" (steady call rate, low latency).
func TestInstrumentingTransportCountsCalls(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	beforeCalls := caddyAdminCallsTotal.Value()
	beforeErrors := caddyAdminErrorsTotal.Value()
	beforeLatency := caddyAdminLatencyBuckets.Count()

	transport := &instrumentingTransport{inner: http.DefaultTransport}
	client := &http.Client{Transport: transport}
	resp, err := client.Get(srv.URL + "/config/")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()

	if got := caddyAdminCallsTotal.Value() - beforeCalls; got != 1 {
		t.Fatalf("calls delta = %d, want 1", got)
	}
	if got := caddyAdminErrorsTotal.Value() - beforeErrors; got != 0 {
		t.Fatalf("errors delta = %d, want 0 on a 200 response", got)
	}
	if caddyAdminLastNanos.Value() <= 0 {
		t.Fatalf("last_nanos = %d, want > 0 after a successful call", caddyAdminLastNanos.Value())
	}
	if got := caddyAdminLatencyBuckets.Count() - beforeLatency; got != 1 {
		t.Fatalf("latency bucket delta = %d, want 1", got)
	}
}

// TestInstrumentingTransportCountsErrors pins that transport-level failures
// (connection refused, DNS, etc.) bump the errors counter. This is the canary
// for "Caddy admin is down" — distinct from HTTP 4xx/5xx which the caller
// classifies (e.g. 404 on DELETE is intentional success).
func TestInstrumentingTransportCountsErrors(t *testing.T) {
	beforeErrors := caddyAdminErrorsTotal.Value()

	transport := &instrumentingTransport{inner: http.DefaultTransport}
	client := &http.Client{Transport: transport}
	// Dial a port nothing's listening on. The OS returns ECONNREFUSED
	// immediately; that's the connection-failure path we want to instrument.
	resp, err := client.Get("http://127.0.0.1:1/config/")
	if err == nil {
		resp.Body.Close()
		t.Fatalf("expected an error dialing 127.0.0.1:1, got nil")
	}

	if got := caddyAdminErrorsTotal.Value() - beforeErrors; got != 1 {
		t.Fatalf("errors delta = %d, want 1 on transport failure", got)
	}
}

// TestInstrumentingTransportIgnoresHTTPErrorCodes pins the carve-out from the
// previous test: a 5xx response from Caddy still completed a round-trip
// successfully — the *transport* succeeded; the application chose how to
// classify the status. Operators can read "calls / non-2xx responses" by
// scraping at the receiver side; conflating transport failures with HTTP
// error codes would make caddyAdminErrorsTotal useless as a Caddy-down
// signal.
func TestInstrumentingTransportIgnoresHTTPErrorCodes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	beforeErrors := caddyAdminErrorsTotal.Value()

	transport := &instrumentingTransport{inner: http.DefaultTransport}
	client := &http.Client{Transport: transport}
	resp, err := client.Get(srv.URL + "/config/")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()

	if got := caddyAdminErrorsTotal.Value() - beforeErrors; got != 0 {
		t.Fatalf("errors delta = %d, want 0 even on HTTP 500 (transport succeeded)", got)
	}
}
