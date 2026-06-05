package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// configureFlags points the package-level flag vars at a test server.
func configureFlags(t *testing.T, baseURL string) {
	t.Helper()
	*apiURL = baseURL
	*patToken = "test-pat"
	*imageRef = "alpine:3.19"
	*probeTimeout = time.Second
}

func TestCreateAndDestroySandbox(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/sandboxes":
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(createResponse{ID: "sb-load", PublicURL: "http://" + r.Host + "/ingress"})
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()
	configureFlags(t, srv.URL)

	id, _, status, err := createSandbox()
	if err != nil || id != "sb-load" || status != http.StatusCreated {
		t.Fatalf("createSandbox = %q, %d, %v", id, status, err)
	}

	dstatus, err := destroySandbox(id)
	if err != nil || dstatus != http.StatusNoContent {
		t.Fatalf("destroySandbox = %d, %v", dstatus, err)
	}
}

func TestCreateSandboxErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	configureFlags(t, srv.URL)

	_, _, status, err := createSandbox()
	if err == nil || status != http.StatusInternalServerError {
		t.Fatalf("expected 500 error, got status=%d err=%v", status, err)
	}
}

func TestProbeIngress(t *testing.T) {
	// Empty URL short-circuits.
	if status, lag := probeIngress(""); status != 0 || lag != 0 {
		t.Fatalf("probeIngress(empty) = %d, %v", status, lag)
	}

	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if hits < 2 {
			w.WriteHeader(http.StatusServiceUnavailable) // in-flux
			return
		}
		w.WriteHeader(http.StatusOK) // converged
	}))
	defer srv.Close()
	configureFlags(t, srv.URL)

	status, lag := probeIngress(srv.URL)
	if status != http.StatusOK {
		t.Fatalf("probeIngress status = %d, want 200", status)
	}
	if lag <= 0 {
		t.Fatalf("expected positive convergence lag, got %v", lag)
	}
}

func TestRunOnce(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(createResponse{ID: "sb-run", PublicURL: "http://" + r.Host + "/x"})
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()
	configureFlags(t, srv.URL)

	samples := make(chan sample, 8)
	runOnce(samples)
	close(samples)

	ops := map[string]bool{}
	for s := range samples {
		ops[s.op] = true
	}
	for _, want := range []string{"create", "probe", "destroy"} {
		if !ops[want] {
			t.Fatalf("runOnce missing %q sample; got %v", want, ops)
		}
	}
}
