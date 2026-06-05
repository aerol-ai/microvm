package apiclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestSandboxCustomDomainWrappers(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost, http.MethodGet:
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"custom_domains": []models.CustomDomain{{
					Hostname:  "api.acme.com",
					Status:    models.CustomDomainPendingDNS,
					CreatedAt: time.Now().UTC(),
					UpdatedAt: time.Now().UTC(),
				}},
			})
		case http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()

	client := NewClient(server.URL, ClientOptions{PATToken: "pat", HTTPClient: server.Client()})
	sb := &Sandbox{Sandbox: models.Sandbox{ID: "sb1"}, client: client}

	domains, err := sb.AddCustomDomain(ctx, "api.acme.com", 0)
	if err != nil || len(domains) != 1 {
		t.Fatalf("AddCustomDomain = %v, %v", domains, err)
	}
	listed, err := sb.ListCustomDomains(ctx)
	if err != nil || len(listed) != 1 {
		t.Fatalf("ListCustomDomains = %v, %v", listed, err)
	}
	if err := sb.RemoveCustomDomain(ctx, "api.acme.com"); err != nil {
		t.Fatalf("RemoveCustomDomain = %v", err)
	}
}

func TestIsTransientTransportError(t *testing.T) {
	if isTransientTransportError(nil) {
		t.Fatal("nil should not be transient")
	}
	if isTransientTransportError(context.Canceled) {
		t.Fatal("context.Canceled should not be transient")
	}
	if !isTransientTransportError(context.DeadlineExceeded) {
		t.Fatal("DeadlineExceeded should be transient")
	}
	for _, msg := range []string{"connection refused", "connection reset by peer", "unexpected EOF", "broken pipe", "i/o timeout"} {
		if !isTransientTransportError(errors.New(msg)) {
			t.Fatalf("%q should be transient", msg)
		}
	}
	if isTransientTransportError(errors.New("some unrelated error")) {
		t.Fatal("unrelated error should not be transient")
	}
}

func TestIsRetryableStatusCode(t *testing.T) {
	for _, code := range []int{http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout} {
		if !isRetryableStatusCode(code) {
			t.Fatalf("%d should be retryable", code)
		}
	}
	for _, code := range []int{http.StatusOK, http.StatusBadRequest, http.StatusNotFound, http.StatusInternalServerError} {
		if isRetryableStatusCode(code) {
			t.Fatalf("%d should not be retryable", code)
		}
	}
}

func TestDoWithRetryRecoversAfter503(t *testing.T) {
	ctx := context.Background()
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(models.Sandbox{ID: "sb1", Status: models.SandboxStatusStarted})
	}))
	defer server.Close()

	client := NewClient(server.URL, ClientOptions{PATToken: "pat", HTTPClient: server.Client()})
	// GetSandbox flows through doWithRetry; the first 503 should be retried.
	if _, err := client.Get(ctx, "sb1"); err != nil {
		t.Fatalf("GetSandbox after retry: %v", err)
	}
	if calls < 2 {
		t.Fatalf("expected a retry, got %d calls", calls)
	}
}
