package apiclient

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// TestAddCustomDomainSendsHostnameAndDecodesEnvelope pins the POST wire shape
// {"hostname": "..."} and the response envelope {"custom_domains":[...]}.
// Drift here (e.g. someone renaming the JSON key, or unwrapping the envelope)
// silently breaks every caller because Go decoders skip unknown fields.
func TestAddCustomDomainSendsHostnameAndDecodesEnvelope(t *testing.T) {
	ctx := context.Background()
	var seenBody models.AddCustomDomainRequest
	var seenPath string
	var seenMethod string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenMethod = r.Method
		seenPath = r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&seenBody); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"custom_domains": []models.CustomDomain{{
				Hostname:  "api.acme.com",
				Status:    models.CustomDomainPendingDNS,
				CreatedAt: time.Now().UTC(),
				UpdatedAt: time.Now().UTC(),
			}},
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, ClientOptions{PATToken: "pat", HTTPClient: server.Client()})
	domains, err := client.AddCustomDomain(ctx, "sb-123", "api.acme.com")
	if err != nil {
		t.Fatalf("AddCustomDomain() error = %v", err)
	}
	if seenMethod != http.MethodPost {
		t.Fatalf("method = %q, want POST", seenMethod)
	}
	if seenPath != "/v1/sandboxes/sb-123/custom-domains" {
		t.Fatalf("path = %q, want /v1/sandboxes/sb-123/custom-domains", seenPath)
	}
	if seenBody.Hostname != "api.acme.com" {
		t.Fatalf("Hostname = %q, want api.acme.com", seenBody.Hostname)
	}
	if len(domains) != 1 || domains[0].Hostname != "api.acme.com" || domains[0].Status != models.CustomDomainPendingDNS {
		t.Fatalf("unexpected domains: %+v", domains)
	}
}

// TestListCustomDomainsDecodesEnvelope mirrors the add-path decoder check on
// the GET route — same shape, different verb.
func TestListCustomDomainsDecodesEnvelope(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/sandboxes/sb-1/custom-domains" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"custom_domains": []models.CustomDomain{
				{Hostname: "a.example.com", Status: models.CustomDomainReady},
				{Hostname: "b.example.com", Status: models.CustomDomainIssuing},
			},
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, ClientOptions{PATToken: "pat", HTTPClient: server.Client()})
	domains, err := client.ListCustomDomains(ctx, "sb-1")
	if err != nil {
		t.Fatalf("ListCustomDomains() error = %v", err)
	}
	if len(domains) != 2 {
		t.Fatalf("len(domains) = %d, want 2", len(domains))
	}
	if domains[0].Status != models.CustomDomainReady || domains[1].Status != models.CustomDomainIssuing {
		t.Fatalf("statuses out of order: %+v", domains)
	}
}

// TestRemoveCustomDomainURLEncodesHostname guards the URL-escaping rule for
// the path segment. Hostnames with dots are normal; this pins that a path
// helper isn't double-escaping or, worse, smuggling a "/" through to confuse
// the router.
func TestRemoveCustomDomainURLEncodesHostname(t *testing.T) {
	ctx := context.Background()
	var seenPath string
	var seenMethod string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenMethod = r.Method
		seenPath = r.URL.Path
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := NewClient(server.URL, ClientOptions{PATToken: "pat", HTTPClient: server.Client()})
	if err := client.RemoveCustomDomain(ctx, "sb-x", "api.acme.com"); err != nil {
		t.Fatalf("RemoveCustomDomain() error = %v", err)
	}
	if seenMethod != http.MethodDelete {
		t.Fatalf("method = %q, want DELETE", seenMethod)
	}
	// Server decodes the path segment, so api.acme.com stays human-readable
	// on the wire. The escape guard kicks in only for non-ASCII / reserved
	// chars; this assertion pins the happy path so the helper is exercised.
	if seenPath != "/v1/sandboxes/sb-x/custom-domains/api.acme.com" {
		t.Fatalf("path = %q, want /v1/sandboxes/sb-x/custom-domains/api.acme.com", seenPath)
	}
}

// TestCreateForwardsCustomDomains proves the create-time custom_domains
// field rides on the wire under its snake_case JSON name. Without this, a
// silent rename (e.g. someone retypes the tag) means CreateSandbox attaches
// nothing and callers only discover the gap when their cert never issues.
func TestCreateForwardsCustomDomains(t *testing.T) {
	ctx := context.Background()
	var seen models.CreateSandboxRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&seen); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		_ = json.NewEncoder(w).Encode(models.CreateSandboxResponse{
			Sandbox: models.Sandbox{
				ID:     "sb-cd",
				Image:  "ubuntu:22.04",
				Status: models.SandboxStatusStarted,
				CustomDomains: []models.CustomDomain{{
					Hostname: "api.acme.com",
					Status:   models.CustomDomainPendingDNS,
				}},
			},
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, ClientOptions{PATToken: "pat", HTTPClient: server.Client()})
	sandbox, _, err := client.Create(ctx, CreateOptions{
		Image:         "ubuntu:22.04",
		CustomDomains: []string{"api.acme.com"},
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if len(seen.CustomDomains) != 1 || seen.CustomDomains[0] != "api.acme.com" {
		t.Fatalf("wire CustomDomains = %+v, want [api.acme.com]", seen.CustomDomains)
	}
	if len(sandbox.CustomDomains) != 1 || sandbox.CustomDomains[0].Hostname != "api.acme.com" {
		t.Fatalf("response CustomDomains = %+v", sandbox.CustomDomains)
	}
}
