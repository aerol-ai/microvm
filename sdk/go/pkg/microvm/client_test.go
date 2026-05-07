package microvm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

func TestNewClientCases(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "new_client_uses_environment_config",
			run: func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Header.Get("Authorization") != "Bearer env-pat" {
						t.Fatalf("unexpected authorization header: %q", r.Header.Get("Authorization"))
					}
					_ = json.NewEncoder(w).Encode([]models.Sandbox{})
				}))
				defer server.Close()

				t.Setenv("SB_PAT_TOKEN", "env-pat")
				t.Setenv("SB_API_URL", server.URL)

				client, err := NewClient()
				if err != nil {
					t.Fatalf("NewClient() error = %v", err)
				}
				if _, err := client.List(ctx); err != nil {
					t.Fatalf("List() error = %v", err)
				}
			},
		},
		{
			name: "new_client_with_config_wraps_sandbox_resource",
			run: func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Header.Get("Authorization") != "Bearer config-pat" {
						t.Fatalf("unexpected authorization header: %q", r.Header.Get("Authorization"))
					}
					if r.Method != http.MethodPost || r.URL.Path != "/v1/sandboxes" {
						t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
					}
					_ = json.NewEncoder(w).Encode(models.Sandbox{ID: "sb-structured", Image: "ubuntu:22.04", Status: models.SandboxStatusStarted})
				}))
				defer server.Close()

				client, err := NewClientWithConfig(&sdktypes.MicroVMConfig{
					PATToken: "config-pat",
					APIUrl:   server.URL,
				})
				if err != nil {
					t.Fatalf("NewClientWithConfig() error = %v", err)
				}

				sandbox, err := client.Create(ctx, sdktypes.CreateSandboxOptions{Image: "ubuntu:22.04"})
				if err != nil {
					t.Fatalf("Create() error = %v", err)
				}
				if sandbox.ID != "sb-structured" {
					t.Fatalf("unexpected sandbox: %+v", sandbox)
				}
			},
		},
		{
			name: "new_client_requires_pat_token",
			run: func(t *testing.T) {
				t.Setenv("SB_PAT_TOKEN", "")
				_, err := NewClientWithConfig(&sdktypes.MicroVMConfig{})
				if err == nil {
					t.Fatal("expected auth error")
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, tc.run)
	}
}
