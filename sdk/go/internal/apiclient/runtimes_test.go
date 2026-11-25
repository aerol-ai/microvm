package apiclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestListRuntimes(t *testing.T) {
	two := 2
	tests := []struct {
		name  string
		reply string
		want  []models.RuntimeListEntry
	}{
		{
			name: "tenant view: features, limits and availability, no node count",
			reply: `{"runtimes":[` +
				`{"name":"firecracker","isolation":"hardware-vm","backend":"kvm","features":{"snapshots":true,"pause":true,"moves":"memory","warm_pool":"snapshot","confidential":false},"available":true},` +
				`{"name":"wasm","isolation":"wasm","features":{"snapshots":false,"pause":false,"moves":"memory","warm_pool":"parked","confidential":false},"limits":{"max_checkpoint_memory_mb":1024},"available":false}]}`,
			want: []models.RuntimeListEntry{
				{Name: "firecracker", Isolation: "hardware-vm", Backend: "kvm", Available: true,
					Features: models.RuntimeFeatures{Snapshots: true, Pause: true, Moves: "memory", WarmPool: "snapshot"}},
				{Name: "wasm", Isolation: "wasm", Limits: &models.RuntimeLimits{MaxCheckpointMemoryMB: 1024},
					Features: models.RuntimeFeatures{Moves: "memory", WarmPool: "parked"}},
			},
		},
		{
			name:  "fleet admin view carries the node count",
			reply: `{"runtimes":[{"name":"docker","isolation":"container","features":{"snapshots":true,"moves":"none","warm_pool":"parked"},"available":true,"nodes":2}]}`,
			want: []models.RuntimeListEntry{{Name: "docker", Isolation: "container", Available: true, Nodes: &two,
				Features: models.RuntimeFeatures{Snapshots: true, Moves: "none", WarmPool: "parked"}}},
		},
		{
			name:  "a null list is an empty one",
			reply: `{"runtimes":null}`,
			want:  []models.RuntimeListEntry{},
		},
		{
			name:  "a field this client does not know is ignored",
			reply: `{"runtimes":[{"name":"gvisor","isolation":"user-space-kernel","features":{"moves":"memory","warm_pool":"parked","later":true},"available":true,"later":"x"}]}`,
			want: []models.RuntimeListEntry{{Name: "gvisor", Isolation: "user-space-kernel", Available: true,
				Features: models.RuntimeFeatures{Moves: "memory", WarmPool: "parked"}}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/v1/runtimes" {
					t.Errorf("request = %s %s, want GET /v1/runtimes", r.Method, r.URL.Path)
				}
				_, _ = w.Write([]byte(tt.reply))
			}))
			defer server.Close()
			client := NewClient(server.URL, ClientOptions{PATToken: "pat", HTTPClient: server.Client()})
			got, err := client.ListRuntimes(context.Background())
			if err != nil {
				t.Fatalf("ListRuntimes: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("ListRuntimes = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestListRuntimesRefusal: a refused list returns the APIError and no rows,
// so a caller never reads a half list as "nothing is offered".
func TestListRuntimesRefusal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"forbidden"}`))
	}))
	defer server.Close()
	client := NewClient(server.URL, ClientOptions{PATToken: "sbt", HTTPClient: server.Client()})
	got, err := client.ListRuntimes(context.Background())
	var apiErr *APIError
	if got != nil || !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusForbidden {
		t.Fatalf("ListRuntimes = (%+v, %v), want no rows and a 403 APIError", got, err)
	}
}
