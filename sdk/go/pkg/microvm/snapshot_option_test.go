package microvm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// CreateSnapshot sends allow_pause only when WithAllowPause is given, so the
// default request is unchanged and the server keeps its default (pause a
// running sandbox briefly).
func TestCreateSnapshotSendsAllowPauseOnlyWhenSet(t *testing.T) {
	var mu sync.Mutex
	var bodies []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/sandboxes/sb-pause/snapshot" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Errorf("decode body %q: %v", raw, err)
		}
		mu.Lock()
		bodies = append(bodies, body)
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(models.SandboxSnapshot{
			Name: "snap", Image: "aerolvm-snapshot/abc:latest", SourceSandboxID: "sb-pause", CreatedAt: time.Now().UTC(),
		})
	}))
	defer server.Close()

	client, err := NewClientWithConfig(&sdktypes.MicroVMConfig{PATToken: "pat", APIUrl: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := client.CreateSnapshot(ctx, "sb-pause", "snap"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.CreateSnapshot(ctx, "sb-pause", "snap", WithAllowPause(false)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.CreateSnapshot(ctx, "sb-pause", "snap", WithAllowPause(true)); err != nil {
		t.Fatal(err)
	}
	sb := &Sandbox{Sandbox: sdktypes.Sandbox{ID: "sb-pause"}, client: client}
	if _, err := sb.CreateSnapshot(ctx, "snap", WithAllowPause(false)); err != nil {
		t.Fatal(err)
	}

	want := []map[string]any{
		{"name": "snap"},
		{"name": "snap", "allow_pause": false},
		{"name": "snap", "allow_pause": true},
		{"name": "snap", "allow_pause": false},
	}
	if !reflect.DeepEqual(bodies, want) {
		t.Fatalf("request bodies = %v, want %v", bodies, want)
	}
}
