package apiclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// ER4: calls that send a newer option first check the agent lists it, and
// fail closed against an older toolboxd instead of having it ignored.
func TestRequireToolboxFeatures(t *testing.T) {
	ctx := context.Background()
	var calls atomic.Int32
	features := []string{"files.create_only"}
	version := "0.6.12"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sandboxes/sb-1/toolbox/version" {
			http.NotFound(w, r)
			return
		}
		calls.Add(1)
		body := map[string]any{"version": version}
		if features != nil {
			body["features"] = features
		}
		_ = json.NewEncoder(w).Encode(body)
	}))
	defer server.Close()
	client := NewClient(server.URL, ClientOptions{PATToken: "t", HTTPClient: server.Client()})

	if err := client.RequireToolboxFeatures(ctx, "sb-1"); err != nil || calls.Load() != 0 {
		t.Fatalf("no features: err=%v calls=%d, want no call", err, calls.Load())
	}
	if err := client.RequireToolboxFeatures(ctx, "sb-1", "files.create_only"); err != nil {
		t.Fatalf("listed feature refused: %v", err)
	}
	if err := client.RequireToolboxFeatures(ctx, "sb-1", "files.create_only"); err != nil || calls.Load() != 1 {
		t.Fatalf("cached check: err=%v calls=%d, want one /version call", err, calls.Load())
	}

	// A miss refetches (a restart can bring a newer agent) and names only
	// what is missing.
	err := client.RequireToolboxFeatures(ctx, "sb-1", "files.create_only", "exec.max_output_bytes")
	if !errors.Is(err, ErrUnsupportedFeature) {
		t.Fatalf("err = %v, want ErrUnsupportedFeature", err)
	}
	var unsupported *UnsupportedFeatureError
	if !errors.As(err, &unsupported) || unsupported.SandboxID != "sb-1" || unsupported.AgentVersion != "0.6.12" ||
		len(unsupported.Features) != 1 || unsupported.Features[0] != "exec.max_output_bytes" {
		t.Fatalf("details = %+v", unsupported)
	}
	if !strings.Contains(err.Error(), "toolboxd 0.6.12") || calls.Load() != 2 {
		t.Fatalf("message %q, calls %d", err.Error(), calls.Load())
	}

	// An agent older than the features list sends none.
	features, version = nil, ""
	err = client.RequireToolboxFeatures(ctx, "sb-1", "exec.max_output_bytes")
	if !errors.As(err, &unsupported) || !strings.Contains(err.Error(), "an older toolboxd") {
		t.Fatalf("pre-features agent: %v", err)
	}

	// A failed /version call is returned as is, not as unsupported.
	err = client.RequireToolboxFeatures(ctx, "sb-missing", "files.create_only")
	if err == nil || errors.Is(err, ErrUnsupportedFeature) {
		t.Fatalf("missing sandbox: %v", err)
	}
}
