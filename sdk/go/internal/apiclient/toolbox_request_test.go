package apiclient

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestToolboxRequest(t *testing.T) {
	var gets, posts int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer pat" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/sandboxes/sb-1/toolbox/files":
			gets++
			if gets == 1 {
				w.WriteHeader(http.StatusServiceUnavailable) // retried
				return
			}
			_, _ = w.Write([]byte(`["a.txt"]` + "|" + r.URL.Query().Get("path")))
		case r.Method == http.MethodPost && r.URL.Path == "/v1/sandboxes/sb-1/toolbox/process/execute":
			posts++
			body, _ := io.ReadAll(r.Body)
			if r.Header.Get("Content-Type") != "application/json" {
				http.Error(w, "content type", http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusBadGateway) // not retried: a body means once
			_, _ = w.Write([]byte(`{"error":"upstream ` + string(body) + `"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	base := 1
	client := NewClient(server.URL, ClientOptions{PATToken: "pat", HTTPClient: server.Client(), Retry: &RetryConfig{BaseDelayMs: &base, MaxDelayMs: &base}})
	ctx := context.Background()

	resp, err := client.ToolboxRequest(ctx, "sb-1", http.MethodGet, "/files", url.Values{"path": {"/work"}}, nil, "")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(b) != `["a.txt"]|/work` || gets != 2 {
		t.Fatalf("GET body %q after %d attempts", b, gets)
	}
	_, err = client.ToolboxRequest(ctx, "sb-1", http.MethodPost, "process/execute", nil, []byte(`x`), "application/json")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusBadGateway || apiErr.Message != "upstream x" {
		t.Fatalf("POST error = %v", err)
	}
	if posts != 1 {
		t.Fatalf("POST sent %d times, want 1", posts)
	}
	if _, err := client.ToolboxRequest(ctx, "sb-1", http.MethodGet, "/nope", nil, nil, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing route error = %v, want ErrNotFound", err)
	}
	if _, err := client.ToolboxRequest(ctx, "sb-1", "BAD METHOD", "/files", nil, []byte("x"), ""); err == nil {
		t.Fatal("an unbuildable request must fail")
	}
}
