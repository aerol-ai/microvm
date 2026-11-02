package apiclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

var generatedKey = regexp.MustCompile(`^[0-9a-f]{32}$`)

// keyServer answers request N with script[N] ("ok", "503", "drop" or "422";
// the last entry repeats) and records each request's Idempotency-Key and
// body.
type keyServer struct {
	mu     sync.Mutex
	keys   []string
	paths  []string
	bodies []map[string]any
}

func (k *keyServer) start(t *testing.T, script ...string) *Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		k.mu.Lock()
		k.keys = append(k.keys, r.Header.Get(HeaderIdempotencyKey))
		k.paths = append(k.paths, r.Method+" "+r.URL.Path)
		k.bodies = append(k.bodies, body)
		step := script[min(len(k.keys), len(script))-1]
		k.mu.Unlock()
		switch step {
		case "drop":
			dropConnection(t, w)
		case "503":
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":"egress deny floor not ready","code":"egress_floor_not_ready"}`))
		case "422":
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = w.Write([]byte(`{"error":"Idempotency-Key reused","code":"idempotency_key_reused"}`))
		default:
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(models.CreateSandboxResponse{Sandbox: models.Sandbox{ID: "sb-keyed"}})
		}
	}))
	t.Cleanup(server.Close)
	return fastRetryClient(server.URL, server.Client())
}

func (k *keyServer) seen() []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]string(nil), k.keys...)
}

// TestCreateIdempotencyKey: a create carries an Idempotency-Key, the
// caller's or one made per call, unchanged on every automatic retry.
func TestCreateIdempotencyKey(t *testing.T) {
	tests := []struct {
		name   string
		script []string
		key    string
		want   string // "" = a generated key
		sends  int
	}{
		{name: "caller's key", script: []string{"ok"}, key: " order-42 ", want: "order-42", sends: 1},
		{name: "caller's key across a 503", script: []string{"503", "ok"}, key: "order-42", want: "order-42", sends: 2},
		{name: "generated key", script: []string{"ok"}, sends: 1},
		{name: "blank key is generated", script: []string{"ok"}, key: "   ", sends: 1},
		{name: "generated key across two 503s", script: []string{"503", "503", "ok"}, sends: 3},
		{name: "generated key across dropped connections", script: []string{"drop", "drop", "ok"}, sends: 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var srv keyServer
			client := srv.start(t, tt.script...)
			sb, _, err := client.CreateWithIdempotencyKey(context.Background(), CreateOptions{Image: "ubuntu:22.04"}, tt.key)
			if err != nil || sb.ID != "sb-keyed" {
				t.Fatalf("CreateWithIdempotencyKey = %+v, %v", sb, err)
			}
			keys := srv.seen()
			if len(keys) != tt.sends {
				t.Fatalf("server saw %d creates, want %d", len(keys), tt.sends)
			}
			want := tt.want
			if want == "" {
				if !generatedKey.MatchString(keys[0]) {
					t.Fatalf("generated key %q is not 32 hex characters", keys[0])
				}
				want = keys[0]
			}
			for i, key := range keys {
				if key != want {
					t.Fatalf("attempt %d sent key %q, want %q (every attempt %q)", i+1, key, want, keys)
				}
			}
			for _, field := range []string{"idempotency_key", "IdempotencyKey"} {
				if _, ok := srv.bodies[0][field]; ok {
					t.Fatalf("the key leaked into the body as %q", field)
				}
			}
		})
	}
}

func TestCreateMakesANewKeyPerCall(t *testing.T) {
	var srv keyServer
	client := srv.start(t, "ok")
	for range 3 {
		if _, _, err := client.Create(context.Background(), CreateOptions{Image: "ubuntu:22.04"}); err != nil {
			t.Fatal(err)
		}
	}
	keys := srv.seen()
	if len(keys) != 3 || keys[0] == keys[1] || keys[1] == keys[2] || keys[0] == keys[2] {
		t.Fatalf("three creates sent keys %q, want three different ones", keys)
	}
}

func TestCreateKeyReusedIsNotRetried(t *testing.T) {
	var srv keyServer
	client := srv.start(t, "422")
	_, _, err := client.CreateWithIdempotencyKey(context.Background(), CreateOptions{Image: "ubuntu:22.04"}, "order-42")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusUnprocessableEntity || apiErr.Code != "idempotency_key_reused" {
		t.Fatalf("error = %#v, want a 422 idempotency_key_reused", err)
	}
	if n := len(srv.seen()); n != 1 {
		t.Fatalf("server saw %d creates, want 1", n)
	}
}

// Only the sandbox create carries the header: exec in particular must not.
func TestOnlySandboxCreateSendsIdempotencyKey(t *testing.T) {
	var srv keyServer
	client := srv.start(t, "ok")
	ctx := context.Background()
	_, _ = client.Get(ctx, "sb-keyed")
	_, _ = client.Exec(ctx, "sb-keyed", ExecRequest{Command: "true"})
	_, _ = client.CreateSnapshot(ctx, "sb-keyed", "snap")
	for i, key := range srv.seen() {
		if key != "" {
			t.Fatalf("%s sent Idempotency-Key %q", srv.paths[i], key)
		}
	}
}

func TestNewIdempotencyKey(t *testing.T) {
	seen := map[string]bool{}
	for range 1000 {
		key := newIdempotencyKey()
		if !generatedKey.MatchString(key) || seen[key] {
			t.Fatalf("key %q is malformed or repeated", key)
		}
		seen[key] = true
	}
}
