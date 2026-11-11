package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/runtime"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/caddy"
)

// pingRuntime answers Health's runtime ping; nothing else is called.
type pingRuntime struct{ runtime.Runtime }

func (pingRuntime) Ping(context.Context) error { return nil }

// C1: GET /ready answers readiness probes without a token, 200 when the
// node should get traffic and 503 with the reason when not.
func TestReadyRoute(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	newServer := func(t *testing.T) (*httptest.Server, *store.Store) {
		t.Helper()
		st, err := store.Open(filepath.Join(t.TempDir(), "ready.db"))
		if err != nil {
			t.Fatal(err)
		}
		svc := service.New(config.Config{}, logger, st, pingRuntime{}, nil, caddy.New(config.Config{}), nil, nil, nil)
		srv := httptest.NewServer(NewServer(logger, svc, nil, nil, config.Config{}, "pat-token", nil).Handler())
		t.Cleanup(srv.Close)
		return srv, st
	}
	get := func(t *testing.T, url string) (int, map[string]string) {
		t.Helper()
		resp, err := http.Get(url + "/ready")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var body map[string]string
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return resp.StatusCode, body
	}

	t.Run("ready", func(t *testing.T) {
		srv, st := newServer(t)
		t.Cleanup(func() { _ = st.Close() })
		if code, body := get(t, srv.URL); code != http.StatusOK || body["status"] != "ready" {
			t.Fatalf("GET /ready = %d %v, want 200 ready", code, body)
		}
	})
	t.Run("not ready", func(t *testing.T) {
		srv, st := newServer(t)
		_ = st.Close()
		code, body := get(t, srv.URL)
		if code != http.StatusServiceUnavailable || body["status"] != "not_ready" || body["reason"] == "" {
			t.Fatalf("GET /ready = %d %v, want 503 not_ready with a reason", code, body)
		}
	})
}
