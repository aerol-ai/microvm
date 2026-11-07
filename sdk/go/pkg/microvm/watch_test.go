package microvm

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/websocket"

	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

func TestSandboxWatchFiles(t *testing.T) {
	var upgrader websocket.Upgrader
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sandboxes/sb-w/toolbox/files/watch" || r.URL.Query().Get("path") != "/work" {
			http.Error(w, `{"error":"unexpected `+r.URL.String()+`"}`, http.StatusBadRequest)
			return
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.WriteJSON(map[string]any{"type": "start", "path": "/work"})
		_ = conn.WriteJSON(map[string]any{"type": "events", "events": []map[string]any{{"type": "write", "path": "/work/a"}}})
		_, _, _ = conn.ReadMessage()
	}))
	defer server.Close()
	client, err := NewClientWithConfig(&sdktypes.MicroVMConfig{PATToken: "pat", APIUrl: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	sb := &Sandbox{Sandbox: sdktypes.Sandbox{ID: "sb-w"}, client: client}
	got := make(chan sdktypes.FileEvent, 1)
	h, err := sb.WatchFiles(context.Background(), "/work", sdktypes.WatchOptions{OnEvent: func(ev sdktypes.FileEvent) { got <- ev }})
	if err != nil {
		t.Fatal(err)
	}
	if ev := <-got; ev.Type != sdktypes.FileEventWrite || ev.Path != "/work/a" {
		t.Fatalf("event = %+v", ev)
	}
	if err := h.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := h.Wait(); err != nil {
		t.Fatalf("Wait after Stop = %v", err)
	}
	<-h.Done()

	if _, err := client.WatchFiles(context.Background(), "sb-other", "/work", sdktypes.WatchOptions{}); err == nil {
		t.Fatal("a refused handshake returned no error")
	}
	var apiErr *APIError
	_, err = client.WatchFiles(context.Background(), "sb-other", "/work", sdktypes.WatchOptions{})
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusBadRequest {
		t.Fatalf("err = %v, want the 400 as an APIError", err)
	}
	if FeatureFilesWatch != "files.watch" {
		t.Fatalf("FeatureFilesWatch = %q", FeatureFilesWatch)
	}
}
