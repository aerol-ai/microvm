package microvm

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

func TestCodeInterpreterClientAndSandboxWrappers(t *testing.T) {
	ctx := context.Background()
	ctxJSON := `{"id":"c1","language":"python","cwd":"/w","createdAt":"2026-11-15T10:00:00Z","active":true}`
	var upgrader websocket.Upgrader
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const base = "/v1/sandboxes/sb-1/toolbox/process/interpreter"
		switch r.Method + " " + r.URL.Path {
		case "GET /v1/sandboxes/sb-1/toolbox/version":
			_ = json.NewEncoder(w).Encode(map[string]any{"features": []string{FeatureCodeInterpreter}})
		case "POST " + base + "/context", "GET " + base + "/context/c1", "POST " + base + "/context/c1/restart":
			_, _ = io.WriteString(w, ctxJSON)
		case "GET " + base + "/context":
			_, _ = io.WriteString(w, `{"contexts":[`+ctxJSON+`]}`)
		case "DELETE " + base + "/context/c1":
			_, _ = io.WriteString(w, `{"message":"Context deleted successfully"}`)
		case "GET " + base + "/execute":
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer conn.Close()
			var start struct {
				Code      string `json:"code"`
				ContextID string `json:"contextId"`
			}
			if err := conn.ReadJSON(&start); err != nil {
				return
			}
			if start.ContextID == "slow" {
				_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(4008, "timed out"), time.Now().Add(time.Second))
				_, _, _ = conn.ReadMessage()
				return
			}
			_ = conn.WriteJSON(map[string]any{"type": "result", "text": start.Code, "is_main_result": true})
			_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second))
			_, _, _ = conn.ReadMessage()
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewClientWithConfig(&sdktypes.MicroVMConfig{PATToken: "pat", APIUrl: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("NewClientWithConfig: %v", err)
	}
	sb := &Sandbox{Sandbox: sdktypes.Sandbox{ID: "sb-1"}, client: client}

	check := func(name string, got sdktypes.CodeContext, err error) {
		t.Helper()
		if err != nil || got.ID != "c1" || !got.Active {
			t.Fatalf("%s = (%+v, %v)", name, got, err)
		}
	}
	got, err := client.CreateCodeContext(ctx, "sb-1", sdktypes.CodeContextOptions{Cwd: "/w"})
	check("client.CreateCodeContext", got, err)
	got, err = sb.CreateCodeContext(ctx, sdktypes.CodeContextOptions{})
	check("sandbox.CreateCodeContext", got, err)
	got, err = client.GetCodeContext(ctx, "sb-1", "c1")
	check("client.GetCodeContext", got, err)
	got, err = sb.GetCodeContext(ctx, "c1")
	check("sandbox.GetCodeContext", got, err)
	got, err = client.RestartCodeContext(ctx, "sb-1", "c1")
	check("client.RestartCodeContext", got, err)
	got, err = sb.RestartCodeContext(ctx, "c1")
	check("sandbox.RestartCodeContext", got, err)
	if list, err := client.ListCodeContexts(ctx, "sb-1"); err != nil || len(list) != 1 {
		t.Fatalf("client.ListCodeContexts = (%+v, %v)", list, err)
	}
	if list, err := sb.ListCodeContexts(ctx); err != nil || len(list) != 1 {
		t.Fatalf("sandbox.ListCodeContexts = (%+v, %v)", list, err)
	}
	if err := client.DeleteCodeContext(ctx, "sb-1", "c1"); err != nil {
		t.Fatalf("client.DeleteCodeContext: %v", err)
	}
	if err := sb.DeleteCodeContext(ctx, "c1"); err != nil {
		t.Fatalf("sandbox.DeleteCodeContext: %v", err)
	}
	if _, err := sb.GetCodeContext(ctx, "gone"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown context: %v", err)
	}

	exec, err := client.RunCode(ctx, "sb-1", "1+1", sdktypes.RunCodeOptions{ContextID: "c1"})
	if err != nil || exec.Text() != "1+1" {
		t.Fatalf("client.RunCode = (%+v, %v)", exec, err)
	}
	exec, err = sb.RunCode(ctx, "x", sdktypes.RunCodeOptions{})
	if err != nil || exec.Text() != "x" {
		t.Fatalf("sandbox.RunCode = (%+v, %v)", exec, err)
	}
	_, err = sb.RunCode(ctx, "x", sdktypes.RunCodeOptions{ContextID: "slow"})
	var runErr *CodeRunError
	if !errors.As(err, &runErr) || !errors.Is(err, ErrCodeRunTimeout) || runErr.Execution == nil {
		t.Fatalf("timed-out run: %v", err)
	}
}

func TestCodeInterpreterUnsupportedAgent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"version": "0.7.5", "features": []string{}})
	}))
	defer server.Close()
	client, err := NewClientWithConfig(&sdktypes.MicroVMConfig{PATToken: "pat", APIUrl: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.RunCode(context.Background(), "sb-1", "x", sdktypes.RunCodeOptions{})
	var unsupported *UnsupportedFeatureError
	if !errors.Is(err, ErrUnsupportedFeature) || !errors.As(err, &unsupported) || unsupported.Features[0] != FeatureCodeInterpreter {
		t.Fatalf("err = %v", err)
	}
}
