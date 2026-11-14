package service

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// The SDKs reach toolboxd's file watch through the v1 toolbox pass-through
// (plans/agent-sandbox-feature-parity.md F5, CEO review R2). The proxy wraps
// its writer in ToolboxStatusRecorder (O4), so this proves the WebSocket
// upgrade still crosses it both ways, with the sandbox's own token, and is
// counted once as a watch success; and that toolboxd's 501 on a shared-kernel
// runtime reaches the caller unchanged.
func TestToolboxReverseProxyCarriesFileWatchWebSocket(t *testing.T) {
	const id = "sb-watch"
	upstreamClosed := make(chan struct{})
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	toolbox := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/files/watch" || r.URL.Query().Get("path") != "/work" || r.URL.Query().Get("recursive") != "true" {
			http.Error(w, "unexpected "+r.URL.String(), http.StatusBadRequest)
			return
		}
		if r.URL.Query().Get("refuse") == "1" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotImplemented)
			_, _ = io.WriteString(w, `{"error":"file watching needs a gVisor or Firecracker sandbox"}`)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer token-"+id {
			http.Error(w, "toolbox saw Authorization "+got, http.StatusUnauthorized)
			return
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer close(upstreamClosed)
		defer conn.Close()
		_ = conn.WriteJSON(map[string]any{"type": "start", "path": "/work", "recursive": true})
		_ = conn.WriteJSON(map[string]any{"type": "events", "events": []map[string]any{{"type": "create", "path": "/work/a"}}})
		// Hold the socket until the client closes it.
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer toolbox.Close()

	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	port, err := strconv.Atoi(toolbox.URL[strings.LastIndex(toolbox.URL, ":")+1:])
	if err != nil {
		t.Fatal(err)
	}
	svc.cfg.ToolboxPort = port
	seedCallSandbox(t, st, id)
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := WithToolboxSurface(r.Context(), ToolboxSurfaceV1)
		if err := svc.ServeToolboxReverseProxy(ctx, id, w, r.WithContext(ctx), "/files/watch"); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
		}
	}))
	defer front.Close()
	wsURL := "ws" + strings.TrimPrefix(front.URL, "http") + "/v1/sandboxes/" + id + "/toolbox/files/watch?path=/work&recursive=true"

	okBefore := toolboxCallCount("v1", "watch", "2xx")
	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, http.Header{"Authorization": {"Bearer caller-pat"}})
	if err != nil {
		t.Fatalf("dial through the proxy: %v (resp %v)", err, resp)
	}
	var msg struct {
		Type   string           `json:"type"`
		Events []map[string]any `json:"events"`
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err := conn.ReadJSON(&msg); err != nil || msg.Type != "start" {
		t.Fatalf("first frame = %+v, %v", msg, err)
	}
	if err := conn.ReadJSON(&msg); err != nil || msg.Type != "events" || msg.Events[0]["path"] != "/work/a" {
		t.Fatalf("second frame = %+v, %v", msg, err)
	}
	_ = conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	_ = conn.Close()
	select {
	case <-upstreamClosed:
	case <-time.After(5 * time.Second):
		t.Fatal("closing the client did not close toolboxd's side")
	}
	deadline := time.Now().Add(5 * time.Second)
	for svc.toolboxCalls.inFlight(id) != 0 || toolboxCallCount("v1", "watch", "2xx") != okBefore+1 {
		if time.Now().After(deadline) {
			t.Fatalf("in flight %d, watch 2xx %d (was %d)", svc.toolboxCalls.inFlight(id), toolboxCallCount("v1", "watch", "2xx"), okBefore)
		}
		time.Sleep(5 * time.Millisecond)
	}

	refusedBefore := toolboxCallCount("v1", "watch", "501")
	_, resp, err = websocket.DefaultDialer.DialContext(context.Background(), wsURL+"&refuse=1", nil)
	if err == nil || resp == nil || resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("refused watch: err %v resp %v, want 501", err, resp)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "gVisor or Firecracker") {
		t.Fatalf("501 body = %s", body)
	}
	if got := toolboxCallCount("v1", "watch", "501"); got != refusedBefore+1 {
		t.Fatalf("watch 501 counted %d times, want 1", got-refusedBefore)
	}
}
