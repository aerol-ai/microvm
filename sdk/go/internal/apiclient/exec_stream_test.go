package apiclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/gorilla/websocket"

	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

func TestExecStreamReceivesFramesAndExit(t *testing.T) {
	var upgrader websocket.Upgrader
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer pat-token" {
			t.Fatalf("unexpected authorization: %q", r.Header.Get("Authorization"))
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Fatalf("Upgrade() error = %v", err)
		}
		defer conn.Close()

		var start map[string]any
		if err := conn.ReadJSON(&start); err != nil {
			t.Fatalf("ReadJSON() error = %v", err)
		}
		if start["command"] != "npm install" {
			t.Fatalf("unexpected start payload: %+v", start)
		}

		if err := conn.WriteMessage(websocket.BinaryMessage, append([]byte{streamPrefixStdout}, []byte("hello")...)); err != nil {
			t.Fatalf("WriteMessage(stdout) error = %v", err)
		}
		if err := conn.WriteMessage(websocket.BinaryMessage, append([]byte{streamPrefixStderr}, []byte("warn")...)); err != nil {
			t.Fatalf("WriteMessage(stderr) error = %v", err)
		}
		if err := conn.WriteJSON(map[string]any{"type": "exit", "code": 0}); err != nil {
			t.Fatalf("WriteJSON(exit) error = %v", err)
		}
	}))
	defer server.Close()

	var stdout string
	var stderr string
	client := NewClient(server.URL, ClientOptions{PATToken: "pat-token", HTTPClient: server.Client()})
	handle, err := client.ExecStream(context.Background(), "sb-stream", sdktypes.ExecStreamOptions{
		Command:  "npm install",
		OnStdout: func(chunk []byte) { stdout += string(chunk) },
		OnStderr: func(chunk []byte) { stderr += string(chunk) },
	})
	if err != nil {
		t.Fatalf("ExecStream() error = %v", err)
	}

	exit, err := handle.Wait()
	if err != nil {
		t.Fatalf("Wait() error = %v", err)
	}
	if stdout != "hello" || stderr != "warn" {
		t.Fatalf("unexpected stream output stdout=%q stderr=%q", stdout, stderr)
	}
	if exit.Code != 0 {
		t.Fatalf("unexpected exit info: %+v", exit)
	}
}

func TestExecStreamSendsControlMessages(t *testing.T) {
	var upgrader websocket.Upgrader
	var gotBinary []byte
	var gotTexts []map[string]any
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Fatalf("Upgrade() error = %v", err)
		}
		defer conn.Close()

		var start map[string]any
		if err := conn.ReadJSON(&start); err != nil {
			t.Fatalf("ReadJSON(start) error = %v", err)
		}

		for i := 0; i < 3; i += 1 {
			messageType, payload, err := conn.ReadMessage()
			if err != nil {
				t.Fatalf("ReadMessage(%d) error = %v", i, err)
			}
			mu.Lock()
			if messageType == websocket.BinaryMessage {
				gotBinary = append([]byte(nil), payload...)
			} else {
				var item map[string]any
				if err := json.Unmarshal(payload, &item); err != nil {
					mu.Unlock()
					t.Fatalf("Unmarshal(control) error = %v", err)
				}
				gotTexts = append(gotTexts, item)
			}
			mu.Unlock()
		}

		if err := conn.WriteJSON(map[string]any{"type": "exit", "code": 0}); err != nil {
			t.Fatalf("WriteJSON(exit) error = %v", err)
		}
	}))
	defer server.Close()

	client := NewClient(server.URL, ClientOptions{PATToken: "pat-token", HTTPClient: server.Client()})
	handle, err := client.ExecStream(context.Background(), "sb-stream", sdktypes.ExecStreamOptions{Command: "bash"})
	if err != nil {
		t.Fatalf("ExecStream() error = %v", err)
	}
	if err := handle.WriteString("pwd\n"); err != nil {
		t.Fatalf("WriteString() error = %v", err)
	}
	if err := handle.Resize(120, 40); err != nil {
		t.Fatalf("Resize() error = %v", err)
	}
	if err := handle.Signal("INT"); err != nil {
		t.Fatalf("Signal() error = %v", err)
	}

	if _, err := handle.Wait(); err != nil {
		t.Fatalf("Wait() error = %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if string(gotBinary) != "pwd\n" {
		t.Fatalf("unexpected binary payload: %q", string(gotBinary))
	}
	if len(gotTexts) != 2 {
		t.Fatalf("unexpected control messages: %+v", gotTexts)
	}
	if gotTexts[0]["type"] != "resize" || int(gotTexts[0]["cols"].(float64)) != 120 || int(gotTexts[0]["rows"].(float64)) != 40 {
		t.Fatalf("unexpected resize payload: %+v", gotTexts[0])
	}
	if gotTexts[1]["type"] != "signal" || gotTexts[1]["signal"] != "INT" {
		t.Fatalf("unexpected signal payload: %+v", gotTexts[1])
	}
}
