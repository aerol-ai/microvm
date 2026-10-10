package apiclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/websocket"

	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// streamServer accepts one stream, reads the client's first message, then
// sends frame, or drops the connection when frame is nil.
func streamServer(t *testing.T, frame map[string]any) *httptest.Server {
	t.Helper()
	var upgrader websocket.Upgrader
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade: %v", err)
			return
		}
		defer conn.Close()
		if _, _, err := conn.ReadMessage(); err != nil {
			return
		}
		if frame != nil {
			_ = conn.WriteJSON(frame)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

// A toolbox "error" frame is a *StreamError carrying the toolbox's message
// as is; a dropped stream is not, so callers can tell "the command could
// not start" from "the connection went away".
func TestStreamErrorFramesAreTyped(t *testing.T) {
	const reason = "this sandbox's image has no shell: neither bash nor sh is installed"
	waits := map[string]func(*httptest.Server) error{
		"exec": func(server *httptest.Server) error {
			client := NewClient(server.URL, ClientOptions{PATToken: "tok", HTTPClient: server.Client()})
			h, err := client.ExecStream(context.Background(), "sb-1", sdktypes.ExecStreamOptions{Command: "true"})
			if err != nil {
				t.Fatalf("ExecStream: %v", err)
			}
			_, err = h.Wait()
			return err
		},
		"session": func(server *httptest.Server) error {
			client := NewClient(server.URL, ClientOptions{PATToken: "tok", HTTPClient: server.Client()})
			h, err := client.AttachSession(context.Background(), "sb-1", "ses-1", SessionAttachOptions{Cols: 80, Rows: 24})
			if err != nil {
				t.Fatalf("AttachSession: %v", err)
			}
			_, _, err = h.Wait()
			return err
		},
	}
	for name, wait := range waits {
		t.Run(name, func(t *testing.T) {
			err := wait(streamServer(t, map[string]any{"type": "error", "message": reason}))
			var streamErr *StreamError
			if !errors.As(err, &streamErr) || streamErr.Message != reason || err.Error() != reason {
				t.Fatalf("error frame = %v (%T), want *StreamError %q", err, err, reason)
			}

			err = wait(streamServer(t, map[string]any{"type": "error"}))
			if !errors.As(err, &streamErr) || err.Error() == "" {
				t.Fatalf("error frame without a message = %v (%T)", err, err)
			}

			err = wait(streamServer(t, nil))
			if err == nil || errors.As(err, &streamErr) {
				t.Fatalf("dropped stream = %v (%T), want a non-StreamError", err, err)
			}
		})
	}
}
