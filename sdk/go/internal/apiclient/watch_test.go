package apiclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// fakeWatchAgent plays toolboxd's /files/watch: it checks the request, says
// start, then runs script on the socket.
func fakeWatchAgent(t *testing.T, check func(r *http.Request), script func(conn *websocket.Conn)) *httptest.Server {
	t.Helper()
	var upgrader websocket.Upgrader
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if check != nil {
			check(r)
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		if err := conn.WriteJSON(map[string]any{"type": "start", "path": r.URL.Query().Get("path")}); err != nil {
			return
		}
		script(conn)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestWatchFilesDeliversEventsInOrder(t *testing.T) {
	var gotPath, gotQuery, gotAuth string
	release := make(chan struct{})
	srv := fakeWatchAgent(t, func(r *http.Request) {
		gotPath, gotQuery, gotAuth = r.URL.Path, r.URL.RawQuery, r.Header.Get("Authorization")
	}, func(conn *websocket.Conn) {
		<-release
		_ = conn.WriteJSON(map[string]any{"type": "events", "events": []map[string]any{
			{"type": "create", "path": "/work/my file.txt"},
			{"type": "create", "path": "/work/sub", "is_dir": true},
			{"type": "overflow", "reason": "kernel_queue"},
		}})
		_ = conn.WriteJSON(map[string]any{"type": "something-new"}) // ignored
		_ = conn.WriteJSON(map[string]any{"type": "events", "events": []map[string]any{{"type": "chmod", "path": "/work/x"}}})
		_ = conn.WriteJSON(map[string]any{"type": "end", "reason": "the watched folder was removed"})
	})

	var mu sync.Mutex
	var events []FileEvent
	client := NewClient(srv.URL, ClientOptions{PATToken: "pat-token", HTTPClient: srv.Client()})
	h, err := client.WatchFiles(context.Background(), "sb-1", "/work dir", WatchOptions{Recursive: true, OnEvent: func(ev FileEvent) {
		mu.Lock()
		events = append(events, ev)
		mu.Unlock()
	}})
	if err != nil {
		t.Fatalf("WatchFiles: %v", err)
	}
	if gotPath != "/v1/sandboxes/sb-1/toolbox/files/watch" || gotQuery != "path=%2Fwork+dir&recursive=true" || gotAuth != "Bearer pat-token" {
		t.Fatalf("request = %s ? %s auth %q", gotPath, gotQuery, gotAuth)
	}
	close(release)
	err = h.Wait()
	var streamErr *StreamError
	if !errors.As(err, &streamErr) || streamErr.Message != "the watched folder was removed" {
		t.Fatalf("Wait = %v, want the end reason", err)
	}
	want := []FileEvent{
		{Type: sdktypes.FileEventCreate, Path: "/work/my file.txt"},
		{Type: sdktypes.FileEventCreate, Path: "/work/sub", IsDir: true},
		{Type: sdktypes.FileEventOverflow, Reason: sdktypes.WatchOverflowKernelQueue},
		{Type: sdktypes.FileEventChmod, Path: "/work/x"},
	}
	mu.Lock()
	defer mu.Unlock()
	if len(events) != len(want) {
		t.Fatalf("events = %+v", events)
	}
	for i := range want {
		if events[i] != want[i] {
			t.Fatalf("event %d = %+v, want %+v", i, events[i], want[i])
		}
	}
	select {
	case <-h.Done():
	default:
		t.Fatal("Done not closed after Wait")
	}
}

func TestWatchFilesNonRecursiveSendsOnlyPath(t *testing.T) {
	var gotQuery string
	srv := fakeWatchAgent(t, func(r *http.Request) { gotQuery = r.URL.RawQuery }, func(conn *websocket.Conn) {
		_, _, _ = conn.ReadMessage()
	})
	client := NewClient(srv.URL, ClientOptions{PATToken: "pat", HTTPClient: srv.Client()})
	h, err := client.WatchFiles(context.Background(), "sb", "/w", WatchOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if gotQuery != "path=%2Fw" {
		t.Fatalf("query = %q, want only the path", gotQuery)
	}
	// Stop: Wait returns nil, twice is fine.
	_ = h.Stop()
	_ = h.Stop()
	if err := h.Wait(); err != nil {
		t.Fatalf("Wait after Stop = %v", err)
	}
	if _, err := client.WatchFiles(context.Background(), "sb", "  ", WatchOptions{}); err == nil {
		t.Fatal("empty path accepted")
	}
}

func TestWatchFilesDroppedConnection(t *testing.T) {
	srv := fakeWatchAgent(t, nil, func(conn *websocket.Conn) {
		_ = conn.UnderlyingConn().Close()
	})
	client := NewClient(srv.URL, ClientOptions{PATToken: "pat", HTTPClient: srv.Client()})
	h, err := client.WatchFiles(context.Background(), "sb", "/w", WatchOptions{OnEvent: func(FileEvent) {}})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Wait(); err == nil || !strings.Contains(err.Error(), "file watch dropped") {
		t.Fatalf("Wait = %v, want a dropped-connection error", err)
	}
}

func TestWatchFilesContextEndsTheWatch(t *testing.T) {
	srv := fakeWatchAgent(t, nil, func(conn *websocket.Conn) {
		_, _, _ = conn.ReadMessage()
	})
	client := NewClient(srv.URL, ClientOptions{PATToken: "pat", HTTPClient: srv.Client()})
	ctx, cancel := context.WithCancel(context.Background())
	h, err := client.WatchFiles(ctx, "sb", "/w", WatchOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := h.Wait(); !errors.Is(err, context.Canceled) {
		t.Fatalf("Wait = %v, want context.Canceled", err)
	}
}

func TestWatchFilesStartIsRequired(t *testing.T) {
	var upgrader websocket.Upgrader
	cases := map[string]func(conn *websocket.Conn){
		"closed before start": func(conn *websocket.Conn) {},
		"wrong first frame": func(conn *websocket.Conn) {
			_ = conn.WriteJSON(map[string]any{"type": "events"})
		},
	}
	for name, script := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				conn, err := upgrader.Upgrade(w, r, nil)
				if err != nil {
					return
				}
				script(conn)
				_ = conn.Close()
			}))
			defer srv.Close()
			client := NewClient(srv.URL, ClientOptions{PATToken: "pat", HTTPClient: srv.Client()})
			if _, err := client.WatchFiles(context.Background(), "sb", "/w", WatchOptions{}); err == nil {
				t.Fatal("WatchFiles succeeded without a start frame")
			}
		})
	}

	// A context that ends while waiting for start.
	hold := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		<-hold
		_ = conn.Close()
	}))
	defer srv.Close()
	defer close(hold)
	client := NewClient(srv.URL, ClientOptions{PATToken: "pat", HTTPClient: srv.Client()})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := client.WatchFiles(ctx, "sb", "/w", WatchOptions{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("WatchFiles = %v, want the context's deadline", err)
	}
}

func TestWatchFilesHandshakeErrors(t *testing.T) {
	cases := []struct {
		name        string
		status      int
		header      string
		body        string
		unsupported bool
		message     string
	}{
		{"agent marks the route missing", 404, "none", `{"error":"not found"}`, true, ""},
		{"agent older than the route mark", 404, "", `{"error":"not found"}`, true, ""},
		{"runtime cannot watch", 501, "", `{"error":"file watching needs a gVisor or Firecracker sandbox"}`, false, "file watching needs a gVisor or Firecracker sandbox"},
		{"missing folder", 404, "", `{"error":"path not found: /x"}`, false, "path not found: /x"},
		{"missing sandbox", 404, "", `{"error":"sandbox not found"}`, false, "sandbox not found"},
		{"too many watches", 429, "", `{"error":"too many file watches open in this sandbox; stop one first"}`, false, "too many file watches"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.header != "" {
					w.Header().Set("X-Toolbox-Route", tc.header)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			client := NewClient(srv.URL, ClientOptions{PATToken: "pat", HTTPClient: srv.Client()})
			_, err := client.WatchFiles(context.Background(), "sb-old", "/x", WatchOptions{})
			if tc.unsupported {
				var unsupported *UnsupportedFeatureError
				if !errors.As(err, &unsupported) || !errors.Is(err, ErrUnsupportedFeature) || unsupported.Features[0] != FeatureFilesWatch || unsupported.SandboxID != "sb-old" {
					t.Fatalf("err = %v, want an UnsupportedFeatureError for files.watch", err)
				}
				if !strings.Contains(err.Error(), "restart the sandbox") {
					t.Fatalf("message %q does not say how to fix it", err)
				}
				return
			}
			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.StatusCode != tc.status || !strings.Contains(apiErr.Message, tc.message) {
				t.Fatalf("err = %v, want an APIError %d %q", err, tc.status, tc.message)
			}
			if errors.Is(err, ErrUnsupportedFeature) {
				t.Fatal("a plain API error matched ErrUnsupportedFeature")
			}
		})
	}

	// No HTTP answer at all.
	client := NewClient("http://127.0.0.1:1", ClientOptions{PATToken: "pat"})
	if _, err := client.WatchFiles(context.Background(), "sb", "/x", WatchOptions{}); err == nil || !strings.Contains(err.Error(), "file watch websocket dial") {
		t.Fatalf("dial to nothing = %v", err)
	}
}

// A watch whose agent accepts the upgrade and never says start gives up after
// the bound, even when the caller's context has no deadline.
func TestWatchFilesStartWaitIsBounded(t *testing.T) {
	old := watchStartTimeout
	watchStartTimeout = 50 * time.Millisecond
	t.Cleanup(func() { watchStartTimeout = old })
	var upgrader websocket.Upgrader
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		<-release
	}))
	defer srv.Close()
	defer close(release)
	client := NewClient(srv.URL, ClientOptions{PATToken: "pat", HTTPClient: srv.Client()})
	start := time.Now()
	_, err := client.WatchFiles(context.Background(), "sb", "/w", WatchOptions{})
	if err == nil || !strings.Contains(err.Error(), "did not start within 50ms") {
		t.Fatalf("err = %v, want the start timeout", err)
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("gave up after %v", took)
	}
}
