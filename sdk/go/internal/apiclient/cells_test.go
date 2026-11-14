package apiclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/gorilla/websocket"

	"github.com/aerol-ai/microvm/pkg/models"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// seenRequest is what a fake cell records of one request.
type seenRequest struct {
	Host, Method, Path, Query, Auth, Team, Body string
}

// fakeCell is one cell's API front door: it records every request and
// answers with respond.
type fakeCell struct {
	*httptest.Server
	mu   sync.Mutex
	seen []seenRequest
}

func newFakeCell(t *testing.T, useTLS bool, respond http.HandlerFunc) *fakeCell {
	t.Helper()
	f := &fakeCell{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.seen = append(f.seen, seenRequest{
			Host: r.Host, Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery,
			Auth: r.Header.Get("Authorization"), Team: r.Header.Get(HeaderTeam), Body: string(body),
		})
		f.mu.Unlock()
		respond(w, r)
	})
	if useTLS {
		f.Server = httptest.NewTLSServer(handler)
	} else {
		f.Server = httptest.NewServer(handler)
	}
	t.Cleanup(f.Close)
	return f
}

func (f *fakeCell) hits() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.seen)
}

func (f *fakeCell) last() seenRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.seen) == 0 {
		return seenRequest{}
	}
	return f.seen[len(f.seen)-1]
}

// toCell answers like the server's redirectToCell: 421, the cell's address
// in HeaderCellEndpoint, and a JSON error. endpoint is read per request so a
// test can point two cells at each other.
func toCell(endpoint *string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(HeaderCellEndpoint, *endpoint)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMisdirectedRequest)
		_, _ = w.Write([]byte(`{"error":"this sandbox is in another cell"}`))
	}
}

func answerSandbox(image string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(models.Sandbox{ID: "sb-x", Image: image})
	}
}

// cellClient retries up to three times with millisecond backoff, so a
// generic retry that should not happen shows up as an extra request.
func cellClient(baseURL string, httpClient *http.Client) *Client {
	maxRetries, delay := 3, 1
	return NewClient(baseURL, ClientOptions{
		PATToken:   "pat",
		Team:       "team-a",
		HTTPClient: httpClient,
		Retry:      &RetryConfig{MaxRetries: &maxRetries, BaseDelayMs: &delay, MaxDelayMs: &delay},
	})
}

func wantAPIStatus(t *testing.T, err error, status int) {
	t.Helper()
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != status {
		t.Fatalf("error = %v, want APIError %d", err, status)
	}
}

func TestCellRedirectResendsOnceAndRemembersCell(t *testing.T) {
	ctx := context.Background()
	cell2 := newFakeCell(t, false, answerSandbox("from-cell-2"))
	// Both bases carry a path prefix, and the cell's a trailing slash: the
	// redirected URL is built like the configured one, prefix and all.
	cell2Base := cell2.URL + "/c2/"
	cell1 := newFakeCell(t, false, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/edge/v1/sandboxes/sb-x") {
			toCell(&cell2Base)(w, r)
			return
		}
		answerSandbox("from-cell-1")(w, r)
	})
	client := cellClient(cell1.URL+"/edge", cell1.Client())

	resized, err := client.Resize(ctx, "sb-x", ResizeOptions{CPU: 2, MemoryMB: 2048})
	if err != nil {
		t.Fatalf("Resize() error = %v", err)
	}
	if resized.Image != "from-cell-2" {
		t.Fatalf("Resize() = %+v, want cell 2's answer", resized.Sandbox)
	}
	if cell1.hits() != 1 || cell2.hits() != 1 {
		t.Fatalf("hits cell1=%d cell2=%d, want 1 and 1", cell1.hits(), cell2.hits())
	}
	first, resent := cell1.last(), cell2.last()
	if !strings.Contains(first.Body, `"memory_mb":2048`) {
		t.Fatalf("cell 1 body = %q", first.Body)
	}
	want := seenRequest{Host: cell2.Listener.Addr().String(), Method: http.MethodPost, Path: "/c2/v1/sandboxes/sb-x/resize", Auth: "Bearer pat", Team: "team-a", Body: first.Body}
	if resent != want {
		t.Fatalf("cell 2 saw %+v, want %+v", resent, want)
	}

	got, err := client.GetWithOptions(ctx, "sb-x", true)
	if err != nil || got.Image != "from-cell-2" {
		t.Fatalf("GetWithOptions() = %+v, %v", got, err)
	}
	if cell1.hits() != 1 || cell2.hits() != 2 {
		t.Fatalf("second call: hits cell1=%d cell2=%d, want it straight to cell 2", cell1.hits(), cell2.hits())
	}
	if last := cell2.last(); last.Path != "/c2/v1/sandboxes/sb-x" || last.Query != "include_env=true" {
		t.Fatalf("cell 2 saw %s?%s", last.Path, last.Query)
	}

	other, err := client.Get(ctx, "sb-y")
	if err != nil || other.Image != "from-cell-1" {
		t.Fatalf("Get(sb-y) = %+v, %v", other, err)
	}
	if cell1.hits() != 2 || cell2.hits() != 2 || cell1.last().Path != "/edge/v1/sandboxes/sb-y" {
		t.Fatalf("sb-y: hits cell1=%d cell2=%d last=%+v, want the configured endpoint", cell1.hits(), cell2.hits(), cell1.last())
	}
}

// TestCellRedirectFollowedOnEverySendPath covers each way the client sends
// an HTTP request: the retry loop (JSON, raw, file calls), exec, and the
// direct sends. A 421 naming a cell is answered before any work, so even
// exec, which a plain 421 never re-sends, goes to the cell once.
func TestCellRedirectFollowedOnEverySendPath(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name   string
		call   func(c *Client) error
		method string
		path   string
	}{
		{"get", func(c *Client) error { _, err := c.Get(ctx, "sb-x"); return err }, http.MethodGet, "/v1/sandboxes/sb-x"},
		{"exec", func(c *Client) error {
			_, err := c.Exec(ctx, "sb-x", ExecRequest{Command: "true"})
			return err
		}, http.MethodPost, "/v1/sandboxes/sb-x/toolbox/process/execute"},
		{"download", func(c *Client) error { _, err := c.DownloadFile(ctx, "sb-x", "/a"); return err }, http.MethodGet, "/v1/sandboxes/sb-x/toolbox/files/download"},
		{"delete file", func(c *Client) error { return c.DeleteFile(ctx, "sb-x", "/a", sdktypes.DeleteFileOptions{}) }, http.MethodDelete, "/v1/sandboxes/sb-x/toolbox/files"},
		{"upload in memory", func(c *Client) error { return c.UploadFile(ctx, "sb-x", "/a", []byte("hello")) }, http.MethodPost, "/v1/sandboxes/sb-x/toolbox/files/upload"},
		{"toolbox request with body", func(c *Client) error {
			resp, err := c.ToolboxRequest(ctx, "sb-x", http.MethodPost, "/custom", nil, []byte(`{"a":1}`), "application/json")
			if err == nil {
				resp.Body.Close()
			}
			return err
		}, http.MethodPost, "/v1/sandboxes/sb-x/toolbox/custom"},
		{"session log", func(c *Client) error { _, err := c.SessionLog(ctx, "sb-x", "s1"); return err }, http.MethodGet, "/v1/sandboxes/sb-x/sessions/s1/log"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cell2 := newFakeCell(t, false, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{}`)) })
			cell1 := newFakeCell(t, false, toCell(&cell2.URL))
			if err := tt.call(cellClient(cell1.URL, cell1.Client())); err != nil {
				t.Fatalf("call error = %v", err)
			}
			if cell1.hits() != 1 || cell2.hits() != 1 {
				t.Fatalf("hits cell1=%d cell2=%d, want 1 and 1", cell1.hits(), cell2.hits())
			}
			first, resent := cell1.last(), cell2.last()
			if resent.Host != cell2.Listener.Addr().String() || resent.Method != tt.method || resent.Path != tt.path || resent.Auth != "Bearer pat" ||
				resent.Query != first.Query || resent.Body != first.Body {
				t.Fatalf("cell 2 saw %+v, cell 1 saw %+v", resent, first)
			}
		})
	}
}

func TestCellRedirectWithoutHeaderRetriesSameEndpoint(t *testing.T) {
	var requests atomic.Int32
	cell := newFakeCell(t, false, func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			w.WriteHeader(http.StatusMisdirectedRequest)
			_, _ = w.Write([]byte(`{"error":"not the owner"}`))
			return
		}
		answerSandbox("owner")(w, r)
	})
	client := cellClient(cell.URL, cell.Client())
	got, err := client.Get(context.Background(), "sb-x")
	if err != nil || got.Image != "owner" {
		t.Fatalf("Get() = %+v, %v", got, err)
	}
	if cell.hits() != 2 {
		t.Fatalf("hits = %d, want the 421 retried once on the same endpoint", cell.hits())
	}
	if n := client.cells.len(); n != 0 {
		t.Fatalf("remembered %d cells, want none", n)
	}
}

func TestCellRedirectIsNotChained(t *testing.T) {
	tests := []struct {
		name string
		next func(cell1, cell3 *fakeCell) string
	}{
		{"to a third cell", func(_, cell3 *fakeCell) string { return cell3.URL }},
		{"back to the first cell", func(cell1, _ *fakeCell) string { return cell1.URL }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cell2Next string
			cell3 := newFakeCell(t, false, answerSandbox("cell-3"))
			cell2 := newFakeCell(t, false, toCell(&cell2Next))
			cell1 := newFakeCell(t, false, toCell(&cell2.URL))
			cell2Next = tt.next(cell1, cell3)
			client := cellClient(cell1.URL, cell1.Client())

			_, err := client.Get(context.Background(), "sb-x")
			wantAPIStatus(t, err, http.StatusMisdirectedRequest)
			if cell1.hits() != 1 || cell2.hits() != 1 || cell3.hits() != 0 {
				t.Fatalf("hits cell1=%d cell2=%d cell3=%d, want 1, 1, 0", cell1.hits(), cell2.hits(), cell3.hits())
			}
			if n := client.cells.len(); n != 0 {
				t.Fatalf("remembered %d cells after a disowning cell 2, want none", n)
			}
		})
	}
}

func TestCellRedirectRefusesHTTPSDowngrade(t *testing.T) {
	tests := []struct {
		name             string
		edgeTLS, cellTLS bool
		followed         bool
	}{
		{name: "https client, http cell", edgeTLS: true, cellTLS: false, followed: false},
		{name: "https client, https cell", edgeTLS: true, cellTLS: true, followed: true},
		{name: "http client, https cell", edgeTLS: false, cellTLS: true, followed: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cell := newFakeCell(t, tt.cellTLS, answerSandbox("cell"))
			edge := newFakeCell(t, tt.edgeTLS, toCell(&cell.URL))
			// Every httptest TLS server uses the same certificate, so one
			// TLS-capable client reaches both.
			httpClient := edge.Client()
			if tt.cellTLS {
				httpClient = cell.Client()
			}
			client := cellClient(edge.URL, httpClient)

			_, err := client.Get(context.Background(), "sb-x")
			if !tt.followed {
				wantAPIStatus(t, err, http.StatusMisdirectedRequest)
				if edge.hits() != 1 || cell.hits() != 0 || client.cells.len() != 0 {
					t.Fatalf("hits edge=%d cell=%d remembered=%d, want 1, 0, 0", edge.hits(), cell.hits(), client.cells.len())
				}
				return
			}
			if err != nil || edge.hits() != 1 || cell.hits() != 1 {
				t.Fatalf("Get() error = %v, hits edge=%d cell=%d", err, edge.hits(), cell.hits())
			}
		})
	}
}

func TestCellRouteForgottenOn404(t *testing.T) {
	ctx := context.Background()
	var cellRequests atomic.Int32
	cell2 := newFakeCell(t, false, func(w http.ResponseWriter, r *http.Request) {
		if cellRequests.Add(1) == 2 {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"sandbox not found","code":"not_found"}`))
			return
		}
		answerSandbox("cell-2")(w, r)
	})
	cell1 := newFakeCell(t, false, toCell(&cell2.URL))
	client := cellClient(cell1.URL, cell1.Client())

	if _, err := client.Get(ctx, "sb-x"); err != nil {
		t.Fatalf("first Get() error = %v", err)
	}
	if _, err := client.Get(ctx, "sb-x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second Get() error = %v, want ErrNotFound", err)
	}
	if cell1.hits() != 1 || cell2.hits() != 2 || client.cells.len() != 0 {
		t.Fatalf("hits cell1=%d cell2=%d remembered=%d, want 1, 2, 0", cell1.hits(), cell2.hits(), client.cells.len())
	}
	if _, err := client.Get(ctx, "sb-x"); err != nil {
		t.Fatalf("third Get() error = %v", err)
	}
	if cell1.hits() != 2 || cell2.hits() != 3 {
		t.Fatalf("third call: hits cell1=%d cell2=%d, want it back through the configured endpoint", cell1.hits(), cell2.hits())
	}
}

// TestCellRedirectOneShotBodyNotResent: a streamed upload cannot be sent
// twice, so the 421 surfaces, but the cell is remembered and the caller's
// retry goes straight there.
func TestCellRedirectOneShotBodyNotResent(t *testing.T) {
	ctx := context.Background()
	cell2 := newFakeCell(t, false, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusCreated) })
	cell1 := newFakeCell(t, false, toCell(&cell2.URL))
	client := cellClient(cell1.URL, cell1.Client())

	err := client.UploadFileStream(ctx, "sb-x", "/a.txt", strings.NewReader("streamed"))
	wantAPIStatus(t, err, http.StatusMisdirectedRequest)
	if cell1.hits() != 1 || cell2.hits() != 0 {
		t.Fatalf("hits cell1=%d cell2=%d, want the stream sent once", cell1.hits(), cell2.hits())
	}
	if got := client.cells.get("sb-x"); got != cell2.URL {
		t.Fatalf("remembered %q, want %q", got, cell2.URL)
	}

	if err := client.UploadFileStream(ctx, "sb-x", "/a.txt", strings.NewReader("streamed")); err != nil {
		t.Fatalf("retry error = %v", err)
	}
	if cell1.hits() != 1 || cell2.hits() != 1 || !strings.Contains(cell2.last().Body, "streamed") {
		t.Fatalf("hits cell1=%d cell2=%d body=%q", cell1.hits(), cell2.hits(), cell2.last().Body)
	}
}

func TestCellRedirectWebSocketHandshake(t *testing.T) {
	ctx := context.Background()
	var mu sync.Mutex
	var agentPaths []string
	cell2 := fakeWatchAgent(t, func(r *http.Request) {
		mu.Lock()
		agentPaths = append(agentPaths, r.URL.Path+" "+r.Header.Get("Authorization"))
		mu.Unlock()
	}, func(conn *websocket.Conn) { _, _, _ = conn.ReadMessage() })
	cell2Base := cell2.URL + "/c2"
	cell1 := newFakeCell(t, false, toCell(&cell2Base))
	client := cellClient(cell1.URL, cell1.Client())

	for i := 0; i < 2; i++ {
		h, err := client.WatchFiles(ctx, "sb-x", "/w", WatchOptions{})
		if err != nil {
			t.Fatalf("WatchFiles() #%d error = %v", i+1, err)
		}
		_ = h.Stop()
		_ = h.Wait()
	}
	mu.Lock()
	defer mu.Unlock()
	want := "/c2/v1/sandboxes/sb-x/toolbox/files/watch Bearer pat"
	if len(agentPaths) != 2 || agentPaths[0] != want || agentPaths[1] != want {
		t.Fatalf("cell 2 saw %q, want %q twice", agentPaths, want)
	}
	if cell1.hits() != 1 {
		t.Fatalf("cell 1 hits = %d, want only the first handshake", cell1.hits())
	}

	// A handshake 421 that names no usable cell surfaces as the 421.
	unusable := "ftp://nowhere"
	other := newFakeCell(t, false, toCell(&unusable))
	_, err := cellClient(other.URL, other.Client()).WatchFiles(ctx, "sb-x", "/w", WatchOptions{})
	wantAPIStatus(t, err, http.StatusMisdirectedRequest)
	if other.hits() != 1 {
		t.Fatalf("hits = %d, want 1", other.hits())
	}
}

func TestCellEndpointAcceptsOnlyBaseURLs(t *testing.T) {
	tests := []struct {
		name, client, header string
		status               int
		want                 string
		ok                   bool
	}{
		{name: "https cell", client: "https://edge", header: "https://cell2.example.com", want: "https://cell2.example.com", ok: true},
		{name: "trailing slash and spaces trimmed", client: "https://edge", header: "  https://cell2.example.com:8443/api/  ", want: "https://cell2.example.com:8443/api", ok: true},
		{name: "http client, http cell", client: "http://edge", header: "http://cell2:21212", want: "http://cell2:21212", ok: true},
		{name: "downgrade", client: "https://edge", header: "http://cell2"},
		{name: "no header", client: "https://edge"},
		{name: "not a 421", client: "https://edge", header: "https://cell2", status: http.StatusBadRequest},
		{name: "other scheme", client: "https://edge", header: "ftp://cell2"},
		{name: "relative", client: "https://edge", header: "/cell2"},
		{name: "no scheme", client: "https://edge", header: "cell2.example.com"},
		{name: "no host", client: "https://edge", header: "https://"},
		{name: "user info", client: "https://edge", header: "https://u:p@cell2"},
		{name: "query", client: "https://edge", header: "https://cell2?x=1"},
		{name: "fragment", client: "https://edge", header: "https://cell2#x"},
		{name: "unparsable", client: "https://edge", header: "https://cell2/%zz"},
		{name: "client base unparsable", client: "https://edge/%zz", header: "https://cell2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := tt.status
			if status == 0 {
				status = http.StatusMisdirectedRequest
			}
			response := &http.Response{StatusCode: status, Header: http.Header{}}
			if tt.header != "" {
				response.Header.Set(HeaderCellEndpoint, tt.header)
			}
			got, ok := NewClient(tt.client, ClientOptions{}).cellEndpoint(response)
			if got != tt.want || ok != tt.ok {
				t.Fatalf("cellEndpoint() = %q, %v; want %q, %v", got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestSandboxRouteSplitsBuiltURLs(t *testing.T) {
	client := NewClient("http://edge:1/api/", ClientOptions{})
	tests := []struct {
		url, rest, id string
	}{
		{url: "http://edge:1/api/v1/sandboxes/sb-1", rest: "/v1/sandboxes/sb-1", id: "sb-1"},
		{url: "http://edge:1/api/v1/sandboxes/sb-1/toolbox/files?path=%2Fa+b", rest: "/v1/sandboxes/sb-1/toolbox/files?path=%2Fa+b", id: "sb-1"},
		{url: "http://edge:1/api/v1/sandboxes?tag.a=b"},
		{url: "http://edge:1/api/v1/sandboxes/"},
		{url: "http://edge:1/api/v1/images/build"},
		{url: "http://edge:1/apix/v1/sandboxes/sb-1"},
		{url: "http://other:1/api/v1/sandboxes/sb-1"},
		{url: "https://edge:1/api/v1/sandboxes/sb-1"},
	}
	for _, tt := range tests {
		u, err := url.Parse(tt.url)
		if err != nil {
			t.Fatal(err)
		}
		if rest, id := client.sandboxRoute(u); rest != tt.rest || id != tt.id {
			t.Errorf("sandboxRoute(%s) = %q, %q; want %q, %q", tt.url, rest, id, tt.rest, tt.id)
		}
	}
}

func TestCellRoutesBoundedAndForgetIsConditional(t *testing.T) {
	var routes cellRoutes
	for i := 0; i <= maxCellRoutes; i++ {
		routes.put(fmt.Sprintf("sb-%d", i), "https://cell2")
	}
	if n := routes.len(); n != maxCellRoutes {
		t.Fatalf("len = %d, want the bound %d", n, maxCellRoutes)
	}
	if routes.get("sb-0") != "" || routes.get(fmt.Sprintf("sb-%d", maxCellRoutes)) != "https://cell2" {
		t.Fatal("the oldest entry should go first")
	}

	routes.put("sb-1", "https://cell3")
	if routes.len() != maxCellRoutes || routes.get("sb-1") != "https://cell3" {
		t.Fatal("updating an entry should replace it in place")
	}
	routes.forget("sb-1", "https://cell2")
	if routes.get("sb-1") != "https://cell3" {
		t.Fatal("a stale cell's 404 erased a newer route")
	}
	routes.forget("sb-1", "https://cell3")
	if routes.get("sb-1") != "" || routes.len() != maxCellRoutes-1 {
		t.Fatal("forget did not drop the route")
	}

	// Concurrent use from many goroutines (run under -race).
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				id := fmt.Sprintf("c-%d", i%17)
				routes.put(id, fmt.Sprintf("https://cell%d", g))
				_ = routes.get(id)
				routes.forget(id, fmt.Sprintf("https://cell%d", g))
			}
		}(g)
	}
	wg.Wait()
	if routes.len() > maxCellRoutes {
		t.Fatalf("len = %d over the bound", routes.len())
	}
}
