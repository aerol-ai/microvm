package clusterroute

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// proxyEdge is an edge whose forwards go through a real httputil.ReverseProxy
// to backend, the way cluster.ForwardHTTP does (minus mTLS), with its cache
// pointing every sandbox at worker-a.
type proxyEdge struct {
	*cluster.Noop
	cache   *cluster.OwnerCache
	proxy   *httputil.ReverseProxy
	ownerOf func(string) (cluster.OwnerInfo, error)
}

func (e *proxyEdge) OwnerCache() *cluster.OwnerCache { return e.cache }
func (e *proxyEdge) OwnerOf(id string) (cluster.OwnerInfo, error) {
	return e.ownerOf(id)
}
func (e *proxyEdge) ForwardHTTP(_ cluster.Endpoint, w http.ResponseWriter, r *http.Request) {
	e.proxy.ServeHTTP(w, r)
}

func newProxyEdge(t *testing.T, backend http.Handler) http.Handler {
	t.Helper()
	srv := httptest.NewServer(backend)
	t.Cleanup(srv.Close)
	target, _ := url.Parse(srv.URL)
	edge := &proxyEdge{
		Noop: cluster.NewNoop("ingress-1", "", ""),
		cache: cluster.NewOwnerCache("ingress-1", 0, 0, func(id string) (cluster.Member, bool) {
			return cluster.Member{NodeID: id, Alive: true, InternalURL: "https://" + id + ":7002"}, true
		}),
		proxy: &httputil.ReverseProxy{Director: func(req *http.Request) {
			req.URL.Scheme, req.URL.Host, req.Host = target.Scheme, target.Host, target.Host
			cluster.StampForward(req, controlplane.Access{})
		}},
		ownerOf: func(string) (cluster.OwnerInfo, error) { return cluster.OwnerInfo{}, cluster.ErrUnknownSandbox },
	}
	for _, id := range []string{"sb-stream", "sb-ws", "sb-moved"} {
		edge.cache.Put(id, cluster.OwnerInfo{NodeID: "worker-a"}, "", false)
	}
	mux := http.NewServeMux()
	mux.Handle("/x/{id}", Wrap(svcWith(t, edge), Options{WriteError: writeErr}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"error":"sandbox not found"}`)
	})))
	// A header the API middleware set before routing; it must survive both a
	// passed-through answer and a swallowed one.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Edge", "1")
		mux.ServeHTTP(w, r)
	})
}

// A swallowed "not here" leaves nothing behind: the caller gets the retry's
// answer with the edge's own headers, none of the 421's.
func TestOwnerCacheThroughProxyRestoresHeaders(t *testing.T) {
	edge := httptest.NewServer(newProxyEdge(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-From-Old-Owner", "yes")
		w.Header().Set(cluster.HeaderNotOwner, r.Header.Get(cluster.HeaderRouteHint))
		http.Error(w, "not here", http.StatusMisdirectedRequest)
	})))
	defer edge.Close()
	resp, err := http.Get(edge.URL + "/x/sb-moved")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusNotFound || string(body) != `{"error":"sandbox not found"}` {
		t.Fatalf("got %d %q, want the edge's own 404", resp.StatusCode, body)
	}
	if resp.Header.Get("X-Edge") != "1" || resp.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("edge headers lost: %v", resp.Header)
	}
	if resp.Header.Get("X-From-Old-Owner") != "" || resp.Header.Get(cluster.HeaderNotOwner) != "" {
		t.Fatalf("the swallowed 421 leaked headers: %v", resp.Header)
	}
}

// A streamed answer keeps streaming through the catcher: the caller reads
// the first chunk before the owner writes the second.
func TestOwnerCacheThroughProxyStreams(t *testing.T) {
	second := make(chan struct{})
	edge := httptest.NewServer(newProxyEdge(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "first\n")
		http.NewResponseController(w).Flush()
		<-second
		_, _ = io.WriteString(w, "second\n")
	})))
	defer edge.Close()
	resp, err := http.Get(edge.URL + "/x/sb-stream")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	br := bufio.NewReader(resp.Body)
	done := make(chan string, 1)
	go func() {
		line, _ := br.ReadString('\n')
		done <- line
	}()
	select {
	case line := <-done:
		if line != "first\n" {
			t.Fatalf("first chunk = %q", line)
		}
	case <-time.After(5 * time.Second):
		close(second)
		t.Fatal("first chunk not flushed through the catcher")
	}
	close(second)
	if rest, _ := io.ReadAll(br); string(rest) != "second\n" {
		t.Fatalf("rest = %q", rest)
	}
}

// A WebSocket-style upgrade switches protocols through the catcher (the proxy
// hijacks the caller's connection through Unwrap).
func TestOwnerCacheThroughProxyUpgrades(t *testing.T) {
	edge := httptest.NewServer(newProxyEdge(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "echo") {
			http.Error(w, "want upgrade", http.StatusBadRequest)
			return
		}
		conn, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
		_ = brw.Flush()
		line, _ := brw.ReadString('\n')
		_, _ = brw.WriteString(line)
		_ = brw.Flush()
	})))
	defer edge.Close()
	conn, err := net.Dial("tcp", strings.TrimPrefix(edge.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.WriteString(conn, "GET /x/sb-ws HTTP/1.1\r\nHost: edge\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols || resp.Header.Get("X-Edge") != "1" {
		t.Fatalf("upgrade answer %d headers %v", resp.StatusCode, resp.Header)
	}
	_, _ = io.WriteString(conn, "ping\n")
	if line, _ := br.ReadString('\n'); line != "ping\n" {
		t.Fatalf("echo = %q", line)
	}
}

// The catcher on its own: a Write with no status is a 200, and a swallowed
// answer discards its body and flushes nothing.
func TestNotOwnerCatcher(t *testing.T) {
	rr := httptest.NewRecorder()
	c := &notOwnerCatcher{w: rr, token: "tok"}
	if _, err := c.Write([]byte("ok")); err != nil || rr.Code != http.StatusOK || rr.Body.String() != "ok" {
		t.Fatalf("implicit 200: code %d body %q err %v", rr.Code, rr.Body.String(), err)
	}
	if err := c.FlushError(); err != nil || !rr.Flushed {
		t.Fatalf("flush: %v flushed=%v", err, rr.Flushed)
	}

	rr = httptest.NewRecorder()
	c = &notOwnerCatcher{w: rr, token: "tok"}
	c.Header().Set(cluster.HeaderNotOwner, "tok")
	c.WriteHeader(http.StatusMisdirectedRequest)
	c.WriteHeader(http.StatusOK) // ignored once caught
	if n, err := c.Write([]byte("not here")); err != nil || n != len("not here") {
		t.Fatalf("swallowed write = %d, %v", n, err)
	}
	if err := c.FlushError(); err != nil {
		t.Fatal(err)
	}
	if !c.caught || rr.Flushed || rr.Body.Len() != 0 {
		t.Fatalf("caught=%v flushed=%v body=%q", c.caught, rr.Flushed, rr.Body.String())
	}
	if c.Unwrap() != rr {
		t.Fatal("Unwrap must return the caller's writer")
	}
}
