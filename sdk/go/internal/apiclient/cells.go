package apiclient

import (
	"container/list"
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/gorilla/websocket"

	"github.com/aerol-ai/microvm/pkg/models"
)

// HeaderCellEndpoint is the response header a 421 carries when the sandbox
// lives in another cell of a federation (plans/kubernetes-v2-architecture.md
// §12.4, C16): the base URL of the cell that holds it. The client sends the
// request there once and remembers the cell for that sandbox.
const HeaderCellEndpoint = models.CellEndpointHeader

// maxCellRoutes bounds the sandbox → cell memory. A long-lived client that
// touches many sandboxes in other cells would otherwise grow it forever;
// dropping the oldest costs that sandbox one extra 421 hop, nothing more.
const maxCellRoutes = 10000

// cellRoutes remembers which cell holds a sandbox, so calls after the first
// skip the 421 hop through the configured endpoint. Entries live until a
// cell disowns the sandbox (a 404, or a 421 naming another cell) or the
// bound pushes them out: a sandbox ID carries its cell, so the answer does
// not go stale on its own.
type cellRoutes struct {
	mu    sync.Mutex
	byID  map[string]*list.Element
	order list.List // *cellRoute, oldest first
}

type cellRoute struct{ id, base string }

func (r *cellRoutes) get(id string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.byID[id]; ok {
		return e.Value.(*cellRoute).base
	}
	return ""
}

func (r *cellRoutes) put(id, base string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.byID[id]; ok {
		e.Value.(*cellRoute).base = base
		return
	}
	if r.byID == nil {
		r.byID = map[string]*list.Element{}
	}
	r.byID[id] = r.order.PushBack(&cellRoute{id: id, base: base})
	for r.order.Len() > maxCellRoutes {
		oldest := r.order.Front()
		r.order.Remove(oldest)
		delete(r.byID, oldest.Value.(*cellRoute).id)
	}
}

// forget drops id's route only while it still points at base, so a late
// answer from a cell another call already moved past does not erase the
// newer route.
func (r *cellRoutes) forget(id, base string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.byID[id]; ok && e.Value.(*cellRoute).base == base {
		r.order.Remove(e)
		delete(r.byID, id)
	}
}

func (r *cellRoutes) len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.byID)
}

// sandboxID names the sandbox a client path (versionPrefix/sandboxes/{id}...)
// is for, or "" for any other path. The server sends cell redirects only on
// per-sandbox routes, so only those are routed by cell.
func (c *Client) sandboxID(path string) string {
	after, ok := strings.CutPrefix(path, c.versionPrefix+"/sandboxes/")
	if !ok {
		return ""
	}
	end := strings.IndexAny(after, "/?")
	if end >= 0 {
		after = after[:end]
	}
	return after
}

// sandboxRoute splits a URL the client built as baseURL+rest back into rest
// and the sandbox it names. A URL that does not start with the configured
// base (it never should) gets no id, so it is sent as built.
func (c *Client) sandboxRoute(u *url.URL) (rest, id string) {
	base := c.base
	if base == nil || u.Scheme != base.Scheme || u.Host != base.Host {
		return "", ""
	}
	rest, ok := strings.CutPrefix(u.EscapedPath(), strings.TrimRight(base.EscapedPath(), "/"))
	if !ok {
		return "", ""
	}
	if id = c.sandboxID(rest); id == "" {
		return "", ""
	}
	if u.RawQuery != "" || u.ForceQuery {
		rest += "?" + u.RawQuery
	}
	return rest, id
}

// namesCell reports a 421 from a front door that knows the sandbox is in
// another cell. Asking the same place again cannot help, so the generic 421
// retry leaves it alone: routed already followed it once, or refused to.
func namesCell(response *http.Response) bool {
	return response.StatusCode == http.StatusMisdirectedRequest &&
		strings.TrimSpace(response.Header.Get(HeaderCellEndpoint)) != ""
}

// cellEndpoint is the cell base URL a 421 names, when the client may send
// its token there.
func (c *Client) cellEndpoint(response *http.Response) (string, bool) {
	if !namesCell(response) || c.base == nil {
		return "", false
	}
	u, err := url.Parse(strings.TrimSpace(response.Header.Get(HeaderCellEndpoint)))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" ||
		u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", false
	}
	// The token follows the redirect. A forged or misconfigured answer must
	// not move an https client's token onto plain http.
	if c.base.Scheme == "https" && u.Scheme == "http" {
		return "", false
	}
	cell := url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path, RawPath: u.RawPath}
	return strings.TrimRight(cell.String(), "/"), true
}

// disowns reports an answer that says the sandbox is not at the base that
// gave it.
func disowns(response *http.Response) bool {
	return response.StatusCode == http.StatusNotFound || namesCell(response)
}

// routed sends one request for sandbox id through try, which sends it to a
// base URL. It goes to the cell remembered for id, or to the configured base;
// a 421 naming another cell is remembered and, when resendable, sent there
// once. A second 421 is returned, not followed, so two cells that point at
// each other cost one hop each, never a loop. An empty id (not a
// per-sandbox path) goes to the configured base as built.
func (c *Client) routed(id string, resendable bool, try func(base string) (*http.Response, error)) (*http.Response, error) {
	if id == "" {
		return try(c.baseURL)
	}
	sent := c.cells.get(id)
	if sent == "" {
		sent = c.baseURL
	}
	response, err := try(sent)
	if response == nil {
		return nil, err
	}
	if disowns(response) {
		c.cells.forget(id, sent)
	}
	cell, ok := c.cellEndpoint(response)
	if !ok || cell == sent {
		return response, err
	}
	c.cells.put(id, cell)
	// A one-shot body is already spent. The 421 goes back to the caller, and
	// the caller's own retry reaches the cell through the memory.
	if !resendable {
		return response, err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	response.Body.Close()
	response, err = try(cell)
	if response != nil && disowns(response) {
		c.cells.forget(id, cell)
	}
	return response, err
}

// send is httpClient.Do with cell routing for per-sandbox requests. Every
// HTTP request the client makes goes through it, so a retry, a stream or an
// escape-hatch call all reach the sandbox's own cell.
func (c *Client) send(request *http.Request) (*http.Response, error) {
	rest, id := c.sandboxRoute(request.URL)
	resendable := request.Body == nil || request.Body == http.NoBody || request.GetBody != nil
	built, host := request.URL, request.Host
	first := true
	return c.routed(id, resendable, func(base string) (*http.Response, error) {
		out := request
		if !first {
			out = request.Clone(request.Context())
			if request.GetBody != nil {
				body, err := request.GetBody()
				if err != nil {
					return nil, err
				}
				out.Body = body
			}
		}
		first = false
		out.URL, out.Host = built, host
		if base != c.baseURL {
			u, err := url.Parse(base + rest)
			if err != nil {
				return nil, err
			}
			// NewRequest copied the configured host into Host; clear it so
			// the Host header names the cell.
			out.URL, out.Host = u, ""
		}
		return c.httpClient.Do(out)
	})
}

// dialSandbox opens a WebSocket on path (versionPrefix/sandboxes/{id}...) at
// the cell that holds the sandbox. A handshake has no body, so a 421 cell
// redirect is always followed. It returns the URL it dialed last, for errors.
func (c *Client) dialSandbox(ctx context.Context, path string, header http.Header) (*websocket.Conn, *http.Response, string, error) {
	var conn *websocket.Conn
	var wsURL string
	dial := func(base string) (*http.Response, error) {
		wsURL = base + path
		target, err := websocketURL(base, path)
		if err != nil {
			return nil, err
		}
		wsURL = target
		var response *http.Response
		conn, response, err = websocket.DefaultDialer.DialContext(ctx, target, header)
		return response, err
	}
	response, err := c.routed(c.sandboxID(path), true, dial)
	return conn, response, wsURL, err
}
