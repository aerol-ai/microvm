package remotemcp

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// inProcessTransport hands each Go SDK request straight to sandboxd's own
// API handler. A remote tool call therefore goes through the same route
// permission, tenant scoping, audit record, cluster forwarding and
// idempotency as a direct API call: there is no second authz path and no
// loopback listener to configure.
//
// Who the call is from travels as the Access hand-off (handoff.go): the
// Access /mcp authenticated, which the API edge uses instead of checking a
// bearer again. The request also keeps the caller's own Authorization
// header, which a forward to the owning node carries so the owner can verify
// it offline.
//
// The response streams back through an io.Pipe. A recorder that buffered
// the whole body would hold an arbitrarily large response (a big file, a
// noisy command) in sandboxd memory before the client's size limit applied;
// with the pipe, the handler blocks once it is a write ahead of the reader.
// Hijacking (WebSockets) is not supported, which is why remote exec uses
// buffered exec on every runtime.
type inProcessTransport struct {
	handler    http.Handler
	remoteAddr string
	// access is the outer /mcp request's Access; hasAccess is false only if
	// /mcp was somehow served without authentication, and then every inner
	// call gets the edge's 500 (finding 2.5).
	access    controlplane.Access
	hasAccess bool
}

func (t *inProcessTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// The inner call is recorded as the tool call it is: one api record per
	// tool call, attributed to the MCP caller, with surface "mcp" (§5.9).
	// Only this transport sets the marker; nothing on the wire can.
	ctx := auditlog.ContextWithSurface(req.Context(), auditlog.SurfaceMCP)
	ctx = contextWithHandoff(ctx, t.access, t.hasAccess)
	in := req.Clone(ctx)
	in.RequestURI = req.URL.RequestURI()
	in.RemoteAddr = t.remoteAddr
	// The team is the hand-off's, resolved when /mcp authenticated. A team
	// header here could only come from the SDK client's own defaults
	// (SB_TEAM in sandboxd's environment, once the SDKs read it, T9), which
	// is the daemon's setting, never the caller's. A forward gets the team
	// back from cluster.StampForward, taken from the hand-off Access.
	in.Header.Del(cluster.HeaderTeam)
	if in.Body == nil {
		in.Body = http.NoBody
	} else if in.ContentLength == 0 && in.Body != http.NoBody {
		// A client request with a body and ContentLength 0 has an unknown
		// length (the SDK's streamed uploads). To a server handler 0 means
		// empty, and httputil.ReverseProxy then drops the body on its way
		// to toolboxd. -1 is the server's "unknown".
		in.ContentLength = -1
	}
	pr, pw := io.Pipe()
	rw := &pipeResponseWriter{header: http.Header{}, pw: pw, headerSent: make(chan struct{})}
	go func() {
		defer func() {
			if p := recover(); p != nil {
				rw.abort(fmt.Errorf("remotemcp: api handler panicked: %v", p))
				return
			}
			rw.finish()
		}()
		t.handler.ServeHTTP(rw, in)
	}()
	select {
	case <-rw.headerSent:
	case <-ctx.Done():
		_ = pr.CloseWithError(ctx.Err())
		return nil, ctx.Err()
	}
	return &http.Response{
		Status:        strconv.Itoa(rw.status) + " " + http.StatusText(rw.status),
		StatusCode:    rw.status,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        rw.sent,
		Body:          pr,
		ContentLength: -1,
		Request:       req,
	}, nil
}

// pipeResponseWriter is the handler side of the pipe.
type pipeResponseWriter struct {
	header     http.Header
	sent       http.Header
	status     int
	pw         *io.PipeWriter
	once       sync.Once
	headerSent chan struct{}
}

func (w *pipeResponseWriter) Header() http.Header { return w.header }

func (w *pipeResponseWriter) WriteHeader(code int) {
	if code >= 100 && code < 200 {
		return // informational responses aren't forwarded
	}
	w.once.Do(func() {
		w.status = code
		w.sent = w.header.Clone()
		close(w.headerSent)
	})
}

// Write blocks until the reader takes the bytes; a closed reader (the
// client stopped reading) makes it fail, which ends the handler's work.
func (w *pipeResponseWriter) Write(b []byte) (int, error) {
	w.WriteHeader(http.StatusOK)
	return w.pw.Write(b)
}

// Flush is a no-op: every Write is already delivered to the reader.
func (w *pipeResponseWriter) Flush() {}

func (w *pipeResponseWriter) finish() {
	w.WriteHeader(http.StatusOK)
	_ = w.pw.Close()
}

func (w *pipeResponseWriter) abort(err error) {
	w.WriteHeader(http.StatusInternalServerError)
	_ = w.pw.CloseWithError(err)
}

var _ http.Flusher = (*pipeResponseWriter)(nil)
