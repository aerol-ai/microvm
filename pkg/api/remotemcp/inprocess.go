package remotemcp

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
)

// inProcessTransport hands each Go SDK request straight to sandboxd's own
// API handler, carrying the MCP caller's Authorization header. A remote tool
// call therefore goes through exactly the same auth, tenant scoping, cluster
// forwarding and idempotency as a direct API call: there is no second authz
// path and no loopback listener to configure.
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
}

func (t *inProcessTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	in := req.Clone(ctx)
	in.RequestURI = req.URL.RequestURI()
	in.RemoteAddr = t.remoteAddr
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
