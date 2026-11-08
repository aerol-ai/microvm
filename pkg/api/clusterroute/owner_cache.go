package clusterroute

import (
	"bytes"
	"crypto/rand"
	"io"
	"maps"
	"net/http"
	"strings"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/auditlog"
)

// The two halves of the owner cache (internal/cluster/owner_cache.go):
// serveFromOwnerCache is the edge, which forwards from an entry and routes the
// call again when the target turns it down; writeNotOwner is the target's
// "not here". Wrap calls both.

// maxReplayBody is the largest request body the edge holds so it can send a
// cache-routed call a second time after a "not here". Calls with a bigger or
// unsized body (file uploads) skip the cache and take the lookup path, which
// streams the body as before. Most routed calls (reads, exec, sessions) send
// no body or a small JSON one.
const maxReplayBody = 64 << 10

// serveFromOwnerCache forwards r to the owner its cache entry names. It
// returns true once a response has been written, and false when the caller
// must route r down the lookup path: no usable entry, a body too big to
// hold, or the target answered "not here". In the last case r's body has been
// rewound, so the second send carries the same bytes as the first.
func serveFromOwnerCache(c cluster.Client, cache *cluster.OwnerCache, id string, w http.ResponseWriter, r *http.Request, write ErrorWriter) bool {
	route, ok := cache.Get(id)
	if ok {
		// The entry may skip the tenant check only when it carries the
		// tenant and the tenant is the caller's. A foreign sandbox goes down
		// the lookup path, which answers it the way it answers an unknown id.
		if caller := strings.TrimSpace(service.OwnerRefForCreate(r.Context())); caller != "" && (!route.HasOwnerRef || route.OwnerRef != caller) {
			ok = false
		}
	}
	if !ok {
		cluster.RecordOwnerCacheMiss()
		return false
	}
	body, ok, err := replayBody(r)
	if err != nil {
		write(w, http.StatusBadRequest, "read request body: "+err.Error())
		return true
	}
	if !ok {
		cluster.RecordOwnerCacheMiss()
		return false
	}
	cluster.RecordOwnerCacheHit()
	token := rand.Text()
	catcher := &notOwnerCatcher{w: w, token: token, before: w.Header().Clone()}
	// The attempt gets its own headers (ForwardHTTP marks them), so a retry
	// starts from exactly the request the client sent.
	attempt := r.WithContext(cluster.ContextWithRouteHint(r.Context(), token))
	attempt.Header = r.Header.Clone()
	attempt.Body = body()
	c.ForwardHTTP(route.Endpoint, catcher, attempt)
	if !catcher.caught {
		switch catcher.status {
		case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			// The target could not be reached or could not answer. Pass the
			// answer on (a retry could run the call twice) and look the
			// sandbox up next time.
			cache.Forget(id)
		}
		return true
	}
	// The target ran nothing. Undo what the attempt left: its response
	// headers, and the audit mark that a peer will record the call.
	h := w.Header()
	clear(h)
	maps.Copy(h, catcher.before)
	auditlog.ClearForwarded(r.Context())
	cache.Forget(id)
	cluster.RecordOwnerCacheRetry()
	r.Body = body()
	return false
}

// writeNotOwner answers a cache-routed forward this node will not serve:
// 421 with the request's token in cluster.HeaderNotOwner.
func writeNotOwner(w http.ResponseWriter, r *http.Request, token string, write ErrorWriter) {
	cluster.RecordOwnerCacheNotOwner()
	// This node runs nothing; the edge routes the call again and the node
	// that answers it writes the one audit record.
	auditlog.MarkForwarded(r.Context())
	w.Header().Set(cluster.HeaderNotOwner, token)
	write(w, http.StatusMisdirectedRequest, "cluster: this node does not own the sandbox; route it again")
}

// replayBody reads r's body into memory so it can be sent twice. ok is false
// when the body is unsized or bigger than maxReplayBody; r is untouched then.
func replayBody(r *http.Request) (next func() io.ReadCloser, ok bool, err error) {
	if r.Body == nil || r.Body == http.NoBody {
		return func() io.ReadCloser { return http.NoBody }, true, nil
	}
	if r.ContentLength < 0 || r.ContentLength > maxReplayBody {
		return nil, false, nil
	}
	buf, err := io.ReadAll(io.LimitReader(r.Body, r.ContentLength))
	if err != nil {
		return nil, false, err
	}
	return func() io.ReadCloser { return io.NopCloser(bytes.NewReader(buf)) }, true, nil
}

// notOwnerCatcher is the ResponseWriter of a cache-routed forward. It passes
// the target's answer through unchanged, except a 421 whose
// cluster.HeaderNotOwner is this request's token: that one it swallows so
// the edge can route the call again. Nothing reaches the caller before the
// status line, so a swallowed answer leaves only headers, which the caller of
// serveFromOwnerCache restores from before.
type notOwnerCatcher struct {
	w      http.ResponseWriter
	token  string
	before http.Header
	status int // final status passed through; 0 = none yet
	caught bool
}

func (c *notOwnerCatcher) Header() http.Header { return c.w.Header() }

func (c *notOwnerCatcher) WriteHeader(code int) {
	if c.caught {
		return
	}
	h := c.w.Header()
	if c.status == 0 && code == http.StatusMisdirectedRequest && h.Get(cluster.HeaderNotOwner) == c.token {
		c.caught = true
		return
	}
	// Cluster-private: never shown to a caller, whoever set it.
	h.Del(cluster.HeaderNotOwner)
	if code >= http.StatusOK && c.status == 0 {
		c.status = code
	}
	c.w.WriteHeader(code)
}

func (c *notOwnerCatcher) Write(b []byte) (int, error) {
	if c.status == 0 && !c.caught {
		c.WriteHeader(http.StatusOK)
	}
	if c.caught {
		return len(b), nil
	}
	return c.w.Write(b)
}

// FlushError keeps a streamed answer (exec output, logs) streaming.
func (c *notOwnerCatcher) FlushError() error {
	if c.caught {
		return nil
	}
	return http.NewResponseController(c.w).Flush()
}

// Unwrap lets the reverse proxy hijack the connection for a WebSocket upgrade
// (a 101 is never a "not here").
func (c *notOwnerCatcher) Unwrap() http.ResponseWriter { return c.w }
