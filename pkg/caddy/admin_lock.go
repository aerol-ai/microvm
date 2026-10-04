package caddy

import (
	"context"
	"errors"
	"net/http"
	"net/url"
)

// Serialized admin writes.
//
// Every Caddy config change is a full reload, and every reload also replaces
// the admin endpoint: Caddy starts a new admin server and shuts the old one
// down in the background, closing the old server's idle connections. Caddy
// itself applies changes one at a time, so issuing them concurrently from
// this process never bought throughput. It did cost correctness, twice:
//
//   - A request sent on a pooled keep-alive connection while the previous
//     write's reload is closing that connection fails with a bare EOF before
//     Caddy sees it. Go only retries GET/HEAD/OPTIONS/TRACE on such a
//     connection, so PATCH/PUT/DELETE surface as errors. Live 2026-10-04
//     (cluster-hetero, ingress-1): two reconcile goroutines each had one
//     write in flight; the second DELETE/PUT got EOF at 05:42:22 and
//     05:42:27 and never reached Caddy's log.
//   - Read-modify-write sequences interleave. EnsureLayer4 GETs the tls-mux
//     server and POSTs the whole object back; a route another goroutine
//     inserted in between is silently dropped by that POST. Likewise a
//     PATCH-404-then-PUT upsert racing another upsert of the same @id
//     inserts it twice, which Caddy refuses ("duplicate ID").
//
// So the client owns one mutex for config mutations, held across the round
// trip (Caddy answers a write only after the reload it caused). do() takes it
// for every non-read request, which makes it impossible for a new call site
// to forget; multi-request helpers take it once with withAdminLock, which
// marks their context so the requests inside don't take it again. Reads are
// not serialized: they cause no reload.
//
// Lock order is adminMu, then gate (batch.go). Batch takes adminMu before
// gate when it opens and when it commits, so the two cannot deadlock.

type adminLockKey struct{}

// withAdminLock runs fn holding the admin write lock. fn must issue every
// admin request with the ctx it is handed: that ctx tells do() the lock is
// already held. Calls nest.
func (c *Client) withAdminLock(ctx context.Context, fn func(context.Context) error) error {
	if holdsAdminLock(ctx) {
		return fn(ctx)
	}
	c.adminMu.Lock()
	defer c.adminMu.Unlock()
	return fn(context.WithValue(ctx, adminLockKey{}, true))
}

func holdsAdminLock(ctx context.Context) bool {
	held, _ := ctx.Value(adminLockKey{}).(bool)
	return held
}

// mutatesConfig reports whether an admin request can change Caddy's config.
func mutatesConfig(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	return true
}

// newAdminTransport is the admin API transport, with keep-alives off.
//
// WHY: a pooled connection belongs to the admin server that accepted it, and
// the next config change shuts that server down. Serializing writes makes
// this worse, not better: the connection the last write just returned to the
// pool is exactly the one being closed when the next write picks it up. A
// fresh loopback dial per call costs microseconds; an admin write costs a
// whole config reload.
func newAdminTransport() http.RoundTripper {
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return &http.Transport{DisableKeepAlives: true}
	}
	t := base.Clone()
	t.DisableKeepAlives = true
	return t
}

// IsTransientAdminError reports whether err is a failure to talk to the admin
// API at all (refused, reset, EOF, timeout) rather than Caddy answering with an
// error status. Such a request may or may not have been applied. Every
// exported helper starts from what Caddy holds (PATCH by @id, or a GET), so
// repeating the helper is safe and callers retry it soon instead of on their
// slow cadence. A cancelled context is the caller stopping, not a transient
// failure.
func IsTransientAdminError(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	var urlErr *url.Error
	return errors.As(err, &urlErr)
}
