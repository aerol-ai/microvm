package api

import (
	"context"
	"expvar"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// Refused requests in the evidence (plans/identity-and-access.md §5.9,
// "Denied calls"; Section 2 finding 2.3):
//
//   - a refusal that names a caller (a 403, or a 400 for a bad team header,
//     from a credential that verified) is an api record with result denied,
//     like a 403 from the permission check;
//   - a refused credential (401) is an auth_denied record, at most one per
//     source address per minute, so a token spray cannot fill the disk. The
//     first 401 from an address is written at once and opens its minute;
//     the 401s after it in that minute are folded. When the minute ends,
//     the folded ones are written as one record that carries their count
//     and describes the last of them, and that record opens the address's
//     next minute. So a spray that stops is still in the evidence at full
//     volume, and an address still gets at most one record a minute. Every
//     401 is also counted in aerolvm_auth_failures_total.
//
// The source address is Server.clientAddress (pat_scope.go): the TCP peer,
// or with SB_L4_FALLBACK_PROXY_PROTOCOL on, the X-AerolVM-Client-IP Caddy
// sets from the address the caddy-l4 PROXY header gave it (CEO review
// D12), trusted only from Caddy's socket or a loopback peer. With the flag
// off, requests through Caddy show the loopback address, as before.
//
// Folded counts live in memory until their record is written. A graceful
// shutdown writes what is still owed (StopBackground). A crash loses the
// folded 401s of each address's open window, at most one window plus one
// flush interval of them; the 401 that opened the window was written when
// it arrived.

const (
	authDeniedWindow = time.Minute
	// authDeniedFlushInterval is how often the flush loop writes the
	// records owed by addresses whose window has closed: a folded 401
	// reaches the audit writer at most one window plus one interval after
	// the 401 that opened its window. A tick walks the address map (at most
	// authDeniedMaxSources entries) under the limiter's lock.
	authDeniedFlushInterval = authDeniedWindow / 6
	// authDeniedMaxSources bounds the per-address map. Past it, after a
	// sweep, a 401 from a new address is counted but not recorded: the cap
	// is the disk bound under a spray from many addresses.
	authDeniedMaxSources = 10_000
	// authDeniedMaxField caps each request detail an address keeps for its
	// owed record, so the map's memory stays bounded. The method is the
	// client's own; no real method or route comes near the cap.
	authDeniedMaxField = 256
)

// auditAuthDeniedSuppressedTotal counts 401s with no auth_denied record of
// their own (folded into a later one, or dropped past the address cap).
var auditAuthDeniedSuppressedTotal = expvar.NewInt("aerolvm_audit_auth_denied_suppressed_total")

type authDeniedSource struct {
	recordedAt time.Time
	suppressed int64
	// last describes the most recent folded 401, for the record written
	// when the window closes.
	last authDeniedRequest
}

// authDeniedRequest is what an auth_denied record says about the 401 it
// describes. Never the credential.
type authDeniedRequest struct {
	method, route, reason string
}

// keep makes r describe req. An address's entry outlives the request, so
// each field is copied out of the request's memory (a substring of the
// request line would pin all of it) and capped. A field that has not
// changed, the common case in a spray, is not copied again.
func (r *authDeniedRequest) keep(req authDeniedRequest) {
	r.method = keepField(r.method, req.method)
	r.route = keepField(r.route, req.route)
	r.reason = keepField(r.reason, req.reason)
}

func keepField(held, s string) string {
	if len(s) > authDeniedMaxField {
		s = s[:authDeniedMaxField]
	}
	if s == held {
		return held
	}
	return strings.Clone(s)
}

// owedAuthDenied is a record the flush writes: count folded 401s from
// source, described by the last of them.
type owedAuthDenied struct {
	source string
	req    authDeniedRequest
	count  int64
}

// authDeniedLimiter allows one record per source address per window.
type authDeniedLimiter struct {
	mu        sync.Mutex
	sources   map[string]*authDeniedSource
	lastSweep time.Time
	now       func() time.Time
	// flushEvery is the flush loop's tick (tests shrink it).
	flushEvery time.Duration
}

func newAuthDeniedLimiter() *authDeniedLimiter {
	return &authDeniedLimiter{sources: map[string]*authDeniedSource{}, now: time.Now, flushEvery: authDeniedFlushInterval}
}

// admit reports whether a 401 from source gets a record now, and how many
// 401s that record stands for (this one plus those folded since the last).
// A folded 401's details are kept for the record its window owes.
func (l *authDeniedLimiter) admit(source string, req authDeniedRequest) (bool, int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if e, ok := l.sources[source]; ok {
		if now.Sub(e.recordedAt) < authDeniedWindow {
			e.suppressed++
			e.last.keep(req)
			auditAuthDeniedSuppressedTotal.Add(1)
			return false, 0
		}
		// The window closed before the flush loop reached it: this record
		// carries what it owed.
		n := e.suppressed + 1
		e.recordedAt, e.suppressed, e.last = now, 0, authDeniedRequest{}
		return true, n
	}
	if len(l.sources) >= authDeniedMaxSources || now.Sub(l.lastSweep) >= authDeniedWindow {
		l.sweep(now)
	}
	if len(l.sources) >= authDeniedMaxSources {
		auditAuthDeniedSuppressedTotal.Add(1)
		return false, 0
	}
	l.sources[source] = &authDeniedSource{recordedAt: now}
	return true, 1
}

// takeOwed returns the records owed by addresses whose window has closed,
// or by every address that owes one when all is set (shutdown). Each one
// taken opens its address's next window, so an address still gets at most
// one record per window; only the shutdown flush can write a second inside
// one. It then forgets the addresses that owe nothing, as admit's sweep
// does.
func (l *authDeniedLimiter) takeOwed(all bool) []owedAuthDenied {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	var owed []owedAuthDenied
	for source, e := range l.sources {
		if e.suppressed == 0 || (!all && now.Sub(e.recordedAt) < authDeniedWindow) {
			continue
		}
		owed = append(owed, owedAuthDenied{source: source, req: e.last, count: e.suppressed})
		e.recordedAt, e.suppressed, e.last = now, 0, authDeniedRequest{}
	}
	l.sweep(now)
	return owed
}

// sweep forgets addresses whose window closed and that owe nothing.
func (l *authDeniedLimiter) sweep(now time.Time) {
	l.lastSweep = now
	for k, e := range l.sources {
		if e.suppressed == 0 && now.Sub(e.recordedAt) >= authDeniedWindow {
			delete(l.sources, k)
		}
	}
}

// recordAuthFailure writes the evidence of a refused request (see above).
func (s *Server) recordAuthFailure(r *http.Request, f *authFailure) {
	if s.service == nil || s.audit == nil || !s.service.APIAuditPolicy().Enabled {
		return
	}
	route := describeRoute(r)
	if f.status != http.StatusUnauthorized {
		if !f.hasCaller {
			return
		}
		ctx := controlplane.ContextWithAccess(r.Context(), f.caller)
		s.service.RecordAPICall(withCorrelationID(ctx, r), service.APICall{
			Method: r.Method, Route: route.route, Status: f.status,
			SandboxID: route.sandboxID, Target: route.target, Denied: true,
			Surface: requestSurface(r),
		})
		return
	}
	source := s.clientAddress(r)
	ok, count := s.authDenied.admit(source, authDeniedRequest{method: r.Method, route: route.route, reason: f.reason})
	if !ok {
		return
	}
	s.service.RecordAuthDenied(withCorrelationID(r.Context(), r), r.Method, route.route, f.reason, source, count)
}

// recordsAuthDenied reports whether this server can ever write an
// auth_denied record: api records are not off.
func (s *Server) recordsAuthDenied() bool {
	return s.service != nil && s.audit != nil && s.authDenied != nil
}

// flushAuthDenied writes the records takeOwed returns. While the audit
// policy is off (the cluster audit gate, closed during a rolling upgrade)
// it takes nothing, so the counts stay owed until the gate opens.
func (s *Server) flushAuthDenied(all bool) {
	if !s.recordsAuthDenied() || !s.service.APIAuditPolicy().Enabled {
		return
	}
	for _, o := range s.authDenied.takeOwed(all) {
		// No request is in flight: the record gets a fresh correlation id.
		s.service.RecordAuthDenied(context.Background(), o.req.method, o.req.route, o.req.reason, o.source, o.count)
	}
}

// StartBackground starts the server's background work, which runs until
// ctx ends or StopBackground is called: the loop that writes the
// auth_denied records owed for folded 401s. It starts nothing when api
// records are off. Call it once, before serving.
func (s *Server) StartBackground(ctx context.Context) {
	s.bgMu.Lock()
	defer s.bgMu.Unlock()
	if s.bgStop != nil || s.bgStopped || !s.recordsAuthDenied() {
		return
	}
	s.bgStop, s.bgDone = make(chan struct{}), make(chan struct{})
	go s.flushAuthDeniedLoop(ctx, s.authDenied.flushEvery, s.bgStop, s.bgDone)
}

// StopBackground ends the background work, then writes every auth_denied
// record still owed, window closed or not. Call it after the HTTP
// listeners have drained, so 401s folded during the drain are written too,
// and before the audit writer closes. Safe to call twice, and without
// StartBackground.
func (s *Server) StopBackground() {
	s.bgMu.Lock()
	stop, done, stopped := s.bgStop, s.bgDone, s.bgStopped
	s.bgStopped = true
	s.bgMu.Unlock()
	if stopped {
		return
	}
	if stop != nil {
		close(stop)
		<-done
	}
	s.flushAuthDenied(true)
}

func (s *Server) flushAuthDeniedLoop(ctx context.Context, every time.Duration, stop <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-stop:
			return
		case <-t.C:
			s.flushAuthDenied(false)
		}
	}
}
