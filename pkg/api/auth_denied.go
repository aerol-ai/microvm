package api

import (
	"expvar"
	"net/http"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/auditlog"
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
//     record carries how many 401s from that address it stands for. Every
//     401 is also counted in aerolvm_auth_failures_total.
//
// The source address is Server.clientAddress (pat_scope.go): the TCP peer,
// or with SB_L4_FALLBACK_PROXY_PROTOCOL on, the X-AerolVM-Client-IP Caddy
// sets from the address the caddy-l4 PROXY header gave it (CEO review
// D12), trusted only from Caddy's socket or a loopback peer. With the flag
// off, requests through Caddy show the loopback address, as before.

const (
	authDeniedWindow = time.Minute
	// authDeniedMaxSources bounds the per-address map. Past it, after a
	// sweep, a 401 from a new address is counted but not recorded: the cap
	// is the disk bound under a spray from many addresses.
	authDeniedMaxSources = 10_000
)

// auditAuthDeniedSuppressedTotal counts 401s with no auth_denied record of
// their own (folded into a later one, or dropped past the address cap).
var auditAuthDeniedSuppressedTotal = expvar.NewInt("aerolvm_audit_auth_denied_suppressed_total")

type authDeniedSource struct {
	recordedAt time.Time
	suppressed int64
}

// authDeniedLimiter allows one record per source address per window.
type authDeniedLimiter struct {
	mu        sync.Mutex
	sources   map[string]*authDeniedSource
	lastSweep time.Time
	now       func() time.Time
}

func newAuthDeniedLimiter() *authDeniedLimiter {
	return &authDeniedLimiter{sources: map[string]*authDeniedSource{}, now: time.Now}
}

// admit reports whether a 401 from source gets a record now, and how many
// 401s that record stands for (this one plus those folded since the last).
func (l *authDeniedLimiter) admit(source string) (bool, int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if e, ok := l.sources[source]; ok {
		if now.Sub(e.recordedAt) < authDeniedWindow {
			e.suppressed++
			auditAuthDeniedSuppressedTotal.Add(1)
			return false, 0
		}
		n := e.suppressed + 1
		e.recordedAt, e.suppressed = now, 0
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
			Surface: auditlog.SurfaceFromContext(ctx),
		})
		return
	}
	source := s.clientAddress(r)
	ok, count := s.authDenied.admit(source)
	if !ok {
		return
	}
	s.service.RecordAuthDenied(withCorrelationID(r.Context(), r), r.Method, route.route, f.reason, source, count)
}
