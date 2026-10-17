package api

import (
	"expvar"
	"net/http"
	"sync"

	"go.opentelemetry.io/otel/attribute"
	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// Auth metrics (plans/identity-and-access.md §5.15), exported through
// /v1/metrics. Nested expvar maps become the positional key/key2 labels, and
// the _total suffix types them as counters:
//
//	aerolvm_auth_requests_total{key=<principal kind>,key2=<origin>}
//	  kind:   operator | node | controlplane (token, oidc from T3/T6)
//	  origin: host | peer | public (see authOrigin)
//	aerolvm_auth_failures_total{key=<kind>,key2=<reason>}
//	  kind:   none | unknown | controlplane (token, oidc from T3/T6)
//	  reason: missing | rejected | no_owner | bad_role | bad_team |
//	          team_not_bound | stale (token mirror out of date, 503) |
//	          a D17 reason (expired, wrong_audience, ...)
//
// Every label value comes from a fixed set, never from the request, so a
// caller cannot grow the series count.
var (
	authRequests = expvar.NewMap("aerolvm_auth_requests_total")
	authFailures = expvar.NewMap("aerolvm_auth_failures_total")
	authMetricMu sync.Mutex
)

func addAuthCount(root *expvar.Map, key, key2 string) {
	inner, ok := root.Get(key).(*expvar.Map)
	if !ok {
		// Two first requests of one kind must not each Set a map and lose
		// the other's count.
		authMetricMu.Lock()
		if inner, ok = root.Get(key).(*expvar.Map); !ok {
			inner = new(expvar.Map)
			root.Set(key, inner)
		}
		authMetricMu.Unlock()
	}
	inner.Add(key2, 1)
}

// Trace attribute values for aerolvm.auth.result.
const (
	authResultOK           = "ok"
	authResultUnauthorized = "unauthorized"
	authResultForbidden    = "forbidden"
	authResultBadRequest   = "bad_request"
	authResultUnavailable  = "unavailable"
)

// observeAuth records one authentication decision: a metric, attributes on
// the request span loggingMiddleware opened, and a debug line for a refusal.
// Display names are never recorded, and neither is any part of a credential.
func (s *Server) observeAuth(r *http.Request, access controlplane.Access, failure *authFailure) {
	span := oteltrace.SpanFromContext(r.Context())
	if failure == nil {
		addAuthCount(authRequests, string(access.Principal.Kind), authOrigin(r))
		if span.IsRecording() {
			attrs := []attribute.KeyValue{
				attribute.String("aerolvm.auth.result", authResultOK),
				attribute.String("aerolvm.principal.kind", string(access.Principal.Kind)),
				attribute.String("aerolvm.principal.id", access.Principal.ID),
			}
			if team := access.Team(); team != "" {
				attrs = append(attrs, attribute.String("aerolvm.team", team))
			}
			span.SetAttributes(attrs...)
		}
		return
	}
	addAuthCount(authFailures, failure.kind, failure.reason)
	if span.IsRecording() {
		span.SetAttributes(attribute.String("aerolvm.auth.result", authResultFor(failure.status)))
	}
	if s.logger != nil {
		s.logger.Debug("authentication refused",
			"status", failure.status, "kind", failure.kind, "reason", failure.reason,
			"origin", authOrigin(r), "path", r.URL.Path)
	}
}

func authResultFor(status int) string {
	switch status {
	case http.StatusForbidden:
		return authResultForbidden
	case http.StatusBadRequest:
		return authResultBadRequest
	case http.StatusServiceUnavailable:
		return authResultUnavailable
	}
	return authResultUnauthorized
}
