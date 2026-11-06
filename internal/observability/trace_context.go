package observability

import (
	"context"
	"net/http"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	oteltrace "go.opentelemetry.io/otel/trace"
)

// Trace context into toolboxd (plans/agent-sandbox-feature-parity.md §5.9,
// A3). Only W3C Trace Context crosses into the sandbox, never baggage:
// baggage is free-form data a caller set, and the sandbox runs tenant code.

// traceContextPropagator is W3C Trace Context alone (traceparent and
// tracestate).
var traceContextPropagator = propagation.TraceContext{}

// ExtractTraceContext is the API edge's extraction: the configured
// propagator first (trace context and baggage once SB_OTEL_TRACES is on),
// then W3C trace context alone when that found none. With tracing off the
// global propagator is a no-op, and the fallback is what still carries a
// caller's trace id through sandboxd to toolboxd's log.
func ExtractTraceContext(ctx context.Context, h http.Header) context.Context {
	carrier := propagation.HeaderCarrier(h)
	ctx = otel.GetTextMapPropagator().Extract(ctx, carrier)
	if oteltrace.SpanContextFromContext(ctx).IsValid() {
		return ctx
	}
	return traceContextPropagator.Extract(ctx, carrier)
}

// InjectTraceContext sets h's traceparent and tracestate to the span
// context ctx carries: sandboxd's API span with tracing on (a child of the
// caller's trace), else the caller's own context. Whatever h held before is
// dropped first, so a header the edge did not accept (malformed, or sent
// on a route that never extracted it) is never forwarded into the sandbox.
func InjectTraceContext(ctx context.Context, h http.Header) {
	h.Del("Traceparent")
	h.Del("Tracestate")
	// The proxies forward a copy of the caller's headers; without this the
	// caller's baggage went on into the sandbox (tenant code) with them.
	h.Del("Baggage")
	if ctx == nil {
		return
	}
	traceContextPropagator.Inject(ctx, propagation.HeaderCarrier(h))
}
