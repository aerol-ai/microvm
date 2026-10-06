package egress

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/aerol-ai/microvm/internal/observability"
)

// UDS calls carry W3C trace context so gateway spans join the sandboxd
// request that caused them (plans/egress-domain-filtering.md P1-15). The
// propagator is fixed to TraceContext rather than the global one: the
// gateway is its own process and must agree on the format even when only
// one side has an exporter. With tracing off the spans are no-ops and the
// frame field stays empty.
const tracerName = "github.com/aerol-ai/microvm/internal/egress"

var traceContext propagation.TraceContext

func injectTrace(ctx context.Context) string {
	carrier := propagation.MapCarrier{}
	traceContext.Inject(ctx, carrier)
	return carrier["traceparent"]
}

func startClientSpan(ctx context.Context, op string) (context.Context, oteltrace.Span) {
	return otel.Tracer(tracerName).Start(ctx, "egress.client."+op, oteltrace.WithSpanKind(oteltrace.SpanKindClient))
}

func startServerSpan(traceparent, op string) oteltrace.Span {
	ctx := context.Background()
	if traceparent != "" {
		ctx = traceContext.Extract(ctx, propagation.MapCarrier{"traceparent": traceparent})
	}
	_, span := otel.Tracer(tracerName).Start(ctx, "egress.gateway."+op, oteltrace.WithSpanKind(oteltrace.SpanKindServer))
	return span
}

func endSpan(span oteltrace.Span, err error) { observability.EndSpan(span, err) }
