package observability

import (
	"context"
	"net/http"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	oteltrace "go.opentelemetry.io/otel/trace"
)

const (
	testTraceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	testTraceID     = "4bf92f3577b34da6a3ce929d0e0e4736"
)

// With tracing off (the no-op global propagator), the edge still takes the
// caller's W3C trace context, and a toolbox request carries it on; with
// tracing on, the configured propagator wins. Baggage never crosses.
func TestTraceContextExtractAndInject(t *testing.T) {
	old := otel.GetTextMapPropagator()
	t.Cleanup(func() { otel.SetTextMapPropagator(old) })

	in := http.Header{}
	in.Set("traceparent", testTraceparent)
	in.Set("tracestate", "vendor=1")
	in.Set("baggage", "user=alice")

	for name, prop := range map[string]propagation.TextMapPropagator{
		"tracing off": propagation.NewCompositeTextMapPropagator(),
		"tracing on":  propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}),
	} {
		t.Run(name, func(t *testing.T) {
			otel.SetTextMapPropagator(prop)
			ctx := ExtractTraceContext(context.Background(), in)
			if got := oteltrace.SpanContextFromContext(ctx).TraceID().String(); got != testTraceID {
				t.Fatalf("extracted trace id %q", got)
			}
			// The proxies send a copy of the caller's headers on to the
			// sandbox, so start from that copy: the caller's baggage is in it.
			out := in.Clone()
			out.Set("traceparent", "00-ffffffffffffffffffffffffffffffff-ffffffffffffffff-01")
			out.Set("tracestate", "stale=1")
			InjectTraceContext(ctx, out)
			if out.Get("traceparent") != testTraceparent || out.Get("tracestate") != "vendor=1" {
				t.Fatalf("injected %q / %q", out.Get("traceparent"), out.Get("tracestate"))
			}
			if out.Get("baggage") != "" {
				t.Fatal("baggage crossed into the sandbox")
			}
		})
	}
}

// A context with no trace drops whatever the outgoing request carried: a
// header the edge never accepted is not forwarded.
func TestInjectTraceContextWithoutATrace(t *testing.T) {
	h := http.Header{}
	h.Set("traceparent", "garbage")
	h.Set("tracestate", "x=1")
	InjectTraceContext(context.Background(), h)
	if h.Get("traceparent") != "" || h.Get("tracestate") != "" {
		t.Fatalf("headers kept: %v", h)
	}
	h.Set("traceparent", "garbage")
	//nolint:staticcheck // a nil context is what an unwired caller passes
	InjectTraceContext(nil, h)
	if h.Get("traceparent") != "" {
		t.Fatal("nil context kept the header")
	}
	// A malformed caller header extracts to nothing.
	bad := http.Header{}
	bad.Set("traceparent", "garbage")
	if oteltrace.SpanContextFromContext(ExtractTraceContext(context.Background(), bad)).IsValid() {
		t.Fatal("a malformed traceparent was accepted")
	}
}
