package egress

import (
	"context"
	"net/netip"
	"testing"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace/noop"
)

// TestUDSCallsCarryTraceContext (P1-15): a sandboxd Attach and the gateway's
// handling of it land in one trace, the gateway span a child of the client
// span, and a failed call marks both spans as errors.
func TestUDSCallsCarryTraceContext(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	otel.SetTracerProvider(tp)
	t.Cleanup(func() {
		_ = tp.Shutdown(context.Background())
		otel.SetTracerProvider(noop.NewTracerProvider())
	})
	c, _, _, _ := startServer(t, ServerHooks{}, nil)
	ctx, parent := otel.Tracer("test").Start(context.Background(), "create")
	if err := c.Attach(ctx, Spec{ID: "sb", IP: netip.MustParseAddr("10.0.0.2"), AllowOut: []string{"pypi.org"}}); err != nil {
		t.Fatal(err)
	}
	if err := c.SetBlocked(ctx, "missing", BlockAll, true); err == nil {
		t.Fatal("SetBlocked on an unknown sandbox must fail")
	}
	parent.End()

	byName := map[string]tracetest.SpanStub{}
	for _, s := range exporter.GetSpans() {
		byName[s.Name] = s
	}
	client, server := byName["egress.client.attach"], byName["egress.gateway.attach"]
	if client.Name == "" || server.Name == "" {
		t.Fatalf("spans = %v", exporter.GetSpans().Snapshots())
	}
	traceID := parent.SpanContext().TraceID()
	if client.SpanContext.TraceID() != traceID || server.SpanContext.TraceID() != traceID {
		t.Fatal("client and gateway spans must join the caller's trace")
	}
	if server.Parent.SpanID() != client.SpanContext.SpanID() {
		t.Fatal("the gateway span must be a child of the client span")
	}
	if byName["egress.gateway.set_blocked"].Status.Code.String() != "Error" ||
		byName["egress.client.set_blocked"].Status.Code.String() != "Error" {
		t.Fatal("a failed call must mark both spans")
	}
	// Without a parent the gateway still records a root span.
	if s := startServerSpan("", "sync"); !s.SpanContext().IsValid() {
		t.Fatal("root gateway span")
	}
}
