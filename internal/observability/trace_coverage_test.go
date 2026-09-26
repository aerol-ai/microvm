package observability

import (
	"context"
	"errors"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestStartAndEndSpanCoverage95(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })

	// Install a recording provider so EndSpan's RecordError/SetStatus path
	// is real work, not a noop global tracer.
	otel.SetTracerProvider(tp)
	t.Cleanup(func() {
		otel.SetTracerProvider(sdktrace.NewTracerProvider())
	})

	ctx, span := StartSpan(context.Background(), "coverage95", attribute.String("k", "v"))
	if span == nil {
		t.Fatal("expected non-nil span")
	}
	EndSpan(span, errors.New("boom"))
	_ = ctx

	EndSpan(nil, errors.New("ignored"))

	_, spanOK := StartSpan(context.Background(), "ok")
	EndSpan(spanOK, nil)

	spans := exporter.GetSpans()
	if len(spans) < 2 {
		t.Fatalf("recorded spans = %d, want >= 2", len(spans))
	}
}
