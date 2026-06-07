package observability

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	oteltrace "go.opentelemetry.io/otel/trace"
)

const serviceTracerName = "github.com/aerol-ai/microvm/internal/service"

// StartSpan begins a child span on the service tracer.
func StartSpan(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, oteltrace.Span) {
	return otel.Tracer(serviceTracerName).Start(ctx, name, oteltrace.WithAttributes(attrs...))
}

// EndSpan records err on the span and ends it.
func EndSpan(span oteltrace.Span, err error) {
	if span == nil {
		return
	}
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}
	span.End()
}
