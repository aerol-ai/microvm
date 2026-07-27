package observability

import (
	"context"
	"errors"
	"expvar"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	otelmetric "go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
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

func TestStartOTELExporterConstructorErrors(t *testing.T) {
	prevMetric := newOTLPMetricExporter
	prevTrace := newOTLPTraceExporter
	t.Cleanup(func() {
		newOTLPMetricExporter = prevMetric
		newOTLPTraceExporter = prevTrace
	})

	newOTLPMetricExporter = func(context.Context, ...otlpmetrichttp.Option) (*otlpmetrichttp.Exporter, error) {
		return nil, errors.New("metric exporter boom")
	}
	if _, err := StartOTELMetrics(context.Background(), nil, OTELMetricsConfig{Enabled: true}); err == nil {
		t.Fatal("want StartOTELMetrics exporter error")
	}

	newOTLPTraceExporter = func(context.Context, ...otlptracehttp.Option) (*otlptrace.Exporter, error) {
		return nil, errors.New("trace exporter boom")
	}
	if _, err := StartOTELTraces(context.Background(), nil, OTELTracesConfig{Enabled: true}); err == nil {
		t.Fatal("want StartOTELTraces exporter error")
	}
}

func TestStartOTELMetricsGaugeError(t *testing.T) {
	prev := newInt64ObservableGauge
	t.Cleanup(func() { newInt64ObservableGauge = prev })
	newInt64ObservableGauge = func(otelmetric.Meter, string, ...otelmetric.Int64ObservableGaugeOption) (otelmetric.Int64ObservableGauge, error) {
		return nil, errors.New("gauge boom")
	}
	if _, err := StartOTELMetrics(context.Background(), nil, OTELMetricsConfig{Enabled: true}); err == nil {
		t.Fatal("want gauge creation error")
	}
}

func TestObserveAerolVMExpvarsCancelledAndHappy(t *testing.T) {
	// metric.Observer has an unexported method, so drive observeAerolVMExpvars
	// through a real Meter callback rather than a hand-rolled fake.
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	meter := provider.Meter("coverage95")
	intGauge, err := meter.Int64ObservableGauge("aerolvm.expvar.int64")
	if err != nil {
		t.Fatal(err)
	}
	floatGauge, err := meter.Float64ObservableGauge("aerolvm.expvar.float64")
	if err != nil {
		t.Fatal(err)
	}

	expvar.NewInt("aerolvm_obs_callback_int").Set(7)
	expvar.NewFloat("aerolvm_obs_callback_float").Set(1.25)

	if _, err := meter.RegisterCallback(func(ctx context.Context, observer otelmetric.Observer) error {
		return observeAerolVMExpvars(ctx, observer, intGauge, floatGauge)
	}, intGauge, floatGauge); err != nil {
		t.Fatal(err)
	}

	// Cancelled collect should hit the ctx.Err early-return inside observeAerolVMExpvars.
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	var rm metricdata.ResourceMetrics
	_ = reader.Collect(canceled, &rm)

	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("happy collect: %v", err)
	}
}
