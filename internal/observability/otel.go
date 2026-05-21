package observability

import (
	"context"
	"log/slog"
	"time"

	"github.com/aerol-ai/microvm/internal/version"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	otelmetric "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

type OTELMetricsConfig struct {
	Enabled     bool
	Endpoint    string
	Interval    time.Duration
	ServiceName string
	NodeID      string
	NodeRole    string
}

type OTELTracesConfig struct {
	Enabled     bool
	Endpoint    string
	SampleRatio float64
	ServiceName string
	NodeID      string
	NodeRole    string
}

const defaultOTELMetricsInterval = 30 * time.Second

type MetricsShutdown func(context.Context) error
type TracesShutdown func(context.Context) error

func StartOTELMetrics(ctx context.Context, logger *slog.Logger, cfg OTELMetricsConfig) (MetricsShutdown, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	opts := []otlpmetrichttp.Option{}
	if cfg.Endpoint != "" {
		opts = append(opts, otlpmetrichttp.WithEndpointURL(cfg.Endpoint))
	}
	exporter, err := otlpmetrichttp.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	interval := defaultOTELMetricsInterval
	if cfg.Interval > 0 {
		interval = cfg.Interval
	}
	reader := sdkmetric.NewPeriodicReader(exporter, sdkmetric.WithInterval(interval))
	provider := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(reader),
		sdkmetric.WithResource(otelResource(cfg.ServiceName, cfg.NodeID, cfg.NodeRole)),
	)
	meter := provider.Meter("github.com/aerol-ai/microvm/sandboxd")
	intGauge, err := meter.Int64ObservableGauge(
		"aerolvm.expvar.int64",
		otelmetric.WithDescription("Current AerolVM expvar int64 value. The original expvar name is in the metric attribute."),
	)
	if err != nil {
		_ = provider.Shutdown(ctx)
		return nil, err
	}
	floatGauge, err := meter.Float64ObservableGauge(
		"aerolvm.expvar.float64",
		otelmetric.WithDescription("Current AerolVM expvar float64 value. The original expvar name is in the metric attribute."),
	)
	if err != nil {
		_ = provider.Shutdown(ctx)
		return nil, err
	}
	if _, err := meter.RegisterCallback(func(ctx context.Context, observer otelmetric.Observer) error {
		// Bail out without surfacing the cancellation as a callback error:
		// the OTEL SDK logs non-nil callback returns on every cycle, which
		// turns routine periodic-reader timeouts into log noise.
		if err := ctx.Err(); err != nil {
			return nil
		}
		for _, sample := range CollectAerolVMExpvars() {
			attrs := expvarAttributes(sample)
			if sample.Int64 != nil {
				observer.ObserveInt64(intGauge, *sample.Int64, otelmetric.WithAttributes(attrs...))
			}
			if sample.Float != nil {
				observer.ObserveFloat64(floatGauge, *sample.Float, otelmetric.WithAttributes(attrs...))
			}
		}
		return nil
	}, intGauge, floatGauge); err != nil {
		_ = provider.Shutdown(ctx)
		return nil, err
	}
	otel.SetMeterProvider(provider)
	if logger != nil {
		logger.Info("otel metrics exporter enabled", "endpoint", cfg.Endpoint, "interval", interval.String())
	}
	return provider.Shutdown, nil
}

func StartOTELTraces(ctx context.Context, logger *slog.Logger, cfg OTELTracesConfig) (TracesShutdown, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	opts := []otlptracehttp.Option{}
	if cfg.Endpoint != "" {
		opts = append(opts, otlptracehttp.WithEndpointURL(cfg.Endpoint))
	}
	exporter, err := otlptracehttp.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	sampleRatio := cfg.SampleRatio
	if sampleRatio < 0 {
		sampleRatio = 0
	} else if sampleRatio > 1 {
		sampleRatio = 1
	}
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(sampleRatio))),
		sdktrace.WithResource(otelResource(cfg.ServiceName, cfg.NodeID, cfg.NodeRole)),
	)
	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))
	if logger != nil {
		logger.Info("otel trace exporter enabled", "endpoint", cfg.Endpoint, "sample_ratio", sampleRatio)
	}
	return provider.Shutdown, nil
}

func otelResource(serviceName, nodeID, nodeRole string) *resource.Resource {
	if serviceName == "" {
		serviceName = "sandboxd"
	}
	return resource.NewWithAttributes("",
		attribute.String("service.name", serviceName),
		attribute.String("service.version", version.Version),
		attribute.String("aerolvm.node.id", nodeID),
		attribute.String("aerolvm.node.role", nodeRole),
	)
}

func expvarAttributes(sample ExpvarSample) []attribute.KeyValue {
	attrs := make([]attribute.KeyValue, 0, len(sample.Labels)+1)
	attrs = append(attrs, attribute.String("metric", sample.Name))
	for _, label := range sample.Labels {
		if label.Name == "" {
			continue
		}
		attrs = append(attrs, attribute.String(label.Name, label.Value))
	}
	return attrs
}
