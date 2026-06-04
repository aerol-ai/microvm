package observability

import (
	"context"
	"testing"
)

func TestOTELDisabledAndHelpers(t *testing.T) {
	metricsShutdown, err := StartOTELMetrics(context.Background(), nil, OTELMetricsConfig{Enabled: false})
	if err != nil {
		t.Fatalf("StartOTELMetrics disabled error = %v", err)
	}
	if metricsShutdown != nil {
		t.Fatalf("expected nil metrics shutdown when disabled")
	}

	tracesShutdown, err := StartOTELTraces(context.Background(), nil, OTELTracesConfig{Enabled: false})
	if err != nil {
		t.Fatalf("StartOTELTraces disabled error = %v", err)
	}
	if tracesShutdown != nil {
		t.Fatalf("expected nil traces shutdown when disabled")
	}

	res := otelResource("", "node-1", "leader")
	if res == nil {
		t.Fatalf("expected non-nil resource")
	}

	attrs := expvarAttributes(ExpvarSample{
		Name: "metric.name",
		Labels: []ExpvarLabel{
			{Name: "sandbox", Value: "sb1"},
			{Name: "", Value: "ignored"},
		},
	})
	if len(attrs) != 2 {
		t.Fatalf("attrs len = %d, want 2", len(attrs))
	}
	if string(attrs[0].Key) != "metric" || attrs[0].Value.AsString() != "metric.name" {
		t.Fatalf("unexpected first attr: %+v", attrs[0])
	}
}
