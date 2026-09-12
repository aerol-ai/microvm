package controlplane

import (
	"context"
	"testing"
)

type stubExporter struct{}

func (stubExporter) ExportEvents(context.Context, AuditEventBatch) (string, error) {
	return "next", nil
}

type stubWitness struct{}

func (stubWitness) WitnessHeads(context.Context, []AuditHead) (WitnessReceipt, error) {
	return WitnessReceipt{ReceiptID: "r1"}, nil
}

func (stubWitness) LastWitnessedHead(context.Context, string) (string, bool, error) {
	return "deadbeef", true, nil
}

func TestHasAuditExporterAndExportEvents(t *testing.T) {
	noop := Noop()
	if noop.HasAuditExporter() {
		t.Fatal("noop must not report an audit exporter")
	}
	if next, err := noop.AuditExporter.ExportEvents(context.Background(), AuditEventBatch{NodeID: "n1"}); err != nil || next != "" {
		t.Fatalf("noop ExportEvents = %q %v", next, err)
	}

	empty := Provider{}
	if empty.HasAuditExporter() || empty.HasExternalWitness() {
		t.Fatal("nil capabilities must not look real")
	}

	filled := Provider{AuditExporter: stubExporter{}, Witness: stubWitness{}}.WithDefaults()
	if !filled.HasAuditExporter() {
		t.Fatal("custom exporter must be detected")
	}
	if !filled.HasExternalWitness() {
		t.Fatal("custom witness must be detected")
	}
	if next, err := filled.AuditExporter.ExportEvents(context.Background(), AuditEventBatch{BatchID: "b1"}); err != nil || next != "next" {
		t.Fatalf("custom ExportEvents = %q %v", next, err)
	}
}
