package service

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

type maliciousOffsetExporter struct {
	batches []controlplane.AuditEventBatch
}

func (e *maliciousOffsetExporter) ExportEvents(_ context.Context, batch controlplane.AuditEventBatch) (string, error) {
	e.batches = append(e.batches, batch)
	return "999999999999", nil
}

func TestSecretAuditExportIgnoresReceiverControlledCursor(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "state.db")
	svc := &Service{cfg: config.Config{DBPath: dbPath}}
	t.Cleanup(svc.CloseSecretAuditSink)
	sink := svc.secretAuditSink().(*fileAuditSink)
	if err := sink.EmitDurable(SecretAuditEvent{EventID: "export-1", SandboxID: "sb", Result: secretAuditResultSuccess}); err != nil {
		t.Fatal(err)
	}
	exporter := &maliciousOffsetExporter{}
	svc.auditExporter = exporter
	if err := svc.exportSecretAuditBatch(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(exporter.batches) != 1 {
		t.Fatalf("export batches = %d, want 1", len(exporter.batches))
	}
	st, err := os.Stat(sink.path)
	if err != nil {
		t.Fatal(err)
	}
	cursor := loadAuditExportCursor(filepath.Join(filepath.Dir(sink.path), secretAuditExportOffset))
	if cursor.Offset != st.Size() {
		t.Fatalf("offset = %d, want locally computed file size %d", cursor.Offset, st.Size())
	}
	if cursor.Generation == "" {
		t.Fatal("export cursor did not record the audit file generation")
	}
}

func TestSecretAuditPruneChangesGenerationAndExportsFromStart(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "state.db")
	svc := &Service{cfg: config.Config{DBPath: dbPath}}
	t.Cleanup(svc.CloseSecretAuditSink)
	sink := svc.secretAuditSink().(*fileAuditSink)
	now := time.Now().UTC()
	if err := sink.EmitDurable(SecretAuditEvent{Time: now.Add(-48 * time.Hour), EventID: "old", SandboxID: "sb", Result: secretAuditResultSuccess}); err != nil {
		t.Fatal(err)
	}
	if err := sink.EmitDurable(SecretAuditEvent{Time: now, EventID: "fresh", SandboxID: "sb", Result: secretAuditResultSuccess}); err != nil {
		t.Fatal(err)
	}
	offsetPath := filepath.Join(filepath.Dir(sink.path), secretAuditExportOffset)
	f, err := os.Open(sink.path)
	if err != nil {
		t.Fatal(err)
	}
	oldGeneration, err := auditFileGeneration(f)
	_ = f.Close()
	if err != nil {
		t.Fatal(err)
	}
	if err := persistAuditExportCursor(offsetPath, auditExportCursor{Generation: oldGeneration, Offset: 123}); err != nil {
		t.Fatal(err)
	}
	if err := sink.Prune(now.Add(-24 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	exporter := &maliciousOffsetExporter{}
	svc.auditExporter = exporter
	if err := svc.exportSecretAuditBatch(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(exporter.batches) != 1 {
		t.Fatalf("export batches = %d, want 1", len(exporter.batches))
	}
	if got := exporter.batches[0].Offset; got != "0" {
		t.Fatalf("post-prune export offset = %q, want generation reset to 0", got)
	}
	var first SecretAuditEvent
	if err := json.Unmarshal(exporter.batches[0].Events[0], &first); err != nil {
		t.Fatal(err)
	}
	if first.Kind != secretAuditKindRetentionCheckpoint {
		t.Fatalf("first post-prune event kind = %q, want retention checkpoint", first.Kind)
	}
	cursor := loadAuditExportCursor(offsetPath)
	if cursor.Generation == "" || cursor.Generation == oldGeneration {
		t.Fatalf("post-prune cursor generation = %q, want new generation", cursor.Generation)
	}
}

func TestHTTPAuditExporterSendsBearerAndIdempotencyKey(t *testing.T) {
	var auth, idem string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		idem = r.Header.Get("Idempotency-Key")
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("X-Aerol-Audit-Next-Offset", "999999")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	exporter := newHTTPAuditBatchExporter(srv.URL, "receiver-token")
	next, err := exporter.ExportEvents(context.Background(), controlplane.AuditEventBatch{
		NodeID: "node-a", Offset: "42", Events: []json.RawMessage{json.RawMessage(`{"event_id":"e1"}`)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if next != "42" {
		t.Fatalf("exporter accepted receiver cursor %q, want submitted offset 42", next)
	}
	if auth != "Bearer receiver-token" || idem == "" || idem == "node-a:42" || !strings.HasPrefix(idem, "node-a:42:") {
		t.Fatalf("headers authorization=%q idempotency=%q", auth, idem)
	}
}

func TestAuditExportBatchIDDoesNotCollideAfterPruneOffsetReset(t *testing.T) {
	oldID := auditExportBatchID("node-a", "0", []json.RawMessage{json.RawMessage(`{"event_id":"old"}`)})
	newID := auditExportBatchID("node-a", "0", []json.RawMessage{json.RawMessage(`{"event_id":"retention-checkpoint"}`)})
	if oldID == newID {
		t.Fatalf("same offset with different post-prune payload reused idempotency key %q", oldID)
	}
	if retry := auditExportBatchID("node-a", "0", []json.RawMessage{json.RawMessage(`{"event_id":"old"}`)}); retry != oldID {
		t.Fatalf("retry id = %q, want stable %q", retry, oldID)
	}
}

func TestHTTPAuditExporterRejectsRedirect(t *testing.T) {
	receiverCalls := 0
	receiver := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		receiverCalls++
	}))
	defer receiver.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, receiver.URL, http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	exporter := newHTTPAuditBatchExporter(redirector.URL, "receiver-token")
	_, err := exporter.ExportEvents(context.Background(), controlplane.AuditEventBatch{
		NodeID: "node-a", Offset: "0", Events: []json.RawMessage{json.RawMessage(`{"event_id":"e1"}`)},
	})
	if err == nil {
		t.Fatal("redirected audit export must fail closed")
	}
	if receiverCalls != 0 {
		t.Fatalf("redirect target calls = %d, want 0", receiverCalls)
	}
}
