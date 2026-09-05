package service

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
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

type channelAuditExporter struct {
	batches chan controlplane.AuditEventBatch
	err     error
}

func (e *channelAuditExporter) ExportEvents(_ context.Context, batch controlplane.AuditEventBatch) (string, error) {
	if e.batches != nil {
		e.batches <- batch
	}
	return batch.Offset, e.err
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

func TestHTTPAuditExporterDisabledAndFailurePaths(t *testing.T) {
	if got := newHTTPAuditBatchExporter("  ", "token"); got != nil {
		t.Fatalf("blank URL exporter = %#v, want nil", got)
	}
	batch := controlplane.AuditEventBatch{Offset: "7"}
	var nilExporter *httpAuditBatchExporter
	if got, err := nilExporter.ExportEvents(context.Background(), batch); err != nil || got != "7" {
		t.Fatalf("nil exporter offset=%q err=%v", got, err)
	}
	badURL := &httpAuditBatchExporter{url: "://bad", client: http.DefaultClient}
	if _, err := badURL.ExportEvents(context.Background(), batch); err == nil {
		t.Fatal("invalid exporter URL must fail")
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Idempotency-Key"); got != "supplied-batch" {
			t.Errorf("idempotency key = %q", got)
		}
		body, _ := io.ReadAll(r.Body)
		if got, want := string(body), "\n{\"event_id\":\"e1\"}\n"; got != want {
			t.Errorf("body = %q, want %q", got, want)
		}
		http.Error(w, "receiver unavailable", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	exporter := newHTTPAuditBatchExporter(srv.URL, "")
	_, err := exporter.ExportEvents(context.Background(), controlplane.AuditEventBatch{
		Offset:  "8",
		BatchID: "supplied-batch",
		Events:  []json.RawMessage{nil, json.RawMessage(`{"event_id":"e1"}` + "\n")},
	})
	if err == nil || !strings.Contains(err.Error(), "status 503") {
		t.Fatalf("status error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := exporter.ExportEvents(ctx, batch); err == nil {
		t.Fatal("cancelled export must fail")
	}
}

func TestSecretAuditExportLoopLifecycleAndDrain(t *testing.T) {
	if (*Service)(nil).getAuditExporter() != nil {
		t.Fatal("nil service returned an exporter")
	}
	(*Service)(nil).SetAuditExporter(&channelAuditExporter{})
	(*Service)(nil).startSecretAuditExportLoop()
	(*Service)(nil).stopSecretAuditExportLoop()
	(*Service)(nil).ConfigureHTTPAuditExporter()

	svc := &Service{cfg: config.Config{DBPath: filepath.Join(t.TempDir(), "state.db")}}
	svc.ensureSecretAuditSink()
	t.Cleanup(svc.CloseSecretAuditSink)
	if err := svc.secretAuditFile.EmitDurable(SecretAuditEvent{EventID: "loop-event", SandboxID: "sb"}); err != nil {
		t.Fatal(err)
	}
	exporter := &channelAuditExporter{batches: make(chan controlplane.AuditEventBatch, 2)}
	svc.SetAuditExporter(exporter)
	select {
	case batch := <-exporter.batches:
		if len(batch.Events) != 1 || batch.BatchID == "" {
			t.Fatalf("loop batch = %+v", batch)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("audit export loop did not perform its initial drain")
	}
	svc.stopSecretAuditExportLoop()
	svc.stopSecretAuditExportLoop()

	configured := &Service{cfg: config.Config{
		DBPath:                       filepath.Join(t.TempDir(), "state.db"),
		SecretAuditExportURL:         "https://audit.example/export",
		SecretAuditExportBearerToken: "token",
	}}
	configured.ConfigureHTTPAuditExporter()
	configured.stopSecretAuditExportLoop()
	if got, ok := configured.getAuditExporter().(*httpAuditBatchExporter); !ok || got.url != "https://audit.example/export" || got.bearerToken != "token" {
		t.Fatalf("configured exporter = %#v", configured.getAuditExporter())
	}
	configured.CloseSecretAuditSink()

	blank := &Service{cfg: config.Config{SecretAuditExportURL: " "}}
	blank.ConfigureHTTPAuditExporter()
	if blank.getAuditExporter() != nil {
		t.Fatal("blank URL configured an exporter")
	}
}

func TestSecretAuditExportCursorSafetyAndMalformedEvidence(t *testing.T) {
	if ok, err := (*Service)(nil).secretAuditFullyExported(); !ok || err != nil {
		t.Fatalf("nil fully exported = %v, %v", ok, err)
	}
	if n, err := (*Service)(nil).exportSecretAuditBatchOnce(nil); n != 0 || err != nil {
		t.Fatalf("nil export n=%d err=%v", n, err)
	}

	dir := t.TempDir()
	svc := &Service{cfg: config.Config{DBPath: filepath.Join(dir, "state.db")}}
	svc.ensureSecretAuditSink()
	t.Cleanup(svc.CloseSecretAuditSink)
	if ok, err := svc.secretAuditFullyExported(); !ok || err != nil {
		t.Fatalf("empty fully exported = %v, %v", ok, err)
	}
	if err := svc.secretAuditFile.EmitDurable(SecretAuditEvent{EventID: "cursor-event", SandboxID: "sb"}); err != nil {
		t.Fatal(err)
	}
	if ok, err := svc.secretAuditFullyExported(); ok || err != nil {
		t.Fatalf("unexported evidence = %v, %v", ok, err)
	}
	svc.auditExporter = &maliciousOffsetExporter{}
	if n, err := svc.exportSecretAuditBatchOnce(nil); n != 1 || err != nil {
		t.Fatalf("export n=%d err=%v", n, err)
	}
	if ok, err := svc.secretAuditFullyExported(); !ok || err != nil {
		t.Fatalf("exported evidence = %v, %v", ok, err)
	}

	offsetPath := filepath.Join(filepath.Dir(svc.secretAuditFile.path), secretAuditExportOffset)
	for name, raw := range map[string]string{
		"malformed": `{`,
		"negative":  `{"generation":"g","offset":-1}`,
		"empty_gen": `{"generation":" ","offset":1}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "cursor")
			if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
				t.Fatal(err)
			}
			if got := loadAuditExportCursor(path); got != (auditExportCursor{}) {
				t.Fatalf("cursor = %+v", got)
			}
		})
	}
	if got := loadAuditExportCursor(filepath.Join(t.TempDir(), "missing")); got != (auditExportCursor{}) {
		t.Fatalf("missing cursor = %+v", got)
	}
	if err := persistAuditExportCursor(offsetPath, auditExportCursor{Generation: "stale", Offset: 1 << 30}); err != nil {
		t.Fatal(err)
	}
	before := len(svc.auditExporter.(*maliciousOffsetExporter).batches)
	if n, err := svc.exportSecretAuditBatchOnce(context.Background()); n != 1 || err != nil {
		t.Fatalf("stale cursor export n=%d err=%v", n, err)
	}
	if got := svc.auditExporter.(*maliciousOffsetExporter).batches[before].Offset; got != "0" {
		t.Fatalf("stale cursor restarted at %q, want 0", got)
	}

	svc.CloseSecretAuditSink()
	if err := os.WriteFile(svc.secretAuditFile.path, []byte("not-json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.exportSecretAuditBatchOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "malformed JSONL") {
		t.Fatalf("malformed evidence error = %v", err)
	}
}

func TestAuditFileGenerationAndLargeBatchDrain(t *testing.T) {
	if _, err := auditFileGeneration(nil); err == nil {
		t.Fatal("nil audit file must fail")
	}
	empty, err := os.Create(filepath.Join(t.TempDir(), "empty.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer empty.Close()
	if got, err := auditFileGeneration(empty); err != nil || got != "empty" {
		t.Fatalf("empty generation = %q, %v", got, err)
	}

	svc := &Service{cfg: config.Config{DBPath: filepath.Join(t.TempDir(), "state.db")}}
	svc.ensureSecretAuditSink()
	t.Cleanup(svc.CloseSecretAuditSink)
	for i := 0; i < secretAuditExportBatchMax+1; i++ {
		if err := svc.secretAuditFile.EmitDurable(SecretAuditEvent{EventID: "batch-" + strconv.Itoa(i), SandboxID: "sb"}); err != nil {
			t.Fatal(err)
		}
	}
	exporter := &maliciousOffsetExporter{}
	svc.auditExporter = exporter
	if err := svc.drainSecretAuditExport(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(exporter.batches) != 2 || len(exporter.batches[0].Events) != secretAuditExportBatchMax || len(exporter.batches[1].Events) != 1 {
		t.Fatalf("drained batches = %d (%d, %d)", len(exporter.batches), len(exporter.batches[0].Events), len(exporter.batches[1].Events))
	}

	failing := &channelAuditExporter{err: errors.New("offline")}
	svc.auditExporter = failing
	if err := svc.drainSecretAuditExport(context.Background()); err != nil {
		t.Fatalf("fully drained exporter should be idle: %v", err)
	}
	if err := svc.secretAuditFile.EmitDurable(SecretAuditEvent{EventID: "failure", SandboxID: "sb"}); err != nil {
		t.Fatal(err)
	}
	if err := svc.drainSecretAuditExport(context.Background()); !errors.Is(err, failing.err) {
		t.Fatalf("drain error = %v", err)
	}
}
