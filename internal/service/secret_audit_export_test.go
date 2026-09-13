package service

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
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

// setAuditExporter installs ex without starting the export loop (unlike
// SetAuditExporter). The prune ticker already reads under auditExportMu.
func setAuditExporter(s *Service, ex controlplane.AuditExporter) {
	s.auditExportMu.Lock()
	s.auditExporter = ex
	s.auditExportMu.Unlock()
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
	setAuditExporter(svc, exporter)
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
	if cursor.Generation == "" || cursor.Head == "" {
		t.Fatalf("export cursor did not record verified generation/head: %+v", cursor)
	}
}

func TestSecretAuditRetentionWaitsForProgrammaticExporter(t *testing.T) {
	svc := &Service{cfg: config.Config{
		DBPath:                   filepath.Join(t.TempDir(), "state.db"),
		SecretAuditRetentionDays: 1,
	}}
	setAuditExporter(svc, &maliciousOffsetExporter{})
	t.Cleanup(svc.CloseSecretAuditSink)
	sink := svc.secretAuditSink().(*fileAuditSink)
	if err := sink.EmitDurable(SecretAuditEvent{
		Time: time.Now().UTC().Add(-48 * time.Hour), EventID: "unexported", SandboxID: "sb",
	}); err != nil {
		t.Fatal(err)
	}
	if err := svc.PruneSecretAudit(context.Background()); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(sink.path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "unexported") {
		t.Fatal("retention removed evidence before the wired exporter advanced")
	}
}

func TestSecretAuditPruneGuardsCloseAppendAfterVerificationWindow(t *testing.T) {
	dir := t.TempDir()
	svc := &Service{cfg: config.Config{DBPath: filepath.Join(dir, "state.db")}}
	setAuditExporter(svc, &maliciousOffsetExporter{})
	t.Cleanup(svc.CloseSecretAuditSink)
	sink := svc.secretAuditSink().(*fileAuditSink)
	old := time.Now().UTC().Add(-48 * time.Hour)
	if err := sink.EmitDurable(SecretAuditEvent{Time: old, EventID: "verified", SandboxID: "sb"}); err != nil {
		t.Fatal(err)
	}
	if err := svc.exportSecretAuditBatch(context.Background()); err != nil {
		t.Fatal(err)
	}
	witnessedHead, _ := sink.chainTip()

	// This append lands after both hypothetical external checks. The writer-side
	// generation/size and chain-tip guards must preserve both records.
	if err := sink.EmitDurable(SecretAuditEvent{Time: old, EventID: "after-check", SandboxID: "sb"}); err != nil {
		t.Fatal(err)
	}
	offsetPath := filepath.Join(filepath.Dir(sink.path), secretAuditExportOffset)
	err := sink.pruneWithGuards(time.Now().UTC().Add(-24*time.Hour), offsetPath, witnessedHead)
	if !errors.Is(err, errSecretAuditPruneGuardChanged) {
		t.Fatalf("prune guard error = %v, want changed guard", err)
	}
	raw, err := os.ReadFile(sink.path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "verified") || !strings.Contains(string(raw), "after-check") {
		t.Fatalf("guarded prune removed evidence: %s", raw)
	}
}

func TestSecretAuditPruneChangesGenerationAndExportsFromStart(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "state.db")
	// Retention 0 now means a one-day crash buffer, and the sink prunes once at
	// open; an explicit 30-day window keeps the 48h-old event for the prune
	// this test performs itself.
	svc := &Service{cfg: config.Config{DBPath: dbPath, SecretAuditRetentionDays: 30}}
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
	setAuditExporter(svc, exporter)
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
	if got, ok := configured.getAuditExporter().(backendExporter); !ok || got.backend == nil || got.backend.Name() != "webhook" {
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
	setAuditExporter(svc, &maliciousOffsetExporter{})
	if n, err := svc.exportSecretAuditBatchOnce(nil); n != 1 || err != nil {
		t.Fatalf("export n=%d err=%v", n, err)
	}
	if ok, err := svc.secretAuditFullyExported(); !ok || err != nil {
		t.Fatalf("exported evidence = %v, %v", ok, err)
	}

	offsetPath := filepath.Join(filepath.Dir(svc.secretAuditFile.path), secretAuditExportOffset)
	for name, raw := range map[string]string{
		"malformed":    `{`,
		"negative":     `{"generation":"g","offset":-1}`,
		"empty_gen":    `{"generation":" ","offset":1,"head":"h"}`,
		"missing_head": `{"generation":"g","offset":1}`,
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
	tampered, err := json.Marshal(SecretAuditEvent{
		Time: time.Now().UTC(), EventID: "tampered", Result: secretAuditResultSuccess,
		PrevHash: "0", EventHash: strings.Repeat("f", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(svc.secretAuditFile.path, append(tampered, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.exportSecretAuditBatchOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "invalid hash chain") {
		t.Fatalf("hash-broken evidence error = %v", err)
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
	setAuditExporter(svc, exporter)
	if err := svc.drainSecretAuditExport(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(exporter.batches) != 2 || len(exporter.batches[0].Events) != secretAuditExportBatchMax || len(exporter.batches[1].Events) != 1 {
		t.Fatalf("drained batches = %d (%d, %d)", len(exporter.batches), len(exporter.batches[0].Events), len(exporter.batches[1].Events))
	}

	failing := &channelAuditExporter{err: errors.New("offline")}
	setAuditExporter(svc, failing)
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
