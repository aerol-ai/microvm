package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
)

func TestShipAndExportAuditRemainingGuards(t *testing.T) {
	if err := (*Service)(nil).shipSecretAuditHead(context.Background()); err != nil {
		t.Fatal(err)
	}
	(*Service)(nil).stopSecretAuditWitnessLoop()
	(*Service)(nil).ConfigureHTTPAuditExporter()
	(&Service{}).ConfigureHTTPAuditExporter()
	if n, err := (*Service)(nil).exportSecretAuditBatchOnce(context.Background()); n != 0 || err != nil {
		t.Fatalf("nil export = %d %v", n, err)
	}
	if err := (*Service)(nil).drainSecretAuditExport(context.Background()); err != nil {
		t.Fatal(err)
	}

	svc := &Service{cfg: config.Config{DBPath: filepath.Join(t.TempDir(), "state.db")}}
	t.Cleanup(svc.CloseSecretAuditSink)
	_ = svc.secretAuditSink()
	if err := svc.shipSecretAuditHead(nil); err != nil {
		t.Fatalf("no witness: %v", err)
	}
	if err := svc.exportSecretAuditBatch(context.Background()); err != nil {
		t.Fatalf("no exporter: %v", err)
	}

	w := &stubWitness{shipErr: errors.New("witness down")}
	svc.SetWitness(w)
	sink := svc.secretAuditSink().(*fileAuditSink)
	if err := sink.EmitDurable(SecretAuditEvent{EventID: "ship-fail", Result: secretAuditResultSuccess}); err != nil {
		t.Fatal(err)
	}
	if err := svc.shipSecretAuditHead(context.Background()); err == nil {
		t.Fatal("ship error was swallowed")
	}
	w.shipErr = nil
	if err := svc.shipSecretAuditHead(nil); err != nil {
		t.Fatalf("ship: %v", err)
	}
	if err := svc.shipSecretAuditHead(context.Background()); err != nil {
		t.Fatalf("already-witnessed ship: %v", err)
	}

	svc.cfg.SecretAuditExportURL = "http://127.0.0.1:1/export"
	svc.cfg.SecretAuditExportBearerToken = "tok"
	svc.ConfigureHTTPAuditExporter()
	if svc.getAuditExporter() == nil {
		t.Fatal("HTTP exporter was not installed")
	}

	cursorPath := filepath.Join(t.TempDir(), "cursor.json")
	if err := os.WriteFile(cursorPath, []byte("{not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := loadAuditExportCursor(cursorPath); got.Generation != "" {
		t.Fatalf("malformed cursor = %+v", got)
	}
	if err := persistAuditExportCursor(filepath.Join(t.TempDir(), "ok.json"), auditExportCursor{Generation: "g", Offset: 1, Head: "h"}); err != nil {
		t.Fatal(err)
	}
	if gen, err := auditFileGeneration(nil); err == nil || gen != "" {
		t.Fatalf("nil generation = %q %v", gen, err)
	}

	ok, _, _, err := (*Service)(nil).VerifySecretAuditWitness()
	if err != nil || !ok {
		t.Fatalf("nil verify = %v %v", ok, err)
	}
	if err := (*Service)(nil).ValidateSecretAuditWitness(); err != nil {
		t.Fatal(err)
	}
}

func TestPruneAndExportAuditWave32(t *testing.T) {
	if err := (&Service{cfg: config.Config{SecretAuditRetentionDays: 0}}).PruneSecretAudit(nil); err != nil {
		t.Fatal(err)
	}
	svc := &Service{cfg: config.Config{
		DBPath: filepath.Join(t.TempDir(), "state.db"), SecretAuditRetentionDays: 30,
		EnterpriseMode: true, SecretAuditExternalWitness: true,
	}}
	t.Cleanup(svc.CloseSecretAuditSink)
	_ = svc.secretAuditSink()
	if err := svc.PruneSecretAudit(context.Background()); err == nil {
		t.Fatal("witness-required prune succeeded")
	}
	svc.SetWitness(&stubWitness{})
	if err := svc.secretAuditFile.EmitDurable(SecretAuditEvent{Time: time.Now().UTC().Add(-48 * time.Hour), EventID: "old32", Result: secretAuditResultSuccess}); err != nil {
		t.Fatal(err)
	}
	// An export cursor that does not cover the file must retain evidence rather
	// than rotate a head the exporter has not yet shipped.
	cursorPath := filepath.Join(filepath.Dir(svc.secretAuditFile.path), secretAuditExportOffset)
	if err := persistAuditExportCursor(cursorPath, auditExportCursor{Generation: "other", Offset: 0, Head: "h"}); err != nil {
		t.Fatal(err)
	}
	if err := svc.PruneSecretAudit(context.Background()); err != nil {
		t.Fatalf("export-guard prune: %v", err)
	}

	ok, err := svc.secretAuditFullyExported()
	if err != nil || ok {
		t.Fatalf("unexported head = %v %v", ok, err)
	}
	if ok, err := (*Service)(nil).secretAuditFullyExported(); err != nil || !ok {
		t.Fatalf("nil fully-exported = %v %v", ok, err)
	}
	_ = os.Remove(svc.secretAuditFile.path)
	if ok, err := svc.secretAuditFullyExported(); err != nil || !ok {
		t.Fatalf("missing file fully-exported = %v %v", ok, err)
	}

	st := openSealTestStore(t)
	acl := &Service{store: st, cfg: config.Config{DBPath: filepath.Join(t.TempDir(), "state.db"), SecretAuditRetentionDays: 1}}
	t.Cleanup(acl.CloseSecretAuditSink)
	if err := acl.PruneSecretAudit(context.Background()); err != nil {
		t.Fatalf("ACL prune: %v", err)
	}
	_ = st.Close()
	if err := acl.PruneSecretAudit(context.Background()); err == nil {
		t.Fatal("closed-store ACL prune succeeded")
	}
}
