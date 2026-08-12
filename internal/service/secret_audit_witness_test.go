package service

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

type stubWitness struct {
	heads []controlplane.AuditHead
}

func (w *stubWitness) WitnessHeads(_ context.Context, heads []controlplane.AuditHead) (controlplane.WitnessReceipt, error) {
	w.heads = append([]controlplane.AuditHead(nil), heads...)
	return controlplane.WitnessReceipt{
		ReceiptID:  "rcpt-1",
		RecordedAt: time.Now().UTC(),
	}, nil
}

func (w *stubWitness) LastWitnessedHead(_ context.Context, _ string) (string, bool, error) {
	if len(w.heads) == 0 {
		return "", false, nil
	}
	return w.heads[len(w.heads)-1].HeadHex, true, nil
}

func TestSecretAuditWitnessShipAndVerify(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	svc := &Service{cfg: config.Config{
		DBPath:                     dbPath,
		EnterpriseMode:             true,
		SecretAuditWitnessInterval: time.Hour,
	}}
	svc.ensureSecretAuditSink()
	if svc.secretAuditFile == nil {
		t.Fatal("expected file audit sink")
	}
	svc.secretAudit.Emit(SecretAuditEvent{
		Time:      time.Now().UTC(),
		SandboxID: "sb-1",
		Result:    secretAuditResultSuccess,
		Reason:    secretAuditReasonOK,
	})
	if err := svc.secretAuditFile.Sync(); err != nil {
		t.Fatalf("sync: %v", err)
	}

	w := &stubWitness{}
	svc.SetWitness(w)
	if err := svc.shipSecretAuditHead(context.Background()); err != nil {
		t.Fatalf("ship: %v", err)
	}
	if len(w.heads) != 1 || w.heads[0].HeadHex == "" || w.heads[0].HeadHex == "0" {
		t.Fatalf("witness heads = %+v", w.heads)
	}
	ok, local, witnessed, err := svc.VerifySecretAuditWitness()
	if err != nil || !ok || local == "" || local != witnessed {
		t.Fatalf("verify = ok=%v local=%q witnessed=%q err=%v", ok, local, witnessed, err)
	}
	svc.CloseSecretAuditSink()
}

func TestWitnessReceiptRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "witness_receipts.jsonl")
	if err := appendWitnessReceipt(path, witnessReceiptRecord{
		HeadHex:   "abc",
		EventID:   "e1",
		ReceiptID: "r1",
		ShippedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	got, err := lastWitnessedHead(path)
	if err != nil || got != "abc" {
		t.Fatalf("lastWitnessedHead = %q err=%v", got, err)
	}
}
