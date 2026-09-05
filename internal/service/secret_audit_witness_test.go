package service

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

type stubWitness struct {
	heads      []controlplane.AuditHead
	receipt    controlplane.WitnessReceipt
	shipErr    error
	remoteHead string
	remoteOK   bool
	remoteErr  error
}

func (w *stubWitness) WitnessHeads(_ context.Context, heads []controlplane.AuditHead) (controlplane.WitnessReceipt, error) {
	w.heads = append([]controlplane.AuditHead(nil), heads...)
	if w.shipErr != nil {
		return controlplane.WitnessReceipt{}, w.shipErr
	}
	if w.receipt.ReceiptID == "" {
		w.receipt.ReceiptID = "rcpt-1"
	}
	if w.receipt.RecordedAt.IsZero() {
		w.receipt.RecordedAt = time.Now().UTC()
	}
	w.remoteHead = heads[len(heads)-1].HeadHex
	w.remoteOK = true
	return w.receipt, nil
}

func (w *stubWitness) LastWitnessedHead(_ context.Context, _ string) (string, bool, error) {
	if w.remoteErr != nil {
		return "", false, w.remoteErr
	}
	return w.remoteHead, w.remoteOK, nil
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

func TestSecretAuditWitnessEmptyMissingAndFailurePaths(t *testing.T) {
	if (*Service)(nil).witness() != nil {
		t.Fatal("nil service returned a witness")
	}
	(*Service)(nil).SetWitness(&stubWitness{})
	(*Service)(nil).startSecretAuditWitnessLoop()
	(*Service)(nil).stopSecretAuditWitnessLoop()
	if err := (*Service)(nil).shipSecretAuditHead(nil); err != nil {
		t.Fatal(err)
	}
	if ok, local, witnessed, err := (*Service)(nil).VerifySecretAuditWitness(); !ok || local != "" || witnessed != "" || err != nil {
		t.Fatalf("nil verify = %v %q %q %v", ok, local, witnessed, err)
	}
	if err := (*Service)(nil).ValidateSecretAuditWitness(); err != nil {
		t.Fatal(err)
	}

	svc := &Service{cfg: config.Config{DBPath: filepath.Join(t.TempDir(), "state.db")}}
	svc.ensureSecretAuditSink()
	t.Cleanup(svc.CloseSecretAuditSink)
	if err := svc.shipSecretAuditHead(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ok, _, witnessed, err := svc.VerifySecretAuditWitness(); !ok || witnessed != "" || err != nil {
		t.Fatalf("no external witness verify = %v %q %v", ok, witnessed, err)
	}
	noop := controlplane.Noop()
	svc.auditWitness = noop.Witness
	if err := svc.ValidateSecretAuditWitness(); err != nil {
		t.Fatalf("noop validation: %v", err)
	}

	w := &stubWitness{}
	svc.auditWitness = w
	if err := svc.shipSecretAuditHead(nil); err != nil || len(w.heads) != 0 {
		t.Fatalf("empty ship heads=%v err=%v", w.heads, err)
	}
	if ok, _, _, err := svc.VerifySecretAuditWitness(); !ok || err != nil {
		t.Fatalf("empty external verify = %v, %v", ok, err)
	}
	if err := svc.secretAuditFile.EmitDurable(SecretAuditEvent{EventID: "unwitnessed", SandboxID: "sb"}); err != nil {
		t.Fatal(err)
	}
	if ok, local, witnessed, err := svc.VerifySecretAuditWitness(); ok || local == "" || witnessed != "" || err != nil {
		t.Fatalf("missing receipt verify = %v %q %q %v", ok, local, witnessed, err)
	}
	if err := svc.ValidateSecretAuditWitness(); err == nil || !strings.Contains(err.Error(), "witness mismatch") {
		t.Fatalf("missing receipt validation = %v", err)
	}

	w.shipErr = errors.New("witness offline")
	if err := svc.shipSecretAuditHead(context.Background()); !errors.Is(err, w.shipErr) {
		t.Fatalf("ship error = %v", err)
	}
	w.shipErr = nil
	w.remoteErr = errors.New("witness read offline")
	if ok, _, _, err := svc.VerifySecretAuditWitness(); ok || !errors.Is(err, w.remoteErr) {
		t.Fatalf("remote error verify = %v, %v", ok, err)
	}
	if err := svc.ValidateSecretAuditWitness(); err == nil || !strings.Contains(err.Error(), "verify secret audit witness") {
		t.Fatalf("remote error validation = %v", err)
	}
}

func TestSecretAuditWitnessAcceptsAncestorAndRejectsForgedReceipt(t *testing.T) {
	svc := &Service{cfg: config.Config{DBPath: filepath.Join(t.TempDir(), "state.db")}}
	svc.ensureSecretAuditSink()
	t.Cleanup(svc.CloseSecretAuditSink)
	w := &stubWitness{receipt: controlplane.WitnessReceipt{ReceiptID: "r-no-time"}}
	svc.auditWitness = w

	if err := svc.secretAuditFile.EmitDurable(SecretAuditEvent{EventID: "first", SandboxID: "sb"}); err != nil {
		t.Fatal(err)
	}
	if err := svc.shipSecretAuditHead(nil); err != nil {
		t.Fatal(err)
	}
	firstHead := w.remoteHead
	firstCalls := len(w.heads)
	if err := svc.shipSecretAuditHead(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(w.heads) != firstCalls {
		t.Fatalf("unchanged head was shipped again: calls=%d want=%d", len(w.heads), firstCalls)
	}
	if err := svc.secretAuditFile.EmitDurable(SecretAuditEvent{EventID: "second", SandboxID: "sb"}); err != nil {
		t.Fatal(err)
	}
	w.remoteHead, w.remoteOK = firstHead, true
	if ok, local, witnessed, err := svc.VerifySecretAuditWitness(); !ok || local == firstHead || witnessed != firstHead || err != nil {
		t.Fatalf("ancestor verify = %v local=%q witnessed=%q err=%v", ok, local, witnessed, err)
	}
	if err := svc.ValidateSecretAuditWitness(); err != nil {
		t.Fatalf("ancestor validation: %v", err)
	}

	forged := strings.Repeat("f", 64)
	if err := persistWitnessReceipt(svc.secretAuditWitnessPath(), svc.secretAuditWitnessTipPath(), witnessReceiptRecord{HeadHex: forged}); err != nil {
		t.Fatal(err)
	}
	w.remoteHead, w.remoteOK = forged, true
	if ok, _, witnessed, err := svc.VerifySecretAuditWitness(); ok || witnessed != forged || err != nil {
		t.Fatalf("forged receipt verify = %v witnessed=%q err=%v", ok, witnessed, err)
	}
}

func TestRetentionWitnessParserUsesNewestValidCheckpoint(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	if got, ok := retentionWitnessedThrough(missing); ok || got != "" {
		t.Fatalf("missing retention witness = %q %v", got, ok)
	}
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	events := []string{
		"",
		"not-json",
		`{"kind":"open","witnessed_through":"ignored"}`,
		`{"kind":"retention_checkpoint"}`,
		`{"kind":"retention_checkpoint","witnessed_through":" old "}`,
		`{"kind":"retention_checkpoint","witnessed_through":"new"}`,
	}
	if err := os.WriteFile(path, []byte(strings.Join(events, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, ok := retentionWitnessedThrough(path); !ok || got != "new" {
		t.Fatalf("retention witness = %q %v", got, ok)
	}
}

func TestWitnessReceiptRetentionAndCorruptionHandling(t *testing.T) {
	dir := t.TempDir()
	receiptPath := filepath.Join(dir, secretAuditWitnessReceiptFile)
	tipPath := filepath.Join(dir, secretAuditWitnessTipFile)
	for i := 0; i < secretAuditWitnessReceiptKeep+3; i++ {
		rec := witnessReceiptRecord{HeadHex: "head-" + strconv.Itoa(i), EventID: "event-" + strconv.Itoa(i)}
		if err := persistWitnessReceipt(receiptPath, tipPath, rec); err != nil {
			t.Fatal(err)
		}
	}
	recs, err := loadWitnessReceipts(receiptPath)
	if err != nil || len(recs) != secretAuditWitnessReceiptKeep {
		t.Fatalf("retained receipts = %d err=%v", len(recs), err)
	}
	if recs[0].HeadHex != "head-3" || recs[len(recs)-1].HeadHex != "head-34" {
		t.Fatalf("receipt window = %q..%q", recs[0].HeadHex, recs[len(recs)-1].HeadHex)
	}
	tip, err := readWitnessTip(tipPath)
	if err != nil || tip.HeadHex != "head-34" {
		t.Fatalf("tip = %+v err=%v", tip, err)
	}
	if tip, err := readWitnessTip(""); err != nil || tip != (witnessReceiptRecord{}) {
		t.Fatalf("blank tip = %+v err=%v", tip, err)
	}
	if tip, err := readWitnessTip(filepath.Join(dir, "missing")); err != nil || tip != (witnessReceiptRecord{}) {
		t.Fatalf("missing tip = %+v err=%v", tip, err)
	}

	valid, _ := json.Marshal(witnessReceiptRecord{HeadHex: "valid"})
	if err := os.WriteFile(receiptPath, []byte("{\n{}\n"+string(valid)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	recs, err = loadWitnessReceipts(receiptPath)
	if err != nil || len(recs) != 1 || recs[0].HeadHex != "valid" {
		t.Fatalf("corrupt receipt filtering = %+v err=%v", recs, err)
	}
	if err := os.WriteFile(tipPath, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readWitnessTip(tipPath); err == nil {
		t.Fatal("malformed tip must fail")
	}
	if _, err := loadWitnessReceipts(dir); err == nil {
		t.Fatal("reading a directory as receipts must fail")
	}
	if _, err := lastWitnessedHead(dir); err == nil {
		t.Fatal("last head must propagate receipt read failure")
	}
	if err := persistWitnessReceipt("", filepath.Join(dir, "tip-only.json"), witnessReceiptRecord{HeadHex: "tip-only"}); err != nil {
		t.Fatal(err)
	}
}
