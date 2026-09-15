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
	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

type stubWitness struct {
	heads      []controlplane.AuditHead
	shipCalls  int
	receipt    controlplane.WitnessReceipt
	shipErr    error
	remoteHead string
	remoteOK   bool
	remoteErr  error
}

func (w *stubWitness) WitnessHeads(_ context.Context, heads []controlplane.AuditHead) (controlplane.WitnessReceipt, error) {
	w.shipCalls++
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

func TestSecretAuditWitnessRepairsMissingRemoteAcknowledgment(t *testing.T) {
	svc := &Service{cfg: config.Config{DBPath: filepath.Join(t.TempDir(), "state.db")}}
	svc.ensureSecretAuditSink()
	t.Cleanup(svc.CloseSecretAuditSink)
	w := &stubWitness{}
	svc.auditWitness = w

	if err := svc.secretAuditFile.EmitDurable(SecretAuditEvent{EventID: "repair-head", SandboxID: "sb"}); err != nil {
		t.Fatal(err)
	}
	if err := svc.shipSecretAuditHead(context.Background()); err != nil {
		t.Fatal(err)
	}
	if w.shipCalls != 1 {
		t.Fatalf("initial witness calls = %d, want 1", w.shipCalls)
	}
	w.remoteHead, w.remoteOK = "", false
	if err := svc.shipSecretAuditHead(context.Background()); err != nil {
		t.Fatal(err)
	}
	if w.shipCalls != 2 {
		t.Fatalf("missing remote acknowledgment was not repaired: calls=%d", w.shipCalls)
	}
	if local, _ := svc.secretAuditFile.chainTip(); !w.remoteOK || w.remoteHead != local {
		t.Fatalf("repaired remote head = %q/%v, want %q", w.remoteHead, w.remoteOK, local)
	}
}

func TestSecretAuditRetentionRequiresCurrentExternalWitness(t *testing.T) {
	svc := &Service{cfg: config.Config{
		DBPath:                     filepath.Join(t.TempDir(), "state.db"),
		SecretAuditExternalWitness: true,
	}}
	svc.ensureSecretAuditSink()
	t.Cleanup(svc.CloseSecretAuditSink)
	stopSecretAuditPruneTickerForTest(svc)
	svc.cfg.SecretAuditRetentionDays = 1
	now := time.Now().UTC()
	if err := svc.secretAuditFile.EmitDurable(SecretAuditEvent{
		Time: now.Add(-48 * time.Hour), EventID: "must-not-prune", SandboxID: "sb",
	}); err != nil {
		t.Fatal(err)
	}
	if err := svc.secretAuditFile.EmitDurable(SecretAuditEvent{
		Time: now, EventID: "fresh", SandboxID: "sb",
	}); err != nil {
		t.Fatal(err)
	}
	w := &stubWitness{shipErr: errors.New("witness offline")}
	svc.auditWitness = w
	// The periodic retention runner historically invoked this with nil. Keep
	// that call safe even when witness validation performs network work first.
	if err := svc.PruneSecretAudit(nil); err == nil {
		t.Fatal("retention succeeded while current head was not witnessed")
	}
	raw, err := os.ReadFile(svc.secretAuditFile.path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "must-not-prune") {
		t.Fatal("retention removed unwitnessed evidence")
	}

	w.shipErr = nil
	if err := svc.PruneSecretAudit(context.Background()); err != nil {
		t.Fatalf("retention after witness recovery: %v", err)
	}
	raw, err = os.ReadFile(svc.secretAuditFile.path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "must-not-prune") || !strings.Contains(string(raw), "fresh") {
		t.Fatalf("retained audit contents = %s", raw)
	}
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

// The scan carries the retention checkpoint's WitnessedThrough and probes
// for named hashes in the same pass, so witness verification never needs a
// second read or an all-hashes slice.
func TestChainScanCarriesRetentionWitnessAndProbes(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	if scan, err := scanSecretAuditChainWith(missing, secretAuditScanOptions{probe: []string{"x"}}); err != nil || scan.witnessedThrough != "" || scan.found != nil || scan.records != 0 {
		t.Fatalf("missing file scan = %+v err=%v", scan, err)
	}
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	cp := SecretAuditEvent{Time: time.Now().UTC(), EventID: "cp", Result: secretAuditResultSuccess, Reason: "prune",
		Kind: secretAuditKindRetentionCheckpoint, WitnessedThrough: " new "}
	auditlog.LinkEvent(strings.Repeat("d", 64), &cp) // predecessor was pruned away
	mid := SecretAuditEvent{Time: time.Now().UTC(), EventID: "mid", SandboxID: "sb", Result: secretAuditResultSuccess}
	auditlog.LinkEvent(cp.EventHash, &mid)
	last := SecretAuditEvent{Time: time.Now().UTC(), EventID: "last", SandboxID: "sb", Result: secretAuditResultSuccess}
	auditlog.LinkEvent(mid.EventHash, &last)
	var raw []byte
	for _, ev := range []SecretAuditEvent{cp, mid, last} {
		line, _ := json.Marshal(ev)
		raw = append(append(raw, line...), '\n')
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	scan, err := scanSecretAuditChainWith(path, secretAuditScanOptions{probe: []string{mid.EventHash, strings.Repeat("0", 64)}})
	if err != nil {
		t.Fatal(err)
	}
	if scan.witnessedThrough != "new" || !scan.found[mid.EventHash] || scan.found[strings.Repeat("0", 64)] || scan.records != 3 || scan.head != last.EventHash {
		t.Fatalf("scan = %+v", scan)
	}
	if scan.lastLineStart != int64(len(raw))-int64(len(raw)-strings.LastIndex(strings.TrimRight(string(raw), "\n"), "\n")-1) {
		t.Fatalf("lastLineStart = %d for a %d-byte file", scan.lastLineStart, len(raw))
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
