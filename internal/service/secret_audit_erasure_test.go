package service

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
)

// TestSecretAuditWitnessRejectsErasedChain pins the cheapest tamper closed:
// deleting the whole local chain used to return "healthy" because an empty
// chain short-circuits before the witness is compared. Either witness to a
// prior chain — the external witness's head, or this node's own receipt —
// must turn an empty chain into a verification failure.
func TestSecretAuditWitnessRejectsErasedChain(t *testing.T) {
	dir := t.TempDir()
	svc := &Service{cfg: config.Config{
		DBPath:                     filepath.Join(dir, "state.db"),
		EnterpriseMode:             true,
		SecretAuditWitnessInterval: time.Hour,
	}}
	svc.ensureSecretAuditSink()
	if svc.secretAuditFile == nil {
		t.Fatal("expected file audit sink")
	}
	t.Cleanup(svc.CloseSecretAuditSink)

	svc.secretAudit.Emit(SecretAuditEvent{
		Time:      time.Now().UTC(),
		SandboxID: "sb-1",
		Result:    secretAuditResultSuccess,
		Reason:    secretAuditReasonOK,
	})
	if err := svc.secretAuditFile.Sync(); err != nil {
		t.Fatalf("sync: %v", err)
	}

	// Assign directly instead of SetWitness: SetWitness starts the periodic
	// ship loop, which would read the stub concurrently with the remoteHead
	// mutations below.
	w := &stubWitness{}
	svc.auditWitness = w
	if err := svc.shipSecretAuditHead(context.Background()); err != nil {
		t.Fatalf("ship: %v", err)
	}
	shipped := w.heads[0].HeadHex
	if shipped == "" {
		t.Fatal("witness received no head")
	}
	w.remoteHead, w.remoteOK = shipped, true

	if ok, _, _, err := svc.VerifySecretAuditWitness(); !ok || err != nil {
		t.Fatalf("healthy chain verify = ok=%v err=%v", ok, err)
	}

	// Erase the whole log, the way an attacker covering their tracks would.
	// VerifySecretAuditWitness always re-reads the file (it never trusts
	// secrets.tip), so truncation is the whole tamper.
	if err := os.Truncate(svc.secretAuditFile.path, 0); err != nil {
		t.Fatalf("truncate audit log: %v", err)
	}

	ok, _, _, err := svc.VerifySecretAuditWitness()
	if err != nil {
		t.Fatalf("erased-chain verify error = %v", err)
	}
	if ok {
		t.Fatal("complete log erasure verified as healthy")
	}

	// Even with the witness silent, this node's own receipt still remembers a
	// head it shipped, so the empty chain is still erasure.
	w.remoteHead, w.remoteOK = "", false
	if ok, _, _, err := svc.VerifySecretAuditWitness(); err != nil || ok {
		t.Fatalf("receipt-only erasure verify = ok=%v err=%v", ok, err)
	}
}

// TestSecretAuditWitnessAcceptsGenuinelyNewChain guards the other direction:
// a node that has never audited anything, with nothing remembering otherwise,
// must still verify clean.
func TestSecretAuditWitnessAcceptsGenuinelyNewChain(t *testing.T) {
	svc := &Service{cfg: config.Config{
		DBPath:                     filepath.Join(t.TempDir(), "state.db"),
		EnterpriseMode:             true,
		SecretAuditWitnessInterval: time.Hour,
	}}
	svc.ensureSecretAuditSink()
	t.Cleanup(svc.CloseSecretAuditSink)
	svc.auditWitness = &stubWitness{}

	if ok, _, _, err := svc.VerifySecretAuditWitness(); !ok || err != nil {
		t.Fatalf("fresh node verify = ok=%v err=%v", ok, err)
	}
}
