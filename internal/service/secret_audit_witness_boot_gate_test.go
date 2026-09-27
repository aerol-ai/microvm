package service

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// lockedWitness makes stubWitness safe for the ship loop's goroutine.
type lockedWitness struct {
	mu sync.Mutex
	w  *stubWitness
}

func (l *lockedWitness) WitnessHeads(ctx context.Context, heads []controlplane.AuditHead) (controlplane.WitnessReceipt, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.WitnessHeads(ctx, heads)
}

func (l *lockedWitness) LastWitnessedHead(ctx context.Context, id string) (string, bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.LastWitnessedHead(ctx, id)
}

func (l *lockedWitness) shipped() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.shipCalls
}

// A node rebooting against a witness that holds a head its chain cannot
// account for must be refused — and must NOT overwrite that head on the way.
//
// Before the gate, SetWitness started the ship loop, whose first ship ran
// before the daemon validated anything; seeing the witness "behind", it
// re-submitted the local head. The refusal then held for exactly one boot and
// systemd's restart booted cleanly (T18, UC-144): the node erased the evidence
// it was being refused for.
func TestWitnessBootValidationGatesEveryShip(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "state.db")
	cfg := config.Config{DBPath: dbPath, EnterpriseMode: true, SecretAuditWitnessInterval: time.Hour}

	// Boot 1: a healthy node records events and ships its head, leaving a
	// local receipt that matches its chain tip.
	first := &Service{cfg: cfg}
	first.ensureSecretAuditSink()
	first.secretAudit.Emit(SecretAuditEvent{Time: time.Now().UTC(), SandboxID: "sb-1", Result: secretAuditResultSuccess, Reason: secretAuditReasonOK})
	if err := first.secretAuditFile.Sync(); err != nil {
		t.Fatal(err)
	}
	first.SetWitness(&stubWitness{})
	first.markSecretAuditWitnessValidated()
	if err := first.shipSecretAuditHead(context.Background()); err != nil {
		t.Fatalf("healthy ship: %v", err)
	}
	first.CloseSecretAuditSink()

	// Boot 2: the witness now holds a planted head the chain never had.
	const planted = "0000000000000000000000000000000000000000000000000000000000000000"
	witness := &lockedWitness{w: &stubWitness{remoteHead: planted, remoteOK: true}}
	second := &Service{cfg: cfg}
	second.SetWitness(witness)
	defer second.CloseSecretAuditSink()

	// Give the ship loop every chance to run its first ship.
	time.Sleep(300 * time.Millisecond)
	if err := second.ValidateSecretAuditWitness(); err == nil {
		t.Fatal("boot validation accepted a witnessed head the chain cannot account for")
	}
	time.Sleep(300 * time.Millisecond)
	if n := witness.shipped(); n != 0 {
		t.Fatalf("a refused boot shipped %d head(s) and overwrote the witness's evidence", n)
	}
	if head, _, _ := witness.LastWitnessedHead(context.Background(), ""); head != planted {
		t.Fatalf("witness head = %q after a refused boot, want the planted head left intact", head)
	}
	if err := second.shipSecretAuditHead(context.Background()); err != errSecretAuditWitnessBootPending {
		t.Fatalf("ship after a refused boot = %v, want the boot-pending refusal", err)
	}
}
