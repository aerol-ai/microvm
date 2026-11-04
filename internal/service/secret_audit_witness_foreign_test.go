package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
)

const foreignHead = "f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0"

// newWitnessShipService is a node with a file sink and a stub witness that
// has already acknowledged one shipped head.
func newWitnessShipService(t *testing.T) (*Service, *stubWitness) {
	t.Helper()
	svc := &Service{cfg: config.Config{
		DBPath:                     filepath.Join(t.TempDir(), "state.db"),
		NodeID:                     "node-1",
		SecretAuditWitnessInterval: time.Hour,
	}}
	svc.ensureSecretAuditSink()
	t.Cleanup(svc.CloseSecretAuditSink)
	w := &stubWitness{}
	// Assigned directly: SetWitness would start the periodic loop and race
	// the stub mutations below.
	svc.auditWitness = w
	emitWitnessTestEvent(t, svc, "first")
	if err := svc.shipSecretAuditHead(context.Background()); err != nil {
		t.Fatal(err)
	}
	if w.shipCalls != 1 {
		t.Fatalf("setup ship calls = %d", w.shipCalls)
	}
	return svc, w
}

func emitWitnessTestEvent(t *testing.T, svc *Service, id string) {
	t.Helper()
	if err := svc.secretAuditFile.EmitDurable(SecretAuditEvent{EventID: id, SandboxID: "sb", Time: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
}

// The ship loop reads the witness before every ship, so a head this node did
// not put there is counted on the next tick whether the node is idle or busy
// (D18, D23). A matching head, a normal advance and a read error are not.
func TestWitnessShipCountsForeignHeads(t *testing.T) {
	cases := []struct {
		name string
		// busy appends a record so the local head moved since the last ship.
		busy      bool
		setRemote func(w *stubWitness)
		foreign   int64
		ships     int
	}{
		{name: "idle, matching head", foreign: 0, ships: 0},
		{name: "idle, foreign head", setRemote: func(w *stubWitness) { w.remoteHead = foreignHead }, foreign: 1, ships: 1},
		{name: "idle, head missing after a ship", setRemote: func(w *stubWitness) { w.remoteHead, w.remoteOK = "", false }, foreign: 1, ships: 1},
		{name: "idle, read error", setRemote: func(w *stubWitness) { w.remoteErr = errors.New("s3 blip") }, foreign: 0, ships: 1},
		{name: "busy, witness holds the last ship", busy: true, foreign: 0, ships: 1},
		{name: "busy, foreign head", busy: true, setRemote: func(w *stubWitness) { w.remoteHead = foreignHead }, foreign: 1, ships: 1},
		{name: "busy, read error", busy: true, setRemote: func(w *stubWitness) { w.remoteErr = errors.New("s3 blip") }, foreign: 0, ships: 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			svc, w := newWitnessShipService(t)
			if c.busy {
				emitWitnessTestEvent(t, svc, "second")
			}
			if c.setRemote != nil {
				c.setRemote(w)
			}
			before := secretAuditWitnessForeignHeads.Value()
			if err := svc.shipSecretAuditHead(context.Background()); err != nil {
				t.Fatal(err)
			}
			if got := secretAuditWitnessForeignHeads.Value() - before; got != c.foreign {
				t.Fatalf("foreign heads counted = %d, want %d", got, c.foreign)
			}
			if got := w.shipCalls - 1; got != c.ships {
				t.Fatalf("ships = %d, want %d", got, c.ships)
			}
			if local, _ := svc.secretAuditFile.chainTip(); c.ships > 0 && w.heads[0].HeadHex != local {
				t.Fatalf("shipped %q, want this node's head %q", w.heads[0].HeadHex, local)
			}
		})
	}
}

// A lost local receipt is not a foreign head: the witness holds this node's
// current head, and the loop re-ships only to record the receipt again.
func TestWitnessShipLostReceiptIsNotForeign(t *testing.T) {
	svc, w := newWitnessShipService(t)
	for _, p := range []string{svc.secretAuditWitnessPath(), svc.secretAuditWitnessTipPath()} {
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
	}
	before := secretAuditWitnessForeignHeads.Value()
	if err := svc.shipSecretAuditHead(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := secretAuditWitnessForeignHeads.Value() - before; got != 0 {
		t.Fatalf("lost receipt counted as foreign: %d", got)
	}
	if w.shipCalls != 2 {
		t.Fatalf("ship calls = %d, want a re-ship that restores the receipt", w.shipCalls)
	}
	if last := svc.lastWitnessShip(); last.HeadHex == "" {
		t.Fatal("receipt not restored")
	}
}

// An unchanged head is written again once per UTC day, so a day-keyed
// witness always has today's key (D20). It is not a foreign head, and a
// later tick the same day does not write again.
func TestWitnessShipCarriesUnchangedHeadIntoNewDay(t *testing.T) {
	svc, w := newWitnessShipService(t)
	last := svc.lastWitnessShip()
	last.ShippedAt = time.Now().UTC().AddDate(0, 0, -1)
	if err := persistWitnessReceipt(svc.secretAuditWitnessPath(), svc.secretAuditWitnessTipPath(), last); err != nil {
		t.Fatal(err)
	}
	before := secretAuditWitnessForeignHeads.Value()
	if err := svc.shipSecretAuditHead(context.Background()); err != nil {
		t.Fatal(err)
	}
	if w.shipCalls != 2 {
		t.Fatalf("ship calls = %d, want the daily re-ship", w.shipCalls)
	}
	if err := svc.shipSecretAuditHead(context.Background()); err != nil {
		t.Fatal(err)
	}
	if w.shipCalls != 2 {
		t.Fatalf("ship calls = %d, want no second re-ship the same day", w.shipCalls)
	}
	if got := secretAuditWitnessForeignHeads.Value() - before; got != 0 {
		t.Fatalf("the daily re-ship counted as foreign: %d", got)
	}
}

func TestShippedBeforeUTCDay(t *testing.T) {
	now := time.Date(2026, 10, 12, 0, 0, 5, 0, time.UTC)
	cases := []struct {
		name    string
		shipped time.Time
		want    bool
	}{
		{"unknown ship time", time.Time{}, false},
		{"earlier today", now.Add(-time.Second), false},
		{"just before midnight", now.Add(-10 * time.Second), true},
		{"other zone, same UTC day", time.Date(2026, 10, 11, 20, 0, 1, 0, time.FixedZone("x", -4*3600)), false},
		{"clock went backwards", now.Add(24 * time.Hour), false},
	}
	for _, c := range cases {
		if got := shippedBeforeUTCDay(c.shipped, now); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// An empty local chain that a witness remembers is refused with the
// recovery that works under Object Lock: a new SB_NODE_ID (D4).
func TestValidateErasedChainNamesNewNodeIDRecovery(t *testing.T) {
	svc, w := newWitnessShipService(t)
	shipped := w.heads[0].HeadHex
	if err := os.Truncate(svc.secretAuditFile.path, 0); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name     string
		remote   string
		remoteOK bool
	}{
		{"witness still holds the head", shipped, true},
		{"only the local receipt remembers it", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w.remoteHead, w.remoteOK = c.remote, c.remoteOK
			err := svc.ValidateSecretAuditWitness()
			if err == nil {
				t.Fatal("an erased chain validated")
			}
			for _, want := range []string{"secret audit witness mismatch", "local audit log is empty", `node "node-1"`, shipped, "new SB_NODE_ID", "Rebuild a node under a new SB_NODE_ID"} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("err = %v, missing %q", err, want)
				}
			}
		})
	}
}
