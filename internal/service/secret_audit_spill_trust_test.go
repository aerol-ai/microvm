package service

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/auditlog"
)

// drainTestSpillKey is the capability signing key every drain test mints and
// verifies with; it stands in for the daemon's persisted audit-ingest key.
const drainTestSpillKey = "drain-test-spill-key"

func newDrainTestSink(t *testing.T) *fileAuditSink {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, secretAuditFileName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	spill := auditlog.SpillFileIn(dir)
	return &fileAuditSink{
		file:             f,
		path:             path,
		lockPath:         spill.LockPath,
		spillPath:        spill.Path,
		spillWorkingPath: filepath.Join(dir, secretAuditSpillWorking),
		spillVerify: func(capability string, now time.Time) (string, string, error) {
			return auditlog.ParseAndVerifyEgressCapability(drainTestSpillKey, capability, now)
		},
		spillActor:    func() string { return "node-self" },
		spillOwnerRef: func(sandboxID string) string { return "acct-" + sandboxID },
	}
}

// mintDrainTestCapability is the capability a worker for sandboxID would hold.
func mintDrainTestCapability(t *testing.T, sandboxID, incarnationID string, expiry time.Time) string {
	t.Helper()
	capability, err := auditlog.MintEgressCapability(drainTestSpillKey, sandboxID, incarnationID, expiry)
	if err != nil {
		t.Fatal(err)
	}
	return capability
}

func spillLines(t *testing.T, records ...auditlog.SpillRecord) []byte {
	t.Helper()
	var payload []byte
	for _, rec := range records {
		line, err := json.Marshal(rec)
		if err != nil {
			t.Fatal(err)
		}
		payload = append(append(payload, line...), '\n')
	}
	return payload
}

func TestDrainSpillRejectsForgedSecretOpenAndFutureTimestamps(t *testing.T) {
	sink := newDrainTestSink(t)

	forged := SecretAuditEvent{
		Time:      time.Now().UTC().Add(365 * 24 * time.Hour),
		EventID:   "ae-forged",
		SandboxID: "victim",
		Ref:       "cluster-secret",
		Result:    secretAuditResultSuccess,
		Reason:    secretAuditReasonOK,
		Kind:      secretAuditKindSecretOpen,
		PrevHash:  "deadbeef",
		EventHash: "cafebabe",
	}
	egress := SecretAuditEvent{
		Time:        time.Now().UTC().Add(time.Hour),
		EventID:     "ae-egress",
		SandboxID:   "sb",
		Kind:        secretAuditKindEgress,
		Destination: "api.example.com:443",
		Result:      secretAuditResultSuccess,
		Reason:      secretAuditReasonOK,
	}
	payload := spillLines(t,
		auditlog.SpillRecord{Event: forged, Capability: mintDrainTestCapability(t, "victim", "inc-victim", time.Now().Add(time.Hour))},
		auditlog.SpillRecord{Event: egress, Capability: mintDrainTestCapability(t, "sb", "inc-sb", time.Now().Add(time.Hour))},
	)
	if err := os.WriteFile(sink.spillPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	requireSpillDrained(t, sink, "drainSpill returned false")

	raw, err := os.ReadFile(sink.path)
	if err != nil {
		t.Fatal(err)
	}
	var sawGap, sawEgress bool
	now := time.Now().UTC().Add(time.Minute)
	for _, line := range nonEmptyLines(string(raw)) {
		var ev SecretAuditEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if ev.Kind == secretAuditKindSecretOpen {
			t.Fatalf("forged secret-open was chained: %s", line)
		}
		if ev.Time.After(now) {
			t.Fatalf("far-future timestamp was chained: %s", line)
		}
		if ev.Kind == secretAuditKindGap {
			sawGap = true
		}
		if ev.Kind == secretAuditKindEgress && ev.Destination == "api.example.com:443" && ev.SandboxID == "sb" {
			sawEgress = true
			if ev.PrevHash == "deadbeef" || ev.EventHash == "cafebabe" {
				t.Fatal("spill hashes were trusted instead of re-linked")
			}
			if ev.IncarnationID != "inc-sb" || ev.Actor != "node-self" || ev.OwnerRef != "acct-sb" {
				t.Fatalf("egress identity not bound from capability/daemon: %+v", ev)
			}
		}
	}
	if !sawGap || !sawEgress {
		t.Fatalf("expected gap + sanitized egress, got:\n%s", raw)
	}
	if _, _, err := RecomputeChainHead(sink.path); err != nil {
		t.Fatalf("chain after untrusted spill drain: %v", err)
	}
}

// The spill file is written by worker subprocesses that share the audit
// directory, so the identity fields on a line prove nothing. The drain must
// authenticate each egress line with the same capability the HTTP ingest
// would have verified, rebind sandbox/incarnation from it, and stamp
// actor/owner itself — otherwise a worker for one tenant can plant egress
// evidence under another tenant's sandbox, and a capability the ingest just
// rejected as stale simply re-enters through the spill.
func TestDrainSpillBindsEgressIdentityToVerifiedCapability(t *testing.T) {
	sink := newDrainTestSink(t)
	now := time.Now().UTC()
	claim := func(eventID string) SecretAuditEvent {
		return SecretAuditEvent{
			Time: now.Add(-time.Minute), EventID: eventID,
			Actor: "evil-node", NodeID: "evil-node", SandboxID: "victim", IncarnationID: "inc-victim", OwnerRef: "acct-victim",
			Kind: secretAuditKindEgress, Destination: "exfil.example:443", Network: "tcp",
			Result: secretAuditResultFailure, Reason: secretAuditReasonRecipientDenied, Ref: "planted-ref",
			BytesIn: 99, BytesOut: 99, Dropped: 5,
		}
	}
	expired := mintDrainTestCapability(t, "attacker", "inc-attacker", now.Add(-time.Minute))
	foreignKey, err := auditlog.MintEgressCapability("some-other-key", "attacker", "inc-attacker", now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	unauthBefore := auditSpillUnauthenticatedTotal.Value()
	payload := spillLines(t,
		// Valid capability for a different sandbox than the line claims.
		auditlog.SpillRecord{Event: claim("ae-rebound"), Capability: mintDrainTestCapability(t, "attacker", "inc-attacker", now.Add(time.Hour))},
		// No capability at all.
		auditlog.SpillRecord{Event: claim("ae-nocap")},
		// Expired capability.
		auditlog.SpillRecord{Event: claim("ae-expired"), Capability: expired},
		// Capability minted under a different key (forged MAC).
		auditlog.SpillRecord{Event: claim("ae-forged-mac"), Capability: foreignKey},
		// Malformed capability string.
		auditlog.SpillRecord{Event: claim("ae-garbage"), Capability: "not|a|cap"},
	)
	if err := os.WriteFile(sink.spillPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	requireSpillDrained(t, sink, "drainSpill returned false")
	raw, err := os.ReadFile(sink.path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("victim")) || bytes.Contains(raw, []byte("evil-node")) || bytes.Contains(raw, []byte("planted-ref")) {
		t.Fatalf("worker-claimed identity reached the chain:\n%s", raw)
	}
	if bytes.Contains(raw, []byte("capability")) || bytes.Contains(raw, []byte(expired)) {
		t.Fatalf("a bearer capability was written to the audit log:\n%s", raw)
	}
	var egress []SecretAuditEvent
	gaps := 0
	for _, line := range nonEmptyLines(string(raw)) {
		var ev SecretAuditEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatal(err)
		}
		switch ev.Kind {
		case secretAuditKindEgress:
			egress = append(egress, ev)
		case secretAuditKindGap:
			gaps++
		}
	}
	if len(egress) != 1 {
		t.Fatalf("egress records chained = %d, want exactly the one with a valid capability:\n%s", len(egress), raw)
	}
	got := egress[0]
	if got.EventID != "ae-rebound" || got.SandboxID != "attacker" || got.IncarnationID != "inc-attacker" ||
		got.Actor != "node-self" || got.NodeID != "node-self" || got.OwnerRef != "acct-attacker" ||
		got.Result != secretAuditResultSuccess || got.Reason != secretAuditReasonOK ||
		got.Ref != "" || got.BytesIn != 0 || got.BytesOut != 0 || got.Dropped != 0 ||
		got.Destination != "exfil.example:443" || got.Network != "tcp" {
		t.Fatalf("authenticated egress was not fully rebound to the capability + daemon identity: %+v", got)
	}
	if gaps != 4 {
		t.Fatalf("unauthenticated lines chained as gaps = %d, want 4", gaps)
	}
	if delta := auditSpillUnauthenticatedTotal.Value() - unauthBefore; delta != 4 {
		t.Fatalf("aerolvm_audit_spill_unauthenticated_total delta = %d, want 4", delta)
	}
	if _, _, err := RecomputeChainHead(sink.path); err != nil {
		t.Fatalf("chain after mixed spill drain: %v", err)
	}
}

// A sink with no verifier wired cannot authenticate anything: every egress
// spill line fails closed to a gap instead of silently reverting to trusting
// the worker.
func TestDrainSpillWithoutVerifierFailsClosed(t *testing.T) {
	sink := newDrainTestSink(t)
	sink.spillVerify = nil
	payload := spillLines(t, auditlog.SpillRecord{
		Event: SecretAuditEvent{
			Time: time.Now().UTC(), EventID: "ae-unverifiable", SandboxID: "sb", Kind: secretAuditKindEgress,
			Destination: "api.example.com:443", Result: secretAuditResultSuccess, Reason: secretAuditReasonOK,
		},
		Capability: mintDrainTestCapability(t, "sb", "inc-sb", time.Now().Add(time.Hour)),
	})
	if err := os.WriteFile(sink.spillPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	requireSpillDrained(t, sink, "drainSpill returned false")
	raw, err := os.ReadFile(sink.path)
	if err != nil {
		t.Fatal(err)
	}
	if stringsContainsKind(raw, secretAuditKindEgress) || !stringsContainsKind(raw, secretAuditKindGap) {
		t.Fatalf("verifier-less drain must chain a gap, not the egress record:\n%s", raw)
	}
}

func TestDrainSpillCapsOversizedLineWithoutBreakingChain(t *testing.T) {
	sink := newDrainTestSink(t)

	huge := append(bytes.Repeat([]byte("x"), auditIngestMaxBody+8), '\n')
	ok := spillLines(t, auditlog.SpillRecord{
		Event: SecretAuditEvent{
			Kind:        secretAuditKindEgress,
			Destination: "ok.example:443",
			SandboxID:   "sb",
			Result:      secretAuditResultSuccess,
			Reason:      secretAuditReasonOK,
		},
		Capability: mintDrainTestCapability(t, "sb", "inc-sb", time.Now().Add(time.Hour)),
	})
	if err := os.WriteFile(sink.spillPath, append(huge, ok...), 0o600); err != nil {
		t.Fatal(err)
	}
	requireSpillDrained(t, sink, "drainSpill returned false")
	raw, err := os.ReadFile(sink.path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, bytes.Repeat([]byte("x"), 32)) {
		t.Fatal("oversized spill line was chained")
	}
	if !stringsContainsKind(raw, secretAuditKindGap) || !stringsContainsKind(raw, secretAuditKindEgress) {
		t.Fatalf("expected gap + egress after oversized spill, got:\n%s", raw)
	}
	if _, _, err := RecomputeChainHead(sink.path); err != nil {
		t.Fatalf("chain after oversized spill: %v", err)
	}
}

func stringsContainsKind(raw []byte, kind string) bool {
	for _, line := range nonEmptyLines(string(raw)) {
		var ev SecretAuditEvent
		if json.Unmarshal([]byte(line), &ev) != nil {
			continue
		}
		if ev.Kind == kind {
			return true
		}
	}
	return false
}
