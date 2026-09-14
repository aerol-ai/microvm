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
	}
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
	forgedLine, _ := json.Marshal(forged)
	egressLine, _ := json.Marshal(egress)
	payload := append(append(forgedLine, '\n'), append(egressLine, '\n')...)
	if err := os.WriteFile(sink.spillPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if !sink.drainSpill() {
		t.Fatal("drainSpill returned false")
	}

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
		}
	}
	if !sawGap || !sawEgress {
		t.Fatalf("expected gap + sanitized egress, got:\n%s", raw)
	}
	if _, _, err := RecomputeChainHead(sink.path); err != nil {
		t.Fatalf("chain after untrusted spill drain: %v", err)
	}
}

func TestDrainSpillCapsOversizedLineWithoutBreakingChain(t *testing.T) {
	sink := newDrainTestSink(t)

	huge := append(bytes.Repeat([]byte("x"), auditIngestMaxBody+8), '\n')
	ok, _ := json.Marshal(SecretAuditEvent{
		Kind:        secretAuditKindEgress,
		Destination: "ok.example:443",
		SandboxID:   "sb",
		Result:      secretAuditResultSuccess,
		Reason:      secretAuditReasonOK,
	})
	if err := os.WriteFile(sink.spillPath, append(huge, append(ok, '\n')...), 0o600); err != nil {
		t.Fatal(err)
	}
	if !sink.drainSpill() {
		t.Fatal("drainSpill returned false")
	}
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
