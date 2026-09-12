package service

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/auditlog"
)

// retentionTestEvents parses every record in the audit file, in file order.
func retentionTestEvents(t *testing.T, path string) []SecretAuditEvent {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []SecretAuditEvent
	for _, line := range nonEmptyLines(string(raw)) {
		var ev SecretAuditEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("record %q: %v", line, err)
		}
		out = append(out, ev)
	}
	return out
}

func retentionTestSink(t *testing.T, events ...SecretAuditEvent) *fileAuditSink {
	t.Helper()
	sink, err := newFileAuditSink(t.TempDir(), 8)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sink.Close)
	for _, ev := range events {
		if err := sink.EmitDurable(ev); err != nil {
			t.Fatal(err)
		}
	}
	return sink
}

// The spill drain and worker ingest land older records after newer ones.
// Retention used to stop at the first fresh record, so an expired record
// behind it was kept for as long as that record lived. Now it is reduced in
// place to a hash-only stub: the payload goes, the chain still verifies, and
// the head is unchanged.
func TestFileAuditSinkPruneRedactsExpiredRecordsBehindFreshOnes(t *testing.T) {
	now := time.Now().UTC()
	sink := retentionTestSink(t,
		SecretAuditEvent{Time: now.Add(-10 * time.Second), EventID: "fresh-1", SandboxID: "sb-fresh", Result: secretAuditResultSuccess},
		SecretAuditEvent{Time: now.Add(-48 * time.Hour), EventID: "old-middle", SandboxID: "sb-old", Actor: "alice", Ref: "secret://sb-old/registry", Result: secretAuditResultSuccess},
		SecretAuditEvent{Time: now, EventID: "fresh-2", SandboxID: "sb-fresh", Result: secretAuditResultSuccess},
	)
	before := retentionTestEvents(t, sink.path)
	headBefore, _, err := RecomputeChainHead(sink.path)
	if err != nil {
		t.Fatal(err)
	}
	dropped, redacted := auditRetentionDroppedTotal.Value(), auditRetentionRedactedTotal.Value()

	if err := sink.Prune(now.Add(-24 * time.Hour)); err != nil {
		t.Fatal(err)
	}

	after := retentionTestEvents(t, sink.path)
	if len(after) != 4 {
		t.Fatalf("records after prune = %d, want checkpoint + fresh-1 + stub + fresh-2: %+v", len(after), after)
	}
	cp, stub := after[0], after[2]
	if cp.Kind != secretAuditKindRetentionCheckpoint || cp.PrevHash != auditlog.GenesisPrevHash {
		t.Fatalf("nothing was dropped, so the checkpoint must anchor at genesis: %+v", cp)
	}
	if after[1] != before[0] || after[3] != before[2] {
		t.Fatalf("fresh records must be copied byte-for-byte: %+v / %+v", after[1], after[3])
	}
	if stub.Kind != secretAuditKindRetentionRedacted || stub.EventID != "old-middle" || !stub.Time.Equal(before[1].Time) {
		t.Fatalf("stub = %+v", stub)
	}
	if stub.PrevHash != before[1].PrevHash || stub.EventHash != before[1].EventHash {
		t.Fatalf("stub must keep the original links: %+v vs %+v", stub, before[1])
	}
	if stub.SandboxID != "" || stub.Actor != "" || stub.Ref != "" {
		t.Fatalf("stub still carries payload: %+v", stub)
	}
	raw, _ := os.ReadFile(sink.path)
	if bytes.Contains(raw, []byte("sb-old")) || bytes.Contains(raw, []byte("alice")) {
		t.Fatalf("expired payload survived retention: %s", raw)
	}
	headAfter, _, err := RecomputeChainHead(sink.path)
	if err != nil {
		t.Fatalf("chain through the stub: %v", err)
	}
	if headAfter != headBefore {
		t.Fatalf("redaction changed the head %s -> %s", headBefore, headAfter)
	}
	if auditRetentionDroppedTotal.Value()-dropped != 0 || auditRetentionRedactedTotal.Value()-redacted != 1 {
		t.Fatalf("counters dropped=%d redacted=%d, want 0/1", auditRetentionDroppedTotal.Value()-dropped, auditRetentionRedactedTotal.Value()-redacted)
	}
}

// A stub is transient: once the record in front of it expires, the next
// prune drops it with the prefix. And a prune that finds nothing expired
// leaves the file untouched (no rewrite, no generation change).
func TestFileAuditSinkPruneReclaimsStubsWithThePrefix(t *testing.T) {
	now := time.Now().UTC()
	sink := retentionTestSink(t,
		SecretAuditEvent{Time: now.Add(-10 * time.Second), EventID: "fresh-1", SandboxID: "sb", Result: secretAuditResultSuccess},
		SecretAuditEvent{Time: now.Add(-48 * time.Hour), EventID: "old-middle", SandboxID: "sb", Result: secretAuditResultSuccess},
		SecretAuditEvent{Time: now, EventID: "fresh-2", SandboxID: "sb", Result: secretAuditResultSuccess},
	)
	if err := sink.Prune(now.Add(-24 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	first, _ := os.ReadFile(sink.path)
	if err := sink.Prune(now.Add(-24 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	again, _ := os.ReadFile(sink.path)
	if !bytes.Equal(first, again) {
		t.Fatalf("a prune with nothing new to remove rewrote the file:\n%s\n---\n%s", first, again)
	}
	stub := retentionTestEvents(t, sink.path)[2]

	if err := sink.Prune(now.Add(-5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	after := retentionTestEvents(t, sink.path)
	if len(after) != 2 || after[0].Kind != secretAuditKindRetentionCheckpoint || after[1].EventID != "fresh-2" {
		t.Fatalf("records after the prefix caught up = %+v", after)
	}
	if after[0].PrevHash != stub.EventHash || after[1].PrevHash != stub.EventHash {
		t.Fatalf("checkpoint must name the dropped stub as the last dropped record: %+v", after)
	}
	if raw, _ := os.ReadFile(sink.path); bytes.Contains(raw, []byte(secretAuditKindRetentionRedacted)) {
		t.Fatalf("stub survived the prefix drop: %s", raw)
	}
	if _, _, err := RecomputeChainHead(sink.path); err != nil {
		t.Fatal(err)
	}
}

// A witness parked on a head the first prune dropped must stay verifiable
// through the second prune, which drops the checkpoint that recorded it.
func TestFileAuditSinkPruneCarriesWitnessedThroughAcrossPrunes(t *testing.T) {
	now := time.Now().UTC()
	sink := retentionTestSink(t,
		SecretAuditEvent{Time: now.Add(-72 * time.Hour), EventID: "old-witnessed", SandboxID: "sb", Result: secretAuditResultSuccess},
		SecretAuditEvent{Time: now.Add(-60 * time.Hour), EventID: "old-later", SandboxID: "sb", Result: secretAuditResultSuccess},
		SecretAuditEvent{Time: now.Add(-36 * time.Hour), EventID: "middle", SandboxID: "sb", Result: secretAuditResultSuccess},
		SecretAuditEvent{Time: now, EventID: "fresh", SandboxID: "sb", Result: secretAuditResultSuccess},
	)
	witnessed := retentionTestEvents(t, sink.path)[0].EventHash
	if err := persistWitnessReceipt("", sink.witnessTipPath, witnessReceiptRecord{HeadHex: witnessed}); err != nil {
		t.Fatal(err)
	}
	if err := sink.Prune(now.Add(-48 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	if cp := retentionTestEvents(t, sink.path)[0]; cp.WitnessedThrough != witnessed {
		t.Fatalf("first prune lost the witnessed ancestor: %+v", cp)
	}
	if err := sink.Prune(now.Add(-24 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	after := retentionTestEvents(t, sink.path)
	if len(after) != 2 || after[0].WitnessedThrough != witnessed {
		t.Fatalf("second prune must carry WitnessedThrough forward: %+v", after)
	}
	scan, err := scanSecretAuditChain(sink.path)
	if err != nil || scan.witnessedThrough != witnessed {
		t.Fatalf("scan witnessedThrough=%q err=%v, want %q", scan.witnessedThrough, err, witnessed)
	}
}

// Retention grew (the cutoff moved earlier than the checkpoint's time) and a
// very late record arrived expired: nothing to drop, one record to redact.
// The rewrite re-mints the leading checkpoint with its ancestry and leaves
// exactly one checkpoint, first.
func TestFileAuditSinkPruneRemintsLeadingCheckpointWhenRetentionGrows(t *testing.T) {
	now := time.Now().UTC()
	sink := retentionTestSink(t,
		SecretAuditEvent{Time: now.Add(-72 * time.Hour), EventID: "a", SandboxID: "sb", Result: secretAuditResultSuccess},
		SecretAuditEvent{Time: now.Add(-60 * time.Hour), EventID: "b", SandboxID: "sb", Result: secretAuditResultSuccess},
		SecretAuditEvent{Time: now.Add(-time.Hour), EventID: "fresh", SandboxID: "sb", Result: secretAuditResultSuccess},
	)
	bHash := retentionTestEvents(t, sink.path)[1].EventHash
	if err := sink.Prune(now.Add(-48 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := sink.EmitDurable(SecretAuditEvent{Time: now.Add(-100 * time.Hour), EventID: "late", SandboxID: "sb-late", Result: secretAuditResultSuccess}); err != nil {
		t.Fatal(err)
	}
	if err := sink.Prune(now.Add(-96 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	after := retentionTestEvents(t, sink.path)
	if len(after) != 3 {
		t.Fatalf("records = %+v", after)
	}
	cp := after[0]
	if cp.Kind != secretAuditKindRetentionCheckpoint || cp.PrevHash != bHash || !cp.Time.Equal(now.Add(-96*time.Hour)) {
		t.Fatalf("re-minted checkpoint = %+v, want prev %s at the new boundary", cp, bHash)
	}
	if after[1].EventID != "fresh" || after[1].Kind != "" {
		t.Fatalf("fresh record changed: %+v", after[1])
	}
	if after[2].Kind != secretAuditKindRetentionRedacted || after[2].EventID != "late" || after[2].SandboxID != "" {
		t.Fatalf("late record must be a stub: %+v", after[2])
	}
	for i, ev := range after[1:] {
		if ev.Kind == secretAuditKindRetentionCheckpoint {
			t.Fatalf("second checkpoint at %d", i+1)
		}
	}
	if _, _, err := RecomputeChainHead(sink.path); err != nil {
		t.Fatal(err)
	}
}

// A stub is linked by its stored hashes, since the payload that produced
// them is gone. It can stand only where a record stood, and it may carry
// nothing but its links: a "stub" with content is a forgery, not evidence.
func TestSecretAuditChainVerifierLinksStubsByStoredHashesOnly(t *testing.T) {
	now := time.Now().UTC()
	e1 := SecretAuditEvent{Time: now.Add(-3 * time.Hour), EventID: "e1", SandboxID: "sb", Result: secretAuditResultSuccess}
	e2 := SecretAuditEvent{Time: now.Add(-2 * time.Hour), EventID: "e2", SandboxID: "sb", Actor: "alice", Result: secretAuditResultSuccess}
	e3 := SecretAuditEvent{Time: now.Add(-time.Hour), EventID: "e3", SandboxID: "sb", Result: secretAuditResultSuccess}
	auditlog.LinkEvent(auditlog.GenesisPrevHash, &e1)
	auditlog.LinkEvent(e1.EventHash, &e2)
	auditlog.LinkEvent(e2.EventHash, &e3)
	stub := redactSecretAuditEvent(e2)

	verify := func(events ...SecretAuditEvent) error {
		v := newSecretAuditChainVerifier()
		for _, ev := range events {
			if err := v.Add(ev); err != nil {
				return err
			}
		}
		return nil
	}
	if err := verify(e1, stub, e3); err != nil {
		t.Fatalf("chain through a stub: %v", err)
	}
	misplaced := stub
	misplaced.PrevHash = "deadbeef"
	if err := verify(e1, misplaced, e3); err == nil || !strings.Contains(err.Error(), "prev_hash mismatch") {
		t.Fatalf("stub off its position accepted: %v", err)
	}
	smuggled := stub
	smuggled.SandboxID = "sb"
	if err := verify(e1, smuggled, e3); err == nil || !strings.Contains(err.Error(), "carries payload") {
		t.Fatalf("stub with payload accepted: %v", err)
	}
	unlinked := stub
	unlinked.EventHash = ""
	if err := verify(e1, unlinked); err == nil || !strings.Contains(err.Error(), "event_hash is missing") {
		t.Fatalf("stub without event_hash accepted: %v", err)
	}
	if err := verifySecretAuditRecord(stub); err != nil {
		t.Fatalf("record verifier rejects a sound stub: %v", err)
	}
	if err := verifySecretAuditRecord(smuggled); err == nil {
		t.Fatal("record verifier accepted a stub with payload")
	}
	if secretAuditEventMatches(stub, "", "", "", time.Time{}, "") || secretAuditEventMatches(SecretAuditEvent{Kind: secretAuditKindRetentionCheckpoint}, "", "", "", time.Time{}, "") {
		t.Fatal("retention records must never match a query")
	}

	path := t.TempDir() + "/secrets.jsonl"
	var buf bytes.Buffer
	for _, ev := range []SecretAuditEvent{e1, stub, e3} {
		line, _ := json.Marshal(ev)
		buf.Write(line)
		buf.WriteByte('\n')
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	scan, err := scanSecretAuditChain(path)
	if err != nil {
		t.Fatal(err)
	}
	if scan.records != 3 || scan.redacted != 1 || scan.head != e3.EventHash {
		t.Fatalf("scan records=%d redacted=%d head=%s", scan.records, scan.redacted, scan.head)
	}
}

// End to end through the real reordering path: an event that reached the
// spill file (worker or overflow) drains behind a newer in-memory event and
// still leaves the log when it expires.
func TestFileAuditSinkSpilledOldEventStillExpires(t *testing.T) {
	sink, err := newFileAuditSinkOpts(t.TempDir(), 8, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sink.Close)
	now := time.Now().UTC()
	if err := sink.EmitDurable(SecretAuditEvent{Time: now, EventID: "fresh", SandboxID: "sb-fresh", Result: secretAuditResultSuccess}); err != nil {
		t.Fatal(err)
	}
	if err := sink.appendSpill(SecretAuditEvent{Time: now.Add(-48 * time.Hour), EventID: "spilled-old", SandboxID: "sb-old", Result: secretAuditResultSuccess}); err != nil {
		t.Fatal(err)
	}
	if err := sink.Sync(); err != nil {
		t.Fatal(err)
	}
	drained := retentionTestEvents(t, sink.path)
	if len(drained) != 2 || drained[1].EventID != "spilled-old" {
		t.Fatalf("spilled record must land behind the fresh one: %+v", drained)
	}
	if err := sink.Prune(now.Add(-24 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	after := retentionTestEvents(t, sink.path)
	if len(after) != 3 || after[2].Kind != secretAuditKindRetentionRedacted || after[2].EventID != "spilled-old" {
		t.Fatalf("records after prune = %+v", after)
	}
	if raw, _ := os.ReadFile(sink.path); bytes.Contains(raw, []byte("sb-old")) {
		t.Fatalf("expired spilled payload survived: %s", raw)
	}
	if _, _, err := RecomputeChainHead(sink.path); err != nil {
		t.Fatal(err)
	}
}
