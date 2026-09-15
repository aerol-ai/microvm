package service

import (
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"
)

func quotaTestEgress(sandboxID, dest string) SecretAuditEvent {
	return SecretAuditEvent{
		Time: time.Now().UTC(), Actor: "node-1", NodeID: "node-1", SandboxID: sandboxID,
		IncarnationID: "inc-" + sandboxID, OwnerRef: "acct-" + sandboxID,
		Kind: secretAuditKindEgress, Result: secretAuditResultSuccess, Reason: secretAuditReasonOK,
		Destination: dest, Network: "tcp",
	}
}

func quotaTestRecords(t *testing.T, path string) (egress map[string]int, markers []SecretAuditEvent, others int) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	egress = map[string]int{}
	for _, line := range nonEmptyLines(string(raw)) {
		var ev SecretAuditEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatal(err)
		}
		switch {
		case ev.Kind == secretAuditKindEgress && ev.Reason == secretAuditReasonRateLimited:
			markers = append(markers, ev)
		case ev.Kind == secretAuditKindEgress:
			egress[ev.SandboxID]++
		default:
			others++
		}
	}
	return egress, markers, others
}

// The budget is a per-sandbox token bucket over egress records only; refused
// records are counted and later reported as one record per sandbox carrying
// the identity of what was refused.
func TestEgressAuditQuotaAdmitsBurstThenCoalescesTheRest(t *testing.T) {
	base := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	now := base
	q := newEgressAuditQuota(1, 3, time.Millisecond)
	q.now = func() time.Time { return now }
	refused := auditEgressRateLimitedTotal.Value()

	batch := []SecretAuditEvent{
		quotaTestEgress("sb-a", "a1"), quotaTestEgress("sb-a", "a2"), quotaTestEgress("sb-a", "a3"),
		quotaTestEgress("sb-a", "a4"), quotaTestEgress("sb-a", "a5"),
		{Kind: secretAuditKindSecretOpen, SandboxID: "sb-a", Result: secretAuditResultSuccess},
		quotaTestEgress("sb-b", "b1"), quotaTestEgress("sb-b", "b2"),
		{Kind: secretAuditKindGap, Result: secretAuditResultGap, Dropped: 7},
	}
	kept, suppressed := q.admit(batch)
	if len(kept) != 7 {
		t.Fatalf("kept %d records, want 3 sb-a egress + secret_open + 2 sb-b + gap = 7", len(kept))
	}
	for i, want := range []bool{false, false, false, true, true, false, false, false, false} {
		if suppressed[i] != want {
			t.Fatalf("suppressed[%d] = %v, want %v", i, suppressed[i], want)
		}
	}
	if auditEgressRateLimitedTotal.Value()-refused != 2 {
		t.Fatalf("rate-limited counter +%d, want 2", auditEgressRateLimitedTotal.Value()-refused)
	}
	if m := q.owedMarkers(false); len(m) != 0 {
		t.Fatalf("marker before the delay elapsed: %+v", m)
	}
	now = base.Add(2 * time.Millisecond)
	markers := q.owedMarkers(false)
	if len(markers) != 1 {
		t.Fatalf("markers = %+v, want one for sb-a", markers)
	}
	m := markers[0]
	if m.SandboxID != "sb-a" || m.Dropped != 2 || m.Reason != secretAuditReasonRateLimited || m.Kind != secretAuditKindEgress ||
		m.IncarnationID != "inc-sb-a" || m.OwnerRef != "acct-sb-a" || m.Actor != "node-1" || !m.Time.Equal(now) {
		t.Fatalf("marker = %+v", m)
	}
	if again := q.owedMarkers(false); len(again) != 0 {
		t.Fatalf("marker owed twice: %+v", again)
	}
	// The bucket refills at the rate: three seconds later three more fit.
	now = base.Add(3 * time.Second)
	kept, suppressed = q.admit([]SecretAuditEvent{quotaTestEgress("sb-a", "a6"), quotaTestEgress("sb-a", "a7"), quotaTestEgress("sb-a", "a8"), quotaTestEgress("sb-a", "a9")})
	if len(kept) != 3 || !suppressed[3] {
		t.Fatalf("after refill kept=%d suppressed=%v", len(kept), suppressed)
	}
	// force reports what is owed regardless of the delay (shutdown).
	if m := q.owedMarkers(true); len(m) != 1 || m[0].Dropped != 1 {
		t.Fatalf("forced markers = %+v", m)
	}
	// Idle buckets that owe nothing are swept after the TTL.
	now = base.Add(3*time.Second + egressQuotaIdleTTL + time.Minute)
	_ = q.owedMarkers(false)
	if len(q.entries) != 0 {
		t.Fatalf("idle buckets survived the sweep: %d", len(q.entries))
	}

	var none *egressAuditQuota
	if k, s := none.admit(batch); len(k) != len(batch) || s != nil {
		t.Fatal("nil quota must admit everything untouched")
	}
	if none.owedMarkers(true) != nil {
		t.Fatal("nil quota owes nothing")
	}
	if newEgressAuditQuota(0, 10, 0) != nil {
		t.Fatal("rate 0 must mean no budget")
	}
}

// The bucket map is capped: past the cap, idle entries are swept and, if the
// map is still full of live sandboxes, new ones are admitted untracked.
func TestEgressAuditQuotaCapAdmitsUntrackedWhenFullOfLiveSandboxes(t *testing.T) {
	base := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	q := newEgressAuditQuota(1, 1, 0)
	q.now = func() time.Time { return base }
	for i := 0; i < egressQuotaMaxEntries; i++ {
		q.entries[string(rune('a'))+itoaQuota(i)] = &egressQuotaEntry{lastSeen: base}
	}
	if e := q.entry("fresh", base); e != nil {
		t.Fatal("full map of live sandboxes must admit the newcomer untracked")
	}
	for _, e := range q.entries {
		e.lastSeen = base.Add(-2 * egressQuotaIdleTTL)
	}
	if e := q.entry("fresh", base); e == nil {
		t.Fatal("idle entries must be swept to make room")
	}
	if len(q.entries) != 1 {
		t.Fatalf("entries after sweep = %d, want 1", len(q.entries))
	}
}

func itoaQuota(i int) string {
	const digits = "0123456789"
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{digits[i%10]}, b...)
		i /= 10
	}
	return string(b)
}

// Through the real sink: over-budget egress records never reach the file, a
// durable emit learns the refusal, secret-open records are exempt, and the
// loss surfaces as the sandbox's own rate_limited record with the right
// identity. The chain stays valid throughout.
func TestFileAuditSinkAppliesEgressBudgetAtTheWriter(t *testing.T) {
	sink, err := newFileAuditSinkFrom(t.TempDir(), fileAuditSinkOptions{buffer: 64, egressRate: 1, egressBurst: 3, egressMarkerDelay: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sink.Close)
	for i := 0; i < 6; i++ {
		sink.Emit(quotaTestEgress("sb-a", "a"))
	}
	sink.Emit(quotaTestEgress("sb-b", "b"))
	sink.Emit(quotaTestEgress("sb-b", "b"))
	sink.Emit(SecretAuditEvent{Kind: secretAuditKindSecretOpen, SandboxID: "sb-a", Ref: "secret://sb-a/env", Result: secretAuditResultSuccess})
	if err := sink.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := sink.EmitDurable(quotaTestEgress("sb-a", "a")); !errors.Is(err, errAuditRateLimited) {
		t.Fatalf("durable emit over budget = %v, want errAuditRateLimited", err)
	}
	if err := sink.EmitDurable(quotaTestEgress("sb-b", "b")); err != nil {
		t.Fatalf("another sandbox's durable emit must be unaffected: %v", err)
	}
	time.Sleep(5 * time.Millisecond)
	if err := sink.Sync(); err != nil {
		t.Fatal(err)
	}
	egress, markers, others := quotaTestRecords(t, sink.path)
	if egress["sb-a"] != 3 || egress["sb-b"] != 3 || others != 1 {
		t.Fatalf("egress=%v others=%d, want sb-a 3 (burst), sb-b 3, one secret_open", egress, others)
	}
	var dropped int64
	for _, m := range markers {
		if m.SandboxID != "sb-a" || m.IncarnationID != "inc-sb-a" || m.OwnerRef != "acct-sb-a" || m.NodeID != "node-1" {
			t.Fatalf("marker identity = %+v", m)
		}
		dropped += m.Dropped
	}
	if dropped != 4 {
		t.Fatalf("markers account for %d refused records, want 4 (3 emitted + 1 durable): %+v", dropped, markers)
	}
	if _, _, err := RecomputeChainHead(sink.path); err != nil {
		t.Fatalf("chain: %v", err)
	}
}

// Records that arrive through the spill file (worker fallback, enterprise
// overflow) take the same budget: the spill is a path into the log, not
// around the quota.
func TestFileAuditSinkAppliesEgressBudgetToSpilledRecords(t *testing.T) {
	sink, err := newFileAuditSinkFrom(t.TempDir(), fileAuditSinkOptions{buffer: 64, spillEnabled: true, egressRate: 1, egressBurst: 3, egressMarkerDelay: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sink.Close)
	spilled := make([]SecretAuditEvent, 0, 6)
	for i := 0; i < 6; i++ {
		spilled = append(spilled, quotaTestEgress("sb-c", "c"))
	}
	if err := sink.appendSpill(spilled...); err != nil {
		t.Fatal(err)
	}
	if err := sink.Sync(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	if err := sink.Sync(); err != nil {
		t.Fatal(err)
	}
	egress, markers, _ := quotaTestRecords(t, sink.path)
	var dropped int64
	for _, m := range markers {
		dropped += m.Dropped
	}
	if egress["sb-c"] != 3 || dropped != 3 {
		t.Fatalf("drained egress=%d dropped=%d, want 3/3", egress["sb-c"], dropped)
	}
}

// Nothing owed is lost at shutdown: Close writes the coalesced records even
// before the marker delay has elapsed.
func TestFileAuditSinkCloseFlushesOwedRateLimitMarkers(t *testing.T) {
	sink, err := newFileAuditSinkFrom(t.TempDir(), fileAuditSinkOptions{buffer: 64, egressRate: 1, egressBurst: 3, egressMarkerDelay: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		sink.Emit(quotaTestEgress("sb-d", "d"))
	}
	if err := sink.Sync(); err != nil {
		t.Fatal(err)
	}
	if _, markers, _ := quotaTestRecords(t, sink.path); len(markers) != 0 {
		t.Fatalf("marker written before its delay: %+v", markers)
	}
	sink.Close()
	egress, markers, _ := quotaTestRecords(t, sink.path)
	if egress["sb-d"] != 3 || len(markers) != 1 || markers[0].Dropped != 2 {
		t.Fatalf("after close egress=%d markers=%+v", egress["sb-d"], markers)
	}
	if _, _, err := RecomputeChainHead(sink.path); err != nil {
		t.Fatal(err)
	}
}

// Without a budget (rate 0, the constructors' default) nothing is refused.
func TestFileAuditSinkWithoutEgressBudgetKeepsEveryRecord(t *testing.T) {
	sink, err := newFileAuditSink(t.TempDir(), 8)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sink.Close)
	for i := 0; i < 50; i++ {
		if err := sink.EmitDurable(quotaTestEgress("sb-e", "e")); err != nil {
			t.Fatal(err)
		}
	}
	egress, markers, _ := quotaTestRecords(t, sink.path)
	if egress["sb-e"] != 50 || len(markers) != 0 {
		t.Fatalf("unbudgeted sink egress=%d markers=%d", egress["sb-e"], len(markers))
	}
}
