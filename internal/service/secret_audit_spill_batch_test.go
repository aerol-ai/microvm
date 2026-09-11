package service

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/pkg/auditlog"
)

// The daemon's overflow spill is group-committed through the shared
// auditlog.SpillFile writer: a queued burst costs one lock and one fsync per
// batch, and a failed batch is accounted as one coalesced gap, never lost
// silently. The sink here has no writer goroutine so the drain is
// deterministic.
func TestFileAuditSinkSpillQueuedGroupCommits(t *testing.T) {
	dir := t.TempDir()
	spill := auditlog.SpillFileIn(dir)
	sink := &fileAuditSink{
		spillPath: spill.Path,
		lockPath:  spill.LockPath,
		gapPath:   filepath.Join(dir, "secrets.gap"),
		spillCh:   make(chan SecretAuditEvent, 512),
	}
	for i := range 300 {
		sink.spillCh <- SecretAuditEvent{SandboxID: "sb", EventID: fmt.Sprintf("e-%03d", i), Result: secretAuditResultSuccess}
	}
	sink.spillQueued(<-sink.spillCh)
	sink.spillQueued(<-sink.spillCh)
	if len(sink.spillCh) != 0 {
		t.Fatalf("%d events left queued after two batches", len(sink.spillCh))
	}
	f, err := os.Open(spill.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var ids []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var ev SecretAuditEvent
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatal(err)
		}
		if ev.Time.IsZero() {
			t.Fatalf("spilled record without a time: %+v", ev)
		}
		ids = append(ids, ev.EventID)
	}
	if len(ids) != 300 {
		t.Fatalf("spilled %d records, want 300", len(ids))
	}
	for i, id := range ids {
		if id != fmt.Sprintf("e-%03d", i) {
			t.Fatalf("record %d = %s: batches reordered", i, id)
		}
	}
	if sink.pendingGap.Load() != 0 {
		t.Fatalf("successful batches owe a gap of %d", sink.pendingGap.Load())
	}

	// A batch the disk refuses is one coalesced gap the size of the batch.
	broken := &fileAuditSink{
		spillPath: filepath.Join(dir, "as-directory"),
		lockPath:  spill.LockPath,
		gapPath:   filepath.Join(dir, "broken.gap"),
		spillCh:   make(chan SecretAuditEvent, 8),
	}
	if err := os.Mkdir(broken.spillPath, 0o700); err != nil {
		t.Fatal(err)
	}
	for range 4 {
		broken.spillCh <- SecretAuditEvent{SandboxID: "sb"}
	}
	dropped := auditEventsDroppedTotal.Value()
	broken.spillQueued(<-broken.spillCh)
	if got := auditEventsDroppedTotal.Value() - dropped; got != 4 {
		t.Fatalf("failed batch dropped delta = %d, want 4", got)
	}
	if broken.pendingGap.Load() != 4 || loadGapCount(broken.gapPath) != 4 {
		t.Fatalf("owed gap = %d (persisted %d), want 4", broken.pendingGap.Load(), loadGapCount(broken.gapPath))
	}
	if err := (&fileAuditSink{}).appendSpill(SecretAuditEvent{}); err == nil {
		t.Fatal("append without a spill path succeeded")
	}
}
