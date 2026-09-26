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

// In-process overflow group-commits onto the authoritative JSONL, not the
// worker-writable spill file. A failed batch is one coalesced gap.
func TestFileAuditSinkSpillQueuedGroupCommits(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, secretAuditFileName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	spill := auditlog.SpillFileIn(dir)
	sink := &fileAuditSink{
		file:     f,
		path:     path,
		lockPath: spill.LockPath,
		gapPath:  filepath.Join(dir, "secrets.gap"),
		spillCh:  make(chan SecretAuditEvent, 512),
	}
	for i := range 300 {
		sink.spillCh <- SecretAuditEvent{SandboxID: "sb", EventID: fmt.Sprintf("e-%03d", i), Result: secretAuditResultSuccess}
	}
	sink.spillQueued(<-sink.spillCh)
	sink.spillQueued(<-sink.spillCh)
	if len(sink.spillCh) != 0 {
		t.Fatalf("%d events left queued after two batches", len(sink.spillCh))
	}
	out, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	var ids []string
	sc := bufio.NewScanner(out)
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

	// A batch the writer refuses is one coalesced gap the size of the batch.
	broken := &fileAuditSink{
		gapPath:     filepath.Join(dir, "broken.gap"),
		lockPath:    filepath.Join(dir, "broken.lock"),
		spillCh:     make(chan SecretAuditEvent, 8),
		writePoison: fmt.Errorf("injected poison"),
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

// A sink with neither a lock path nor a log path must fail closed. The old
// fallback concatenated an empty path into a bare relative ".lock", which
// flocked a file in the process working directory: two audit directories
// would have serialized against one unrelated file, and a unit test dropped
// the sidecar into the source tree.
func TestWithAuditFileLockRefusesUnsetPath(t *testing.T) {
	ran := false
	if err := (&fileAuditSink{}).withAuditFileLock(func() error { ran = true; return nil }); err == nil {
		t.Fatal("unset audit lock path was accepted")
	}
	if ran {
		t.Fatal("entered the critical section without holding a lock")
	}
	// The regression signal: the bare sidecar lands in whatever directory the
	// process happens to be in, which under `go test` is the package source.
	if _, err := os.Stat(".lock"); !os.IsNotExist(err) {
		t.Fatalf("bare .lock created in the working directory: %v", err)
	}

	// A sink carrying only its log path still derives the sidecar beside it.
	dir := t.TempDir()
	path := filepath.Join(dir, secretAuditFileName)
	locked := false
	if err := (&fileAuditSink{path: path}).withAuditFileLock(func() error { locked = true; return nil }); err != nil {
		t.Fatalf("derived sidecar rejected: %v", err)
	}
	if !locked {
		t.Fatal("critical section did not run under the derived sidecar")
	}
	if _, err := os.Stat(path + ".lock"); err != nil {
		t.Fatalf("derived sidecar missing: %v", err)
	}
}
