package auditlog

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func readSpillLines(t *testing.T, path string) []Event {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		var ev Event
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatalf("line %d does not parse: %v (%q)", len(out)+1, err, sc.Text())
		}
		out = append(out, ev)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestSpillFileAppendIsOneBatchWithIDsAndTimes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "audit", "nested")
	s := SpillFileIn(dir)
	if s.Path != filepath.Join(dir, SpillFileName) || s.LockPath != filepath.Join(dir, LockFileName) {
		t.Fatalf("paths = %+v", s)
	}
	if err := s.Append(nil); err != nil {
		t.Fatalf("empty append: %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("empty append must not touch the filesystem")
	}
	fixed := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	batch := []Event{
		{SandboxID: "sb-1", Kind: "egress", Destination: "a:1", Result: "success"},
		{SandboxID: "sb-2", Kind: "egress", Destination: "b:2", Result: "success", Time: fixed, EventID: "keep-me"},
		GapMarker("node-x", 7, fixed),
	}
	if err := s.Append(batch); err != nil {
		t.Fatal(err)
	}
	got := readSpillLines(t, s.Path)
	if len(got) != 3 {
		t.Fatalf("lines = %d, want 3", len(got))
	}
	if got[0].EventID == "" || got[0].Time.IsZero() || got[1].EventID != "keep-me" || !got[1].Time.Equal(fixed) {
		t.Fatalf("ids/times not filled: %+v", got[:2])
	}
	if got[2].Kind != "gap" || got[2].Reason != "overflow" || got[2].Dropped != 7 || got[2].NodeID != "node-x" || got[2].Actor != "node-x" {
		t.Fatalf("gap marker = %+v", got[2])
	}
	// The caller's slice is not mutated (ids are assigned on copies).
	if batch[0].EventID != "" {
		t.Fatal("Append mutated the caller's events")
	}
	if _, err := os.Stat(s.LockPath); err != nil {
		t.Fatalf("lock sidecar not created: %v", err)
	}
	if err := (SpillFile{}).Append(batch); !errors.Is(err, ErrNoSpillPath) {
		t.Fatalf("unset paths err = %v", err)
	}
}

func TestSpillFileAppendSerializesWholeBatches(t *testing.T) {
	s := SpillFileIn(filepath.Join(t.TempDir(), "audit"))
	const writers, perWriter, batchSize = 8, 20, 50
	var wg sync.WaitGroup
	for w := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for b := range perWriter {
				batch := make([]Event, batchSize)
				for i := range batch {
					batch[i] = Event{SandboxID: fmt.Sprintf("w%d", w), Ref: fmt.Sprintf("b%d", b), Result: "success", Destination: fmt.Sprintf("i%d", i)}
				}
				if err := s.Append(batch); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
	got := readSpillLines(t, s.Path)
	if len(got) != writers*perWriter*batchSize {
		t.Fatalf("lines = %d, want %d", len(got), writers*perWriter*batchSize)
	}
	// Batches never interleave: consecutive lines of one batch are contiguous.
	for i := 0; i < len(got); i += batchSize {
		for j := 1; j < batchSize; j++ {
			if got[i+j].SandboxID != got[i].SandboxID || got[i+j].Ref != got[i].Ref {
				t.Fatalf("batch interleaved at line %d: %+v vs %+v", i+j, got[i], got[i+j])
			}
		}
	}
}

func TestSpillFileAppendAndLockErrors(t *testing.T) {
	// The lock sidecar cannot be opened (its directory is a file).
	blockedLock := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blockedLock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := (SpillFile{Path: filepath.Join(t.TempDir(), SpillFileName), LockPath: filepath.Join(blockedLock, LockFileName)}).Append([]Event{{SandboxID: "sb"}}); err == nil {
		t.Fatal("unopenable lock accepted")
	}
	if err := WithFileLock("", func() error { return nil }); err == nil {
		t.Fatal("empty lock path accepted")
	}
	// The spill path is a directory: the append fails after the lock.
	dir2 := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir2, SpillFileName), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := SpillFileIn(dir2).Append([]Event{{SandboxID: "sb"}}); err == nil {
		t.Fatal("spill-as-directory accepted")
	}
	// The audit directory cannot be created (a file is in the way).
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SpillFileIn(filepath.Join(blocker, "audit")).Append([]Event{{SandboxID: "sb"}}); err == nil {
		t.Fatal("mkdir through a file accepted")
	}
	ran := false
	if err := WithFileLock(filepath.Join(dir2, LockFileName), func() error { ran = true; return errors.New("inner") }); err == nil || !ran {
		t.Fatalf("lock did not run fn or propagate its error: ran=%v err=%v", ran, err)
	}
}
