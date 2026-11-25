package service

import (
	"bytes"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// auditLines counts the records chained into the audit log.
func auditLines(t *testing.T, s *fileAuditSink) int {
	t.Helper()
	out, err := os.ReadFile(s.path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Count(string(out), "\n")
}

// A worker that kept its handle on its spill segment can still write to it
// once the drain has claimed it. The drain reads what was there at the
// claim and no more: it neither chains what came later nor follows a
// writer that never stops, which would hold every audit write on the node.
func TestDrainStopsAtClaimedSize(t *testing.T) {
	s, _ := workerSpillSink(t)
	f, err := os.OpenFile(s.workerSpillPath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var early bytes.Buffer
	for i := range 2000 {
		early.Write(gapLine(t, "early-"+strconv.Itoa(i)))
	}
	if _, err := f.Write(early.Bytes()); err != nil {
		t.Fatal(err)
	}
	const perChunk = 512
	lateLine := gapLine(t, "late")
	chunk := bytes.Repeat(lateLine, perChunk)
	working := s.spillWorkingPath
	if working == "" {
		working = s.spillPath + ".working"
	}
	// claimed is the size the drain kept at the claim, read back from its
	// file. The drain measures it right after the rename, so whatever the
	// writer got in between is inside it. That gap has no fixed length: on
	// a busy machine the writer can add many MiB while the drain waits to
	// run. So the bound comes from the size the drain kept, not from a
	// guess of a chunk or two, which failed on CI runners.
	var claimed atomic.Int64
	claimed.Store(-1)
	readClaim := func() {
		if claimed.Load() >= 0 {
			return
		}
		raw, err := os.ReadFile(working + spillSizeSuffix)
		if err != nil {
			return
		}
		if n, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64); err == nil {
			claimed.Store(n)
		}
	}
	var stop atomic.Bool
	var late atomic.Int64
	writer := make(chan struct{})
	go func() {
		defer close(writer)
		// Write on through the old handle once the drain has claimed the
		// segment (renamed it away), as fast as it can; bounded, so a
		// drain that follows it still ends.
		for !stop.Load() {
			if _, err := os.Lstat(s.workerSpillPath); os.IsNotExist(err) {
				break
			}
			time.Sleep(20 * time.Microsecond)
		}
		for !stop.Load() && late.Load() < 48<<20 {
			readClaim()
			n, err := f.Write(chunk)
			if err != nil {
				return
			}
			late.Add(int64(n))
		}
		for !stop.Load() && claimed.Load() < 0 {
			readClaim()
			time.Sleep(20 * time.Microsecond)
		}
	}()
	start := time.Now()
	s.drainSpill()
	took := time.Since(start)
	stop.Store(true)
	<-writer
	// The late lines inside the claim. If the writer never saw the size
	// file (the drain had already removed it), all it wrote bounds them.
	inClaim := late.Load()
	if n := claimed.Load(); n >= 0 {
		inClaim = max(n-int64(early.Len()), 0)
	}
	// +1: a line cut by the claim's end is chained as one gap record.
	limit := 2000 + int(inClaim/int64(len(lateLine))) + 1
	if got := auditLines(t, s); got < 2000 || got > limit {
		t.Fatalf("%d records chained, want 2000 to %d: the drain chained past the size kept at the claim (claim %d bytes, %d MiB written after the rename, drain took %v)",
			got, limit, claimed.Load(), late.Load()>>20, took)
	}
	// The writer wrote far more than the claim holds: had the drain read
	// on to the end of the file, it would have chained past the limit.
	if late.Load() < inClaim+int64(len(chunk)) {
		t.Logf("the writer added nothing after the claim this run (claim %d bytes, %d bytes written)", claimed.Load(), late.Load())
	}
}

// The size kept at the claim bounds a drain that resumes after a crash, and
// a claim from before that rule is bounded by the size found on resume.
func TestDrainResumesWithinClaimedSize(t *testing.T) {
	s, _ := workerSpillSink(t)
	working := s.spillWorkingPath
	two := append(gapLine(t, "one"), gapLine(t, "two")...)
	cov96aWrite(t, working, append(append([]byte{}, two...), gapLine(t, "after-the-claim")...))
	cov96aWrite(t, working+".size", []byte(strconv.Itoa(len(two))+"\n"))
	for s.drainSpill() {
	}
	if got := auditLines(t, s); got != 2 {
		t.Fatalf("%d records chained, want the 2 inside the claim", got)
	}
	for _, p := range []string{working, working + ".size"} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("%s left behind: %v", p, err)
		}
	}
}
