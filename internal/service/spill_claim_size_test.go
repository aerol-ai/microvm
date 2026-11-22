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
	chunk := bytes.Repeat(gapLine(t, "late"), perChunk)
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
			n, err := f.Write(chunk)
			if err != nil {
				return
			}
			late.Add(int64(n))
		}
	}()
	start := time.Now()
	s.drainSpill()
	took := time.Since(start)
	stop.Store(true)
	<-writer
	if took > 5*time.Second {
		t.Fatalf("the drain followed the writer for %v (%d MiB written behind the claim)", took, late.Load()>>20)
	}
	// The claim's size is taken right after the rename: a chunk or two the
	// writer got in between are inside it, the rest is not.
	if got := auditLines(t, s); got < 2000 || got > 2000+2*perChunk {
		t.Fatalf("%d records chained, want the 2000 there before the claim (%d MiB written after)", got, late.Load()>>20)
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
