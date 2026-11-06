package service

import (
	"fmt"
	"slices"
	"testing"
)

func TestSweepRetryWait(t *testing.T) {
	for failures, want := range map[int]uint64{0: 1, 1: 1, 2: 2, 3: 4, 4: 8, 5: 8, 40: 8} {
		if got := sweepRetryWait(failures); got != want {
			t.Fatalf("sweepRetryWait(%d) = %d, want %d", failures, got, want)
		}
	}
}

// TestSweepRotationReachesEveryRecord: with room for k tries a pass and the
// first records failing every time, every record is tried within
// ceil(n/k) passes. Without the rotation each pass tried the same first k.
func TestSweepRotationReachesEveryRecord(t *testing.T) {
	var r sweepRotation
	var ids []string
	for i := 0; i < 41; i++ {
		ids = append(ids, fmt.Sprintf("sb-%02d", i))
	}
	const perPass = 8
	tried := map[string]int{}
	for pass := 1; pass <= 6; pass++ {
		order := r.plan(ids)
		for _, id := range order[:min(perPass, len(order))] {
			r.tried(id)
			tried[id]++
			// Cut short by the pass's deadline: tried, not failed.
		}
	}
	for _, id := range ids {
		if tried[id] == 0 {
			t.Fatalf("%s never tried in 6 passes of %d", id, perPass)
		}
	}
}

// TestSweepRotationBacksOffFailures: a record that keeps failing is tried
// on passes 1, 2, 4, 8, 16, 24 (waits of 1, 2, 4, then 8), one that
// succeeds every pass, and a success resets the wait.
func TestSweepRotationBacksOffFailures(t *testing.T) {
	var r sweepRotation
	ids := []string{"bad", "good"}
	var badPasses []int
	for pass := 1; pass <= 24; pass++ {
		for _, id := range r.plan(ids) {
			r.tried(id)
			if id == "bad" {
				badPasses = append(badPasses, pass)
			}
			r.done(id, id == "good")
		}
	}
	if want := []int{1, 2, 4, 8, 16, 24}; !slices.Equal(badPasses, want) {
		t.Fatalf("failing record tried on passes %v, want %v", badPasses, want)
	}
	// One success and it is asked every pass again.
	r.done("bad", true)
	for i := 0; i < 3; i++ {
		if order := r.plan(ids); !slices.Contains(order, "bad") {
			t.Fatalf("after a success, pass %d left it out: %v", i, order)
		}
	}
}

// TestSweepRotationOrderAndForget: least recently tried first, the caller's
// order between equals, a repeated id once, and records with no work any
// more are forgotten (a later one starts afresh).
func TestSweepRotationOrderAndForget(t *testing.T) {
	var r sweepRotation
	if got := r.plan([]string{"a", "b", "c", "a"}); !slices.Equal(got, []string{"a", "b", "c"}) {
		t.Fatalf("first pass = %v", got)
	}
	r.tried("a")
	r.tried("b")
	if got := r.plan([]string{"a", "b", "c"}); !slices.Equal(got, []string{"c", "a", "b"}) {
		t.Fatalf("second pass = %v, want the untried one first", got)
	}
	r.tried("c")
	r.done("c", false)
	// "c" leaves the work list: its failure is forgotten.
	r.plan([]string{"a", "b"})
	r.mu.Lock()
	_, kept := r.records["c"]
	r.mu.Unlock()
	if kept {
		t.Fatal("a record with no work was kept")
	}
	if got := r.plan([]string{"c", "a"}); !slices.Contains(got, "c") || got[0] != "c" {
		t.Fatalf("a returning record = %v, want it first and due", got)
	}
	// done on a zero rotation is safe; a first failure waits one pass,
	// which is the next one.
	var z sweepRotation
	z.done("x", false)
	z.done("x", false)
	if got := z.plan([]string{"x"}); len(got) != 0 {
		t.Fatalf("a record that failed twice = %v, want it to wait a pass", got)
	}
	if got := z.plan([]string{"x"}); !slices.Equal(got, []string{"x"}) {
		t.Fatalf("after its wait = %v", got)
	}
}
