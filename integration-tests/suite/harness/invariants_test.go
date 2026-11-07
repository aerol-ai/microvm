package harness

import (
	"fmt"
	"strings"
	"sync"
	"testing"
)

// recordingTB captures what an Invariants writes, so its verdict logic is
// tested without failing the real test. Only the methods Invariants calls are
// implemented; the embedded nil TB makes any other call panic loudly.
type recordingTB struct {
	testing.TB
	mu       sync.Mutex
	errors   []string
	logs     []string
	cleanups []func()
}

func (r *recordingTB) Helper() {}
func (r *recordingTB) Errorf(format string, args ...any) {
	r.mu.Lock()
	r.errors = append(r.errors, fmt.Sprintf(format, args...))
	r.mu.Unlock()
}
func (r *recordingTB) Log(args ...any) { r.logs = append(r.logs, fmt.Sprint(args...)) }
func (r *recordingTB) Cleanup(f func()) {
	r.cleanups = append(r.cleanups, f)
}

func (r *recordingTB) runCleanups() {
	for i := len(r.cleanups) - 1; i >= 0; i-- {
		r.cleanups[i]()
	}
}

func TestInvariantVerdicts(t *testing.T) {
	rt := &recordingTB{}
	iv := TrackInvariants(rt, "I1", "I7", "I3")
	iv.Hold("I1", "max 1 running copy over %d samples", 40)
	iv.Violate("I7", "cut-off ingress served the old copy at +%ds", 41)
	iv.Hold("I7", "this evidence must not clear the violation")
	rt.runCleanups()

	got := map[string]InvariantResult{}
	for _, line := range rt.logs {
		r, ok := ParseInvariantMarker(line)
		if !ok {
			t.Fatalf("emitted line is not a marker: %q", line)
		}
		got[r.ID] = r
	}
	if r := got["I1"]; r.Result != InvariantHeld || r.Detail != "max 1 running copy over 40 samples" {
		t.Errorf("I1 = %+v, want held with its evidence", r)
	}
	if r := got["I7"]; r.Result != InvariantViolated || !strings.Contains(r.Detail, "+41s") {
		t.Errorf("I7 = %+v, want violated naming the violation (a later Hold must not clear it)", r)
	}
	if r := got["I3"]; r.Result != InvariantNotExercised {
		t.Errorf("I3 = %+v, want not-exercised: nothing was recorded for it", r)
	}
	if len(rt.errors) != 1 || !strings.HasPrefix(rt.errors[0], "I7 violated: ") {
		t.Errorf("Violate must fail the test once, naming the invariant: %q", rt.errors)
	}
	// Order is the order the case named them, so the report reads the same
	// way on every run.
	var order []string
	for _, line := range rt.logs {
		r, _ := ParseInvariantMarker(line)
		order = append(order, r.ID)
	}
	if strings.Join(order, ",") != "I1,I7,I3" {
		t.Errorf("marker order = %v, want I1,I7,I3", order)
	}
}

func TestInvariantViolationDetailsAreCapped(t *testing.T) {
	rt := &recordingTB{}
	iv := TrackInvariants(rt, "I1")
	for i := 0; i < maxViolationDetails+4; i++ {
		iv.Violate("I1", "copy %d", i)
	}
	if !iv.Violated("I1") || iv.Violated("I2") {
		t.Fatal("Violated must report I1 and not an untracked id")
	}
	res := iv.Results()
	if len(res) != 1 || !strings.HasSuffix(res[0].Detail, "; and 4 more") {
		t.Errorf("detail = %q, want the first %d and a count of the rest", res[0].Detail, maxViolationDetails)
	}
	if len(rt.errors) != maxViolationDetails+4 {
		t.Errorf("every violation must reach the test log, got %d", len(rt.errors))
	}
}

func TestInvariantViolateIsSafeAcrossGoroutines(t *testing.T) {
	rt := &recordingTB{}
	iv := TrackInvariants(rt, "I4")
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			iv.Violate("I4", "worker %d over budget", i)
		}(i)
	}
	wg.Wait()
	if len(rt.errors) != 32 {
		t.Errorf("got %d errors, want 32", len(rt.errors))
	}
}

func TestInvariantMarkerRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		in   InvariantResult
		line string
	}{
		{"held with detail", InvariantResult{ID: "I6", Result: InvariantHeld, Detail: "converged in 41s"}, "invariant=I6 held: converged in 41s"},
		{"no detail", InvariantResult{ID: "I8", Result: InvariantNotExercised}, "invariant=I8 not-exercised"},
		{"multi-line detail is flattened", InvariantResult{ID: "I1", Result: InvariantViolated, Detail: "two copies\n  on worker-1 and worker-2"}, "invariant=I1 violated: two copies on worker-1 and worker-2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			line := FormatInvariantMarker(tt.in)
			if line != tt.line {
				t.Fatalf("format = %q, want %q", line, tt.line)
			}
			// go test prefixes t.Log output with the file and line.
			got, ok := ParseInvariantMarker("    invariants.go:171: " + line + "\n")
			if !ok {
				t.Fatalf("parse(%q) failed", line)
			}
			want := tt.in
			want.Detail = strings.Join(strings.Fields(want.Detail), " ")
			if got != want {
				t.Fatalf("parse = %+v, want %+v", got, want)
			}
		})
	}
	for _, bad := range []string{"ucid=UC-470", "invariant=X1 held", "invariant=I1 maybe", "I1 held"} {
		if _, ok := ParseInvariantMarker(bad); ok {
			t.Errorf("ParseInvariantMarker(%q) accepted a non-marker", bad)
		}
	}
}
