package harness

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// Invariant results for the cluster-correctness use cases
// (plans/cluster-correctness-and-create-latency.md §1, I1..I8).
//
// A chaos case passing says little on its own: "no error" is what a case
// that never injected its fault also reports. So each case names the
// invariants it checks, records every violation as it sees it, and records
// the evidence that an invariant held (how many samples, how long). The
// verdicts reach the report as one marker line per invariant, which
// report/gen.go joins to the use case the same way it joins the ucid=
// marker: the line is the only channel from a flat-named test to its row.

// Invariant verdicts as they appear in the marker and in reports/*.json.
const (
	InvariantHeld         = "held"
	InvariantViolated     = "violated"
	InvariantNotExercised = "not-exercised"
)

// InvariantResult is one invariant's verdict for one use case.
type InvariantResult struct {
	ID     string `json:"id"`
	Result string `json:"result"`
	Detail string `json:"detail,omitempty"`
}

// invariantMarkerRE matches the line Invariants.emit logs. Keep the
// "invariant=" prefix in sync with FormatInvariantMarker; report/gen.go
// parses with ParseInvariantMarker, so the two cannot drift apart.
var invariantMarkerRE = regexp.MustCompile(`invariant=(I[0-9]+) (held|violated|not-exercised)(?:: (.*))?$`)

// FormatInvariantMarker renders the one-line marker for a verdict. The
// detail is flattened to one line: go test -json splits output on
// newlines, and a second line would reach the report as a stray reason.
func FormatInvariantMarker(r InvariantResult) string {
	line := "invariant=" + r.ID + " " + r.Result
	if d := oneLine(r.Detail); d != "" {
		line += ": " + d
	}
	return line
}

// ParseInvariantMarker finds a marker anywhere in an output line (go test
// prefixes t.Logf output with "file.go:NN: ").
func ParseInvariantMarker(line string) (InvariantResult, bool) {
	m := invariantMarkerRE.FindStringSubmatch(strings.TrimRight(line, "\r\n"))
	if m == nil {
		return InvariantResult{}, false
	}
	return InvariantResult{ID: m[1], Result: m[2], Detail: strings.TrimSpace(m[3])}, true
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// maxViolationDetails caps how many violations one invariant keeps for its
// marker. The test log keeps all of them (each is a t.Errorf); the report
// cell only needs enough to say what broke.
const maxViolationDetails = 3

type invariantState struct {
	violations []string
	total      int
	held       string
}

// Invariants records the verdicts of the invariants one use case checks.
// Build it with TrackInvariants at the top of the case; the markers are
// logged from a t.Cleanup, so a case that stops early with t.Fatal still
// reports what it had checked, and the rest as not-exercised.
type Invariants struct {
	t     testing.TB
	mu    sync.Mutex
	order []string
	state map[string]*invariantState
}

// TrackInvariants starts recording the given invariant ids ("I1", "I7", ...)
// for t. Each id ends as violated (any Violate), held (a Hold and no
// Violate) or not-exercised (neither).
func TrackInvariants(t testing.TB, ids ...string) *Invariants {
	t.Helper()
	iv := &Invariants{t: t, state: map[string]*invariantState{}}
	for _, id := range ids {
		iv.ensure(id)
	}
	t.Cleanup(iv.emit)
	return iv
}

func (iv *Invariants) ensure(id string) *invariantState {
	st, ok := iv.state[id]
	if !ok {
		st = &invariantState{}
		iv.state[id] = st
		iv.order = append(iv.order, id)
	}
	return st
}

// Violate records a violation of id and fails the test with the message.
// Safe to call from several goroutines.
func (iv *Invariants) Violate(id, format string, args ...any) {
	iv.t.Helper()
	msg := fmt.Sprintf(format, args...)
	iv.mu.Lock()
	st := iv.ensure(id)
	st.total++
	if len(st.violations) < maxViolationDetails {
		st.violations = append(st.violations, oneLine(msg))
	}
	iv.mu.Unlock()
	iv.t.Errorf("%s violated: %s", id, msg)
}

// Hold records the evidence that id held (the last call wins). It does not
// clear a violation: one violation is the verdict however much evidence
// of holding follows it.
func (iv *Invariants) Hold(id, format string, args ...any) {
	iv.mu.Lock()
	iv.ensure(id).held = fmt.Sprintf(format, args...)
	iv.mu.Unlock()
}

// Violated reports whether id has any violation so far.
func (iv *Invariants) Violated(id string) bool {
	iv.mu.Lock()
	defer iv.mu.Unlock()
	st, ok := iv.state[id]
	return ok && st.total > 0
}

// Results returns the verdict of every tracked invariant, in the order they
// were first named.
func (iv *Invariants) Results() []InvariantResult {
	iv.mu.Lock()
	defer iv.mu.Unlock()
	out := make([]InvariantResult, 0, len(iv.order))
	for _, id := range iv.order {
		st := iv.state[id]
		r := InvariantResult{ID: id}
		switch {
		case st.total > 0:
			r.Result = InvariantViolated
			r.Detail = strings.Join(st.violations, "; ")
			if extra := st.total - len(st.violations); extra > 0 {
				r.Detail += fmt.Sprintf("; and %d more", extra)
			}
		case st.held != "":
			r.Result = InvariantHeld
			r.Detail = st.held
		default:
			r.Result = InvariantNotExercised
		}
		out = append(out, r)
	}
	return out
}

func (iv *Invariants) emit() {
	for _, r := range iv.Results() {
		iv.t.Log(FormatInvariantMarker(r))
	}
}
