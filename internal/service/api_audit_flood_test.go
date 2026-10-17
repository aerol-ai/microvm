package service

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/auditlog"
)

// floodClock is the controllable clock the flood tests drive: budgets,
// merge windows and marker delays are all decided on it, never on sleeps.
type floodClock struct{ t time.Time }

func (c *floodClock) now() time.Time          { return c.t }
func (c *floodClock) advance(d time.Duration) { c.t = c.t.Add(d) }
func newFloodClock() *floodClock {
	return &floodClock{t: time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC)}
}
func callerTok(id string) *auditlog.Caller {
	return &auditlog.Caller{Kind: "token", ID: id, Team: "payments"}
}
func floodControl(mode apiFloodMode, rate float64, burst int, c *floodClock) *apiFloodControl {
	fc := newAPIFloodControl(mode, rate, burst, 5*time.Second)
	fc.now = c.now
	return fc
}

// apiCall is one exec-like api record by caller on sandbox; digest tells
// commands apart.
func apiCall(sandbox, caller, route, digest string, status int) auditlog.Event {
	return auditlog.Event{
		Kind: auditlog.KindAPI, SandboxID: sandbox, Ref: "POST " + route, Result: auditlog.APIResultForStatus(status),
		Caller:  callerTok(caller),
		Request: &auditlog.Request{Method: "POST", Route: route, Status: status, Digest: digest},
	}
}

// feed runs events through absorb and returns the ones written now.
func feed(fc *apiFloodControl, evs ...auditlog.Event) []auditlog.Event {
	var kept []auditlog.Event
	for _, ev := range evs {
		if !fc.absorb(ev) {
			kept = append(kept, ev)
		}
	}
	return kept
}

func repeat(n int, mk func(i int) auditlog.Event) []auditlog.Event {
	out := make([]auditlog.Event, n)
	for i := range out {
		out[i] = mk(i)
	}
	return out
}

const execRoute = "/v1/sandboxes/{id}/toolbox/{path...}"

// TestAPIFloodBudget is the D14 budget table: burst then refill per
// (sandbox, caller), one rate_limited record naming the caller, the count
// and the routes, secret opens and sandbox-less records never charged, and
// one caller's flood never spending another's budget.
func TestAPIFloodBudget(t *testing.T) {
	t.Run("burst, then refill", func(t *testing.T) {
		clk := newFloodClock()
		fc := floodControl(apiFloodBudget, 1, 3, clk)
		kept := feed(fc, repeat(5, func(i int) auditlog.Event { return apiCall("sb-1", "tok_a", execRoute, fmt.Sprint(i), 200) })...)
		if len(kept) != 3 {
			t.Fatalf("burst of 3 kept %d of 5", len(kept))
		}
		clk.advance(2 * time.Second)
		kept = feed(fc, repeat(3, func(i int) auditlog.Event { return apiCall("sb-1", "tok_a", execRoute, "x", 200) })...)
		if len(kept) != 2 {
			t.Fatalf("after 2s at 1/s, kept %d of 3, want 2", len(kept))
		}
	})

	t.Run("one rate_limited record names the caller, the count and the routes", func(t *testing.T) {
		clk := newFloodClock()
		fc := floodControl(apiFloodBudget, 1, 1, clk)
		feed(fc,
			apiCall("sb-1", "tok_a", execRoute, "1", 200),
			apiCall("sb-1", "tok_a", execRoute, "2", 200),
			apiCall("sb-1", "tok_a", "/v1/sandboxes/{id}/stop", "", 200),
			apiCall("sb-1", "tok_a", execRoute, "3", 403),
		)
		if m := fc.owed(false); len(m) != 0 {
			t.Fatalf("marker before the delay: %+v", m)
		}
		clk.advance(5 * time.Second)
		markers := fc.owed(false)
		if len(markers) != 1 {
			t.Fatalf("markers = %+v, want one", markers)
		}
		m := markers[0]
		if m.Kind != auditlog.KindAPI || m.Reason != auditlog.ReasonRateLimited || m.Dropped != 3 || m.SandboxID != "sb-1" {
			t.Fatalf("marker = %+v", m)
		}
		if m.Caller == nil || m.Caller.ID != "tok_a" || m.Caller.Team != "payments" {
			t.Fatalf("marker caller = %+v", m.Caller)
		}
		if want := []string{"POST /v1/sandboxes/{id}/stop", "POST " + execRoute}; !reflect.DeepEqual(m.Request.Routes, want) {
			t.Fatalf("marker routes = %v, want %v", m.Request.Routes, want)
		}
		if m.Result != auditlog.APIResultDenied {
			t.Fatalf("a marker standing for a refused call says result %q, want denied", m.Result)
		}
		if again := fc.owed(true); len(again) != 0 {
			t.Fatalf("a marker is owed once: %+v", again)
		}
	})

	t.Run("secret opens, gap markers and sandbox-less records are never charged", func(t *testing.T) {
		clk := newFloodClock()
		fc := floodControl(apiFloodBudget, 1, 1, clk)
		exempt := []auditlog.Event{
			{Kind: "secret_open", SandboxID: "sb-1", Result: "success"},
			{Kind: "secret_open", SandboxID: "sb-1", Result: "success"},
			{Kind: "gap", Result: "gap", Dropped: 4},
			{Kind: auditlog.KindAPI, Result: auditlog.APIResultOK, Caller: callerTok("tok_admin"), Request: &auditlog.Request{Method: "POST", Route: "/v1/tokens"}},
			{Kind: auditlog.KindAPI, Result: auditlog.APIResultOK, Caller: callerTok("tok_admin"), Request: &auditlog.Request{Method: "POST", Route: "/v1/tokens"}},
			{Kind: auditlog.KindAPI, SandboxID: "sb-1", Reason: auditlog.ReasonRateLimited, Dropped: 2},
		}
		if kept := feed(fc, exempt...); len(kept) != len(exempt) {
			t.Fatalf("kept %d of %d exempt records", len(kept), len(exempt))
		}
	})

	t.Run("per-caller isolation", func(t *testing.T) {
		clk := newFloodClock()
		fc := floodControl(apiFloodBudget, 1, 2, clk)
		feed(fc, repeat(50, func(i int) auditlog.Event { return apiCall("sb-1", "tok_flood", execRoute, fmt.Sprint(i), 200) })...)
		kept := feed(fc, apiCall("sb-1", "tok_quiet", execRoute, "a", 200), apiCall("sb-1", "tok_quiet", execRoute, "b", 200))
		if len(kept) != 2 {
			t.Fatalf("a flood by one caller spent another's budget: kept %d of 2", len(kept))
		}
		other := feed(fc, apiCall("sb-2", "tok_flood", execRoute, "a", 200))
		if len(other) != 1 {
			t.Fatal("a flood on one sandbox spent the caller's budget on another")
		}
	})

	t.Run("idle buckets are swept", func(t *testing.T) {
		clk := newFloodClock()
		fc := floodControl(apiFloodBudget, 1, 1, clk)
		feed(fc, apiCall("sb-1", "tok_a", execRoute, "1", 200))
		clk.advance(egressQuotaIdleTTL + egressQuotaSweepEvery + time.Second)
		fc.owed(false)
		if len(fc.buckets) != 0 {
			t.Fatalf("buckets after idle TTL = %d", len(fc.buckets))
		}
	})
}

// TestAPIFloodCoalesce is the coalesce table: identical calls in one
// second become one record with a count; anything that tells two calls
// apart (digest, caller, status, sandbox, route) keeps them apart; and
// there is no cap.
func TestAPIFloodCoalesce(t *testing.T) {
	cases := []struct {
		name      string
		calls     []auditlog.Event
		wantCount []int64 // request.count per written record, oldest first; 0 = one call
	}{
		{
			name:      "identical calls merge",
			calls:     repeat(40, func(int) auditlog.Event { return apiCall("sb-1", "tok_a", execRoute, "d1", 200) }),
			wantCount: []int64{40},
		},
		{
			name: "different digests never merge",
			calls: []auditlog.Event{
				apiCall("sb-1", "tok_a", execRoute, "ls", 200),
				apiCall("sb-1", "tok_a", execRoute, "rm", 200),
				apiCall("sb-1", "tok_a", execRoute, "ls", 200),
			},
			wantCount: []int64{2, 0},
		},
		{
			name:      "different callers never merge",
			calls:     []auditlog.Event{apiCall("sb-1", "tok_a", execRoute, "d", 200), apiCall("sb-1", "tok_b", execRoute, "d", 200)},
			wantCount: []int64{0, 0},
		},
		{
			name:      "different status never merge",
			calls:     []auditlog.Event{apiCall("sb-1", "tok_a", execRoute, "d", 200), apiCall("sb-1", "tok_a", execRoute, "d", 500)},
			wantCount: []int64{0, 0},
		},
		{
			name:      "different sandboxes never merge",
			calls:     []auditlog.Event{apiCall("sb-1", "tok_a", execRoute, "d", 200), apiCall("sb-2", "tok_a", execRoute, "d", 200)},
			wantCount: []int64{0, 0},
		},
		{
			name: "no cap: a flood of different commands is all written",
			calls: repeat(300, func(i int) auditlog.Event {
				return apiCall("sb-1", "tok_a", execRoute, fmt.Sprint(i), 200)
			}),
			wantCount: make([]int64, 300),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clk := newFloodClock()
			fc := floodControl(apiFloodCoalesce, 1, 1, clk)
			if kept := feed(fc, tc.calls...); len(kept) != 0 {
				t.Fatalf("coalesce wrote %d calls at once; it holds them for the window", len(kept))
			}
			if early := fc.dueMerged(); len(early) != 0 {
				t.Fatalf("written before the window closed: %d", len(early))
			}
			clk.advance(apiCoalesceWindow)
			got := fc.dueMerged()
			if len(got) != len(tc.wantCount) {
				t.Fatalf("wrote %d records, want %d", len(got), len(tc.wantCount))
			}
			for i, ev := range got {
				if ev.Request.Count != tc.wantCount[i] {
					t.Fatalf("record %d count = %d, want %d", i, ev.Request.Count, tc.wantCount[i])
				}
			}
			if m := fc.owed(true); len(m) != 0 {
				t.Fatalf("coalesce alone never rate-limits: %+v", m)
			}
		})
	}

	t.Run("a call after the window starts a new record", func(t *testing.T) {
		clk := newFloodClock()
		fc := floodControl(apiFloodCoalesce, 1, 1, clk)
		feed(fc, apiCall("sb-1", "tok_a", execRoute, "d", 200), apiCall("sb-1", "tok_a", execRoute, "d", 200))
		clk.advance(apiCoalesceWindow)
		first := fc.dueMerged()
		feed(fc, apiCall("sb-1", "tok_a", execRoute, "d", 200))
		second := fc.owed(true) // Sync and shutdown flush what is pending
		if len(first) != 1 || first[0].Request.Count != 2 || len(second) != 1 || second[0].Request.Count != 0 {
			t.Fatalf("first %+v second %+v", first, second)
		}
	})

	t.Run("the pending cap writes a call on its own rather than lose it", func(t *testing.T) {
		clk := newFloodClock()
		fc := floodControl(apiFloodCoalesce, 1, 1, clk)
		feed(fc, repeat(apiCoalesceMaxPending, func(i int) auditlog.Event { return apiCall("sb-1", "tok_a", execRoute, fmt.Sprint(i), 200) })...)
		if kept := feed(fc, apiCall("sb-1", "tok_a", execRoute, "over", 200)); len(kept) != 1 {
			t.Fatal("a call past the pending cap must be written, not held or dropped")
		}
	})
}

// TestAPIFloodBoth: coalesce first, then the budget. Identical calls cost
// one token for their merged record; a flood of different commands is
// bounded and summarised.
func TestAPIFloodBoth(t *testing.T) {
	clk := newFloodClock()
	fc := floodControl(apiFloodBoth, 1, 3, clk)
	feed(fc, repeat(100, func(int) auditlog.Event { return apiCall("sb-1", "tok_a", execRoute, "same", 200) })...)
	for i := 0; i < 10; i++ {
		clk.advance(time.Millisecond)
		feed(fc, apiCall("sb-1", "tok_a", execRoute, fmt.Sprint(i), 200))
	}
	clk.advance(apiCoalesceWindow)
	written := fc.dueMerged()
	// Eleven merged records (one for the 100 identical calls, ten distinct)
	// against a burst of 3: the identical calls cost one token between them.
	if len(written) != 3 || written[0].Request.Count != 100 || written[1].Request.Count != 0 {
		t.Fatalf("wrote %d records, want 3 with the 100 identical calls merged into the first", len(written))
	}
	clk.advance(5 * time.Second)
	markers := fc.owed(false)
	if len(markers) != 1 || markers[0].Dropped != 8 || markers[0].Caller.ID != "tok_a" {
		t.Fatalf("markers = %+v, want one rate_limited record for the 8 records over budget", markers)
	}

	t.Run("a merged record over budget counts every call it stood for", func(t *testing.T) {
		clk := newFloodClock()
		fc := floodControl(apiFloodBoth, 1, 1, clk)
		feed(fc, apiCall("sb-1", "tok_a", execRoute, "x", 200))
		clk.advance(time.Millisecond)
		feed(fc, repeat(20, func(int) auditlog.Event { return apiCall("sb-1", "tok_a", execRoute, "y", 200) })...)
		clk.advance(apiCoalesceWindow)
		written := fc.dueMerged()
		clk.advance(5 * time.Second)
		markers := fc.owed(false)
		if len(written) != 1 || written[0].Request.Digest != "x" || len(markers) != 1 || markers[0].Dropped != 20 {
			t.Fatalf("written %+v, markers %+v; want x written and the 20 merged y calls counted", written, markers)
		}
	})
}

func TestEffectiveAPIFloodMode(t *testing.T) {
	cases := []struct {
		configured apiFloodMode
		owners     int
		want       apiFloodMode
	}{
		{apiFloodBudget, 0, apiFloodBudget},
		{apiFloodBudget, 5, apiFloodBudget},
		{apiFloodBoth, 1, apiFloodBoth},
		{apiFloodCoalesce, 0, apiFloodCoalesce},
		{apiFloodCoalesce, 1, apiFloodCoalesce},
		{apiFloodCoalesce, 2, apiFloodBoth},
	}
	for _, c := range cases {
		if got := effectiveAPIFloodMode(c.configured, c.owners); got != c.want {
			t.Errorf("effective(%s, %d owners) = %s, want %s", c.configured, c.owners, got, c.want)
		}
	}
	for raw, want := range map[string]apiFloodMode{
		"": apiFloodBudget, "budget": apiFloodBudget, " Coalesce ": apiFloodCoalesce, "both": apiFloodBoth, "nonsense": apiFloodBudget,
	} {
		if got := parseAPIFloodMode(raw); got != want {
			t.Errorf("parse(%q) = %s, want %s", raw, got, want)
		}
	}
	if apiFloodMode(0).String() != config.AuditAPIFloodBudget {
		t.Error("an unset mode reads as the default")
	}
	var nilControl *apiFloodControl
	nilControl.setMode(apiFloodBoth)
	if nilControl.currentMode() != 0 || nilControl.absorb(apiCall("sb", "t", execRoute, "", 200)) || nilControl.owed(true) != nil || nilControl.dueMerged() != nil {
		t.Error("a nil control writes everything and owes nothing")
	}
}

// TestSpillOverflowAppliesAPIFlood: in enterprise mode a full queue sends
// records down the in-process overflow path, which is exactly when a flood
// is happening; the budget applies there too.
func TestSpillOverflowAppliesAPIFlood(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, secretAuditFileName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	clk := newFloodClock()
	sink := &fileAuditSink{
		file:     f,
		path:     path,
		lockPath: auditlog.SpillFileIn(dir).LockPath,
		gapPath:  filepath.Join(dir, "secrets.gap"),
		spillCh:  make(chan SecretAuditEvent, 64),
		apiFlood: floodControl(apiFloodBudget, 1, 2, clk),
	}
	for i := 0; i < 9; i++ {
		sink.spillCh <- apiCall("sb-1", "tok_flood", execRoute, fmt.Sprint(i), 200)
	}
	sink.spillQueued(apiCall("sb-1", "tok_flood", execRoute, "first", 200))
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(raw), "\n"); n != 2 {
		t.Fatalf("overflow wrote %d records, want the burst of 2", n)
	}
	// A batch the budget takes entirely writes nothing.
	sink.spillQueued(apiCall("sb-1", "tok_flood", execRoute, "again", 200))
	if again, _ := os.ReadFile(path); len(again) != len(raw) {
		t.Fatal("a fully budgeted overflow batch wrote records")
	}
	clk.advance(5 * time.Second)
	if m := sink.apiFlood.owed(false); len(m) != 1 || m[0].Dropped != 9 {
		t.Fatalf("markers = %+v, want one for the 9 over budget", m)
	}
}
