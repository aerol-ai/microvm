package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/auditlog"
)

// send401 sends one request that must be refused with a 401.
func send401(t *testing.T, srv *Server, method, path, addr, bearer string) {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.RemoteAddr = addr
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("%s %s from %s = %d, want 401", method, path, addr, rec.Code)
	}
}

// refusals is how many 401s an auth_denied record stands for.
func refusals(ev auditlog.Event) int64 { return 1 + ev.Dropped }

// TestAuthDeniedBurstThenSilence: a source that sprays bad tokens inside
// one window and then stops is in the evidence at full volume. The first
// 401 is written at once; when the window closes, one more record carries
// the other burst-1, described by the last of them. Before, that second
// record was only written if the same address sent another 401 later.
func TestAuthDeniedBurstThenSilence(t *testing.T) {
	srv, sink, _ := auditServer(t, config.Config{})
	t0 := time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	now := t0
	srv.authDenied.now = func() time.Time { return now }

	const burst = 6
	for i := 0; i < burst-1; i++ {
		send401(t, srv, "POST", "/v1/sandboxes/sb-1/stop", "203.0.113.9:4000", "wrong")
	}
	// The last 401 of the burst differs, so the owed record shows it
	// describes the most recent one.
	send401(t, srv, "GET", "/v1/whoami", "203.0.113.9:4001", "")
	if got := sink.records(); len(got) != 1 || refusals(got[0]) != 1 {
		t.Fatalf("during the burst: %+v, want only the first 401's record", got)
	}

	now = t0.Add(authDeniedWindow - time.Second)
	srv.flushAuthDenied(false)
	if got := sink.records(); len(got) != 1 {
		t.Fatalf("flush inside the window wrote %d records, want 1", len(got))
	}

	now = t0.Add(authDeniedWindow)
	srv.flushAuthDenied(false)
	got := sink.records()
	if len(got) != 2 {
		t.Fatalf("after the window: %d records, want 2: %+v", len(got), got)
	}
	owed := got[1]
	if owed.Kind != auditlog.KindAuthDenied || owed.Caller != nil || owed.Request == nil ||
		owed.Request.Source != "203.0.113.9" || owed.Ref != "GET /v1/whoami" || owed.Request.Route != "/v1/whoami" ||
		owed.Request.Method != "GET" || owed.Request.Status != http.StatusUnauthorized || owed.Reason != "missing" ||
		refusals(owed) != burst-1 || owed.CorrelationID == "" {
		t.Fatalf("owed record = %+v (request %+v), want the last 401 standing for %d", owed, owed.Request, burst-1)
	}
	if total := refusals(got[0]) + refusals(got[1]); total != burst {
		t.Fatalf("records stand for %d refusals, want %d", total, burst)
	}

	// Nothing more is owed: a second flush in the window, or after it,
	// writes nothing, and the silent address is forgotten.
	srv.flushAuthDenied(false)
	now = t0.Add(2 * authDeniedWindow)
	srv.flushAuthDenied(false)
	if got := sink.records(); len(got) != 2 {
		t.Fatalf("idle flushes wrote more: %+v", got)
	}
	if n := len(srv.authDenied.sources); n != 0 {
		t.Fatalf("%d addresses kept after a silent window, want 0", n)
	}
	// The next 401 is a fresh record of one: nothing is counted twice.
	send401(t, srv, "GET", "/v1/whoami", "203.0.113.9:4002", "avm_expired")
	if got := sink.records(); len(got) != 3 || refusals(got[2]) != 1 || got[2].Reason != "expired" {
		t.Fatalf("after the address was forgotten: %+v", got)
	}
}

// TestAuthDeniedSteadyTrickle: an address that never stops (one 401 every
// 7 s, the flush ticking every 10 s, for 10 minutes) still gets one record
// per window, each standing for exactly the 401s since the one before, and
// together for every 401 sent.
func TestAuthDeniedSteadyTrickle(t *testing.T) {
	srv, sink, _ := auditServer(t, config.Config{})
	t0 := time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	now := t0
	srv.authDenied.now = func() time.Time { return now }

	var (
		sent, pending, total int64
		writtenAt            []time.Time
	)
	check := func(what string) {
		got := sink.records()
		if len(got) == len(writtenAt) {
			return
		}
		if len(got) != len(writtenAt)+1 {
			t.Fatalf("%s at %s wrote %d records, want at most 1", what, now.Sub(t0), len(got)-len(writtenAt))
		}
		ev := got[len(got)-1]
		if refusals(ev) != pending {
			t.Fatalf("%s at %s: record stands for %d, want the %d 401s since the last record", what, now.Sub(t0), refusals(ev), pending)
		}
		if n := len(writtenAt); n > 0 && now.Sub(writtenAt[n-1]) < authDeniedWindow {
			t.Fatalf("%s at %s: second record %s after the last, inside one window", what, now.Sub(t0), now.Sub(writtenAt[n-1]))
		}
		writtenAt = append(writtenAt, now)
		total += refusals(ev)
		pending = 0
	}
	for sec := 0; sec <= 600; sec++ {
		now = t0.Add(time.Duration(sec) * time.Second)
		if sec%10 == 0 {
			srv.flushAuthDenied(false)
			check("flush")
		}
		if sec%7 == 0 {
			send401(t, srv, "POST", "/v1/sandboxes/sb-1/stop", "198.51.100.20:5000", "wrong")
			sent++
			pending++
			check("401")
		}
	}
	srv.StopBackground()
	check("shutdown")
	// A record at 0 s opens the first window; each later one is the flush
	// at the tick that closes a window: 60 s, 120 s, ... 600 s.
	if len(writtenAt) != 11 {
		t.Fatalf("%d records over 10 minutes, want 11 (one per window)", len(writtenAt))
	}
	if total != sent {
		t.Fatalf("records stand for %d refusals, %d were sent", total, sent)
	}
}

// TestAuthDeniedFlushBoundsManySources: the flush keeps the disk bound under
// a spray from many addresses. Every address in the map owes a record when
// its window closes, but each gets one, a second flush in the same window
// writes nothing, an address past the cap stays unrecorded, and the map
// never grows past the cap. Once a window passes in silence the map
// empties, so a new address is recorded again (before, an address that owed
// a count kept its slot until it sent another 401).
func TestAuthDeniedFlushBoundsManySources(t *testing.T) {
	l := newAuthDeniedLimiter()
	t0 := time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	now := t0
	l.now = func() time.Time { return now }
	addr := func(i int) string { return fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255) }
	req := authDeniedRequest{method: "GET", route: "/v1/whoami", reason: "rejected"}

	for i := 0; i < authDeniedMaxSources; i++ {
		if ok, _ := l.admit(addr(i), req); !ok {
			t.Fatalf("address %d refused below the cap", i)
		}
		if ok, _ := l.admit(addr(i), req); ok {
			t.Fatalf("address %d recorded twice in one window", i)
		}
	}
	if ok, _ := l.admit("192.0.2.1", req); ok {
		t.Fatal("an address past the cap was recorded")
	}

	now = t0.Add(authDeniedWindow - time.Second)
	if owed := l.takeOwed(false); len(owed) != 0 {
		t.Fatalf("flush inside the window took %d records", len(owed))
	}

	now = t0.Add(authDeniedWindow)
	owed := l.takeOwed(false)
	if len(owed) != authDeniedMaxSources {
		t.Fatalf("flush took %d records, want one per address (%d)", len(owed), authDeniedMaxSources)
	}
	seen := make(map[string]bool, len(owed))
	for _, o := range owed {
		if seen[o.source] || o.source == "192.0.2.1" || o.count != 1 || o.req != req {
			t.Fatalf("owed record %+v (seen before: %v)", o, seen[o.source])
		}
		seen[o.source] = true
	}
	if n := len(l.sources); n > authDeniedMaxSources {
		t.Fatalf("map holds %d addresses, past the cap", n)
	}
	if owed := l.takeOwed(false); len(owed) != 0 {
		t.Fatalf("second flush in the window took %d records", len(owed))
	}

	// Each flushed address's next window runs from the flush: it holds its
	// slot until that window closes in silence.
	now = t0.Add(2*authDeniedWindow - time.Second)
	if ok, _ := l.admit("192.0.2.1", req); ok {
		t.Fatal("an address past the cap was recorded while every slot's window is open")
	}
	now = t0.Add(2 * authDeniedWindow)
	if owed := l.takeOwed(false); len(owed) != 0 || len(l.sources) != 0 {
		t.Fatalf("after a silent window: took %d, kept %d addresses", len(owed), len(l.sources))
	}
	if ok, n := l.admit("192.0.2.1", req); !ok || n != 1 {
		t.Fatalf("a new address after the map emptied: %v %d", ok, n)
	}
}

// TestAuthDeniedStopBackgroundFlushesOwed: a graceful shutdown writes what
// is still owed, window closed or not, and writes nothing for an address
// that owes nothing. Stopping twice writes nothing more, and starting after
// a stop starts nothing.
func TestAuthDeniedStopBackgroundFlushesOwed(t *testing.T) {
	srv, sink, _ := auditServer(t, config.Config{})
	t0 := time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	now := t0
	srv.authDenied.now = func() time.Time { return now }

	for i := 0; i < 3; i++ {
		send401(t, srv, "POST", "/v1/sandboxes/sb-1/stop", "203.0.113.9:4000", "avm_bad")
	}
	send401(t, srv, "POST", "/v1/sandboxes/sb-1/stop", "203.0.113.10:4000", "wrong")
	now = t0.Add(5 * time.Second)
	srv.StopBackground()
	got := sink.records()
	if len(got) != 3 {
		t.Fatalf("after shutdown: %d records, want 3: %+v", len(got), got)
	}
	last := got[2]
	if last.Request.Source != "203.0.113.9" || refusals(last) != 2 || last.Reason != "malformed" {
		t.Fatalf("shutdown record = %+v (request %+v), want the 2 folded 401s from 203.0.113.9", last, last.Request)
	}
	send401(t, srv, "POST", "/v1/sandboxes/sb-1/stop", "203.0.113.9:4000", "avm_bad")
	srv.StopBackground()
	srv.StartBackground(context.Background())
	if got := sink.records(); len(got) != 3 || srv.bgStop != nil {
		t.Fatalf("second stop or start after stop acted: %d records, loop %v", len(got), srv.bgStop != nil)
	}
}

// TestAuthDeniedFlushLoop drives the real loop: with the clock past the
// window the loop writes the owed record on its own, StopBackground ends the
// goroutine, and a loop ended by its context still leaves the final flush to
// StopBackground.
func TestAuthDeniedFlushLoop(t *testing.T) {
	t0 := time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	start := func(t *testing.T, ctx context.Context) (*Server, *recSink, *atomic.Int64) {
		srv, sink, _ := auditServer(t, config.Config{})
		var clock atomic.Int64
		clock.Store(t0.UnixNano())
		srv.authDenied.now = func() time.Time { return time.Unix(0, clock.Load()) }
		srv.authDenied.flushEvery = time.Millisecond
		srv.StartBackground(ctx)
		srv.StartBackground(ctx) // a second start is a no-op
		t.Cleanup(srv.StopBackground)
		return srv, sink, &clock
	}
	closed := func(ch chan struct{}) bool {
		select {
		case <-ch:
			return true
		case <-time.After(5 * time.Second):
			return false
		}
	}

	t.Run("tick writes the owed record", func(t *testing.T) {
		srv, sink, clock := start(t, context.Background())
		send401(t, srv, "GET", "/v1/whoami", "203.0.113.9:4000", "wrong")
		send401(t, srv, "GET", "/v1/whoami", "203.0.113.9:4000", "wrong")
		clock.Add(int64(authDeniedWindow))
		if got := sink.waitRecords(t, 2); len(got) != 2 || refusals(got[1]) != 1 || got[1].Request.Source != "203.0.113.9" {
			t.Fatalf("the loop did not write the owed record: %+v", got)
		}
		srv.StopBackground()
		if !closed(srv.bgDone) {
			t.Fatal("the flush goroutine still runs after StopBackground")
		}
	})

	t.Run("context end stops the loop, stop still flushes", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		srv, sink, _ := start(t, ctx)
		send401(t, srv, "GET", "/v1/whoami", "203.0.113.9:4000", "wrong")
		send401(t, srv, "GET", "/v1/whoami", "203.0.113.9:4000", "wrong")
		cancel()
		if !closed(srv.bgDone) {
			t.Fatal("the flush goroutine still runs after its context ended")
		}
		srv.StopBackground()
		if got := sink.records(); len(got) != 2 || refusals(got[1]) != 1 {
			t.Fatalf("stop after the context ended: %+v", got)
		}
	})

	t.Run("records off: nothing starts", func(t *testing.T) {
		srv, _, _ := auditServer(t, config.Config{AuditAPIRecords: config.AuditAPIRecordsOff})
		srv.StartBackground(context.Background())
		if srv.bgStop != nil {
			t.Fatal("a flush loop started with api records off")
		}
		srv.StopBackground()
	})
}

// TestAuthDeniedKeepField: an address's kept details are capped and copied
// out of the request, and an unchanged one is not copied again.
func TestAuthDeniedKeepField(t *testing.T) {
	long := "X" + strings.Repeat("Y", 2*authDeniedMaxField)
	held := strings.Clone("GET")
	cases := []struct {
		name, held, in, want string
		reuse                bool
	}{
		{name: "new value", in: "POST", want: "POST"},
		{name: "unchanged value is not copied", held: held, in: "GET", want: "GET", reuse: true},
		{name: "client-sized method is capped", in: long, want: long[:authDeniedMaxField]},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := keepField(tc.held, tc.in)
			if got != tc.want {
				t.Fatalf("keepField = %q, want %q", got, tc.want)
			}
			if tc.reuse && unsafe.StringData(got) != unsafe.StringData(tc.held) {
				t.Fatal("an unchanged value was copied")
			}
			if !tc.reuse && len(got) > 0 && unsafe.StringData(got) == unsafe.StringData(tc.in) {
				t.Fatal("the kept value shares the request's memory")
			}
		})
	}
}
