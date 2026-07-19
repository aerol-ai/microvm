package catalogue

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestFormatPercentileGauges(t *testing.T) {
	body := FormatPercentileGauges("aerolvm_bench_create", "wasm", 22, 40, 80)
	if !contains(body, `runtime="wasm"`) || !contains(body, "_p50_ms") {
		t.Fatalf("unexpected body: %s", body)
	}
}

func TestPushgatewayURLUnset(t *testing.T) {
	t.Setenv("AEROL_PUSHGATEWAY_URL", "")
	if err := PushText("job", "inst", "a 1\n"); err != nil {
		t.Fatal(err)
	}
}

// doSimHeartbeat is the synchronous push; assert it targets the sim job and
// carries the heartbeat gauge.
func TestDoSimHeartbeatDelivers(t *testing.T) {
	type captured struct {
		path string
		body string
	}
	got := make(chan captured, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got <- captured{path: r.URL.Path, body: string(b)}
	}))
	defer srv.Close()
	t.Setenv("AEROL_PUSHGATEWAY_URL", srv.URL)

	if err := doSimHeartbeat("postgres-supabase"); err != nil {
		t.Fatalf("doSimHeartbeat: %v", err)
	}
	select {
	case c := <-got:
		if !strings.Contains(c.path, "/metrics/job/aerolvm_sims/instance/postgres-supabase") {
			t.Fatalf("unexpected path: %s", c.path)
		}
		if !strings.Contains(c.body, `aerolvm_sim_heartbeat{sim="postgres-supabase"} 1`) {
			t.Fatalf("unexpected body: %s", c.body)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no heartbeat request received")
	}
}

// PushSimHeartbeat must never block the caller, and a single failed beat must
// trip the circuit breaker so a dead Pushgateway can't stall the run (the
// ~730s-on-56-sims regression this replaced).
func TestPushSimHeartbeatFireAndForgetCircuitBreaker(t *testing.T) {
	heartbeatDisabled.Store(false)
	t.Cleanup(func() { heartbeatDisabled.Store(false) })

	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		http.Error(w, "boom", http.StatusInternalServerError) // force the push to fail
	}))
	defer srv.Close()
	t.Setenv("AEROL_PUSHGATEWAY_URL", srv.URL)

	// Returns immediately even though the background push will fail.
	start := time.Now()
	if err := PushSimHeartbeat("sim-1"); err != nil {
		t.Fatalf("PushSimHeartbeat returned error: %v", err)
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("PushSimHeartbeat blocked %v; expected fire-and-forget", d)
	}

	// The failed beat should trip the breaker in the background.
	deadline := time.Now().Add(3 * time.Second)
	for !heartbeatDisabled.Load() {
		if time.Now().After(deadline) {
			t.Fatal("circuit breaker did not trip after a failed heartbeat")
		}
		time.Sleep(10 * time.Millisecond)
	}
	hitsAtTrip := atomic.LoadInt32(&hits)

	// Once tripped, subsequent beats skip entirely — no new server hits.
	for i := 0; i < 5; i++ {
		if err := PushSimHeartbeat("sim-x"); err != nil {
			t.Fatalf("PushSimHeartbeat: %v", err)
		}
	}
	time.Sleep(100 * time.Millisecond)
	if extra := atomic.LoadInt32(&hits) - hitsAtTrip; extra != 0 {
		t.Fatalf("breaker tripped but %d extra beat(s) reached the server", extra)
	}
}

// A disabled breaker short-circuits before any network work.
func TestPushSimHeartbeatDisabledSkips(t *testing.T) {
	heartbeatDisabled.Store(true)
	t.Cleanup(func() { heartbeatDisabled.Store(false) })

	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
	}))
	defer srv.Close()
	t.Setenv("AEROL_PUSHGATEWAY_URL", srv.URL)

	if err := PushSimHeartbeat("sim-y"); err != nil {
		t.Fatalf("PushSimHeartbeat: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Fatalf("disabled heartbeat still hit the server %d time(s)", got)
	}
}
