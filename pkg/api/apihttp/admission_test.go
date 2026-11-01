package apihttp

import (
	"context"
	"encoding/json"
	"errors"
	"expvar"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func newTestGateMetrics() GateMetrics {
	// expvar.Int values outside the registry: tests must not publish names.
	return GateMetrics{InFlight: new(expvar.Int), Admitted: new(expvar.Int), Shed: new(expvar.Int)}
}

// A full gate refuses at once (no queue wait) or after its queue wait, with
// ErrOverloaded; a slot that frees inside the wait is taken.
func TestGateShedsWhenFullAndAdmitsWhenASlotFrees(t *testing.T) {
	m := newTestGateMetrics()
	g := NewGate(2, 0, m)
	if g.Limit() != 2 {
		t.Fatalf("Limit = %d, want 2", g.Limit())
	}
	r1, err := g.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	r2, err := g.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := m.InFlight.Value(); got != 2 {
		t.Fatalf("in flight = %d, want 2", got)
	}
	start := time.Now()
	if _, err := g.Acquire(context.Background()); !errors.Is(err, ErrOverloaded) {
		t.Fatalf("third acquire on a full gate = %v, want ErrOverloaded", err)
	}
	if took := time.Since(start); took > 100*time.Millisecond {
		t.Fatalf("a gate with no queue wait took %v to refuse", took)
	}
	r1()
	r1() // a second release must not free a second slot
	if got := m.InFlight.Value(); got != 1 {
		t.Fatalf("in flight after a double release = %d, want 1", got)
	}
	r3, err := g.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire after a release = %v", err)
	}
	if _, err := g.Acquire(context.Background()); !errors.Is(err, ErrOverloaded) {
		t.Fatal("the double release freed an extra slot")
	}
	r2()
	r3()
	if m.InFlight.Value() != 0 || m.Admitted.Value() != 3 || m.Shed.Value() != 2 {
		t.Fatalf("metrics in_flight=%d admitted=%d shed=%d, want 0/3/2", m.InFlight.Value(), m.Admitted.Value(), m.Shed.Value())
	}
}

func TestGateQueueWait(t *testing.T) {
	m := newTestGateMetrics()
	g := NewGate(1, 200*time.Millisecond, m)
	release, err := g.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Freed inside the wait: admitted.
	time.AfterFunc(20*time.Millisecond, release)
	r, err := g.Acquire(context.Background())
	if err != nil {
		t.Fatalf("a slot freed inside the queue wait was not taken: %v", err)
	}
	// Not freed: refused after about the wait, not before and not forever.
	start := time.Now()
	if _, err := g.Acquire(context.Background()); !errors.Is(err, ErrOverloaded) {
		t.Fatalf("err = %v, want ErrOverloaded", err)
	}
	if took := time.Since(start); took < 150*time.Millisecond || took > 2*time.Second {
		t.Fatalf("refused after %v, want about the 200ms queue wait", took)
	}
	// The caller leaving while it waits is answered like a shed (silently)
	// but not counted as one.
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(20*time.Millisecond, cancel)
	shedBefore := m.Shed.Value()
	_, err = g.Acquire(ctx)
	if !errors.Is(err, ErrOverloaded) || !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want ErrOverloaded wrapping context.Canceled", err)
	}
	if m.Shed.Value() != shedBefore {
		t.Fatal("a caller that left was counted as shed")
	}
	r()
}

// No gate admits everything; a non-positive limit means no gate.
func TestNilGateAdmitsEverything(t *testing.T) {
	if NewGate(0, time.Second, GateMetrics{}) != nil || NewGate(-1, 0, GateMetrics{}) != nil {
		t.Fatal("a non-positive limit must mean no gate")
	}
	var g *Gate
	if g.Limit() != 0 {
		t.Fatal("nil gate limit")
	}
	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release, err := g.Acquire(context.Background())
			if err != nil {
				t.Error(err)
				return
			}
			release()
		}()
	}
	wg.Wait()
	// A negative wait is treated as none, and nil metrics are fine.
	g = NewGate(1, -time.Second, GateMetrics{})
	release, _ := g.Acquire(context.Background())
	if _, err := g.Acquire(context.Background()); !errors.Is(err, ErrOverloaded) {
		t.Fatalf("err = %v", err)
	}
	release()
}

// The wire shape every surface writes through WriteStoreAwareError: 503,
// Retry-After, a stable code.
func TestWriteStoreAwareErrorOverloaded(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteStoreAwareError(nil, rec, ErrOverloaded)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got != strconv.Itoa(OverloadedRetryAfterSeconds) {
		t.Fatalf("Retry-After = %q", got)
	}
	var body models.ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Code != models.ErrorCodeOverloaded || body.Error == "" {
		t.Fatalf("body = %+v (%v)", body, err)
	}
}
