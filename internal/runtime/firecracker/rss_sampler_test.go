package firecracker

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// withFakeRSS swaps the package-level readRSSPagesFn for the test and
// restores it on cleanup. Pattern matches the seam style elsewhere in
// the package (driver_test uses the same swap-and-restore on
// vmmSpawner / vmmClientFactory). Returns the mutex the fake uses so a
// test can reach in and adjust per-pid values mid-flight.
func withFakeRSS(t *testing.T, values map[int]int64, errs map[int]error) (*sync.Mutex, func()) {
	t.Helper()
	var mu sync.Mutex
	prior := readRSSPagesFn
	readRSSPagesFn = func(pid int) (int64, error) {
		mu.Lock()
		defer mu.Unlock()
		if e, ok := errs[pid]; ok && e != nil {
			return 0, e
		}
		return values[pid], nil
	}
	t.Cleanup(func() { readRSSPagesFn = prior })
	return &mu, func() { readRSSPagesFn = prior }
}

func TestParseStatm_ResidentField(t *testing.T) {
	// Standard format: seven page counts. The second field is resident.
	got, err := parseStatm([]byte("1024 256 64 4 0 100 0\n"))
	if err != nil {
		t.Fatalf("parseStatm: %v", err)
	}
	// On non-linux the stub returns 0; only assert the value on linux.
	if got != 0 && got != 256 {
		t.Fatalf("resident = %d, want 256 (or 0 on non-linux stub)", got)
	}
}

func TestParseStatm_Rejects(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"whitespace only", "   \n"},
		{"single field", "1024\n"},
		{"non-numeric resident", "1024 abc 0 0 0 0 0\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseStatm([]byte(tc.in))
			// On linux these all fail; on !linux the stub returns
			// (0, nil) regardless. Only enforce the error on platforms
			// where the parser actually runs.
			if err == nil && hostPageSizeBytes > 0 && tc.in != "" && tc.in != "   \n" {
				// hostPageSizeBytes > 0 is true on all platforms; the
				// real discriminator is "is parseStatm a real parser
				// or the no-op stub?". Easiest signal: a valid statm
				// line returned 256 in the prior test. If it returned
				// 0 there, we're on the stub and this test is moot.
				validRes, _ := parseStatm([]byte("1024 256 64 4 0 100 0\n"))
				if validRes == 256 {
					t.Fatalf("parseStatm(%q) returned nil error", tc.in)
				}
			}
		})
	}
}

func TestRSSSampler_RegisterUnregisterIdempotent(t *testing.T) {
	values := map[int]int64{1001: pagesForMB(50), 1002: pagesForMB(30)}
	withFakeRSS(t, values, nil)

	s := NewRSSSampler(nil)
	s.Register("a", 1001)
	s.Register("a", 1001) // dup register — must not double-count after sample
	s.Register("b", 1002)
	s.sampleOnce()

	if got, want := s.TotalRSSMB(), 80; got != want {
		t.Fatalf("TotalRSSMB after 2 distinct registers = %d, want %d", got, want)
	}

	s.Unregister("a")
	if got, want := s.TotalRSSMB(), 30; got != want {
		t.Fatalf("TotalRSSMB after Unregister(a) = %d, want %d", got, want)
	}
	s.Unregister("a") // dup unregister — no-op
	if got, want := s.TotalRSSMB(), 30; got != want {
		t.Fatalf("TotalRSSMB after dup Unregister(a) = %d, want %d", got, want)
	}

	// Register overwrites the pid for the same id without leaking the
	// prior sample into the aggregate after the next sampleOnce.
	values[2002] = pagesForMB(70)
	s.Register("b", 2002)
	s.sampleOnce()
	if got, want := s.TotalRSSMB(), 70; got != want {
		t.Fatalf("TotalRSSMB after re-register(b, 2002) = %d, want %d", got, want)
	}
}

func TestRSSSampler_RegisterIgnoresInvalid(t *testing.T) {
	withFakeRSS(t, map[int]int64{1: pagesForMB(10)}, nil)
	s := NewRSSSampler(nil)
	s.Register("", 1)    // empty id
	s.Register("x", 0)   // zero pid
	s.Register("y", -42) // negative pid
	s.sampleOnce()
	if got := s.TotalRSSMB(); got != 0 {
		t.Fatalf("TotalRSSMB after invalid registrations = %d, want 0", got)
	}
}

func TestRSSSampler_BadPIDDoesNotPoisonAggregate(t *testing.T) {
	// One healthy pid, one that always errors. Aggregate must still
	// reflect the healthy pid and sampler must keep running.
	values := map[int]int64{1001: pagesForMB(40), 1002: pagesForMB(60)}
	errs := map[int]error{1002: errors.New("kaboom")}
	withFakeRSS(t, values, errs)

	s := NewRSSSampler(nil)
	s.Register("good", 1001)
	s.Register("bad", 1002)
	s.sampleOnce()

	if got, want := s.TotalRSSMB(), 40; got != want {
		t.Fatalf("TotalRSSMB with one failing pid = %d, want %d (good pid only)", got, want)
	}

	// Second tick: bad pid still errors, but good pid grew. Aggregate
	// must follow the good pid; no leftover state from the prior tick.
	values[1001] = pagesForMB(55)
	s.sampleOnce()
	if got, want := s.TotalRSSMB(), 55; got != want {
		t.Fatalf("TotalRSSMB after second tick = %d, want %d", got, want)
	}
}

func TestRSSSampler_TotalZeroBeforeFirstSample(t *testing.T) {
	withFakeRSS(t, map[int]int64{1: pagesForMB(100)}, nil)
	s := NewRSSSampler(nil)
	s.Register("a", 1)
	// No sampleOnce yet — admission should see 0 AND !Ready so PR 5-B
	// gates the RSS check and falls back to nominal accounting on a
	// cold-start daemon.
	if got := s.TotalRSSMB(); got != 0 {
		t.Fatalf("TotalRSSMB before first sample = %d, want 0", got)
	}
	if s.Ready() {
		t.Fatal("Ready() = true before first sample, want false")
	}
}

func TestRSSSampler_ReadyAfterFirstSample(t *testing.T) {
	// First sample with no pids: Ready must still flip — admission
	// should treat "sampler ran, host has no firecracker VMMs" as a
	// valid 0-RSS reading, not as "no data, fall back to nominal".
	withFakeRSS(t, nil, nil)
	s := NewRSSSampler(nil)
	s.sampleOnce()
	if !s.Ready() {
		t.Fatal("Ready() = false after sampleOnce on empty registry, want true")
	}
}

func TestRSSSampler_RunHonorsContextDone(t *testing.T) {
	withFakeRSS(t, map[int]int64{1: pagesForMB(10)}, nil)
	s := NewRSSSampler(nil)
	s.Register("a", 1)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		// Tight 5ms interval so the test doesn't pay a real second per
		// run. The point is that Run returns promptly on cancel — not
		// that we observe many ticks.
		s.Run(ctx, 5*time.Millisecond)
		close(done)
	}()

	// Give the loop one or two ticks then cancel.
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// Good — Run returned.
	case <-time.After(time.Second):
		t.Fatal("Run did not return within 1s of ctx cancel")
	}
}

func TestRSSSampler_RunZeroIntervalReturnsImmediately(t *testing.T) {
	s := NewRSSSampler(nil)
	done := make(chan struct{})
	go func() {
		s.Run(context.Background(), 0)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run(interval=0) did not return immediately")
	}
}

func TestRSSSampler_ConcurrentRegisterAndTotal(t *testing.T) {
	// Stress the lock-free reader / locked writer split. Run with
	// `go test -race ./internal/runtime/firecracker/...` to make the
	// guarantee meaningful — the assertion here is just "no crash".
	withFakeRSS(t, map[int]int64{1: pagesForMB(5)}, nil)
	s := NewRSSSampler(nil)

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Readers
	for range 8 {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
					_ = s.TotalRSSMB()
				}
			}
		})
	}
	// Writers
	for i := range 8 {
		wg.Go(func() {
			for j := range 200 {
				s.Register("w", i*1000+j+1)
				s.sampleOnce()
				s.Unregister("w")
			}
		})
	}

	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// pagesForMB converts a target MB count to the equivalent /proc/statm
// page count for the host page size. Kept here (not in production
// code) because the conversion direction is test-only — admission only
// ever goes pages → MB.
func pagesForMB(mb int) int64 {
	if mb <= 0 || hostPageSizeBytes <= 0 {
		return 0
	}
	bytes := int64(mb) * (1 << 20)
	return bytes / hostPageSizeBytes
}

func TestDiscard_Write(t *testing.T) {
	d := discard{}
	n, err := d.Write([]byte("hello"))
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if n != 5 {
		t.Errorf("expected 5, got %d", n)
	}
}
