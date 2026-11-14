//go:build itest_failpoints

package failpoint

import (
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// useTempDir points Hit at a fresh directory and swaps block for one that
// counts how many callers fired and parks them until release is closed.
func useTempDir(t *testing.T) (d string, fired *atomic.Int32, release chan struct{}) {
	t.Helper()
	d = t.TempDir()
	fired = &atomic.Int32{}
	release = make(chan struct{})
	oldDir, oldBlock := dir, block
	dir = d
	block = func() {
		fired.Add(1)
		<-release
	}
	t.Cleanup(func() { dir, block = oldDir, oldBlock })
	return d, fired, release
}

func arm(t *testing.T, d, name, prefix string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(d, name), []byte(prefix), 0o600); err != nil {
		t.Fatal(err)
	}
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func TestHitWithoutAMatchReturnsAndLeavesTheArm(t *testing.T) {
	tests := []struct {
		name   string
		armed  bool
		prefix string
		key    string
	}{
		{name: "not armed", key: "sb-1"},
		{name: "another prefix", armed: true, prefix: "chaos-480-", key: "chaos-470-x"},
		{name: "empty file matches nothing", armed: true, prefix: "", key: "anything"},
		{name: "whitespace only matches nothing", armed: true, prefix: " \n", key: "anything"},
		{name: "key shorter than the prefix", armed: true, prefix: "chaos-480-long", key: "chaos-480"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, fired, _ := useTempDir(t)
			if tt.armed {
				arm(t, d, CreateBeforePersist, tt.prefix)
			}
			Hit(CreateBeforePersist, tt.key)
			if fired.Load() != 0 {
				t.Fatal("Hit blocked without a match")
			}
			if exists(filepath.Join(d, CreateBeforePersist+HitSuffix)) {
				t.Fatal("a hit marker was written without a match")
			}
			if tt.armed && !exists(filepath.Join(d, CreateBeforePersist)) {
				t.Fatal("a failpoint that did not fire was disarmed")
			}
		})
	}
}

func TestHitFiresOnceWritesTheMarkerAndBlocks(t *testing.T) {
	d, fired, release := useTempDir(t)
	arm(t, d, CreateBeforePersist, "chaos-480-\n")

	done := make(chan struct{})
	go func() {
		Hit(CreateBeforePersist, "chaos-480-abc")
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for fired.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("Hit never fired on a matching key")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case <-done:
		t.Fatal("Hit returned instead of blocking")
	case <-time.After(50 * time.Millisecond):
	}
	if exists(filepath.Join(d, CreateBeforePersist)) {
		t.Fatal("the arm survived a hit; the failpoint would fire again")
	}
	// The key is written just after the rename that fires; give it a moment.
	var raw []byte
	for deadline := time.Now().Add(5 * time.Second); string(raw) != "chaos-480-abc\n"; time.Sleep(time.Millisecond) {
		raw, _ = os.ReadFile(filepath.Join(d, CreateBeforePersist+HitSuffix))
		if time.Now().After(deadline) {
			t.Fatalf("hit marker = %q; want the key", raw)
		}
	}

	// Fired once: the next matching create goes straight through.
	Hit(CreateBeforePersist, "chaos-480-abc")
	if fired.Load() != 1 {
		t.Fatalf("fired %d times, want 1", fired.Load())
	}
	close(release)
	<-done
}

func TestConcurrentMatchesFireExactlyOnce(t *testing.T) {
	d, fired, release := useTempDir(t)
	arm(t, d, CreateBeforePersist, "chaos-")

	const callers = 16
	var returned atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			Hit(CreateBeforePersist, "chaos-same-prefix")
			returned.Add(1)
		}()
	}
	deadline := time.Now().Add(5 * time.Second)
	for returned.Load() < callers-1 {
		if time.Now().After(deadline) {
			t.Fatalf("only %d of %d callers returned; %d fired", returned.Load(), callers, fired.Load())
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	if got := fired.Load(); got != 1 {
		t.Fatalf("%d callers fired, want exactly 1", got)
	}
	close(release)
	wg.Wait()
}

func TestHitRefusesANameOutsideTheDirectory(t *testing.T) {
	d, fired, _ := useTempDir(t)
	sub := filepath.Join(d, "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	arm(t, sub, "x", "k")
	for _, name := range []string{"", "sub/x", "../x", ".."} {
		Hit(name, "key")
	}
	if fired.Load() != 0 {
		t.Fatal("Hit followed a name out of its directory")
	}
}

// The rename that claims the failpoint also makes the marker; when it
// cannot (here a directory sits where the marker goes), there is no marker to
// tell the suite which process to kill, so Hit must not block.
func TestHitDoesNotBlockWhenTheMarkerCannotBeMade(t *testing.T) {
	d, fired, _ := useTempDir(t)
	arm(t, d, CreateBeforePersist, "k")
	if err := os.Mkdir(filepath.Join(d, CreateBeforePersist+HitSuffix), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, CreateBeforePersist+HitSuffix, "x"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	Hit(CreateBeforePersist, "key")
	if fired.Load() != 0 {
		t.Fatal("Hit blocked with no marker to tell the suite which process to kill")
	}
}

// A marker an earlier hit left (the suite never disarmed) is replaced, and
// the new one names the new key.
func TestHitReplacesAStaleMarker(t *testing.T) {
	d, fired, release := useTempDir(t)
	marker := filepath.Join(d, CreateBeforePersist+HitSuffix)
	if err := os.WriteFile(marker, []byte("old-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	arm(t, d, CreateBeforePersist, "new-")
	done := make(chan struct{})
	go func() {
		Hit(CreateBeforePersist, "new-key")
		close(done)
	}()
	for deadline := time.Now().Add(5 * time.Second); fired.Load() == 0; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("Hit never fired")
		}
	}
	if raw, err := os.ReadFile(marker); err != nil || string(raw) != "new-key\n" {
		t.Fatalf("marker = %q, %v; want the new key", raw, err)
	}
	close(release)
	<-done
}
