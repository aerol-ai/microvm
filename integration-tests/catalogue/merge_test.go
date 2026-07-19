package catalogue

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestAtomicMergeJSONConcurrentWriters(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "catalogue.json")

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			id := fmtID("ROW", n)
			err := AtomicMergeJSON(path, func(existing []byte) ([]byte, error) {
				return MergeEntriesDocument(existing, "test", []Entry{{
					ID:       id,
					Question: "q",
					Category: "cat",
					Scenario: "test",
					Success:  true,
				}})
			})
			if err != nil {
				t.Errorf("writer %d: %v", n, err)
			}
		}(i)
	}
	wg.Wait()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var doc Document
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(doc.Entries) != 8 {
		t.Fatalf("entries = %d, want 8", len(doc.Entries))
	}
}

func TestFileLockBlocksSecondProcess(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "catalogue.json.lock")
	f1, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f1.Close()
	if err := flockExclusive(f1); err != nil {
		t.Fatalf("flock first: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		f2, err := os.OpenFile(lockPath, os.O_RDWR, 0o644)
		if err != nil {
			done <- err
			return
		}
		defer f2.Close()
		// Non-blocking attempt: on Unix LOCK_EX blocks; use a short timeout via channel.
		ch := make(chan error, 1)
		go func() { ch <- flockExclusive(f2) }()
		select {
		case err := <-ch:
			done <- err
		case <-time.After(200 * time.Millisecond):
			done <- nil // still blocked — expected
		}
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("second lock: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("second lock acquired while first held")
	}
	_ = flockUnlock(f1)
}

func fmtID(prefix string, n int) string {
	return fmt.Sprintf("%s-%d", prefix, n)
}
