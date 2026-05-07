package sessions

import (
	"bytes"
	"testing"
)

func TestRingWriteSmallerThanCapacity(t *testing.T) {
	r := newRing(16)
	if _, err := r.Write([]byte("hello")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got := r.Snapshot()
	if string(got) != "hello" {
		t.Fatalf("snapshot: %q", string(got))
	}
}

func TestRingWriteWrapAround(t *testing.T) {
	r := newRing(8)
	for _, chunk := range []string{"abcd", "efgh", "ij"} {
		if _, err := r.Write([]byte(chunk)); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	got := r.Snapshot()
	// We've written "abcdefghij" — last 8 should remain.
	if string(got) != "cdefghij" {
		t.Fatalf("expected cdefghij, got %q", string(got))
	}
}

func TestRingWriteLargerThanCapacity(t *testing.T) {
	r := newRing(4)
	if _, err := r.Write([]byte("0123456789")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got := r.Snapshot()
	if string(got) != "6789" {
		t.Fatalf("expected 6789, got %q", string(got))
	}
}

func TestRingSnapshotIsCopy(t *testing.T) {
	r := newRing(8)
	_, _ = r.Write([]byte("abcd"))
	snap := r.Snapshot()
	snap[0] = 'X'
	again := r.Snapshot()
	if !bytes.Equal(again, []byte("abcd")) {
		t.Fatalf("snapshot mutation leaked into ring: %q", string(again))
	}
}

func TestRingEmptySnapshot(t *testing.T) {
	r := newRing(8)
	got := r.Snapshot()
	if len(got) != 0 {
		t.Fatalf("expected empty, got %q", string(got))
	}
}
