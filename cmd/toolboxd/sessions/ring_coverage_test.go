package sessions

import (
	"testing"
)

func TestRingDefaultCapAndWrapRemainder(t *testing.T) {
	r := newRing(0)
	if r.cap != 1 {
		t.Fatalf("newRing(0).cap = %d, want 1", r.cap)
	}
	r = newRing(8)
	if _, err := r.Write([]byte("abcdef")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	// end=6, first=2, rem=2 → covers the wrap-remainder copy branch.
	if _, err := r.Write([]byte("WXYZ")); err != nil {
		t.Fatalf("Write wrap: %v", err)
	}
	got := string(r.Snapshot())
	if len(got) != 8 {
		t.Fatalf("snapshot len = %d, want 8 (%q)", len(got), got)
	}
}
