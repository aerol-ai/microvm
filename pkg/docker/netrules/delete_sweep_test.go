package netrules

import (
	"errors"
	"strings"
	"testing"
)

// alwaysDeletes answers every Delete with success, as a fake or a broken
// backend may, and Exists with what it is told.
type alwaysDeletes struct {
	present bool
	deletes int
}

func (a *alwaysDeletes) Exists(string, string, ...string) (bool, error) { return a.present, nil }
func (a *alwaysDeletes) Insert(string, string, int, ...string) error    { return nil }
func (a *alwaysDeletes) Delete(string, string, ...string) error         { a.deletes++; return nil }

// TestDeleteUntilGoneIsBounded: a backend that answers every delete with
// success can no longer spin the sweep for good. Past maxDupSweep deletes
// it asks whether the rule is still there: gone ends the sweep, present is
// an error.
func TestDeleteUntilGoneIsBounded(t *testing.T) {
	gone := &alwaysDeletes{}
	if err := NewWithBackend(gone).deleteUntilGone("filter", "C", "-j", "X"); err != nil || gone.deletes != maxDupSweep+1 {
		t.Fatalf("gone: err=%v after %d deletes", err, gone.deletes)
	}
	stuck := &alwaysDeletes{present: true}
	err := NewWithBackend(stuck).deleteUntilGone("filter", "C", "-j", "X")
	if err == nil || !strings.Contains(err.Error(), "still holds") || errors.Is(err, nil) {
		t.Fatalf("stuck: %v", err)
	}
}
