package firecracker

import (
	"testing"
)

func TestRSSSampler_UnregisterEmptyID(t *testing.T) {
	s := NewRSSSampler(nil)
	s.Register("a", 100)
	s.Unregister("")
	if got := s.TotalRSSMB(); got != 0 {
		t.Fatalf("TotalRSSMB = %d before sample, want 0", got)
	}
}
