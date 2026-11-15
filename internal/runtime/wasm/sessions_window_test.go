package wasm

import (
	"math"
	"testing"

	"github.com/aerol-ai/microvm/internal/logring"
)

// TestRingWindowLimits: a logs read returns at most limit bytes, and a
// limit too big to add one to (the largest int64) means everything, not
// nothing. It used to overflow and return an empty window that never moved
// the reader forward.
func TestRingWindowLimits(t *testing.T) {
	var r logring.Ring
	r.Write([]byte("hello world"), 1<<10, nil)
	for _, tc := range []struct {
		name  string
		from  int64
		limit int64
		want  string
	}{
		{"no limit", 0, 0, "hello world"},
		{"cut", 0, 5, "hello"},
		{"cut from an offset", 6, 3, "wor"},
		{"limit one short of the window", 0, 10, "hello worl"},
		{"limit equal to the window", 0, 11, "hello world"},
		{"limit past the window", 0, 12, "hello world"},
		{"largest int64", 0, math.MaxInt64, "hello world"},
		{"largest int64 from an offset", 6, math.MaxInt64, "world"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := ringWindow(&r, tc.from, tc.limit, true)
			if w.Text != tc.want || w.End != tc.from+int64(len(tc.want)) || w.Length != 11 {
				t.Fatalf("window = %+v, want %q ending at %d", w, tc.want, tc.from+int64(len(tc.want)))
			}
		})
	}
}
