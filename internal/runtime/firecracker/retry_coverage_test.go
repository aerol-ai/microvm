package firecracker

import (
	"testing"
	"time"
)

func TestNextRetryDelay_ZeroOrNegativeCurrent(t *testing.T) {
	cases := []struct {
		current time.Duration
		max     time.Duration
		want    time.Duration
	}{
		{0, 20 * time.Millisecond, 20 * time.Millisecond},
		{-1, 50 * time.Millisecond, 50 * time.Millisecond},
	}
	for _, tc := range cases {
		if got := nextRetryDelay(tc.current, tc.max); got != tc.want {
			t.Fatalf("nextRetryDelay(%s, %s) = %s, want %s", tc.current, tc.max, got, tc.want)
		}
	}
}
