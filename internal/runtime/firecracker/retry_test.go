package firecracker

import (
	"testing"
	"time"
)

func TestRetryDelayBackoffSequence(t *testing.T) {
	cases := []struct {
		name    string
		initial time.Duration
		max     time.Duration
		want    []time.Duration
	}{
		{
			name:    "socket wait",
			initial: socketPollInitial,
			max:     socketPollMax,
			want: []time.Duration{
				2 * time.Millisecond,
				4 * time.Millisecond,
				8 * time.Millisecond,
				16 * time.Millisecond,
				20 * time.Millisecond,
				20 * time.Millisecond,
			},
		},
		{
			name:    "vsock handshake",
			initial: vsockPollInitial,
			max:     vsockPollMax,
			want: []time.Duration{
				5 * time.Millisecond,
				10 * time.Millisecond,
				20 * time.Millisecond,
				40 * time.Millisecond,
				50 * time.Millisecond,
				50 * time.Millisecond,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			delay := tc.initial
			for i, want := range tc.want {
				if delay != want {
					t.Fatalf("delay[%d] = %s, want %s", i, delay, want)
				}
				delay = nextRetryDelay(delay, tc.max)
			}
		})
	}
}
