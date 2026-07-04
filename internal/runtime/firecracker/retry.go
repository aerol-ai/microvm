package firecracker

import "time"

const (
	socketPollInitial = 2 * time.Millisecond
	socketPollMax     = 20 * time.Millisecond
	vsockPollInitial  = 5 * time.Millisecond
	vsockPollMax      = 50 * time.Millisecond
)

func nextRetryDelay(current, max time.Duration) time.Duration {
	if current <= 0 {
		return max
	}
	next := current * 2
	if next > max {
		return max
	}
	return next
}
