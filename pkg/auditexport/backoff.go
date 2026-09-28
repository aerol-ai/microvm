package auditexport

import (
	"math/rand/v2"
	"time"
)

// Backoff is exponential with full jitter, capped at Max. The tailer keeps
// one per backend: Next after a failure says how long to skip ticks, Reset
// on success. Full jitter keeps 2,000 nodes that lost the same receiver at
// the same moment from retrying in lockstep.
type Backoff struct {
	Base     time.Duration
	Max      time.Duration
	attempts int
	rand     func() float64 // test seam; nil = math/rand
}

// Next records a failure and returns the delay before the next attempt.
func (b *Backoff) Next() time.Duration {
	if b.Base <= 0 {
		b.Base = time.Second
	}
	if b.Max <= 0 {
		b.Max = DefaultMaxBackoff
	}
	b.attempts++
	ceiling := b.Base
	for i := 1; i < b.attempts && ceiling < b.Max; i++ {
		ceiling *= 2
	}
	if ceiling > b.Max {
		ceiling = b.Max
	}
	r := b.rand
	if r == nil {
		r = rand.Float64
	}
	// Keep a floor so jitter cannot collapse into a hot loop.
	return max(time.Duration(float64(ceiling)*r()), b.Base/2)
}

// Reset clears the failure streak after a success.
func (b *Backoff) Reset() { b.attempts = 0 }

// Attempts is the current consecutive-failure count.
func (b *Backoff) Attempts() int { return b.attempts }
