package sessions

import "sync"

// ring is a fixed-capacity byte ring buffer used as a session's replay log.
// Writes never block: when the buffer is full, the oldest bytes are
// overwritten. Snapshot returns a copy of the current contents for new
// attachers, so they see whatever's still in the window.
type ring struct {
	mu    sync.Mutex
	buf   []byte
	start int
	size  int
	cap   int
}

func newRing(cap int) *ring {
	if cap <= 0 {
		cap = 1
	}
	return &ring{buf: make([]byte, cap), cap: cap}
}

// Write appends p to the ring. Always returns len(p), nil.
func (r *ring) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	n := len(p)
	if n >= r.cap {
		// Last r.cap bytes of p replace the entire buffer.
		copy(r.buf, p[n-r.cap:])
		r.start = 0
		r.size = r.cap
		return n, nil
	}

	end := (r.start + r.size) % r.cap
	first := r.cap - end
	if first > n {
		first = n
	}
	copy(r.buf[end:end+first], p[:first])
	if rem := n - first; rem > 0 {
		copy(r.buf[:rem], p[first:])
	}

	if r.size+n > r.cap {
		overflow := (r.size + n) - r.cap
		r.start = (r.start + overflow) % r.cap
		r.size = r.cap
	} else {
		r.size += n
	}
	return n, nil
}

// Snapshot returns a copy of the buffer's current contents in oldest→newest
// order.
func (r *ring) Snapshot() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]byte, r.size)
	if r.size == 0 {
		return out
	}
	first := r.cap - r.start
	if first > r.size {
		first = r.size
	}
	copy(out, r.buf[r.start:r.start+first])
	if r.size > first {
		copy(out[first:], r.buf[:r.size-first])
	}
	return out
}
