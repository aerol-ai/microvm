// Package logring keeps the newest bytes of an output stream in a bounded
// buffer while counting every byte the stream ever wrote.
//
// Command output on a WASM sandbox is kept in sandboxd's own memory (Daytona
// session logs) or in the sandbox's worker process (the entrypoint's
// output), and a guest can write without end. A ring grows on demand up to
// its limit and then overwrites its oldest bytes, so a reader still gets the
// most recent output, and offsets counted in the stream's own bytes (Base,
// Total) stay true after the head is gone.
package logring

// minGrowth is the smallest allocation a growing ring makes, so a stream of
// tiny writes does not reallocate on every one.
const minGrowth = 4 << 10

// Ring is the tail of one stream. The zero value is empty and ready to use.
// It is not safe for concurrent use; callers hold their own lock.
type Ring struct {
	buf   []byte // storage; len(buf) is the ring's size
	start int    // index of the oldest byte kept
	n     int    // bytes kept
	total int64  // bytes ever written
}

// Write appends p, keeping at most max bytes, the newest. When the ring has
// to grow, grow (if not nil) is asked for want more bytes and returns how
// many it grants; the ring never grows past what it is granted. A ring that
// gets no room at all still counts p in Total.
func (r *Ring) Write(p []byte, max int, grow func(want int) int) {
	r.total += int64(len(p))
	size := len(r.buf)
	if need := r.n + len(p); need > size && size < max {
		want := min(max, maxInt(need, 2*size, minGrowth)) - size
		got := want
		if grow != nil {
			got = min(grow(want), want)
		}
		if got > 0 {
			r.resize(size + got)
			size = len(r.buf)
		}
	}
	if size == 0 || len(p) == 0 {
		return
	}
	if len(p) >= size {
		copy(r.buf, p[len(p)-size:])
		r.start, r.n = 0, size
		return
	}
	end := (r.start + r.n) % size
	k := copy(r.buf[end:], p)
	copy(r.buf, p[k:])
	if over := r.n + len(p) - size; over > 0 {
		// The write wrapped onto the oldest bytes: they are gone.
		r.start = (r.start + over) % size
		r.n = size
	} else {
		r.n += len(p)
	}
}

func maxInt(a, b, c int) int { return max(a, max(b, c)) }

// resize moves the kept bytes into new storage of the given size, oldest
// first.
func (r *Ring) resize(size int) {
	buf := make([]byte, size)
	r.copyOut(buf, 0, r.n)
	r.buf, r.start = buf, 0
}

// copyOut copies kept bytes [lo, hi) (0 = the oldest kept) into dst.
func (r *Ring) copyOut(dst []byte, lo, hi int) {
	if hi <= lo {
		return
	}
	i := (r.start + lo) % len(r.buf)
	k := copy(dst, r.buf[i:min(len(r.buf), i+hi-lo)])
	copy(dst[k:], r.buf[:hi-lo-k])
}

// Total is every byte ever written: the stream's length.
func (r *Ring) Total() int64 { return r.total }

// Base is the stream offset of the oldest byte kept.
func (r *Ring) Base() int64 { return r.total - int64(r.n) }

// Len is the number of bytes kept.
func (r *Ring) Len() int { return r.n }

// Size is the storage the ring holds, kept or not.
func (r *Ring) Size() int { return len(r.buf) }

// Bytes returns a copy of the bytes kept, oldest first.
func (r *Ring) Bytes() []byte {
	return r.Slice(0, r.n)
}

// Slice returns a copy of kept bytes [lo, hi), 0 being the oldest kept.
// Both bounds are clamped to what is kept.
func (r *Ring) Slice(lo, hi int) []byte {
	lo, hi = max(0, min(lo, r.n)), max(0, min(hi, r.n))
	if hi <= lo {
		return nil
	}
	out := make([]byte, hi-lo)
	r.copyOut(out, lo, hi)
	return out
}

// Release drops the bytes kept and the storage, and returns the storage
// freed. Total is unchanged: the stream's length does not shrink.
func (r *Ring) Release() int {
	freed := len(r.buf)
	r.buf, r.start, r.n = nil, 0, 0
	return freed
}
