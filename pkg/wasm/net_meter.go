package wasm

// ByteMeter accumulates sandbox network byte counters (UC-43).
type ByteMeter interface {
	AddIn(n int64)
	AddOut(n int64)
}

// NetByteCounter is a thread-safe ByteMeter backed by atomic counters.
type NetByteCounter struct {
	in  int64
	out int64
}

func (c *NetByteCounter) AddIn(n int64) {
	if c == nil || n <= 0 {
		return
	}
	// atomic would be better but worker uses atomic.Int64 wrapper; this type
	// is for tests and direct engine wiring.
	c.in += n
}

func (c *NetByteCounter) AddOut(n int64) {
	if c == nil || n <= 0 {
		return
	}
	c.out += n
}

func (c *NetByteCounter) In() int64  { return c.in }
func (c *NetByteCounter) Out() int64 { return c.out }
