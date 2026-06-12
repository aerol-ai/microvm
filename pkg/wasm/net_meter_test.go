package wasm

import "testing"

func TestNetByteCounter(t *testing.T) {
	var c *NetByteCounter
	// Should not panic when nil
	c.AddIn(10)
	c.AddOut(10)

	c = &NetByteCounter{}
	// Should not add when n <= 0
	c.AddIn(0)
	c.AddOut(-5)

	if c.In() != 0 || c.Out() != 0 {
		t.Errorf("expected 0, got %d, %d", c.In(), c.Out())
	}
}
