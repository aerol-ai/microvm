package hostnet

import "testing"

func TestFlushConntrackEmptyIP(t *testing.T) {
	if err := FlushConntrackForIP(""); err != nil {
		t.Fatal(err)
	}
}
