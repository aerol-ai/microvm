package hostnet

import "testing"

func TestEnsureForwardingSysctlsNonLinuxNoOp(t *testing.T) {
	if err := EnsureForwardingSysctls(); err != nil {
		t.Fatal(err)
	}
}

func TestFlushConntrackEmptyIP(t *testing.T) {
	if err := FlushConntrackForIP(""); err != nil {
		t.Fatal(err)
	}
}
