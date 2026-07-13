//go:build !linux

package hostnet

import "testing"

func TestEnsureForwardingSysctlsNonLinuxNoOp(t *testing.T) {
	if err := EnsureForwardingSysctls(); err != nil {
		t.Fatal(err)
	}
}
