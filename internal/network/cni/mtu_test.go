package cni

import "testing"

func TestBridgeMTUDefault(t *testing.T) {
	if got := BridgeMTU(); got != DefaultBridgeMTU {
		t.Fatalf("BridgeMTU() = %d, want %d", got, DefaultBridgeMTU)
	}
	if DefaultBridgeMTU != 1500 {
		t.Fatalf("DefaultBridgeMTU = %d, want docker-parity 1500", DefaultBridgeMTU)
	}
}
