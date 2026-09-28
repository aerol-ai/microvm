package cluster

import (
	"testing"
)

func TestMintIncarnationID(t *testing.T) {
	a, err := MintIncarnationID()
	if err != nil {
		t.Fatal(err)
	}
	b, err := MintIncarnationID()
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 32 || len(b) != 32 {
		t.Fatalf("len a=%d b=%d, want 32 hex chars", len(a), len(b))
	}
	if a == b {
		t.Fatal("expected distinct incarnation ids")
	}
}
