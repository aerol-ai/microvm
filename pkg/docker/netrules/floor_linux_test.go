//go:build linux

package netrules

import (
	"errors"
	"testing"

	"github.com/google/nftables/expr"
)

// TestNetlinkFloorChain covers the netlink half offline: the jump is
// inserted once, and FlushChain flushes the named chain.
func TestNetlinkFloorChain(t *testing.T) {
	fake := &fakeNFT{}
	b := &netlinkBackend{newConn: func() (nftAPI, error) { return fake, nil }}
	if err := b.EnsureJumpChain(ChainAerolvmUser, ChainAerolvmFloor); err != nil {
		t.Fatal(err)
	}
	if len(fake.inserted) != 1 {
		t.Fatalf("jump inserts = %d", len(fake.inserted))
	}
	if v, ok := fake.inserted[0].Exprs[1].(*expr.Verdict); !ok || v.Chain != ChainAerolvmFloor {
		t.Fatalf("jump rule = %+v", fake.inserted[0].Exprs)
	}
	if err := b.EnsureJumpChain(ChainAerolvmUser, ChainAerolvmFloor); err != nil || len(fake.inserted) != 1 {
		t.Fatal("the jump is idempotent")
	}
	if err := b.FlushChain(ChainAerolvmFloor); err != nil || len(fake.flushedChains) != 1 || fake.flushedChains[0] != ChainAerolvmFloor {
		t.Fatalf("flush: %v %v", err, fake.flushedChains)
	}
	fake.flushErr = errors.New("boom")
	if err := b.FlushChain(ChainAerolvmFloor); err == nil {
		t.Fatal("flush errors surface")
	}
	fake.flushErr = nil
	fake.getErr = errors.New("boom")
	if err := b.EnsureJumpChain(ChainAerolvmUser, ChainAerolvmFloor); err == nil {
		t.Fatal("list errors surface")
	}
}
