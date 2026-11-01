//go:build linux

package netrules

import (
	"errors"
	"syscall"
	"testing"
)

func TestClearAddressNetlink(t *testing.T) {
	f := newChainNFT()
	for _, r := range addressRules {
		f.add(r.chain, r.spec...)
	}
	m := &Manager{enabled: true, ipt: netlinkChainBackend(f), userChain: ChainAerolvmUser}
	m.inputReady.Store(true)
	if err := m.ClearAddress("10.0.0.5"); err != nil {
		t.Fatal(err)
	}
	for _, r := range addressRules {
		if n := f.count(r.chain, r.spec...); (n == 0) != r.ours {
			t.Fatalf("rule %v ours=%v count=%d after clear", r.spec, r.ours, n)
		}
	}
	if f.flushes != 1 {
		t.Fatalf("%d commits, want one transaction", f.flushes)
	}
	// Nothing left: no commit.
	if err := m.ClearAddress("10.0.0.5"); err != nil || f.flushes != 1 {
		t.Fatalf("second clear: err=%v flushes=%d", err, f.flushes)
	}
}

func TestClearAddressNetlinkEdges(t *testing.T) {
	// A stale commit is redone from a fresh listing.
	f := newChainNFT()
	f.add(ChainAerolvmUser, egressDropSpec("10.0.0.5")...)
	f.staleFlushes = 1
	b := netlinkChainBackend(f)
	if err := b.ClearAddressRules([]string{ChainAerolvmUser}, "10.0.0.5"); err != nil || f.count(ChainAerolvmUser, egressDropSpec("10.0.0.5")...) != 0 {
		t.Fatalf("stale retry: %v", err)
	}
	// A chain that isn't there holds none.
	f2 := newChainNFT()
	f2.getErr = syscall.ENOENT
	if err := netlinkChainBackend(f2).ClearAddressRules([]string{ChainAerolvmUser}, "10.0.0.5"); err != nil {
		t.Fatalf("missing chain: %v", err)
	}
	f2.getErr = errors.New("boom")
	if err := netlinkChainBackend(f2).ClearAddressRules([]string{ChainAerolvmUser}, "10.0.0.5"); err == nil {
		t.Fatal("list error hidden")
	}
	f3 := newChainNFT()
	f3.add(ChainAerolvmUser, egressDropSpec("10.0.0.5")...)
	f3.flushErr = errors.New("flush boom")
	if err := netlinkChainBackend(f3).ClearAddressRules([]string{ChainAerolvmUser}, "10.0.0.5"); err == nil {
		t.Fatal("flush error hidden")
	}
	f4 := newChainNFT()
	f4.add(ChainAerolvmUser, egressDropSpec("10.0.0.5")...)
	f4.delErr = errors.New("del boom")
	if err := netlinkChainBackend(f4).ClearAddressRules([]string{ChainAerolvmUser}, "10.0.0.5"); err == nil {
		t.Fatal("del error hidden")
	}
	if err := netlinkChainBackend(newChainNFT()).ClearAddressRules([]string{"nat|x"}, "10.0.0.5"); err == nil {
		t.Log("odd chain accepted")
	}
	bad := &netlinkBackend{newConn: func() (nftAPI, error) { return nil, errors.New("conn boom") }}
	if err := bad.ClearAddressRules([]string{ChainAerolvmUser}, "10.0.0.5"); err == nil {
		t.Fatal("conn error hidden")
	}
}

// TestClearAddressNetlinkGivesUp: a chain that keeps moving under the
// transaction fails after the retries, and the manager reports it.
func TestClearAddressNetlinkGivesUp(t *testing.T) {
	f := newChainNFT()
	f.add(ChainAerolvmUser, egressDropSpec("10.0.0.5")...)
	f.staleFlushes = batchAttempts
	m := &Manager{enabled: true, ipt: netlinkChainBackend(f), userChain: ChainAerolvmUser}
	m.inputReady.Store(true)
	if err := m.ClearAddress("10.0.0.5"); !errors.Is(err, errBatchStale) {
		t.Fatalf("err = %v, want the stale error", err)
	}
}
