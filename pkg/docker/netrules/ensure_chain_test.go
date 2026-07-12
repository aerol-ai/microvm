package netrules

import (
	"errors"
	"testing"
)

func TestEnsureChainIdempotentLatch(t *testing.T) {
	be := &memBackend{}
	mgr := &Manager{enabled: true, ipt: be, userChain: ChainAerolvmUser}

	if err := mgr.EnsureChain(); err != nil {
		t.Fatalf("first EnsureChain: %v", err)
	}
	if !mgr.chainReady.Load() {
		t.Fatal("chainReady should latch")
	}
	if !be.hasChain(ChainAerolvmUser) {
		t.Fatal("user chain not created")
	}
	if got := be.countMatching("|FORWARD|-j|" + ChainAerolvmUser); got != 1 {
		t.Fatalf("forward jump count = %d", got)
	}

	// Second call is a no-op (latch fast path).
	if err := mgr.EnsureChain(); err != nil {
		t.Fatalf("second EnsureChain: %v", err)
	}
	if got := be.countMatching("|FORWARD|-j|" + ChainAerolvmUser); got != 1 {
		t.Fatalf("forward jump duplicated: %d", got)
	}
}

func TestEnsureChainDisabledNoOp(t *testing.T) {
	mgr := &Manager{enabled: false, userChain: ChainAerolvmUser}
	if err := mgr.EnsureChain(); err != nil {
		t.Fatal(err)
	}
	if mgr.chainReady.Load() {
		t.Fatal("disabled manager should not latch")
	}
}

func TestEnsureChainBothUserChainsRegression(t *testing.T) {
	chains := []string{ChainDockerUser, ChainAerolvmUser}
	for _, chain := range chains {
		t.Run(chain, func(t *testing.T) {
			be := &memBackend{}
			mgr := &Manager{enabled: true, ipt: be, userChain: chain}
			if err := mgr.EnsureChain(); err != nil {
				t.Fatal(err)
			}
			if !be.hasChain(chain) {
				t.Fatalf("chain %s not bootstrapped", chain)
			}
			// Per-IP rules must target the bootstrapped chain.
			if err := mgr.BlockAllEgress("10.1.2.3"); err != nil {
				t.Fatal(err)
			}
			if got := be.countMatching("|" + chain + "|"); got != 1 {
				t.Fatalf("egress rule not in %s: %d", chain, got)
			}
		})
	}
}

func TestEnsureChainRetriesAfterReset(t *testing.T) {
	be := &memBackend{}
	mgr := &Manager{enabled: true, ipt: be, userChain: ChainAerolvmUser}
	if err := mgr.EnsureChain(); err != nil {
		t.Fatal(err)
	}
	mgr.ResetChainLatch()
	if err := mgr.EnsureChain(); err != nil {
		t.Fatal(err)
	}
	if !mgr.chainReady.Load() {
		t.Fatal("should re-latch")
	}
}

type failingBootstrap struct {
	memBackend
	failChain bool
	failJump  bool
}

func (f *failingBootstrap) EnsureUserChain(chain string) error {
	if f.failChain {
		return errors.New("chain boom")
	}
	return f.memBackend.EnsureUserChain(chain)
}

func (f *failingBootstrap) EnsureForwardJump(userChain string) error {
	if f.failJump {
		return errors.New("jump boom")
	}
	return f.memBackend.EnsureForwardJump(userChain)
}

func TestEnsureChainPropagatesBootstrapErrors(t *testing.T) {
	mgr := &Manager{enabled: true, ipt: &failingBootstrap{failChain: true}, userChain: ChainAerolvmUser}
	if err := mgr.EnsureChain(); err == nil {
		t.Fatal("want chain error")
	}
	if mgr.chainReady.Load() {
		t.Fatal("must not latch on failure")
	}

	mgr = &Manager{enabled: true, ipt: &failingBootstrap{failJump: true}, userChain: ChainAerolvmUser}
	if err := mgr.EnsureChain(); err == nil {
		t.Fatal("want jump error")
	}
}
