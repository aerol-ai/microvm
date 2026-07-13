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

func TestEnsureChainInstallsBridgeForwardAccept(t *testing.T) {
	be := &memBackend{}
	mgr := &Manager{enabled: true, ipt: be, userChain: ChainAerolvmUser}
	mgr.SetBridgeSubnet("10.88.0.0/16")
	if err := mgr.EnsureChain(); err != nil {
		t.Fatal(err)
	}
	// Subnet-scoped FORWARD ACCEPTs (both directions) survive dockerd's DROP.
	if be.countMatching("|-s|10.88.0.0/16|-j|ACCEPT") != 1 {
		t.Fatalf("missing -s subnet accept: %v", be.rules)
	}
	if be.countMatching("|-d|10.88.0.0/16|-j|ACCEPT") != 1 {
		t.Fatalf("missing -d subnet accept: %v", be.rules)
	}
	// Idempotent — re-assert does not duplicate.
	if err := mgr.ReassertChain(); err != nil {
		t.Fatal(err)
	}
	if be.countMatching("|-s|10.88.0.0/16|-j|ACCEPT") != 1 {
		t.Fatalf("subnet accept duplicated on reassert: %v", be.rules)
	}
	// A per-IP block coexists (isolation still enforced via the DROP).
	if err := mgr.BlockAllEgress("10.88.0.5"); err != nil {
		t.Fatal(err)
	}
	if be.countMatching("|-s|10.88.0.5|-j|DROP") != 1 {
		t.Fatalf("per-IP block missing alongside bridge accept: %v", be.rules)
	}
}

func TestEnsureChainNoBridgeAcceptWithoutSubnet(t *testing.T) {
	be := &memBackend{}
	mgr := &Manager{enabled: true, ipt: be, userChain: ChainAerolvmUser}
	if err := mgr.EnsureChain(); err != nil {
		t.Fatal(err)
	}
	if be.countMatching("ACCEPT") != 0 {
		t.Fatalf("no bridge subnet set: expected no ACCEPT rules, got %v", be.rules)
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

// ruleOnlyBackend implements RuleBackend but NOT bootstrapBackend — modeling a
// backend that can insert per-IP rules but cannot create the user chain or its
// FORWARD jump.
type ruleOnlyBackend struct{}

func (ruleOnlyBackend) Exists(string, string, ...string) (bool, error) { return false, nil }
func (ruleOnlyBackend) Insert(string, string, int, ...string) error    { return nil }
func (ruleOnlyBackend) Delete(string, string, ...string) error         { return nil }

// TestEnsureChainFailsLoudOnNonBootstrapBackend is the regression for the
// silent-latch trap: a backend that cannot bootstrap must make EnsureChain
// return an error and NOT latch success (which would leave every per-IP egress
// rule ineffective while reporting the chain "ready").
func TestEnsureChainFailsLoudOnNonBootstrapBackend(t *testing.T) {
	mgr := &Manager{enabled: true, ipt: ruleOnlyBackend{}, userChain: ChainAerolvmUser}
	if err := mgr.EnsureChain(); err == nil {
		t.Fatal("want error: non-bootstrap backend must not silently succeed")
	}
	if mgr.chainReady.Load() {
		t.Fatal("must not latch success when the chain was never created")
	}
}

// TestReassertChainReappliesJump proves re-assertion re-creates the chain and
// jump after they are dropped (simulating a dockerd restart that flushed
// FORWARD), without relying on the one-shot latch.
func TestReassertChainReappliesJump(t *testing.T) {
	be := &memBackend{}
	mgr := &Manager{enabled: true, ipt: be, userChain: ChainAerolvmUser}
	if err := mgr.EnsureChain(); err != nil {
		t.Fatal(err)
	}
	// Simulate dockerd flushing FORWARD + our chain.
	be.reset()
	if be.hasChain(ChainAerolvmUser) {
		t.Fatal("precondition: chain should be gone after reset")
	}
	if err := mgr.ReassertChain(); err != nil {
		t.Fatalf("ReassertChain: %v", err)
	}
	if !be.hasChain(ChainAerolvmUser) {
		t.Fatal("ReassertChain must recreate the chain even after the latch is set")
	}
	if got := be.countMatching("|FORWARD|-j|" + ChainAerolvmUser); got != 1 {
		t.Fatalf("forward jump not re-asserted: %d", got)
	}
}
