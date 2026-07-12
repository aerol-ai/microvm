package netrules

import "testing"

// TestUserChainSelection pins the filter chain each Manager targets. This is
// the dark-default regression (empty userChain must stay DOCKER-USER so the
// dockerd path is byte-identical) plus the containerd path (AEROLVM-USER),
// proving per-IP rules never cross chains between engines.
func TestUserChainSelection(t *testing.T) {
	cases := []struct {
		name      string
		userChain string
		wantChain string
	}{
		{"empty defaults to DOCKER-USER (dark default)", "", ChainDockerUser},
		{"explicit DOCKER-USER", ChainDockerUser, ChainDockerUser},
		{"containerd uses AEROLVM-USER", ChainAerolvmUser, ChainAerolvmUser},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			be := &memBackend{}
			mgr := &Manager{enabled: true, ipt: be, userChain: tc.userChain}

			if err := mgr.BlockAllEgress("10.0.0.5"); err != nil {
				t.Fatalf("BlockAllEgress: %v", err)
			}
			if got := be.countMatching("|" + tc.wantChain + "|"); got != 1 {
				t.Fatalf("expected 1 rule in %s, got %d (rules=%v)", tc.wantChain, got, be.rules)
			}
			// No rule may land in the other chain.
			other := ChainAerolvmUser
			if tc.wantChain == ChainAerolvmUser {
				other = ChainDockerUser
			}
			if got := be.countMatching("|" + other + "|"); got != 0 {
				t.Fatalf("rule leaked into %s chain: %d", other, got)
			}

			// Clear must target the same chain (else the DROP rule leaks).
			if err := mgr.ClearBlockAllEgress("10.0.0.5"); err != nil {
				t.Fatalf("ClearBlockAllEgress: %v", err)
			}
			if got := be.countMatching("|" + tc.wantChain + "|"); got != 0 {
				t.Fatalf("rule not cleared from %s: %d remain", tc.wantChain, got)
			}
		})
	}
}

func TestFilterChainNilAndEmptyDefault(t *testing.T) {
	var nilMgr *Manager
	if got := nilMgr.filterChain(); got != ChainDockerUser {
		t.Fatalf("nil manager filterChain = %q, want DOCKER-USER", got)
	}
	if got := (&Manager{}).filterChain(); got != ChainDockerUser {
		t.Fatalf("empty manager filterChain = %q, want DOCKER-USER", got)
	}
}
