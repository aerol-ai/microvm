package cluster

import (
	"errors"
	"fmt"
	"testing"
)

// IsLeaderUnavailable is the classifier the enterprise boot path hinges on:
// it decides whether a failed re-fanout is a transient election or a reason
// to refuse to start. Getting it wrong took a live 3-node cluster's seed
// down permanently, so it gets a direct test rather than relying on the
// caller's coverage in another package.
func TestIsLeaderUnavailable(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil is not a leadership problem", err: nil, want: false},
		{name: "someone else is the leader", err: ErrNotLeader, want: true},
		{name: "no leader seated yet", err: ErrNoLeader, want: true},
		{
			// The exact wrapping chain from the live failure. If the sentinel
			// ever stops surviving the wrap, the boot path silently goes back
			// to treating an election as fatal.
			name: "the live wrapped form still classifies",
			err: fmt.Errorf("cluster: validate/re-fanout durable secrets at boot: %w",
				fmt.Errorf("authoritative cluster placement snapshot during secret re-fanout: %w", ErrNotLeader)),
			want: true,
		},
		{name: "doubly wrapped ErrNoLeader", err: fmt.Errorf("a: %w", fmt.Errorf("b: %w", ErrNoLeader)), want: true},
		{
			// The half that must stay fatal: a real failure is not an
			// election, and treating it as retryable would defeat the
			// fail-closed behaviour enterprise mode exists for.
			name: "an unrelated error is not leadership",
			err:  errors.New("secret blob failed to decrypt"),
			want: false,
		},
		{name: "a same-text error that is not the sentinel", err: errors.New("cluster: not raft leader"), want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsLeaderUnavailable(tc.err); got != tc.want {
				t.Fatalf("IsLeaderUnavailable(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// The two sentinels must stay distinct: "someone else leads" and "nobody
// leads yet" are different states, and collapsing them would make the
// distinction untestable even though both are currently retryable.
func TestLeaderSentinelsAreDistinct(t *testing.T) {
	if errors.Is(ErrNotLeader, ErrNoLeader) || errors.Is(ErrNoLeader, ErrNotLeader) {
		t.Fatal("ErrNotLeader and ErrNoLeader have collapsed into one sentinel")
	}
}
