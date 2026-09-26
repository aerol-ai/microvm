package daemon

import (
	"errors"
	"fmt"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
)

// A live 3-node enterprise cluster lost its seed permanently to this:
//
//	cluster: validate/re-fanout durable secrets at boot: authoritative
//	  cluster placement snapshot during secret re-fanout: cluster: not raft leader
//	sandboxd.service: Start request repeated too quickly.
//
// The boot re-fanout needs one leader RPC. A node restarting into an
// in-flight election finds no leader, enterprise mode made that fatal, and
// systemd's restart limit made it final — the node never came back for the
// rest of the run. Leadership being momentarily unsettled is the normal
// state of a starting cluster and is not evidence that the durable secrets
// are bad, which is the only thing enterprise mode is meant to fail closed
// on.
func TestBootRefanoutDisposition(t *testing.T) {
	// The exact wrapping chain from the live failure, so this test breaks if
	// the leader sentinel stops surviving the wrap.
	liveErr := fmt.Errorf("authoritative cluster placement snapshot during secret re-fanout: %w", cluster.ErrNotLeader)

	for _, tc := range []struct {
		name       string
		err        error
		enterprise bool
		want       bootRefanoutOutcome
	}{
		{name: "no error", err: nil, enterprise: true, want: refanoutWarn},
		{
			name: "the live failure must not be fatal under enterprise",
			err:  liveErr, enterprise: true, want: refanoutRetry,
		},
		{
			name: "no leader seated yet is the same class",
			err:  fmt.Errorf("wrapped: %w", cluster.ErrNoLeader), enterprise: true, want: refanoutRetry,
		},
		{
			name: "leader-unavailable defers off enterprise too",
			err:  cluster.ErrNotLeader, enterprise: false, want: refanoutRetry,
		},
		{
			// The fail-closed behaviour enterprise mode exists for must
			// survive the fix.
			name: "a real validation failure still ends the process",
			err:  errors.New("secret blob failed to decrypt"), enterprise: true, want: refanoutFatal,
		},
		{
			name: "the same failure only warns without enterprise",
			err:  errors.New("secret blob failed to decrypt"), enterprise: false, want: refanoutWarn,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := bootRefanoutDisposition(tc.err, tc.enterprise); got != tc.want {
				t.Fatalf("disposition = %v, want %v", got, tc.want)
			}
		})
	}
}

// The ordering IS the fix: enterprise must not be consulted before the error
// is classified. A test that only checked the two branches separately would
// pass with them swapped.
func TestLeaderUnavailableIsCheckedBeforeEnterprise(t *testing.T) {
	if got := bootRefanoutDisposition(cluster.ErrNotLeader, true); got == refanoutFatal {
		t.Fatal("enterprise mode is consulted before the error is classified, so a routine election again takes the node down permanently")
	}
}
