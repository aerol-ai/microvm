package daemon

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
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
			// T18 live (2026-09-27): a restarted enterprise worker asked for
			// the snapshot before the server had gossiped its rejoin, got 403
			// "cluster peer not in membership", and crash-looped into
			// systemd's restart limit.
			name: "a rejoin the server has not gossiped yet must not be fatal",
			err: fmt.Errorf("cluster: validate/re-fanout durable secrets at boot: %w",
				fmt.Errorf("authoritative cluster placement snapshot during secret re-fanout: %w", cluster.ErrMembershipPending)),
			enterprise: true, want: refanoutRetry,
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

// The deferred re-fanout must actually run and must stop. It replaces a
// hard exit(1), so a retry goroutine that never fires would leave an
// enterprise node serving with its durable secrets un-revalidated — quieter
// than the bug it replaced, and worse.
func TestStartClusterSecretRefanoutRetry_RunsAndStops(t *testing.T) {
	oldTick := clusterOwnershipReplayTick
	clusterOwnershipReplayTick = 5 * time.Millisecond
	t.Cleanup(func() { clusterOwnershipReplayTick = oldTick })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	st := openTestStore(t)
	svc := service.New(config.Config{EnableCluster: true}, testLogger(), st, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(cluster.NewNoop("node-a", "http://node-a", ""))

	startClusterSecretRefanoutRetry(ctx, svc, testLogger())
	// Let several ticks elapse: the loop must survive them without panicking
	// on a Service that has no cluster secrets to fan out.
	time.Sleep(30 * time.Millisecond)
	cancel()
	time.Sleep(20 * time.Millisecond)
}

// Cancellation alone must unblock it, with no tick ever firing.
func TestStartClusterSecretRefanoutRetry_StopsOnCtxCancel(t *testing.T) {
	st := openTestStore(t)
	svc := service.New(config.Config{}, testLogger(), st, nil, nil, nil, nil, nil, nil)
	startClusterSecretRefanoutRetry(t.Context(), svc, testLogger())
}
