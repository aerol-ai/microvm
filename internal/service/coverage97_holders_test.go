package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"testing/synctest"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
)

// cov97Cluster answers the two placement reads differently. Gossip still
// shows the sandbox so the refresh builds a job; the authoritative read
// omits it, which is the "placement disappeared between the two reads"
// branch. PruneAuditACL fails so the maintenance loop logs the sweep error
// instead of treating a nil error as success.
type cov97Cluster struct {
	*cluster.Noop
	members []cluster.Member
	gossip  map[string]cluster.Placement
	auth    map[string]cluster.Placement
}

func (c *cov97Cluster) LocalMembers() []cluster.Member { return c.members }
func (c *cov97Cluster) Members() []cluster.Member      { return c.members }
func (c *cov97Cluster) PruneAuditACL(context.Context, time.Time) error {
	return errors.New("acl prune failed")
}
func (c *cov97Cluster) PlacementsByIDs(ids []string) map[string]cluster.Placement {
	out := make(map[string]cluster.Placement, len(ids))
	for _, id := range ids {
		if p, ok := c.gossip[id]; ok {
			out[id] = p
		}
	}
	return out
}
func (c *cov97Cluster) AuthoritativePlacementsByIDs(_ context.Context, ids []string) (map[string]cluster.Placement, error) {
	out := make(map[string]cluster.Placement, len(ids))
	for _, id := range ids {
		if p, ok := c.auth[id]; ok {
			out[id] = p
		}
	}
	return out, nil
}

// droppingProbePusher removes a target while the probe is in flight, so the
// refresh sees a peer that was in the captured job but is no longer a
// target, and reports the probe error.
type droppingProbePusher struct {
	fakePeerPusher
	sandboxID string
	inc       string
	drop      string
}

func (p *droppingProbePusher) ProbeSecretOnPeers(ctx context.Context, sandboxID, incarnationID string, recipients []string, gen int64) ([]string, error) {
	if sandboxID == p.sandboxID {
		hs := holderSetFor(p.sandboxID, p.inc)
		hs.mu.Lock()
		delete(hs.targets, p.drop)
		hs.mu.Unlock()
	}
	return p.fakePeerPusher.ProbeSecretOnPeers(ctx, sandboxID, incarnationID, recipients, gen)
}

func TestCov97HolderRefreshBranches(t *testing.T) {
	const (
		inc   = "inc-cov97"
		self  = "node-a"
		peer  = "node-b"
		dead  = "node-dead"
		expA  = "sb-cov97-exp-a"
		expB  = "sb-cov97-exp-b"
		probe = "sb-cov97-probe"
		gone  = "sb-cov97-gone"
	)
	for _, id := range []string{expA, expB, probe, gone} {
		clearSecretFanoutHolders(id)
	}
	t.Cleanup(func() {
		for _, id := range []string{expA, expB, probe, gone} {
			clearSecretFanoutHolders(id)
		}
	})

	live := cluster.Placement{IncarnationID: inc, SecretSealGeneration: 3, SecretRecipients: []string{self, peer}}
	cl := &cov97Cluster{
		Noop:    cluster.NewNoop(self, "http://"+self, ""),
		members: []cluster.Member{{NodeID: self, Alive: true}, {NodeID: peer, Alive: true}},
		gossip: map[string]cluster.Placement{
			expA: live, expB: live, probe: live, gone: live,
		},
		auth: map[string]cluster.Placement{probe: live},
	}
	pusher := &droppingProbePusher{
		fakePeerPusher: fakePeerPusher{probeStrict: true, probeErr: errors.New("partition")},
		sandboxID:      probe, inc: inc, drop: peer,
	}
	svc := &Service{
		cfg:                  config.Config{EnableCluster: true},
		cluster:              cl,
		logger:               slog.New(slog.NewTextHandler(io.Discard, nil)),
		testSecretPeerPusher: pusher,
	}

	// Two reseal candidates with distinct non-zero clocks, so the fair-queue
	// sort takes the "both already attempted" comparison rather than the
	// zero-clock shortcuts.
	for i, id := range []string{expA, expB} {
		setSecretHolderTargets(id, inc, 1, []string{self, dead})
		hs := holderSetFor(id, inc)
		hs.mu.Lock()
		hs.lastExpand = time.Now().Add(-time.Duration(i+1) * time.Hour)
		hs.mu.Unlock()
	}
	setSecretHolderTargets(probe, inc, 3, []string{self, peer})
	hs := holderSetFor(probe, inc)
	hs.mu.Lock()
	hs.nodes = nil
	hs.mu.Unlock()
	setSecretHolderTargets(gone, inc, 3, []string{self, peer})
	goneHS := holderSetFor(gone, inc)
	goneHS.mu.Lock()
	goneHS.nodes[peer] = time.Now().Add(-secretHolderACKTTL)
	goneHS.mu.Unlock()

	svc.refreshSecretHolderPossession(context.Background())

	pusher.mu.Lock()
	probes := pusher.probeByID[probe]
	pusher.mu.Unlock()
	if probes == 0 {
		t.Fatal("probe sandbox was not refreshed")
	}
}

func TestCov97SecretReconcileLogsStoreErrors(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
		if err != nil {
			t.Fatal(err)
		}
		st.Close()
		cl := &cov97Cluster{
			Noop: cluster.NewNoop("self", "http://self", ""),
		}
		svc := &Service{
			cfg:     config.Config{SecretTombRetentionDays: 1, AuditDeletedGrace: time.Hour},
			store:   st,
			cluster: cl,
			logger:  slog.New(slog.DiscardHandler),
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		svc.StartSecretDeleteOutboxReconcile(ctx)
		synctest.Wait()
		time.Sleep(31 * time.Second)
		synctest.Wait()
		cancel()
		synctest.Wait()
	})
}
