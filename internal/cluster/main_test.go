package cluster

import (
	"os"
	"testing"
	"time"

	"github.com/hashicorp/memberlist"
	"github.com/hashicorp/raft"
)

// TestMain gives in-process test clusters fast Raft and gossip timers. Production keeps
// raft's defaults (1 s heartbeat and election timeouts); here a node elects
// itself in 250-500 ms instead of 1-2 s. 100 ms timers were tried and made a
// two-node leader step down between test steps under -race on a busy machine
// (TestEvictDeadOwnerRemovesRaftVoter), so these keep a 250 ms margin.
func TestMain(m *testing.M) {
	testTuneRaft = func(c *raft.Config) {
		c.HeartbeatTimeout = 250 * time.Millisecond
		c.ElectionTimeout = 250 * time.Millisecond
		c.LeaderLeaseTimeout = 250 * time.Millisecond
		c.CommitTimeout = 10 * time.Millisecond
	}
	// Gossip probes and failure detection about 10x faster than memberlist's
	// LAN defaults (1 s probes, 4x suspicion, 30 s push-pull).
	testTuneMemberlist = func(c *memberlist.Config) {
		c.ProbeInterval = 100 * time.Millisecond
		c.ProbeTimeout = 50 * time.Millisecond
		c.SuspicionMult = 2
		c.GossipInterval = 20 * time.Millisecond
		c.PushPullInterval = time.Second
		c.GossipToTheDeadTime = 2 * time.Second
	}
	os.Exit(m.Run())
}
