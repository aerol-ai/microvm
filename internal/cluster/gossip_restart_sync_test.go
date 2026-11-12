package cluster

import (
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/testport"
	"github.com/hashicorp/memberlist"
)

// freeGossipPort returns a loopback port free for both TCP and UDP, which
// memberlist binds together. A restarted node has to come back on the same
// one, so ":0" will not do.
func freeGossipPort(t *testing.T) int {
	t.Helper()
	return testport.Reserve(t, true)
}

type restartGossipNode struct {
	id, role, addr, cacheDir string
	peers                    []string
	refresh                  time.Duration
	gn                       *gossipNode
}

func (n *restartGossipNode) start(t *testing.T, key []byte) {
	t.Helper()
	gn, err := setupGossip(gossipSetupConfig{
		NodeID: n.id, BindAddr: n.addr, AdvertiseAddr: n.addr,
		APIURL: "http://" + n.addr, DataPlaneHost: "127.0.0.1",
		RaftAddr: n.addr, InternalURL: "https://" + n.addr, Role: n.role,
		BootstrapPeers: n.peers, GossipInterval: n.refresh,
		SecretKey: key, PeerCacheDir: n.cacheDir,
	}, nil, nil)
	if err != nil {
		t.Fatalf("start %s: %v", n.id, err)
	}
	n.gn = gn
}

// crash stops gossip without a leave message, as SIGKILL does.
func (n *restartGossipNode) crash() {
	if n.gn == nil {
		return
	}
	n.gn.stopRefresh()
	<-n.gn.refreshDone
	_ = n.gn.ml.Shutdown()
	n.gn = nil
}

func (n *restartGossipNode) seesAlive(ids []string) bool {
	if n.gn == nil {
		return false
	}
	alive := map[string]bool{}
	for _, m := range n.gn.ml.Members() {
		if m.State == memberlist.StateAlive {
			alive[m.Name] = true
		}
	}
	for _, id := range ids {
		if !alive[id] {
			return false
		}
	}
	return true
}

// UC-481 on loopback: every server restarts at once, and each must see every
// worker and the ingress again without help from them.
//
// The two other ways back are switched off so the test cannot pass by luck:
// memberlist's periodic full sync (PushPullInterval 0), and the agents'
// rejoin (their refresh loop never ticks). A restarted server then learns the
// agents only by dialling the members it remembered (syncRememberedPeers).
// Without that it never sees them here; live, it saw them after up to 58 s,
// when an agent's full sync came round.
func TestEveryServerSeesTheAgentsRightAfterAllServersRestart(t *testing.T) {
	if testing.Short() {
		t.Skip("multi-node gossip restart test")
	}
	saved := testTuneMemberlist
	t.Cleanup(func() { testTuneMemberlist = saved })
	testTuneMemberlist = func(c *memberlist.Config) {
		if saved != nil {
			saved(c)
		}
		c.PushPullInterval = 0
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	// With the full sync off, gossip alone may miss a node at first start,
	// so every node joins, and is joined by, the ones it must see directly:
	// each server the servers before it, each agent every server.
	var servers, agents, all []*restartGossipNode
	var serverAddrs []string
	for i := 1; i <= 3; i++ {
		n := &restartGossipNode{id: fmt.Sprintf("server-%d", i), role: config.NodeRoleServer,
			addr: fmt.Sprintf("127.0.0.1:%d", freeGossipPort(t)), cacheDir: t.TempDir(), refresh: 50 * time.Millisecond,
			peers: append([]string(nil), serverAddrs...)}
		serverAddrs = append(serverAddrs, n.addr)
		servers = append(servers, n)
	}
	for i, role := range []string{config.NodeRoleIngress, config.NodeRoleWorker, config.NodeRoleWorker, config.NodeRoleWorker} {
		agents = append(agents, &restartGossipNode{id: fmt.Sprintf("agent-%d", i+1), role: role,
			addr: fmt.Sprintf("127.0.0.1:%d", freeGossipPort(t)), cacheDir: t.TempDir(), peers: serverAddrs, refresh: time.Hour})
	}
	all = append(append(all, servers...), agents...)
	var allIDs, serverIDs, agentIDs []string
	for _, n := range all {
		allIDs = append(allIDs, n.id)
	}
	for _, n := range servers {
		serverIDs = append(serverIDs, n.id)
	}
	for _, n := range agents {
		agentIDs = append(agentIDs, n.id)
	}
	t.Cleanup(func() {
		for _, n := range all {
			n.crash()
		}
	})
	for _, n := range all {
		n.start(t, key)
	}
	waitFor(t, 10*time.Second, "every server to see every node, and every agent every server", func() bool {
		for _, s := range servers {
			if !s.seesAlive(allIDs) {
				return false
			}
		}
		for _, a := range agents {
			if !a.seesAlive(serverIDs) {
				return false
			}
		}
		return true
	})
	waitFor(t, 10*time.Second, "every server to remember some agents", func() bool {
		for _, s := range servers {
			if len(newGossipMemberCache(s.cacheDir).load()) != maxCachedMemberPeers {
				return false
			}
		}
		return true
	})

	for _, s := range servers {
		s.crash()
	}
	for _, s := range servers {
		s.start(t, key)
	}
	waitFor(t, 5*time.Second, "every restarted server to see every agent", func() bool {
		for _, s := range servers {
			if !s.seesAlive(agentIDs) {
				return false
			}
		}
		return true
	})
}
