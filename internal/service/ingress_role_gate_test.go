package service

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/caddy"
)

// shardRecordingCluster records every shard filter the service asks with.
type shardRecordingCluster struct {
	*cluster.Noop
	mu      sync.Mutex
	filters []cluster.PlacementShardFilter
	members []cluster.Member
	rows    []cluster.Placement
}

func newShardRecordingCluster(self string, ingressNodes int) *shardRecordingCluster {
	c := &shardRecordingCluster{Noop: cluster.NewNoop(self, "http://"+self, "")}
	c.members = []cluster.Member{{NodeID: self, Alive: true, Role: config.NodeRoleWorker, APIURL: "http://" + self}}
	for i := range ingressNodes {
		id := fmt.Sprintf("ing-%03d", i)
		c.members = append(c.members, cluster.Member{NodeID: id, Alive: true, Role: config.NodeRoleIngress, APIURL: "http://" + id})
	}
	return c
}

func (c *shardRecordingCluster) PlacementsForShards(filter cluster.PlacementShardFilter) []cluster.Placement {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.filters = append(c.filters, filter)
	return append([]cluster.Placement(nil), c.rows...)
}

func (c *shardRecordingCluster) LocalMembers() []cluster.Member {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]cluster.Member(nil), c.members...)
}

func (c *shardRecordingCluster) Members() []cluster.Member { return c.LocalMembers() }

func (c *shardRecordingCluster) requested() []cluster.PlacementShardFilter {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]cluster.PlacementShardFilter(nil), c.filters...)
}

// A dedicated worker installs no peer-forwarding routes, so its zombie-route
// sweep must not read the cluster placement view at all. Before the role gate
// the shard helper added the worker to a hypothetical ingress ring: at 100
// ingress nodes that asked for a couple of hundred unrelated shards, and at
// small ingress counts it asked for the whole fleet.
func TestWorkerRouteGCRequestsNoIngressShards(t *testing.T) {
	for _, tc := range []struct {
		name         string
		ingressNodes int
	}{
		{"small ingress tier", 9},
		{"sharded ingress tier", 100},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cl := newShardRecordingCluster("wrk-self", tc.ingressNodes)
			svc := &Service{
				cfg:     config.Config{EnableCluster: true, NodeRole: config.NodeRoleWorker},
				cluster: cl,
			}
			svc.addClusterIngressExpectedRoutes(map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{})

			if got := cl.requested(); len(got) != 0 {
				t.Fatalf("worker route GC made %d placement reads (%+v); it installs no peer-forwarding routes", len(got), got)
			}
			filter := svc.clusterIngressShardFilter(cl, "wrk-self")
			if !filter.None {
				t.Fatalf("worker shard filter = %+v, want an explicit no-shards filter (the zero value means ALL shards)", filter)
			}
		})
	}
}

// The gate must not disable real ingress work.
func TestIngressNodeStillRequestsItsShards(t *testing.T) {
	cl := newShardRecordingCluster("ing-000", 9)
	cl.members[0] = cluster.Member{NodeID: "ing-000", Alive: true, Role: config.NodeRoleIngress, APIURL: "http://ing-000"}
	svc := &Service{
		cfg:     config.Config{EnableCluster: true, NodeRole: config.NodeRoleIngress},
		cluster: cl,
	}
	svc.addClusterIngressExpectedRoutes(map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{})

	got := cl.requested()
	if len(got) != 1 {
		t.Fatalf("ingress node made %d placement reads, want 1", len(got))
	}
	if got[0].None {
		t.Fatalf("ingress node asked for no shards (%+v); it owns public routes", got[0])
	}
}

// Mixed / legacy-empty roles keep their pre-role-split behavior.
func TestMixedNodeStillReconcilesClusterIngress(t *testing.T) {
	for _, role := range []string{"", config.NodeRoleMixed} {
		svc := &Service{cfg: config.Config{EnableCluster: true, NodeRole: role}}
		if !svc.servesClusterIngress() {
			t.Fatalf("role %q must still serve cluster ingress", role)
		}
	}
	for _, role := range []string{config.NodeRoleWorker, config.NodeRoleServer, "server,worker"} {
		svc := &Service{cfg: config.Config{EnableCluster: true, NodeRole: role}}
		if svc.servesClusterIngress() {
			t.Fatalf("role %q must not install peer-forwarding routes", role)
		}
	}
}

// A non-ingress node must also skip the reconcile pass outright.
func TestReconcileClusterIngressSkipsNonIngressRoles(t *testing.T) {
	cl := newShardRecordingCluster("wrk-self", 9)
	svc := &Service{
		cfg:     config.Config{EnableCluster: true, NodeRole: config.NodeRoleWorker},
		cluster: cl,
		// Caddy is deliberately ENABLED: the role gate, not a disabled admin
		// client, has to be what stops the read.
		caddy: caddy.New(config.Config{EnableCaddy: true, HTTPClientTimeout: time.Second}),
	}
	if err := svc.ReconcileClusterIngress(context.Background()); err != nil {
		t.Fatalf("ReconcileClusterIngress: %v", err)
	}
	if got := cl.requested(); len(got) != 0 {
		t.Fatalf("worker reconcile read %d placement views (%+v)", len(got), got)
	}
}
