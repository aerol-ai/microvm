package cluster

import (
	"fmt"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/capacity"
)

// BenchmarkSelectPlacementFleet measures E6's premise (plans/
// kubernetes-v2-architecture.md §9.4, L-f): choosing a worker walks the
// whole fleet on every create. It times one placement decision on the
// leader at fleet sizes up to past G3's 500 workers, three zones, every
// worker with room.
//
//	go test -run '^$' -bench BenchmarkSelectPlacementFleet ./internal/cluster/
func BenchmarkSelectPlacementFleet(b *testing.B) {
	for _, n := range []int{100, 500, 2000} {
		b.Run(fmt.Sprintf("workers=%d", n), func(b *testing.B) {
			c := &Cluster{
				nodeID: "server-0",
				apiURL: "http://server-0",
				fsm:    newPlacementFSM(),
				gossip: &gossipNode{memberIndex: newGossipMemberIndex()},
			}
			members := make([]Member, 0, n+6)
			for i := range 3 {
				members = append(members,
					Member{NodeID: fmt.Sprintf("server-%d", i), Alive: true, Role: config.NodeRoleServer},
					Member{NodeID: fmt.Sprintf("gateway-%d", i), Alive: true, Role: config.NodeRoleIngress})
			}
			for i := range n {
				id := fmt.Sprintf("worker-%04d", i)
				members = append(members, Member{
					NodeID: id, Alive: true, Role: config.NodeRoleWorker, APIURL: "http://" + id,
					Capacity: capacity.Snapshot{HostCPUCores: 16, HostMemoryTotalMB: 65536, CPUBudget: 15, MemoryBudgetMB: 60000,
						ReservedCPU: float64(i % 10), ReservedMemoryMB: (i % 10) * 4096,
						Labels: map[string]string{"zone": fmt.Sprintf("z-%c", 'a'+i%3)}},
				})
			}
			c.gossip.memberIndex.replace(members)
			req := capacity.Request{CPU: 1, MemoryMB: 1024}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := c.SelectPlacement(req); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkAdmitReservationFleet times the leader's check of one
// reservation at fleet sizes up to past G3's 500 workers. It read every
// member and its capacity lease; it reads the owner's now, so the cost is
// flat (C18, bench-full-4).
//
//	go test -run '^$' -bench BenchmarkAdmitReservationFleet ./internal/cluster/
func BenchmarkAdmitReservationFleet(b *testing.B) {
	for _, n := range []int{100, 500, 2000} {
		b.Run(fmt.Sprintf("workers=%d", n), func(b *testing.B) {
			c := sampledFleet(n, nil, nil)
			cmd := reserveOn("sb-bench", "worker-0001")
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := c.admitReservationCommand(cmd); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkOwnerLookupFleet times the member read behind every owner
// lookup the leader answers (OwnerOf, then peerInternalURL).
func BenchmarkOwnerLookupFleet(b *testing.B) {
	for _, n := range []int{100, 500, 2000} {
		b.Run(fmt.Sprintf("workers=%d", n), func(b *testing.B) {
			c := sampledFleet(n, nil, nil)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = c.gossip.peerInternalURL("worker-0001")
			}
		})
	}
}
