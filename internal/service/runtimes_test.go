package service

import (
	"maps"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

// runtimeOffersCluster is a cluster client that holds members' capacity the
// way a server's lease overlay (or a worker's control-plane answer) does.
// It counts Members() reads: on a worker each one is a control-plane call.
type runtimeOffersCluster struct {
	*cluster.Noop
	members []cluster.Member
	reads   atomic.Int32
}

func (c *runtimeOffersCluster) Members() []cluster.Member {
	c.reads.Add(1)
	return c.members
}

// runtimeOffersServer adds the one-read drained set and the deny list a
// server and an agent both have.
type runtimeOffersServer struct {
	*runtimeOffersCluster
	drained map[string]bool
	denied  map[string]bool
}

func (c *runtimeOffersServer) DrainedNodes() map[string]bool { return c.drained }
func (c *runtimeOffersServer) IsNodeDenied(id string) bool   { return c.denied[id] }

// IsNodeDrained must never be asked per member: on a worker each answer is
// a control-plane round trip.
func (c *runtimeOffersServer) IsNodeDrained(string) bool {
	panic("RuntimeOffers asked IsNodeDrained per member")
}

func offerMember(id, role string, runtimes ...string) cluster.Member {
	return cluster.Member{NodeID: id, Role: role, Alive: true,
		Capacity: capacity.Snapshot{HostCPUCores: 8, HostMemoryTotalMB: 16384, SupportedRuntimes: runtimes}}
}

func TestRuntimeOffersSingleNode(t *testing.T) {
	for _, tc := range []struct {
		name     string
		admitter *capacity.Admitter
		want     map[string]int
	}{
		{"no admitter", nil, map[string]int{}},
		{"default docker", capacity.New(capacity.HostInfo{CPUCores: 4, MemoryTotalMB: 8192}, capacity.Limits{}, nil),
			map[string]int{models.RuntimeDocker: 1}},
		{"declared", capacity.New(capacity.HostInfo{CPUCores: 4, MemoryTotalMB: 8192,
			SupportedRuntimes: []string{models.RuntimeDocker, models.RuntimeGvisor, models.RuntimeFirecracker}}, capacity.Limits{}, nil),
			map[string]int{models.RuntimeDocker: 1, models.RuntimeGvisor: 1, models.RuntimeFirecracker: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := &Service{cfg: config.Config{}, admitter: tc.admitter}
			if got := svc.RuntimeOffers(); !maps.Equal(got, tc.want) {
				t.Fatalf("offers = %v, want %v", got, tc.want)
			}
		})
	}
	// Cluster mode with no client attached falls back to this node's own.
	svc := &Service{cfg: config.Config{EnableCluster: true},
		admitter: capacity.New(capacity.HostInfo{CPUCores: 4, MemoryTotalMB: 8192}, capacity.Limits{}, nil)}
	if got := svc.RuntimeOffers(); !maps.Equal(got, map[string]int{models.RuntimeDocker: 1}) {
		t.Fatalf("cluster without a client = %v", got)
	}
}

// TestRuntimeOffersCluster: a member counts when placement would consider
// it at all (alive, not restarting, a sandbox-owning role, a fresh capacity
// heartbeat, not drained, not deleted), whether or not it has room. Each
// member counts a name once.
func TestRuntimeOffersCluster(t *testing.T) {
	stale := offerMember("stale", "worker", models.RuntimeIsolate)
	stale.CapacityStale = true
	dead := offerMember("dead", "worker", models.RuntimeIsolate)
	dead.Alive = false
	restarting := offerMember("restarting", "worker", models.RuntimeIsolate)
	restarting.Restarting = true
	noHeartbeat := offerMember("no-heartbeat", "worker", models.RuntimeIsolate)
	noHeartbeat.Capacity.HostCPUCores, noHeartbeat.Capacity.HostMemoryTotalMB = 0, 0
	full := offerMember("full", "worker", models.RuntimeWasm)
	full.Capacity.CanAdmit = false
	full.Capacity.Reasons = []string{"memory"}
	members := []cluster.Member{
		offerMember("w1", "worker", models.RuntimeDocker, models.RuntimeFirecracker),
		offerMember("w2", "worker", models.RuntimeDocker, models.RuntimeDocker, ""),
		offerMember("mixed", "", models.RuntimeGvisor), // a pre-role build reads as mixed
		offerMember("legacy", "worker"),                // pre-field: claims nothing
		offerMember("srv", "server", models.RuntimeIsolate),
		offerMember("gw", "ingress", models.RuntimeIsolate),
		offerMember("drained", "worker", models.RuntimeIsolate),
		offerMember("deleted", "worker", models.RuntimeIsolate),
		stale, dead, restarting, noHeartbeat, full,
	}
	base := &runtimeOffersCluster{Noop: cluster.NewNoop("srv", "http://srv", ""), members: members}
	for _, tc := range []struct {
		name   string
		client cluster.Client
		want   map[string]int
	}{
		{"server", &runtimeOffersServer{runtimeOffersCluster: base,
			drained: map[string]bool{"drained": true}, denied: map[string]bool{"deleted": true}},
			map[string]int{models.RuntimeDocker: 2, models.RuntimeFirecracker: 1, models.RuntimeGvisor: 1, models.RuntimeWasm: 1}},
		// A client with no one-read drained set and no deny list: drained
		// and deleted members count, rather than one call per member.
		{"client without the sets", base,
			map[string]int{models.RuntimeDocker: 2, models.RuntimeFirecracker: 1, models.RuntimeGvisor: 1, models.RuntimeWasm: 1, models.RuntimeIsolate: 2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := &Service{cfg: config.Config{EnableCluster: true}}
			svc.AttachCluster(tc.client)
			if got := svc.RuntimeOffers(); !maps.Equal(got, tc.want) {
				t.Fatalf("offers = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestRuntimeOffersCache: in a cluster the answer is read once per TTL, so
// a burst of callers on a worker makes one control-plane call, and no
// caller can change what the next one reads.
func TestRuntimeOffersCache(t *testing.T) {
	stub := &runtimeOffersCluster{Noop: cluster.NewNoop("srv", "http://srv", ""),
		members: []cluster.Member{offerMember("w1", "worker", models.RuntimeDocker)}}
	svc := &Service{cfg: config.Config{EnableCluster: true}}
	svc.AttachCluster(stub)
	now := time.Unix(1_700_000_000, 0)
	svc.runtimeOffers.now = func() time.Time { return now }

	first := svc.RuntimeOffers()
	first[models.RuntimeDocker] = 99
	stub.members = append(stub.members, offerMember("w2", "worker", models.RuntimeDocker))
	now = now.Add(runtimeOffersTTL - time.Millisecond)
	if got := svc.RuntimeOffers(); got[models.RuntimeDocker] != 1 || stub.reads.Load() != 1 {
		t.Fatalf("inside the TTL: offers %v after %d reads, want the cached {docker:1} after 1", got, stub.reads.Load())
	}
	now = now.Add(time.Millisecond)
	if got := svc.RuntimeOffers(); got[models.RuntimeDocker] != 2 || stub.reads.Load() != 2 {
		t.Fatalf("after the TTL: offers %v after %d reads, want {docker:2} after 2", got, stub.reads.Load())
	}
}
