package cluster

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

// zoned is a live worker in zone with cpuFree of 8 cores free.
func zoned(id, zone string, cpuFree float64) Member {
	labels := map[string]string{}
	if zone != "" {
		labels[models.PlacementZoneLabel] = zone
	}
	return Member{NodeID: id, APIURL: "http://" + id, Alive: true, Role: config.NodeRoleWorker, Capacity: capacity.Snapshot{
		HostCPUCores: 8, HostMemoryTotalMB: 16384, CPUBudget: 8, MemoryBudgetMB: 16384,
		ReservedCPU: 8 - cpuFree, CanAdmit: true, Labels: labels,
	}}
}

func cpuRoom(m Member) float64 { return m.Capacity.CPUBudget - m.Capacity.ReservedCPU }

func TestSpreadByZone(t *testing.T) {
	cases := []struct {
		name      string
		in        []Member
		wantZones map[string]bool // zones the pick may come from
	}{
		{name: "one node", in: []Member{zoned("a1", "a", 1)}, wantZones: map[string]bool{"a": true}},
		{name: "one zone stays whole", in: []Member{zoned("a1", "a", 1), zoned("a2", "a", 7)}, wantZones: map[string]bool{"a": true}},
		{name: "no zones anywhere (plain VM cluster)", in: []Member{zoned("n1", "", 1), zoned("n2", "", 7)}, wantZones: map[string]bool{"": true}},
		{name: "two zones: the roomier wins", in: []Member{zoned("a1", "a", 1), zoned("a2", "a", 2), zoned("b1", "b", 7)}, wantZones: map[string]bool{"b": true}},
		{name: "three zones: the fullest never wins", in: []Member{zoned("a1", "a", 1), zoned("b1", "b", 5), zoned("c1", "c", 7)}, wantZones: map[string]bool{"b": true, "c": true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for i := 0; i < 50; i++ {
				got := spreadByZone(tc.in, cpuRoom)
				if len(got) == 0 {
					t.Fatal("empty pool")
				}
				z := memberZone(got[0])
				if !tc.wantZones[z] {
					t.Fatalf("picked zone %q, want one of %v", z, tc.wantZones)
				}
				for _, m := range got {
					if memberZone(m) != z {
						t.Fatalf("pool mixes zones: %+v", got)
					}
				}
			}
		})
	}
}

func TestZoneRoomSamplesAtMostSixteen(t *testing.T) {
	var big []Member
	for i := 0; i < 40; i++ {
		big = append(big, zoned(fmt.Sprintf("n%d", i), "a", 4), zoned(fmt.Sprintf("m%d", i), "b", 1))
	}
	calls := 0
	room := zoneRoom(big, "a", func(m Member) float64 {
		if memberZone(m) != "a" {
			t.Fatal("scored a member of another zone")
		}
		calls++
		return cpuRoom(m)
	})
	if calls != zoneSampleSize || room != 4 {
		t.Fatalf("calls %d room %v, want %d and 4", calls, room, zoneSampleSize)
	}
	if zoneRoom(nil, "a", cpuRoom) != 0 || zoneRoom(big, "c", cpuRoom) != 0 {
		t.Fatal("empty zone has room")
	}
}

// One zone (or none) is the usual cluster: its creates get the candidates
// back as they are, with no copy.
func TestSpreadByZoneOneZoneCopiesNothing(t *testing.T) {
	in := []Member{zoned("n1", "", 1), zoned("n2", "", 7), zoned("n3", "", 3)}
	if got := spreadByZone(in, cpuRoom); &got[0] != &in[0] || len(got) != len(in) {
		t.Fatal("one zone: candidates were copied")
	}
	allocs := testing.AllocsPerRun(100, func() { spreadByZone(in, cpuRoom) })
	if allocs > 1 {
		t.Fatalf("one zone: %v allocations per call, want at most the zone count", allocs)
	}
}

// The placement cost at the design's scale (2,000 workers), with no zones
// and with three.
func BenchmarkSpreadByZone(b *testing.B) {
	for _, zones := range []int{1, 3} {
		var in []Member
		for i := 0; i < 2000; i++ {
			z := ""
			if zones > 1 {
				z = fmt.Sprintf("z-%d", i%zones)
			}
			in = append(in, zoned(fmt.Sprintf("n%d", i), z, float64(i%8)))
		}
		b.Run(fmt.Sprintf("zones=%d", zones), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				spreadByZone(in, cpuRoom)
			}
		})
	}
}

func TestWithoutZone(t *testing.T) {
	a, b := zoned("a1", "a", 4), zoned("b1", "b", 4)
	for _, tc := range []struct {
		name string
		in   []Member
		zone string
		want []string
	}{
		{name: "no zone to avoid", in: []Member{a, b}, zone: "", want: []string{"a1", "b1"}},
		{name: "drops the zone", in: []Member{a, b}, zone: "a", want: []string{"b1"}},
		{name: "only that zone: keep it", in: []Member{a}, zone: "a", want: []string{"a1"}},
	} {
		got := withoutZone(tc.in, tc.zone)
		if len(got) != len(tc.want) {
			t.Fatalf("%s: got %d members, want %v", tc.name, len(got), tc.want)
		}
		for i := range got {
			if got[i].NodeID != tc.want[i] {
				t.Fatalf("%s: got %s, want %v", tc.name, got[i].NodeID, tc.want)
			}
		}
	}
}

func TestZoneMemory(t *testing.T) {
	var nilMem *zoneMemory
	nilMem.record("n", "a")
	nilMem.forget("n")
	if nilMem.zoneOf("n") != "" {
		t.Fatal("nil memory knows a zone")
	}
	z := &zoneMemory{}
	z.record("", "a")
	z.record("n", "a")
	z.record("n", "b") // a node that moved keeps its newest zone
	if z.zoneOf("n") != "b" {
		t.Fatalf("zoneOf = %q, want b", z.zoneOf("n"))
	}
	z.forget("n")
	if z.zoneOf("n") != "" {
		t.Fatal("forget kept the zone")
	}
	for i := 0; i < maxRememberedZones; i++ {
		z.record(fmt.Sprintf("n%d", i), "a")
	}
	z.record("late", "a")
	if z.zoneOf("late") != "" {
		t.Fatal("memory grew past its bound")
	}
	z.record("n1", "c") // known nodes still update at the bound
	if z.zoneOf("n1") != "c" {
		t.Fatal("a known node stopped updating at the bound")
	}

	leases := newCapacityLeaseCache("srv", nil, 5*time.Second, nil)
	leases.set("w1", zoned("w1", "eu-1b", 4).Capacity, time.Now())
	leases.retain(map[string]struct{}{"srv": {}}) // w1 left the membership view
	if got := leases.lastKnownZone("w1"); got != "eu-1b" {
		t.Fatalf("lastKnownZone after the lease was dropped = %q", got)
	}
	var nilLeases *capacityLeaseCache
	if nilLeases.lastKnownZone("w1") != "" {
		t.Fatal("nil cache knows a zone")
	}
	if (*Cluster)(nil).lastKnownZone("w1") != "" {
		t.Fatal("nil cluster knows a zone")
	}
}

// Nodes churn on Kubernetes (each replaced worker is a new ID): a full
// memory drops facts no heartbeat renewed for zoneFactStale, so new nodes
// keep their zone rule; facts heard recently are kept.
func TestZoneMemoryDropsStaleFacts(t *testing.T) {
	z := &zoneMemory{}
	t0 := time.Unix(1000, 0)
	for i := 0; i < maxRememberedZones; i++ {
		seen := t0
		if i%2 == 0 {
			seen = t0.Add(zoneFactStale) // heard recently
		}
		z.recordFact(fmt.Sprintf("n%d", i), nodeFact{zone: "a", seen: seen})
	}
	now := t0.Add(zoneFactStale + time.Minute)
	z.recordFact("new", nodeFact{zone: "b", seen: now})
	if z.zoneOf("new") != "b" {
		t.Fatal("a new node got no zone with the memory full of stale facts")
	}
	if z.zoneOf("n0") != "a" || z.zoneOf("n1") != "" {
		t.Fatalf("kept n0=%q (recent) and n1=%q (stale), want a and none", z.zoneOf("n0"), z.zoneOf("n1"))
	}
	// Full of recent facts: nothing to drop, nothing added.
	f := &zoneMemory{}
	for i := 0; i < maxRememberedZones; i++ {
		f.recordFact(fmt.Sprintf("n%d", i), nodeFact{zone: "a", seen: now})
	}
	f.recordFact("late", nodeFact{zone: "b", seen: now})
	if f.zoneOf("late") != "" {
		t.Fatal("memory grew past its bound")
	}
}

func zoneCluster(t *testing.T, members ...Member) *Cluster {
	t.Helper()
	idx := newGossipMemberIndex()
	idx.replace(members)
	leases := newCapacityLeaseCache("srv", nil, 5*time.Second, nil)
	for _, m := range members {
		leases.set(m.NodeID, m.Capacity, time.Now())
	}
	return &Cluster{nodeID: "srv", apiURL: "http://srv", fsm: newPlacementFSM(), gossip: &gossipNode{memberIndex: idx}, capacityLeases: leases}
}

func TestPlacementSpreadsAcrossZonesByRoom(t *testing.T) {
	c := zoneCluster(t, zoned("a1", "a", 1), zoned("a2", "a", 1), zoned("b1", "b", 8))
	for i := 0; i < 30; i++ {
		target, err := c.SelectPlacement(capacity.Request{CPU: 0.5, MemoryMB: 64})
		if err != nil || target.NodeID != "b1" {
			t.Fatalf("placement = %+v %v, want b1 (the roomier zone)", target, err)
		}
	}
	// A zone rule still wins: spreading only chooses among allowed nodes.
	for i := 0; i < 10; i++ {
		target, err := c.SelectPlacement(capacity.Request{CPU: 0.5, MemoryMB: 64, Labels: map[string]string{models.PlacementZoneLabel: "a"}})
		if err != nil || (target.NodeID != "a1" && target.NodeID != "a2") {
			t.Fatalf("zone rule placement = %+v %v, want zone a", target, err)
		}
	}
	// The candidates handed back for secret recipients are not narrowed.
	_, candidates, err := c.SelectPlacementWithCandidates(capacity.Request{CPU: 0.5, MemoryMB: 64})
	if err != nil || len(candidates) != 3 {
		t.Fatalf("candidates = %d %v, want all 3", len(candidates), err)
	}
}

func TestFailoverAvoidsTheDeadNodesZone(t *testing.T) {
	dead := zoned("a-dead", "a", 0)
	dead.Alive = false
	// a2 has the most room, but it is in the zone that just lost a node.
	c := zoneCluster(t, dead, zoned("a2", "a", 8), zoned("b1", "b", 2))
	secretless := Placement{SandboxID: "sb", OwnerNodeID: "a-dead", Spec: recreatePolicySpec(1)}
	for i := 0; i < 20; i++ {
		target, err := c.selectFailoverTarget(secretless, "a-dead")
		if err != nil || target.NodeID != "b1" {
			t.Fatalf("secretless failover = %+v %v, want b1", target, err)
		}
	}
	// The scan used for sandboxes with sealed secrets follows the same rule.
	sealed := secretless
	sealed.SecretRef = "local:sb"
	sealed.SecretSealGeneration = 1
	sealed.SecretRecipients = []string{"a-dead", "a2", "b1"}
	if !placementHasSecretHandle(sealed) {
		t.Skip("placement handle shape changed; update the fixture")
	}
	target, err := c.selectFailoverTarget(sealed, "a-dead")
	if err != nil || target.NodeID != "b1" {
		t.Fatalf("sealed failover = %+v %v, want b1", target, err)
	}

	// No room outside the zone: failing over into it beats no failover.
	full := zoneCluster(t, dead, zoned("a2", "a", 8), zoned("b1", "b", 0))
	target, err = full.selectFailoverTarget(secretless, "a-dead")
	if err != nil || target.NodeID != "a2" {
		t.Fatalf("failover with zone b full = %+v %v, want a2", target, err)
	}
	target, err = full.selectFailoverTarget(sealed, "a-dead")
	if err != nil || target.NodeID != "a2" {
		t.Fatalf("sealed failover with zone b full = %+v %v, want a2", target, err)
	}

	// A dead node whose zone this server never heard: no zone rule (today's
	// behavior), so the roomiest node wins.
	target, err = c.selectFailoverTarget(sealed, "never-seen")
	if err != nil || target.NodeID != "a2" {
		t.Fatalf("unknown zone failover = %+v %v, want a2", target, err)
	}
	if _, err := c.selectFailoverTarget(Placement{}, "a-dead"); !errors.Is(err, ErrNoReassignTarget) {
		t.Fatalf("no spec: %v", err)
	}
}

func TestSecretBackupsGoToOtherZones(t *testing.T) {
	owner := zoned("own", "a", 4)
	cases := []struct {
		name       string
		candidates []Member
		backups    int
		// wantZones: the zones of the backups, in order.
		wantZones []string
	}{
		{
			name:       "two backups land in the two other zones",
			candidates: []Member{owner, zoned("a1", "a", 4), zoned("a2", "a", 4), zoned("b1", "b", 4), zoned("b2", "b", 4), zoned("c1", "c", 4)},
			backups:    2,
			wantZones:  []string{"b|c", "b|c"},
		},
		{
			name:       "a third backup prefers an unknown zone over the owner's",
			candidates: []Member{owner, zoned("a1", "a", 4), zoned("b1", "b", 4), zoned("x1", "", 4)},
			backups:    3,
			wantZones:  []string{"b", "", "a"},
		},
		{
			name:       "only the owner's zone left: it is used",
			candidates: []Member{owner, zoned("a1", "a", 4), zoned("a2", "a", 4)},
			backups:    2,
			wantZones:  []string{"a", "a"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			zoneOf := map[string]string{}
			for _, m := range tc.candidates {
				zoneOf[m.NodeID] = memberZone(m)
			}
			for _, sb := range []string{"sb-1", "sb-2", "sb-3", "sb-4"} {
				got := SelectSecretRecipients(sb, tc.candidates, "own", tc.backups)
				if len(got) != tc.backups+1 || got[0] != "own" {
					t.Fatalf("%s: recipients %v", sb, got)
				}
				seen := map[string]bool{}
				for i, id := range got[1:] {
					z := zoneOf[id]
					if !zoneIn(z, tc.wantZones[i]) {
						t.Fatalf("%s: backup %d is %s in zone %q, want %q (%v)", sb, i, id, z, tc.wantZones[i], got)
					}
					if tc.wantZones[i] == "b|c" && seen[z] {
						t.Fatalf("%s: two backups in zone %s: %v", sb, z, got)
					}
					seen[z] = true
				}
				// Stable for a sandbox.
				again := SelectSecretRecipients(sb, tc.candidates, "own", tc.backups)
				if fmt.Sprint(again) != fmt.Sprint(got) {
					t.Fatalf("%s: not stable: %v then %v", sb, got, again)
				}
			}
		})
	}
}

// A cluster without zones keeps exactly the HRW set it had before C10.
func TestSecretBackupsWithoutZonesUnchanged(t *testing.T) {
	var candidates []Member
	for i := 0; i < 8; i++ {
		candidates = append(candidates, zoned(fmt.Sprintf("n%d", i), "", 4))
	}
	for _, sb := range []string{"sb-a", "sb-b", "sb-c"} {
		got := SelectSecretRecipients(sb, candidates, "n0", 2)
		best, second := "", ""
		var bs, ss uint64
		for _, m := range candidates[1:] {
			s := secretRecipientScore(sb, m.NodeID)
			switch {
			case best == "" || s > bs:
				second, ss = best, bs
				best, bs = m.NodeID, s
			case second == "" || s > ss:
				second, ss = m.NodeID, s
			}
		}
		if fmt.Sprint(got) != fmt.Sprint([]string{"n0", best, second}) {
			t.Fatalf("%s: %v, want HRW order [n0 %s %s]", sb, got, best, second)
		}
	}
}

func zoneIn(z, want string) bool {
	if want == "b|c" {
		return z == "b" || z == "c"
	}
	return z == want
}
