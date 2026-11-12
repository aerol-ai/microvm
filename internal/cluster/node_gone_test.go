package cluster

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/capacity"
)

func TestGoneTrackerEarliestFailover(t *testing.T) {
	const lease = 15 * time.Second
	base := time.Unix(1000, 0)
	cases := []struct {
		name        string
		leaderSince time.Time
		contact     time.Time
		gone        bool
		lone        bool          // only one contact
		gap         time.Duration // between the two contacts (default lease/3)
		heard       time.Duration // last heartbeat after the last contact (default 0)
		want        time.Time
		wantOK      bool
	}{
		{name: "not gone", leaderSince: base, wantOK: false},
		{name: "not leading", gone: true, wantOK: false},
		{
			name: "contact after takeover counts", gone: true, leaderSince: base, contact: base.Add(10 * time.Second),
			want: base.Add(10*time.Second + lease + lease/15), wantOK: true,
		},
		{
			// It was not renewing by reads (no recreate-policy sandbox
			// ran), so its lease may be newer than anything seen here.
			name: "no contact seen: the grace", gone: true, leaderSince: base, wantOK: false,
		},
		{
			// A read the old leader answered may be as late as just after
			// this one took over.
			name: "contact older than takeover: takeover wins", gone: true, leaderSince: base, contact: base.Add(-time.Minute),
			want: base.Add(leaderHandoverMargin + lease + lease/15), wantOK: true,
		},
		{
			name: "one lone contact: the grace", gone: true, leaderSince: base, contact: base.Add(10 * time.Second), lone: true, wantOK: false,
		},
		{
			name: "contacts further apart than a read interval: the grace", gone: true, leaderSince: base, contact: base.Add(10 * time.Second), gap: lease, wantOK: false,
		},
		{
			// It read every 5 s, then went idle (its recreate sandboxes
			// stopped) and kept heartbeating: its lease since is its own.
			name: "reads stopped long before its last heartbeat: the grace", gone: true, leaderSince: base, contact: base.Add(10 * time.Second), heard: time.Minute, wantOK: false,
		},
		{
			name: "last read one interval before its last heartbeat: early", gone: true, leaderSince: base, contact: base.Add(10 * time.Second), heard: lease / 3,
			want: base.Add(10*time.Second + lease + lease/15), wantOK: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var g goneTracker
			if !tc.leaderSince.IsZero() {
				g.observeLeadership(true, 1, tc.leaderSince)
			}
			if !tc.contact.IsZero() {
				gap := tc.gap
				if gap == 0 {
					gap = lease / 3
				}
				if !tc.lone {
					g.noteContact("n", tc.contact.Add(-gap), lease)
				}
				g.noteContact("n", tc.contact, lease)
			}
			if tc.gone {
				g.markGone("n", base)
			}
			heard := tc.contact
			if tc.heard != 0 {
				heard = tc.contact.Add(tc.heard)
			}
			got, ok := g.earliestFailover("n", lease, heard)
			if ok != tc.wantOK || !got.Equal(tc.want) {
				t.Fatalf("earliestFailover = %v %v, want %v %v", got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

func TestGoneTrackerBookkeeping(t *testing.T) {
	var g goneTracker
	t0 := time.Unix(100, 0)
	g.observeLeadership(true, 3, t0)
	g.observeLeadership(true, 3, t0.Add(time.Hour)) // still the same term
	g.noteContact("n", t0.Add(4*time.Second), time.Minute)
	g.noteContact("n", t0.Add(5*time.Second), time.Minute)
	g.noteContact("n", t0.Add(time.Second), time.Minute) // an older answer never moves it back
	g.markGone("n", t0)
	g.markGone("n", t0.Add(time.Hour)) // the first mark stays
	if at, ok := g.earliestFailover("n", 3*time.Second, t0.Add(5*time.Second)); !ok || !at.Equal(t0.Add(5*time.Second+3*time.Second+200*time.Millisecond)) {
		t.Fatalf("earliest = %v %v", at, ok)
	}
	g.clearGone("n")
	if g.isGone("n") {
		t.Fatal("clearGone kept the mark")
	}
	g.observeLeadership(false, 0, t0)
	g.markGone("n", t0)
	if _, ok := g.earliestFailover("n", 3*time.Second, time.Time{}); ok {
		t.Fatal("a follower computed an early failover")
	}
	// Bounded like zoneMemory.
	var b goneTracker
	b.observeLeadership(true, 1, t0)
	for i := 0; i < maxGoneMarks; i++ {
		b.markGone(fmt.Sprintf("n%d", i), t0)
		b.noteContact(fmt.Sprintf("n%d", i), t0, time.Minute)
	}
	b.markGone("late", t0)
	b.noteContact("late", t0, time.Minute)
	if b.isGone("late") || !b.contacts["late"].at.IsZero() {
		t.Fatal("gone tracker grew past its bound")
	}
	b.noteContact("n1", t0.Add(time.Second), time.Minute) // known nodes still update
	if !b.contacts["n1"].at.Equal(t0.Add(time.Second)) {
		t.Fatal("a known node stopped updating at the bound")
	}
	// A contact it could not record may have been the latest: a node with
	// no recorded contact gets no early failover now.
	b.markGone("n1", t0) // n1 renewed by reads one second apart: still early
	if _, ok := b.earliestFailover("n1", 3*time.Second, t0.Add(time.Second)); !ok {
		t.Fatal("a recorded node lost its early failover")
	}
	b.gone = map[string]time.Time{"late": t0}
	if _, ok := b.earliestFailover("late", time.Second, t0); ok {
		t.Fatal("a node whose contact was dropped failed over early")
	}
}

// Contacts older than the lease bound change no decision, so a full map
// drops them for new ones: node churn (every replaced worker is a new ID)
// cannot fill it for good.
func TestGoneTrackerDropsStaleContacts(t *testing.T) {
	var g goneTracker
	t0 := time.Unix(100, 0)
	const stale = 16 * time.Second
	g.observeLeadership(true, 1, t0)
	for i := 0; i < maxGoneMarks; i++ {
		g.noteContact(fmt.Sprintf("old%d", i), t0, stale)
	}
	later := t0.Add(time.Minute)
	g.noteContact("new", later, stale)
	if !g.contacts["new"].at.Equal(later) || len(g.contacts) != 1 {
		t.Fatalf("stale contacts kept: %d, new %v", len(g.contacts), g.contacts["new"])
	}
}

// Leadership lost and won back between two looks: another leader may have
// answered the node's reads in between, so the start is the new term's,
// and this leader's older answers no longer count.
func TestGoneTrackerNewTermIsANewStart(t *testing.T) {
	const lease = 15 * time.Second
	var g goneTracker
	t0 := time.Unix(100, 0)
	g.observeLeadership(true, 4, t0)
	g.noteContact("n", t0.Add(time.Second), lease)
	g.markGone("n", t0)
	t1 := t0.Add(time.Hour)
	// No look while it lost and won leadership back; the next look is in
	// term 6, and the node goes on reading.
	g.observeLeadership(true, 6, t1)
	g.noteContact("n", t1.Add(-time.Second), lease)
	g.noteContact("n", t1.Add(4*time.Second), lease)
	at, ok := g.earliestFailover("n", lease, t1.Add(4*time.Second))
	if want := t1.Add(4*time.Second + lease + lease/15); !ok || !at.Equal(want) {
		t.Fatalf("earliest = %v %v, want %v (from this term's contacts)", at, ok, want)
	}
	if c := g.contacts["n"]; c.gap != 5*time.Second {
		t.Fatalf("a contact from the old term counted: %+v", c)
	}
}

func TestMarkNodeGoneRefusals(t *testing.T) {
	if _, err := (&Cluster{}).MarkNodeGone(" "); err == nil {
		t.Fatal("empty id accepted")
	}
	if _, err := (&Cluster{}).MarkNodeGone("n"); !errors.Is(err, ErrNotLeader) {
		t.Fatalf("no raft: %v", err)
	}
	var nilC *Cluster
	if _, err := nilC.MarkNodeGone("n"); !errors.Is(err, ErrNotLeader) {
		t.Fatalf("nil cluster: %v", err)
	}
	nilC.NoteOwnershipContact("n")
	(&Cluster{}).NoteOwnershipContact(" ")
	// Its failover done, a node's zone facts go too.
	leases := newCapacityLeaseCache("srv", nil, 5*time.Second, nil)
	leases.set("w1", zoned("w1", "eu-1b", 4).Capacity, time.Now())
	leases.forgetNode("w1")
	if got := leases.lastKnownZone("w1"); got != "" {
		t.Fatalf("lastKnownZone after forgetNode = %q", got)
	}
	var nilLeases *capacityLeaseCache
	nilLeases.forgetNode("w1")
}

// The live rule on a real Raft leader: a gone machine whose runtime enforces
// the lease is failed over at its lease limit, before the grace; one that
// does not waits the grace. A node gossip sees again is not gone.
func TestReconcileDeadOwnersGoneMachine(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	const grace = 3 * time.Second // lease = 1.5 s; limit = 1.6 s after contact
	cases := []struct {
		name       string
		leaseFile  bool
		restarting bool
		// movedEarly: orphaned after the lease limit, before the grace.
		movedEarly bool
	}{
		{name: "lease enforced: early", leaseFile: true, movedEarly: true},
		{name: "lease enforced and restart announced: gone wins", leaseFile: true, restarting: true, movedEarly: true},
		{name: "plain VM (no lease file): waits the grace", leaseFile: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, cleanup := newTestClusterWithCfg(t, "ldr", true, nil, func(cfg *config.Config) {
				cfg.ClusterDeadOwnerGrace = grace
				cfg.ClusterRestartWindow = time.Minute
			})
			defer cleanup()
			waitForLeader(t, c, 10*time.Second)
			c.rolloutStop()
			ctx := context.Background()
			payload, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb-g", OwnerNodeID: "wkr"})
			if err := c.raft.raft.Apply(payload, 2*time.Second).Error(); err != nil {
				t.Fatal(err)
			}
			c.capacityLeases.set("wkr", capacity.Snapshot{HostCPUCores: 4, HostMemoryTotalMB: 4096, OwnershipLeaseFile: tc.leaseFile}, time.Now())
			// This leader took office long ago, so its last answer to wkr
			// is the contact that counts.
			c.gone.observeLeadership(false, 0, time.Now())
			c.gone.observeLeadership(true, c.raft.raft.CurrentTerm(), time.Now().Add(-time.Minute))
			// It renews by reads, one interval apart.
			c.gone.noteContact("wkr", time.Now().Add(-OwnershipLease(c.cfg)/3), time.Minute)
			c.NoteOwnershipContact("wkr")
			c.handleMemberLeave("wkr", tc.restarting)
			res, err := c.MarkNodeGone("wkr")
			if err != nil || res.Early != tc.leaseFile || (res.Early && res.NotBefore.IsZero()) || (!res.Early && res.Reason == "") {
				t.Fatalf("MarkNodeGone = %+v %v", res, err)
			}

			c.reconcileDeadOwners(ctx)
			if _, err := c.OwnerOf("sb-g"); err != nil {
				t.Fatalf("moved before the lease limit: %v", err)
			}
			time.Sleep(time.Until(res.NotBefore.Add(100 * time.Millisecond)))
			if !tc.leaseFile {
				time.Sleep(1700 * time.Millisecond) // past a lease limit, short of the grace
			}
			c.reconcileDeadOwners(ctx)
			_, err = c.OwnerOf("sb-g")
			if tc.movedEarly {
				if !errors.Is(err, ErrOrphaned) {
					t.Fatalf("past the lease limit OwnerOf err = %v, want ErrOrphaned", err)
				}
				// Evicted: its marks go, so node churn cannot fill the map.
				if c.gone.isGone("wkr") || !c.gone.contacts["wkr"].at.IsZero() || c.capacityLeases.lastKnownLeaseFile("wkr") {
					t.Fatal("the gone mark or the node's facts outlived its eviction")
				}
				return
			}
			if err != nil {
				t.Fatalf("a node without a lease file moved before the grace: %v", err)
			}
		})
	}
}

func TestMarkNodeGoneOnLeader(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	c, cleanup := newTestCluster(t, "ldr-gone", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	if _, err := c.MarkNodeGone("ldr-gone"); !errors.Is(err, ErrNodeGoneSelf) {
		t.Fatalf("self: %v", err)
	}
	c.capacityLeases.set("w", capacity.Snapshot{HostCPUCores: 1, OwnershipLeaseFile: true}, time.Now())
	// Never seen renewing by reads (an idle worker renews on its own): the
	// grace, and the answer says why.
	res, err := c.MarkNodeGone("w")
	if err != nil || res.Early || !strings.Contains(res.Reason, "renew its ownership lease by reads") {
		t.Fatalf("MarkNodeGone with no reads seen = %+v %v", res, err)
	}
	c.gone.noteContact("w", time.Now().Add(-OwnershipLease(c.cfg)/3), time.Minute)
	c.NoteOwnershipContact("w")
	res, err = c.MarkNodeGone("w")
	if err != nil || !res.Early || res.NodeID != "w" {
		t.Fatalf("MarkNodeGone = %+v %v", res, err)
	}
	// A rejoin clears it: the machine was not gone.
	c.cancelDeadOwnerWatch("w")
	if c.gone.isGone("w") {
		t.Fatal("rejoin kept the gone mark")
	}
	if c.goneFailoverDue("w", time.Now().Add(time.Hour)) {
		t.Fatal("a cleared node is due")
	}
}
