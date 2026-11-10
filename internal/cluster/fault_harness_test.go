package cluster

import (
	"bytes"
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cloudidentity"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/hashicorp/raft"
)

// Offline fault harness (plans/cluster-correctness-and-create-latency.md,
// Section 3.1). It runs several real Raft servers in one process, built with
// the same newTestClusterFromConfig as every other multi-node test here, and
// adds what fault tests need on top: restarting a server as the same Raft
// member, moving or killing the leader, waiting until every live server has
// applied the same log prefix, and checking the invariants a test can see
// without a runtime (I3, I4, I5, I8 and the FSM's own index bookkeeping).

// faultServer is one Raft server. dir and the three addresses stay the same
// across restarts: Raft keeps the peer address in its configuration and the
// log under dir, so a restarted server rejoins as the same voter and replays
// its own log instead of joining as a stranger.
type faultServer struct {
	id         string
	dir        string
	raftAddr   string
	gossipAddr string
	apiURL     string

	mu      sync.Mutex
	c       *Cluster
	cleanup func()
}

// cluster returns the running Cluster, or nil while the server is down.
func (s *faultServer) cluster() *Cluster {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.c
}

type faultCluster struct {
	t       *testing.T
	servers []*faultServer

	// leases is the capacity every server's lease cache reports for each
	// owner node. The harness runs no sandbox runtime and no /v1/capacity
	// endpoint, so a background loop writes these snapshots into every live
	// server's cache, standing in for the capacity heartbeat (start stops
	// the real one).
	leaseMu sync.Mutex
	leases  map[string]capacity.Snapshot
	stop    chan struct{}
	done    chan struct{}
}

const (
	// faultWait bounds every "wait until the cluster gets there" step. It is
	// generous because -race and a busy runner slow elections down; a
	// healthy run takes a small fraction of it.
	faultWait = 30 * time.Second
	// faultLeaseRefresh is how often the stand-in heartbeat rewrites the
	// capacity leases (their TTL is 15 s, ClusterCapacityGossipInterval 1 s).
	faultLeaseRefresh = 500 * time.Millisecond
)

// newFaultCluster starts n Raft servers named <name>-s1..sn and waits until
// all are voters. Each server may own sandboxes (empty role = mixed).
func newFaultCluster(t *testing.T, name string, n int) *faultCluster {
	t.Helper()
	if testing.Short() {
		t.Skip("fault harness: opens real raft/memberlist sockets")
	}
	fc := &faultCluster{
		t:      t,
		leases: make(map[string]capacity.Snapshot),
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
	}
	for i := 1; i <= n; i++ {
		fc.servers = append(fc.servers, &faultServer{
			id:         fmt.Sprintf("%s-s%d", name, i),
			dir:        t.TempDir(),
			raftAddr:   fmt.Sprintf("127.0.0.1:%d", pickFreeTCPPort(t)),
			gossipAddr: fmt.Sprintf("127.0.0.1:%d", pickFreeTCPPort(t)),
			apiURL:     fmt.Sprintf("http://127.0.0.1:%d", pickFreeTCPPort(t)),
		})
	}
	t.Cleanup(fc.close)
	go fc.leaseLoop()

	first := fc.servers[0]
	fc.start(first, true)
	waitForLeader(t, first.cluster(), faultWait)
	for _, s := range fc.servers[1:] {
		fc.start(s, false)
		waitForVoter(t, first.cluster(), s.id, faultWait)
	}
	fc.settle()
	return fc
}

func (fc *faultCluster) start(s *faultServer, bootstrap bool) {
	fc.t.Helper()
	var peers []string
	for _, o := range fc.servers {
		if o != s && o.cluster() != nil {
			peers = append(peers, o.gossipAddr)
		}
	}
	cfg := testClusterConfig(fc.t, s.id, bootstrap, peers, s.apiURL, s.dir)
	cfg.RaftBindAddr, cfg.RaftAdvertiseAddr = s.raftAddr, s.raftAddr
	cfg.GossipBindAddr, cfg.GossipAdvertiseAddr = s.gossipAddr, s.gossipAddr
	// Production values for the delete record, so the C2 fence (which keys
	// off it) is active; the test default of zero disables retention.
	cfg.AuditDeletedGrace = time.Hour
	cfg.AuditDeletedIndexMax = 100_000
	// A stopped server must not be evicted from Raft by the dead-owner loop
	// in the middle of a test; eviction is driven explicitly instead.
	cfg.ClusterDeadOwnerGrace = time.Hour
	c, cleanup := newTestClusterFromConfig(fc.t, cfg)
	// The harness serves no /v1/capacity, so this server's capacity sweep
	// (refreshCapacityLeases) never stores a lease. All it can do here is
	// delete one: retain drops the lease of any server its gossip does not
	// list, and a restarted server stays unlisted on a peer until that peer
	// takes its refute of the old leave. A leader that lost a lease that way
	// refused the next create onto the server with "no fresh capacity
	// heartbeat" until leaseLoop wrote it again. leaseLoop is the only lease
	// source here, so the sweep is stopped and nothing takes a lease back.
	if c.capacityLeaseStop != nil {
		c.capacityLeaseStop()
	}
	s.mu.Lock()
	s.c, s.cleanup = c, cleanup
	s.mu.Unlock()
	// Leases go in after gossip converges: New started one sweep before it
	// could be stopped, and that sweep runs its retain before its first fetch.
	fc.awaitGossip()
	fc.writeLeases()
}

// awaitGossip waits until every live server's gossip lists every live server
// alive. Raft does not wait for gossip: a restarted server can be caught up
// while a peer still holds its old leave, and until the peer takes the
// refute, its admission refuses every reservation onto that server.
func (fc *faultCluster) awaitGossip() {
	fc.t.Helper()
	deadline := time.Now().Add(faultWait)
	for {
		missing := fc.gossipGap()
		if missing == "" {
			return
		}
		if time.Now().After(deadline) {
			fc.t.Fatalf("gossip never converged within %s: %s", faultWait, missing)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// gossipGap names a live server that some live server's gossip does not list
// alive, or returns "" when every one lists every other.
func (fc *faultCluster) gossipGap() string {
	up := fc.up()
	for _, s := range up {
		c := s.cluster()
		if c == nil {
			continue
		}
		for _, o := range up {
			if m, ok := c.gossip.lookupMember(o.id); !ok || !m.Alive {
				return fmt.Sprintf("%s does not list %s alive", s.id, o.id)
			}
		}
	}
	return ""
}

// stopServer closes s the way a crash-free shutdown does: gossip leaves, the
// internal listener closes, Raft shuts down. No leadership hand-off.
func (fc *faultCluster) stopServer(s *faultServer) {
	s.mu.Lock()
	cleanup := s.cleanup
	s.c, s.cleanup = nil, nil
	s.mu.Unlock()
	if cleanup != nil {
		cleanup()
	}
}

// restartServer stops s and starts it again on the same data dir and
// addresses, then waits until it has rejoined and caught up.
func (fc *faultCluster) restartServer(s *faultServer, down time.Duration) {
	fc.t.Helper()
	fc.stopServer(s)
	time.Sleep(down)
	fc.startAgain(s)
}

// startAgain brings a stopped server back and waits for it to catch up.
func (fc *faultCluster) startAgain(s *faultServer) {
	fc.t.Helper()
	fc.start(s, false)
	c := s.cluster()
	deadline := time.Now().Add(faultWait)
	for time.Now().Before(deadline) {
		if c.Leader() != "" && c.PlacementViewCaughtUp() {
			fc.settle()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	fc.t.Fatalf("restarted server %s never caught up (leader %q)", s.id, c.Leader())
}

func (fc *faultCluster) close() {
	select {
	case <-fc.stop:
	default:
		close(fc.stop)
		<-fc.done
	}
	for _, s := range fc.servers {
		fc.stopServer(s)
	}
}

func (fc *faultCluster) up() []*faultServer {
	var out []*faultServer
	for _, s := range fc.servers {
		if s.cluster() != nil {
			out = append(out, s)
		}
	}
	return out
}

func (fc *faultCluster) server(id string) *faultServer {
	for _, s := range fc.servers {
		if s.id == id {
			return s
		}
	}
	return nil
}

// setLease makes every server see owner with snap as its capacity.
func (fc *faultCluster) setLease(owner string, snap capacity.Snapshot) {
	fc.leaseMu.Lock()
	fc.leases[owner] = snap
	fc.leaseMu.Unlock()
	fc.writeLeases()
}

func (fc *faultCluster) writeLeases() {
	fc.leaseMu.Lock()
	leases := make(map[string]capacity.Snapshot, len(fc.leases))
	for k, v := range fc.leases {
		leases[k] = v
	}
	fc.leaseMu.Unlock()
	now := time.Now()
	for _, s := range fc.servers {
		c := s.cluster()
		if c == nil || c.capacityLeases == nil {
			continue
		}
		for owner, snap := range leases {
			c.capacityLeases.set(owner, snap, now)
		}
	}
}

func (fc *faultCluster) leaseLoop() {
	defer close(fc.done)
	t := time.NewTicker(faultLeaseRefresh)
	defer t.Stop()
	for {
		select {
		case <-fc.stop:
			return
		case <-t.C:
			fc.writeLeases()
		}
	}
}

// staticCapacity is a capacity heartbeat with room for exactly cpu one-CPU
// sandboxes; memory and disk are far from binding.
func staticCapacity(cpu int) capacity.Snapshot {
	return capacity.Snapshot{
		HostCPUCores:      cpu,
		HostMemoryTotalMB: 1 << 20,
		HostDiskTotalGB:   1 << 20,
		CPUBudget:         float64(cpu),
		MemoryBudgetMB:    1 << 20,
		DiskBudgetGB:      1 << 20,
		AvailableCPU:      float64(cpu),
		AvailableMemoryMB: 1 << 20,
		AvailableDiskGB:   1 << 20,
		CanAdmit:          true,
	}
}

// leader waits until exactly one live server is Raft leader and every live
// server names it, and returns it.
func (fc *faultCluster) leader() *faultServer {
	fc.t.Helper()
	deadline := time.Now().Add(faultWait)
	var last string
	for time.Now().Before(deadline) {
		var leaders []*faultServer
		agree := true
		up := fc.up()
		for _, s := range up {
			c := s.cluster()
			if c == nil {
				agree = false
				break
			}
			if c.raft.raft.State() == raft.Leader {
				leaders = append(leaders, s)
			}
		}
		if agree && len(leaders) == 1 {
			for _, s := range up {
				if c := s.cluster(); c == nil || c.Leader() != leaders[0].id {
					agree = false
					break
				}
			}
			if agree {
				return leaders[0]
			}
		}
		last = fmt.Sprintf("%d leaders among %d live servers", len(leaders), len(up))
		time.Sleep(20 * time.Millisecond)
	}
	fc.t.Fatalf("no single agreed leader within %s (%s)", faultWait, last)
	return nil
}

// transferLeadership moves leadership off the current leader (to a chosen
// server when to is non-nil) and waits for the new leader to be agreed.
func (fc *faultCluster) transferLeadership(to *faultServer) *faultServer {
	fc.t.Helper()
	old := fc.leader()
	var f raft.Future
	if to != nil {
		f = old.cluster().raft.raft.LeadershipTransferToServer(raft.ServerID(to.id), raft.ServerAddress(to.raftAddr))
	} else {
		f = old.cluster().raft.raft.LeadershipTransfer()
	}
	if err := f.Error(); err != nil {
		fc.t.Fatalf("leadership transfer from %s: %v", old.id, err)
	}
	deadline := time.Now().Add(faultWait)
	for time.Now().Before(deadline) {
		if l := fc.leader(); l != old {
			return l
		}
		time.Sleep(20 * time.Millisecond)
	}
	fc.t.Fatalf("leadership never left %s", old.id)
	return nil
}

// settle waits until every live server has applied the same FSM log prefix
// as the leader, and returns that FSM version (the last applied index).
// The leader's barrier makes it apply everything it has committed first.
func (fc *faultCluster) settle() uint64 {
	fc.t.Helper()
	deadline := time.Now().Add(faultWait)
	for time.Now().Before(deadline) {
		l := fc.leader()
		c := l.cluster()
		if err := c.raft.raft.Barrier(faultCommitTimeout).Error(); err != nil {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		want := c.fsm.currentVersion()
		inner := time.Now().Add(5 * time.Second)
		for time.Now().Before(inner) {
			same := true
			for _, s := range fc.up() {
				sc := s.cluster()
				if sc == nil || sc.fsm.currentVersion() != want {
					same = false
					break
				}
			}
			if same {
				return want
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	fc.t.Fatalf("live servers never applied the same log prefix within %s", faultWait)
	return 0
}

const faultCommitTimeout = 2 * time.Second

// fsmDump is one server's replicated state at one FSM version: the snapshot
// payload Raft would persist (rows sorted, since Persist builds them from a
// map) plus every placement joined with its recovery payload.
type fsmDump struct {
	server  string
	version uint64
	payload fsmSnapshotPayload
	full    map[string]Placement
}

// dumpFSM reads f's replicated state. ok is false when f applied an entry
// while it was being read; the caller retries.
func dumpFSM(server string, f *placementFSM) (fsmDump, bool, error) {
	before := f.currentVersion()
	snap, err := f.Snapshot()
	if err != nil {
		return fsmDump{}, false, err
	}
	fs := snap.(*fsmSnapshot)
	// Persist's recovery-store side effects (fsync, blob GC) belong to a
	// real Raft snapshot, not to a read; without a store they are skipped.
	fs.recoveryStore = nil
	sink := &faultSnapshotSink{}
	err = fs.Persist(sink)
	fs.Release()
	if err != nil {
		return fsmDump{}, false, err
	}
	var payload fsmSnapshotPayload
	if err := gob.NewDecoder(bytes.NewReader(sink.buf.Bytes())).Decode(&payload); err != nil {
		return fsmDump{}, false, err
	}
	sort.Slice(payload.Rows, func(i, j int) bool {
		return payload.Rows[i].Placement.SandboxID < payload.Rows[j].Placement.SandboxID
	})
	// Same meaning, two encodings: a server that replayed its log has no
	// identity state until the first identity op, and one restored from a
	// snapshot always has one (restoreIdentityLocked). Every reader answers
	// "no keys" for both (identityKeys), so compare them as equal.
	if payload.IdentityKeys == nil {
		payload.IdentityKeys = &cloudidentity.KeySet{}
	}
	full := f.snapshot()
	if f.currentVersion() != before || payload.Version != before {
		return fsmDump{}, false, nil
	}
	return fsmDump{server: server, version: before, payload: payload, full: full}, true, nil
}

type faultSnapshotSink struct{ buf bytes.Buffer }

func (s *faultSnapshotSink) Write(p []byte) (int, error) { return s.buf.Write(p) }
func (s *faultSnapshotSink) Close() error                { return nil }
func (s *faultSnapshotSink) ID() string                  { return "fault-harness" }
func (s *faultSnapshotSink) Cancel() error               { return nil }

// dumpAll settles the cluster and dumps every live server at one version.
func (fc *faultCluster) dumpAll() []fsmDump {
	fc.t.Helper()
	for attempt := 0; attempt < 50; attempt++ {
		fc.settle()
		var dumps []fsmDump
		consistent := true
		for _, s := range fc.up() {
			c := s.cluster()
			if c == nil {
				consistent = false
				break
			}
			d, ok, err := dumpFSM(s.id, c.fsm)
			if err != nil {
				fc.t.Fatalf("dump %s: %v", s.id, err)
			}
			if !ok || (len(dumps) > 0 && d.version != dumps[0].version) {
				consistent = false
				break
			}
			dumps = append(dumps, d)
		}
		if consistent {
			return dumps
		}
	}
	fc.t.Fatal("could not read every live server at the same FSM version")
	return nil
}

// diffDumps describes every difference between two dumps of the same FSM
// version. Empty means the replicated state is identical.
func diffDumps(a, b fsmDump) []string {
	var out []string
	rowsA := make(map[string]placementSnapshotRow, len(a.payload.Rows))
	for _, r := range a.payload.Rows {
		rowsA[r.Placement.SandboxID] = r
	}
	rowsB := make(map[string]placementSnapshotRow, len(b.payload.Rows))
	for _, r := range b.payload.Rows {
		rowsB[r.Placement.SandboxID] = r
	}
	for _, id := range unionKeys(rowsA, rowsB) {
		ra, okA := rowsA[id]
		rb, okB := rowsB[id]
		switch {
		case !okA:
			out = append(out, fmt.Sprintf("row %s only on %s: %+v", id, b.server, rb.Placement))
		case !okB:
			out = append(out, fmt.Sprintf("row %s only on %s: %+v", id, a.server, ra.Placement))
		case !reflect.DeepEqual(ra, rb):
			out = append(out, fmt.Sprintf("row %s differs: %s", id, fieldDiff(a.server, b.server, ra.Placement, rb.Placement)))
		}
	}
	va, vb := reflect.ValueOf(a.payload), reflect.ValueOf(b.payload)
	for i := 0; i < va.NumField(); i++ {
		name := va.Type().Field(i).Name
		if name == "Rows" {
			continue
		}
		if !reflect.DeepEqual(va.Field(i).Interface(), vb.Field(i).Interface()) {
			out = append(out, fmt.Sprintf("snapshot field %s differs: %s=%+v %s=%+v", name, a.server, va.Field(i).Interface(), b.server, vb.Field(i).Interface()))
		}
	}
	for _, id := range unionKeys(a.full, b.full) {
		pa, okA := a.full[id]
		pb, okB := b.full[id]
		if okA && okB && !reflect.DeepEqual(pa, pb) {
			out = append(out, fmt.Sprintf("full placement %s differs: %s", id, fieldDiff(a.server, b.server, pa, pb)))
		}
	}
	return out
}

func fieldDiff(nameA, nameB string, a, b Placement) string {
	va, vb := reflect.ValueOf(a), reflect.ValueOf(b)
	var parts []string
	for i := 0; i < va.NumField(); i++ {
		fa, fb := va.Field(i).Interface(), vb.Field(i).Interface()
		if !reflect.DeepEqual(fa, fb) {
			parts = append(parts, fmt.Sprintf("%s: %s=%+v %s=%+v", va.Type().Field(i).Name, nameA, fa, nameB, fb))
		}
	}
	return strings.Join(parts, "; ")
}

func unionKeys[A, B any](a map[string]A, b map[string]B) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	for k := range a {
		seen[k] = struct{}{}
	}
	for k := range b {
		seen[k] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// requireIdenticalServers fails when two live servers that applied the same
// log prefix hold different replicated state (I5).
func (fc *faultCluster) requireIdenticalServers(context string) []fsmDump {
	fc.t.Helper()
	dumps := fc.dumpAll()
	for _, d := range dumps[1:] {
		if diffs := diffDumps(dumps[0], d); len(diffs) > 0 {
			fc.t.Fatalf("%s: servers %s and %s applied the same log (FSM version %d) but disagree (I5):\n  %s",
				context, dumps[0].server, d.server, d.version, strings.Join(diffs, "\n  "))
		}
	}
	return dumps
}

// checkFSMInvariants lists what f breaks of the invariants one FSM can show
// by itself at time now: the derived indexes agree with the rows they index
// (one owner per sandbox), and the pending load the leader admits against
// equals what the live reservations ask for (I4).
func checkFSMInvariants(server string, f *placementFSM, now int64) []string {
	load, runtimes := f.pendingReservationLoadByNode(now)
	full := f.snapshot()

	var out []string
	bad := func(format string, args ...any) {
		out = append(out, server+": "+fmt.Sprintf(format, args...))
	}

	wantLoad := make(map[string]capacity.Request)
	wantRuntimes := make(map[string]map[string]int)
	for id, p := range full {
		if !p.IsReserved() || (p.ExpiresUnix > 0 && now > p.ExpiresUnix) {
			continue
		}
		req := capacityRequestFromSpec(p.Spec)
		cur := wantLoad[p.OwnerNodeID]
		cur.CPU += req.CPU
		cur.MemoryMB += req.MemoryMB
		cur.DiskGB += req.DiskGB
		cur.GPUs += req.GPUs
		wantLoad[p.OwnerNodeID] = cur
		if wantRuntimes[p.OwnerNodeID] == nil {
			wantRuntimes[p.OwnerNodeID] = make(map[string]int)
		}
		wantRuntimes[p.OwnerNodeID][req.Runtime]++
		_ = id
	}
	if !reflect.DeepEqual(load, wantLoad) {
		bad("pending load %+v, live reservations ask for %+v (I4)", load, wantLoad)
	}
	if !reflect.DeepEqual(runtimes, wantRuntimes) {
		bad("pending runtime counts %+v, live reservations %+v (I4)", runtimes, wantRuntimes)
	}

	f.mu.RLock()
	defer f.mu.RUnlock()
	ownerOf := make(map[string]string)
	for node, ids := range f.ownerIndex {
		ids.Ascend(func(id string) bool {
			if prev, dup := ownerOf[id]; dup {
				bad("sandbox %s indexed under two owners %s and %s", id, prev, node)
			}
			ownerOf[id] = node
			p, ok := full[id]
			switch {
			case !ok:
				bad("owner index lists %s under %s, but it has no placement", id, node)
			case p.OwnerNodeID != node:
				bad("owner index lists %s under %s, placement owner is %q", id, node, p.OwnerNodeID)
			case p.IsReserved():
				bad("owner index lists reservation %s under %s", id, node)
			}
			return true
		})
	}
	for id, p := range full {
		if p.State == PlacementStatePlaced && !p.IsOrphaned() && p.OwnerNodeID != "" && ownerOf[id] != p.OwnerNodeID {
			bad("placement %s owned by %s is missing from the owner index", id, p.OwnerNodeID)
		}
		if p.IsReserved() {
			if _, ok := f.reservedIndex[id]; !ok {
				bad("reservation %s is missing from the reserved index", id)
			}
			if _, ok := f.pendingReservationIDsByOwner[p.OwnerNodeID][id]; !ok {
				bad("reservation %s is missing from owner %s's pending set", id, p.OwnerNodeID)
			}
		}
		if p.IsDeleting() {
			if _, ok := f.deletingIndex[id]; !ok {
				bad("deleting placement %s is missing from the deleting index", id)
			}
		}
		if name := strings.TrimSpace(p.Name); name != "" && f.nameIndex[name] != id {
			bad("placement %s holds name %q, name index says %q", id, name, f.nameIndex[name])
		}
	}
	for id := range f.reservedIndex {
		if p, ok := full[id]; !ok || !p.IsReserved() {
			bad("reserved index lists %s, which is not a reservation", id)
		}
	}
	for id := range f.deletingIndex {
		if p, ok := full[id]; !ok || !p.IsDeleting() {
			bad("deleting index lists %s, which is not being deleted", id)
		}
	}
	for owner, ids := range f.pendingReservationIDsByOwner {
		for id := range ids {
			if p, ok := full[id]; !ok || !p.IsReserved() || p.OwnerNodeID != owner {
				bad("owner %s's pending set lists %s, which is not its reservation", owner, id)
			}
		}
	}
	for name, id := range f.nameIndex {
		if p, ok := full[id]; !ok || strings.TrimSpace(p.Name) != name {
			bad("name index maps %q to %s, which does not hold it", name, id)
		}
	}
	sort.Strings(out)
	return out
}

// requireInvariants settles the cluster, then runs checkFSMInvariants on
// every live server.
func (fc *faultCluster) requireInvariants(context string) {
	fc.t.Helper()
	fc.settle()
	now := time.Now().Unix()
	var all []string
	for _, s := range fc.up() {
		if c := s.cluster(); c != nil {
			all = append(all, checkFSMInvariants(s.id, c.fsm, now)...)
		}
	}
	if len(all) > 0 {
		fc.t.Fatalf("%s: FSM invariants broken:\n  %s", context, strings.Join(all, "\n  "))
	}
}

// retryLeaderChange runs op until it returns something other than a
// leader-change error, or the deadline passes. Leader changes, forwarding to
// a leader that just stopped, and Raft apply timeouts are all answered with
// a retry by real callers; the answer that ends the loop is what the test
// judges.
func retryLeaderChange(ctx context.Context, backoff time.Duration, op func(context.Context) error) error {
	var err error
	for {
		err = op(ctx)
		if err == nil || !faultRetryable(err) {
			return err
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%w (last error: %v)", ctx.Err(), err)
		case <-time.After(backoff):
		}
	}
}

// faultRetryable reports whether err only means "leadership or transport was
// unsettled": the write may or may not have committed, and a retry of the
// same idempotent command settles which. A verdict from the FSM ("fsm
// apply: ...", or a sentinel restored across the forward hop) is final.
func faultRetryable(err error) bool {
	if err == nil {
		return false
	}
	if IsControlPlaneUnavailable(err) || errors.Is(err, ErrPeerInternalURLRequired) {
		return true
	}
	for _, sentinel := range []error{raft.ErrLeadershipTransferInProgress, raft.ErrEnqueueTimeout, raft.ErrRaftShutdown, raft.ErrAbortedByRestore} {
		if errors.Is(err, sentinel) {
			return true
		}
	}
	// Across the forward hop a Raft-level failure arrives as a 500 whose body
	// is the leader's error text.
	return strings.Contains(err.Error(), "raft apply: ")
}
