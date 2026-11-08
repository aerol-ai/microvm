package cluster

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// Property test for the placement state machine
// (plans/cluster-correctness-and-create-latency.md, Section 3.1, I1-I8).
//
// A seeded random sequence of operations runs against a real in-process
// cluster and against a small in-memory model of what the cluster should
// hold. After every step the test waits until every live server has applied
// the same log, then checks what can be seen offline:
//
//   - the leader holds exactly the placements the model holds, with the
//     owner, state and incarnation the model expects (I1: one owner each);
//   - no server holds a lifetime that was deleted (I3);
//   - every server's derived indexes agree with its rows, and its pending
//     load equals what its live reservations ask for (I4);
//   - every live server holds the same replicated state (I5);
//   - after the leader's reservation sweep, no reservation is past its TTL,
//     and a failed create left nothing behind (I8).
//
// The seed fixes the operation sequence, not Raft's timing: no pick reads
// the clock or the leader's identity, so a failing seed replays the same
// operations as long as the cluster gives the same answers. Knobs:
//
//	SB_CLUSTER_PROPERTY_SEED   seed (default 7; "random" picks one)
//	SB_CLUSTER_PROPERTY_STEPS  steps per subtest (default 40)
//
// A long run, e.g. SB_CLUSTER_PROPERTY_STEPS=2000 SB_CLUSTER_PROPERTY_SEED=random,
// is opt-in; make test runs the short default.
const (
	propertyServers = 3
	// propertyDefaultSeed is the seed make test runs. 7 because on main its
	// restart run reaches the C2 resurrection at step 36, inside the default
	// step count: the PR that fixes C2 proves it by deleting one t.Skip.
	propertyDefaultSeed = 7
	propertyStepsEnv    = "SB_CLUSTER_PROPERTY_STEPS"
	propertySeedEnv     = "SB_CLUSTER_PROPERTY_SEED"
	propertyStepsShort  = 40
	// propertyIDs is the sandbox id pool. Small on purpose: ids are reused
	// after a delete, the way keyed creates (E2B, Runloop) reuse them.
	propertyIDs = 12
	// propertyLongTTL is the TTL of a reservation that is promoted at once.
	propertyLongTTL = time.Minute
	// propertyShortTTL is the TTL of a reservation whose create never
	// promotes it (a crash mid-create, a rollback that did not land).
	propertyShortTTL  = 2 * time.Second
	propertyOpTimeout = 20 * time.Second
)

func TestClusterFaultPropertyModel(t *testing.T) {
	seed, steps := propertyKnobs(t)
	t.Run("steady", func(t *testing.T) {
		runPropertyModel(t, "pms", seed, steps, false)
	})
	t.Run("restarts", func(t *testing.T) {
		runPropertyModel(t, "pmr", seed, steps, true)
	})
}

func propertyKnobs(t *testing.T) (int64, int) {
	t.Helper()
	seed := int64(propertyDefaultSeed)
	if v := strings.TrimSpace(os.Getenv(propertySeedEnv)); v == "random" {
		seed = time.Now().UnixNano()
	} else if v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			t.Fatalf("%s=%q: %v", propertySeedEnv, v, err)
		}
		seed = n
	}
	steps := propertyStepsShort
	if v := strings.TrimSpace(os.Getenv(propertyStepsEnv)); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			t.Fatalf("%s=%q: want a positive integer", propertyStepsEnv, v)
		}
		steps = n
	}
	return seed, steps
}

// propRow is the model's view of one placement.
type propRow struct {
	state        string // "reserved", "placed" or "orphaned"
	owner        string // current owner; empty when orphaned
	orphanedFrom string
	incarnation  string
	expires      int64 // reservations only
}

type propModel struct {
	rows map[string]*propRow
	// deleted holds every (id, incarnation) the cluster deleted. None may
	// ever be held again (I3).
	deleted map[string]bool
	// local is what each server runs: the rows its SQLite would hold. A
	// reassign leaves the old owner's row behind, as a cut-off owner's is;
	// the restart replay (AssertOwnership) is what must not resurrect it.
	local map[string]map[string]string
	down  map[string]bool
}

func lifetimeKey(id, incarnation string) string { return id + "/" + incarnation }

type propertyRun struct {
	t       *testing.T
	fc      *faultCluster
	m       *propModel
	rng     *rand.Rand
	seed    int64
	step    int
	op      string
	history []string
	spec    *models.CreateSandboxRequest
	// checkReplicas enables the cross-server comparison (I5); see the gate
	// subtest in runPropertyModel.
	checkReplicas bool
}

func runPropertyModel(t *testing.T, name string, seed int64, steps int, restarts bool) {
	t.Logf("seed %d, %d steps (replay: %s=%d %s=%d go test -run '%s' ./internal/cluster/)",
		seed, steps, propertySeedEnv, seed, propertyStepsEnv, steps, t.Name())
	r := &propertyRun{
		t:    t,
		rng:  rand.New(rand.NewSource(seed)),
		seed: seed,
		m: &propModel{
			rows:    make(map[string]*propRow),
			deleted: make(map[string]bool),
			local:   make(map[string]map[string]string),
			down:    make(map[string]bool),
		},
		spec: &models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 64, DiskGB: 1},
	}
	t.Run("replicas-identical", func(t *testing.T) {
		r.checkReplicas = true
	})
	r.fc = newFaultCluster(t, name, propertyServers)
	for _, s := range r.fc.servers {
		r.m.local[s.id] = make(map[string]string)
		// Room for every sandbox the id pool can hold: this test is about
		// ownership and lifetimes; capacity is the leader-change test's.
		r.fc.setLease(s.id, staticCapacity(1000))
	}
	for r.step = 1; r.step <= steps; r.step++ {
		r.runOneStep(restarts)
		r.check()
	}
}

// fail reports a broken invariant with what is needed to replay it.
func (r *propertyRun) fail(format string, args ...any) {
	r.t.Helper()
	tail := r.history
	if len(tail) > 15 {
		tail = tail[len(tail)-15:]
	}
	r.t.Fatalf("seed %d step %d (%s): %s\nlast steps:\n  %s\nreplay: %s=%d %s=%d go test -run '%s' ./internal/cluster/",
		r.seed, r.step, r.op, fmt.Sprintf(format, args...), strings.Join(tail, "\n  "),
		propertySeedEnv, r.seed, propertyStepsEnv, r.step, r.t.Name())
}

func (r *propertyRun) ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), propertyOpTimeout)
}

func (r *propertyRun) upServers() []*faultServer {
	var out []*faultServer
	for _, s := range r.fc.servers {
		if !r.m.down[s.id] {
			out = append(out, s)
		}
	}
	return out
}

func (r *propertyRun) pickUp() *faultServer {
	up := r.upServers()
	return up[r.rng.Intn(len(up))]
}

// pickID picks an id for a create. It skips ids held as reservations:
// whether a reserve may overwrite one depends on which side of its expiry
// second the leader stamps the entry, which the model cannot know.
func (r *propertyRun) pickID() string {
	start := r.rng.Intn(propertyIDs)
	for i := 0; i < propertyIDs; i++ {
		id := fmt.Sprintf("sb-prop-%02d", (start+i)%propertyIDs)
		if row, ok := r.m.rows[id]; !ok || row.state != "reserved" {
			return id
		}
	}
	return fmt.Sprintf("sb-prop-%02d", start)
}

// rowsWhere lists model ids matching keep, sorted, so a pick is replayable.
func (r *propertyRun) rowsWhere(keep func(id string, row *propRow) bool) []string {
	var ids []string
	for id, row := range r.m.rows {
		if keep(id, row) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

func (r *propertyRun) runOneStep(restarts bool) {
	type weighted struct {
		w  int
		fn func()
	}
	ops := []weighted{
		{30, r.opCreate},
		{8, r.opAbandonedCreate},
		{8, r.opFailedCreate},
		{14, r.opDestroy},
		{10, r.opReassign},
		{4, r.opEvict},
		{6, r.opClaimOrphan},
		{6, r.opTransferLeader},
		{6, r.opSweep},
	}
	if restarts {
		ops = append(ops, weighted{8, r.opStopOrStart})
	}
	total := 0
	for _, o := range ops {
		total += o.w
	}
	n := r.rng.Intn(total)
	for _, o := range ops {
		if n < o.w {
			o.fn()
			return
		}
		n -= o.w
	}
}

func (r *propertyRun) record(format string, args ...any) {
	r.op = fmt.Sprintf(format, args...)
	r.history = append(r.history, fmt.Sprintf("%d: %s", r.step, r.op))
}

// reserve runs one ReserveOnTarget through via, retrying leader changes.
func (r *propertyRun) reserve(via, owner *faultServer, id, incarnation string, ttl time.Duration) error {
	ctx, cancel := r.ctx()
	defer cancel()
	oc := owner.cluster()
	target := PlacementTarget{NodeID: oc.nodeID, APIURL: oc.apiURL, DataPlaneHost: oc.dataPlaneHost}
	return retryLeaderChange(ctx, 50*time.Millisecond, func(ctx context.Context) error {
		return via.cluster().ReserveOnTarget(ctx, id, target, r.spec, PlacementSecrets{IncarnationID: incarnation}, ttl)
	})
}

func (r *propertyRun) apply(op func(ctx context.Context) error) error {
	ctx, cancel := r.ctx()
	defer cancel()
	return retryLeaderChange(ctx, 50*time.Millisecond, op)
}

func mustIncarnation(t *testing.T) string {
	inc, err := MintIncarnationID()
	if err != nil {
		t.Fatalf("MintIncarnationID: %v", err)
	}
	return inc
}

// expectReserveConflict checks the verdict for a reserve of an id the model
// already holds: the cluster must refuse it, and with a conflict, never
// grant a second reservation.
func (r *propertyRun) expectReserveConflict(id string, err error) {
	if err == nil {
		r.fail("reserve of %s granted while the model holds it as %+v", id, *r.m.rows[id])
	}
	if !errors.Is(err, ErrReservationConflict) && !errors.Is(err, ErrIncarnationConflict) {
		r.fail("reserve of held %s refused with %v, want a reservation or incarnation conflict", id, err)
	}
}

// opCreate is a full create: reserve on an owner, then the owner promotes.
func (r *propertyRun) opCreate() {
	id, via, owner := r.pickID(), r.pickUp(), r.pickUp()
	inc := mustIncarnation(r.t)
	r.record("create %s on %s via %s", id, owner.id, via.id)
	err := r.reserve(via, owner, id, inc, propertyLongTTL)
	if _, held := r.m.rows[id]; held {
		r.expectReserveConflict(id, err)
		return
	}
	if err != nil {
		r.fail("reserve of free %s: %v", id, err)
	}
	if err := r.apply(func(ctx context.Context) error {
		return owner.cluster().RecordPlacement(ctx, id, nil, PlacementSecrets{IncarnationID: inc})
	}); err != nil {
		r.fail("promote of %s on %s: %v", id, owner.id, err)
	}
	r.m.rows[id] = &propRow{state: "placed", owner: owner.id, incarnation: inc}
	r.m.local[owner.id][id] = inc
}

// opAbandonedCreate reserves and never promotes: the create crashed after
// the reservation committed. Only the TTL sweep may remove it.
func (r *propertyRun) opAbandonedCreate() {
	id, via, owner := r.pickID(), r.pickUp(), r.pickUp()
	inc := mustIncarnation(r.t)
	r.record("abandoned create %s on %s via %s", id, owner.id, via.id)
	before := time.Now().Add(propertyShortTTL).Unix()
	err := r.reserve(via, owner, id, inc, propertyShortTTL)
	if _, held := r.m.rows[id]; held {
		r.expectReserveConflict(id, err)
		return
	}
	if err != nil {
		r.fail("reserve of free %s: %v", id, err)
	}
	r.m.rows[id] = &propRow{state: "reserved", owner: owner.id, incarnation: inc, expires: r.reservedExpiry(id, before)}
}

// reservedExpiry reads the expiry the reservation was stored with: the
// router stamps it, so the model learns it instead of guessing the second.
func (r *propertyRun) reservedExpiry(id string, fallback int64) int64 {
	if p, ok := r.fc.leader().cluster().PlacementOf(id); ok && p.IsReserved() {
		return p.ExpiresUnix
	}
	return fallback
}

// opFailedCreate reserves, then rolls the reservation back the way the
// create path does when the owner's local create fails (I8).
func (r *propertyRun) opFailedCreate() {
	id, via, owner := r.pickID(), r.pickUp(), r.pickUp()
	inc := mustIncarnation(r.t)
	r.record("failed create %s on %s via %s", id, owner.id, via.id)
	before := time.Now().Add(propertyShortTTL).Unix()
	err := r.reserve(via, owner, id, inc, propertyShortTTL)
	if _, held := r.m.rows[id]; held {
		r.expectReserveConflict(id, err)
		return
	}
	if err != nil {
		r.fail("reserve of free %s: %v", id, err)
	}
	expires := r.reservedExpiry(id, before)
	canceller := r.pickUp()
	if err := r.apply(func(ctx context.Context) error {
		return canceller.cluster().CancelReservation(ctx, id)
	}); err != nil {
		// The rollback did not land: the reservation must still go at its TTL.
		r.m.rows[id] = &propRow{state: "reserved", owner: owner.id, incarnation: inc, expires: expires}
		return
	}
}

// opDestroy deletes a placed sandbox from its owner, the way DestroySandbox
// does once the local copy is gone.
func (r *propertyRun) opDestroy() {
	ids := r.rowsWhere(func(_ string, row *propRow) bool { return row.state == "placed" && !r.m.down[row.owner] })
	if len(ids) == 0 {
		r.opCreate()
		return
	}
	id := ids[r.rng.Intn(len(ids))]
	row := r.m.rows[id]
	owner := r.fc.server(row.owner)
	r.record("destroy %s on %s", id, owner.id)
	if err := r.apply(func(ctx context.Context) error {
		return owner.cluster().DeletePlacementExact(ctx, id, row.owner, row.incarnation)
	}); err != nil {
		r.fail("destroy of %s: %v", id, err)
	}
	r.m.deleted[lifetimeKey(id, row.incarnation)] = true
	delete(r.m.rows, id)
	delete(r.m.local[owner.id], id)
}

// opReassign moves a placed sandbox to another server, as failover does.
// The old owner keeps its local row: a cut-off owner has not heard.
func (r *propertyRun) opReassign() {
	ids := r.rowsWhere(func(_ string, row *propRow) bool { return row.state == "placed" })
	if len(ids) == 0 {
		r.opCreate()
		return
	}
	id := ids[r.rng.Intn(len(ids))]
	row := r.m.rows[id]
	var targets []*faultServer
	for _, s := range r.upServers() {
		if s.id != row.owner {
			targets = append(targets, s)
		}
	}
	if len(targets) == 0 {
		r.opSweep()
		return
	}
	target := targets[r.rng.Intn(len(targets))]
	r.record("reassign %s %s -> %s", id, row.owner, target.id)
	tc := target.cluster()
	if err := r.apply(func(ctx context.Context) error {
		return r.fc.leader().cluster().ReassignPlacement(ctx, id, PlacementTarget{NodeID: tc.nodeID, APIURL: tc.apiURL, DataPlaneHost: tc.dataPlaneHost})
	}); err != nil {
		r.fail("reassign of %s: %v", id, err)
	}
	row.owner = target.id
	r.m.local[target.id][id] = row.incarnation
}

// opEvict orphans every placement of one server and drops its pending
// reservations, the FSM half of a dead-owner eviction (opOrphanOwner).
func (r *propertyRun) opEvict() {
	node := r.fc.servers[r.rng.Intn(len(r.fc.servers))]
	r.record("evict %s", node.id)
	if err := r.apply(func(ctx context.Context) error {
		return r.fc.leader().cluster().orphanOwner(ctx, node.id)
	}); err != nil {
		r.fail("evict %s: %v", node.id, err)
	}
	for id, row := range r.m.rows {
		if row.owner != node.id {
			continue
		}
		switch row.state {
		case "placed":
			row.state, row.owner, row.orphanedFrom = "orphaned", "", node.id
		case "reserved":
			delete(r.m.rows, id)
		}
	}
}

// opClaimOrphan is the evicted server taking its sandbox back, as its
// ownership replay does after a false dead-owner verdict.
func (r *propertyRun) opClaimOrphan() {
	ids := r.rowsWhere(func(_ string, row *propRow) bool { return row.state == "orphaned" && !r.m.down[row.orphanedFrom] })
	if len(ids) == 0 {
		r.opEvict()
		return
	}
	id := ids[r.rng.Intn(len(ids))]
	row := r.m.rows[id]
	node := r.fc.server(row.orphanedFrom)
	r.record("claim orphan %s on %s", id, node.id)
	if err := r.apply(func(ctx context.Context) error {
		return node.cluster().ClaimOrphan(ctx, id, nil, PlacementSecrets{IncarnationID: row.incarnation})
	}); err != nil {
		r.fail("claim of %s by %s: %v", id, node.id, err)
	}
	row.state, row.owner, row.orphanedFrom = "placed", node.id, ""
	r.m.local[node.id][id] = row.incarnation
}

func (r *propertyRun) opTransferLeader() {
	if len(r.upServers()) < len(r.fc.servers) {
		// Two of three servers: a transfer target may not be caught up, and
		// raft refuses. Sweep instead.
		r.opSweep()
		return
	}
	r.record("transfer leadership")
	r.fc.transferLeadership(nil)
}

// opSweep runs the leader's reservation sweep, then checks no reservation
// outlived its TTL (I8).
//
// It first waits until every reservation the model holds has expired, so
// which rows the sweep removes never depends on how long earlier steps took:
// the model, and so every later pick, is the same on every run of a seed.
func (r *propertyRun) opSweep() {
	r.record("reservation sweep")
	ctx, cancel := r.ctx()
	defer cancel()
	var latest int64
	for _, row := range r.m.rows {
		if row.state == "reserved" && row.expires > latest {
			latest = row.expires
		}
	}
	for time.Now().Unix() <= latest {
		time.Sleep(50 * time.Millisecond)
	}
	start := time.Now().Unix()
	r.fc.leader().cluster().reconcileReservations(ctx)
	r.fc.settle()
	for _, s := range r.fc.up() {
		for id, p := range s.cluster().fsm.snapshot() {
			if p.IsReserved() && p.ExpiresUnix > 0 && p.ExpiresUnix < start {
				r.fail("%s: reservation %s expired at %d and survived the sweep at %d", s.id, id, p.ExpiresUnix, start)
			}
		}
	}
	for id, row := range r.m.rows {
		if row.state == "reserved" {
			delete(r.m.rows, id)
		}
	}
}

// opStopOrStart stops a server, or starts the stopped one. A started server
// replays its log, then runs the boot-time ownership replay with the rows it
// runs locally, as the service does.
func (r *propertyRun) opStopOrStart() {
	var down *faultServer
	for _, s := range r.fc.servers {
		if r.m.down[s.id] {
			down = s
		}
	}
	if down == nil {
		s := r.fc.servers[r.rng.Intn(len(r.fc.servers))]
		r.record("stop %s", s.id)
		r.fc.stopServer(s)
		r.m.down[s.id] = true
		return
	}
	r.record("start %s", down.id)
	r.fc.startAgain(down)
	delete(r.m.down, down.id)
	c := down.cluster()
	var local []LocalSandboxState
	ids := make([]string, 0, len(r.m.local[down.id]))
	for id := range r.m.local[down.id] {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		local = append(local, LocalSandboxState{ID: id, Spec: r.spec, Secrets: PlacementSecrets{IncarnationID: r.m.local[down.id][id]}})
	}
	ctx, cancel := r.ctx()
	defer cancel()
	if err := c.AssertOwnership(ctx, local); err != nil {
		r.t.Logf("step %d: AssertOwnership on %s: %v", r.step, down.id, err)
	}
	r.fc.settle()
	// What the replay may change: an orphan of this server is claimed back.
	for _, id := range ids {
		row, ok := r.m.rows[id]
		if ok && row.state == "orphaned" && row.orphanedFrom == down.id && row.incarnation == r.m.local[down.id][id] {
			row.state, row.owner, row.orphanedFrom = "placed", down.id, ""
		}
	}
	// Then the service drops every local row the cluster says is not this
	// server's (reconcileStaleOwnership, and C2's destroy of a deleted one).
	// The check after this step is what catches a replay that placed one.
	for _, id := range ids {
		row, ok := r.m.rows[id]
		if !ok || row.owner != down.id || row.incarnation != r.m.local[down.id][id] {
			delete(r.m.local[down.id], id)
		}
	}
}

// check compares every live server with the model and with each other.
func (r *propertyRun) check() {
	r.t.Helper()
	r.fc.settle()
	now := time.Now().Unix()
	leader := r.fc.leader()
	held := leader.cluster().fsm.snapshot()

	for _, s := range r.fc.up() {
		for id, p := range s.cluster().fsm.snapshot() {
			if r.m.deleted[lifetimeKey(id, p.IncarnationID)] {
				r.fail("%s holds %s incarnation %s, which was deleted (I3): %+v", s.id, id, p.IncarnationID, p)
			}
		}
	}
	for _, id := range unionKeys(held, r.m.rows) {
		p, inFSM := held[id]
		row, inModel := r.m.rows[id]
		switch {
		case inModel && !inFSM && row.state == "reserved" && now > row.expires:
			// The leader's background sweep removed an expired reservation
			// before opSweep did. The model keeps it until opSweep, so the
			// sequence of picks does not depend on that timing.
		case !inModel:
			r.fail("leader %s holds %s, which the model does not: %+v", leader.id, id, p)
		case !inFSM:
			r.fail("leader %s lost %s, which the model holds as %+v", leader.id, id, *row)
		case p.IncarnationID != row.incarnation:
			r.fail("%s has incarnation %s, model %s", id, p.IncarnationID, row.incarnation)
		case row.state == "placed" && (p.State != PlacementStatePlaced || p.IsOrphaned() || p.OwnerNodeID != row.owner):
			r.fail("%s should be placed on %s, is %+v", id, row.owner, p)
		case row.state == "orphaned" && (!p.IsOrphaned() || p.OrphanedOwnerNodeID != row.orphanedFrom):
			r.fail("%s should be orphaned from %s, is %+v", id, row.orphanedFrom, p)
		case row.state == "reserved" && (!p.IsReserved() || p.OwnerNodeID != row.owner):
			r.fail("%s should be reserved on %s, is %+v", id, row.owner, p)
		}
	}
	for _, s := range r.fc.up() {
		if bad := checkFSMInvariants(s.id, s.cluster().fsm, now); len(bad) > 0 {
			r.fail("FSM invariants broken:\n  %s", strings.Join(bad, "\n  "))
		}
	}
	if r.checkReplicas {
		dumps := r.fc.dumpAll()
		for _, d := range dumps[1:] {
			if diffs := diffDumps(dumps[0], d); len(diffs) > 0 {
				r.fail("servers %s and %s applied the same log (FSM version %d) but disagree (I5):\n  %s",
					dumps[0].server, d.server, d.version, strings.Join(diffs, "\n  "))
			}
		}
	}
}
