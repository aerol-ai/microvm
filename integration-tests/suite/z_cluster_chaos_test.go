//go:build integration

package suite

// Cluster correctness under faults: UC-470..UC-479, the live layer of
// plans/cluster-correctness-and-create-latency.md §3.2. Each case injects
// one fault on the role-separated cluster-chaos scenario and asserts the §1
// invariants it threatens, recording a verdict per invariant
// (harness.TrackInvariants) that the report shows next to the row:
//
//	I1 one executor          a node runs or serves X only while it may own X
//	I3 no resurrection       a deleted (X, incarnation) never runs again
//	I4 capacity              no worker runs more than its budget
//	I6 convergence           after the faults, one copy of X, on its owner,
//	                         within T (two reconcile intervals + the grace)
//	I7 routing safety        only the owner serves X; others answer 421/503
//	I8 failed create         a failed create leaves no sandbox, no placement
//
// Several of these FAIL on main today: the fixes (plan C2..C7) are in
// flight. Each doc comment names the plan item it guards, so a red row maps
// to a fix, and stays red until that fix lands.
//
// The file sorts last (z_) and only runs on the focused cluster-chaos
// scenario (its caps file passes -run '^TestClusterChaos'); every case
// restores what it broke before it returns.

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	"github.com/aerol-ai/microvm/internal/failpoint"
	"github.com/aerol-ai/microvm/pkg/models"
)

// UC-470 — partition an owner worker AND the ingress from the servers (and
// the other workers) for AEROL_CHAOS_PARTITION_SECONDS (default 120).
//
// Guards plan C4 (a cut-off owner keeps running and serving): parts 1-3, the
// worker ownership lease, the stale-read refusal and the ingress feed age
// limit. Expected to FAIL on main until C4 lands: the old owner keeps its
// copy running while the majority recreates it (I1), and the ingress on its
// side keeps routing to that copy (I7).
//
// I1: every ~3 s every worker's engine is asked whether it runs the
// sandbox; two at once is a violation, during the partition or after it.
// I7: after the majority has moved the placement, each request through the
// cut-off ingress must be refused with 421 or 503; an answer from the old
// copy (its own copy id, made when its process started) is the violation the
// plan's release gate counts. I6: after the heal, exactly one copy runs, on
// the placement's owner, within chaosConvergeBound, and the domain never
// serves the old copy again.
func TestClusterChaosPartitionedOwnerAndIngress(t *testing.T) {
	harness.Require(t, sc, "UC-470")
	requireDisruptive(t, "this partitions a worker and the ingress from the servers")
	tp := chaosTopology(t)
	inv := harness.TrackInvariants(t, "I1", "I7", "I6")
	tag := chaosTag(t)
	api := chaosAPI(t, tp.servers[len(tp.servers)-1])
	ids := chaosNodeIDs(t, api, tp)

	cpu, mem := chaosSmallSize()
	id := chaosNewSandbox(t, operatorAPI(), chaosRequest(harness.UniqueName(sc, t), tag, true, cpu, mem,
		"python:3.12-alpine", []string{"python3", "-c", chaosCopyServer}))
	ownerID := chaosOwner(t, api, id)
	owner, ok := chaosNodeByID(tp, ids, ownerID)
	if !ok || owner.Role != "worker" {
		t.Fatalf("owner %s of %s is not a worker", ownerID, id)
	}
	url := chaosExpose(t, operatorAPI(), id)
	hc := chaosProbeClient()
	oldCopy := chaosAwaitServed(t, hc, url, 3*time.Minute)
	t.Logf("sandbox %s on %s serves copy %s at %s", id, owner.Name, oldCopy[:8], url)

	ingress := tp.ingresses[0]
	partitionFor := chaosSeconds("AEROL_CHAOS_PARTITION_SECONDS", 120)
	bound := chaosConvergeBound(t, tp)
	heal := chaosPartition(t, []harness.IntegrationNode{owner, ingress}, chaosExcept(tp.all(), owner, ingress), partitionFor+bound+5*time.Minute)
	cut := time.Now()

	var (
		reassignedAt time.Time
		newOwnerID   string
		samples      int
		unobserved   int
		dupSamples   int
		firstDup     string
		maxCopies    int
		tally        = map[string]int{}
		oldServed    int
		firstOld     string
		badRefusals  int
		firstBad     string
	)
	sample := func(phase string) chaosFleetCensus {
		fc := chaosCensusAll(t, tp.workers)
		if !fc.complete() {
			unobserved++
			t.Logf("census incomplete %s: %s", phase, fc.errSummary())
		}
		on := fc.runningOn(id)
		if len(on) > maxCopies {
			maxCopies = len(on)
		}
		if len(on) > 1 {
			dupSamples++
			if firstDup == "" {
				firstDup = fmt.Sprintf("%v at +%s %s", on, time.Since(cut).Round(time.Second), phase)
			}
		}
		samples++
		return fc
	}
	for time.Since(cut) < partitionFor {
		tick := time.Now()
		if newOwnerID == "" {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			pv, found, err := chaosPlacement(ctx, api, id)
			cancel()
			if err == nil && found && pv.Owner.NodeID != "" && pv.Owner.NodeID != ownerID {
				newOwnerID, reassignedAt = pv.Owner.NodeID, time.Now()
				t.Logf("the majority reassigned %s to %s at +%s", id, newOwnerID, reassignedAt.Sub(cut).Round(time.Second))
			}
		}
		sample("during the partition")
		p := chaosProbeCopy(hc, url)
		if !reassignedAt.IsZero() && p.at.After(reassignedAt) {
			tally[p.String()]++
			switch {
			case p.copyID == oldCopy:
				oldServed++
				if firstOld == "" {
					firstOld = fmt.Sprintf("+%s", p.at.Sub(cut).Round(time.Second))
				}
			case p.status == http.StatusMisdirectedRequest || p.status == http.StatusServiceUnavailable:
				// The refusal I7 asks for.
			default:
				badRefusals++
				if firstBad == "" {
					firstBad = fmt.Sprintf("%s at +%s", p, p.at.Sub(cut).Round(time.Second))
				}
			}
		}
		if wait := 3*time.Second - time.Since(tick); wait > 0 {
			time.Sleep(wait)
		}
	}
	heal()
	healedAt := time.Now()

	if newOwnerID == "" {
		t.Errorf("precondition: %s was never reassigned during the %s partition, so the cut-off side was never stale and I7 was not exercised (is SB_DEAD_OWNER_GRACE longer than the partition?)", id, partitionFor)
	} else {
		if oldServed > 0 {
			inv.Violate("I7", "the cut-off ingress served the old copy %d times after the placement moved to %s (first %s)", oldServed, newOwnerID, firstOld)
		}
		if badRefusals > 0 {
			inv.Violate("I7", "the cut-off ingress answered %d requests with something other than 421/503 after the reassign (first %s)", badRefusals, firstBad)
		}
		if oldServed == 0 && badRefusals == 0 {
			inv.Hold("I7", "after the reassign the cut-off ingress answered %v", tally)
		}
	}

	// I6, and I1 through the convergence: one copy, on the owner, the old
	// owner's gone.
	converged := time.Time{}
	var lastOn []string
	lastOwner := ""
	for time.Since(healedAt) < bound {
		fc := sample("after the heal")
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		pv, found, err := chaosPlacement(ctx, api, id)
		cancel()
		lastOn = fc.runningOn(id)
		if err == nil && found {
			lastOwner = pv.Owner.NodeID
			if n, ok := chaosNodeByID(tp, ids, lastOwner); ok && fc.complete() && len(lastOn) == 1 && lastOn[0] == n.Name {
				converged = time.Now()
				break
			}
		}
		time.Sleep(5 * time.Second)
	}
	if converged.IsZero() {
		inv.Violate("I6", "%s after the heal the sandbox runs on %v while its placement names %q", bound, lastOn, lastOwner)
	} else {
		inv.Hold("I6", "one copy, on the owner, %s after the heal", converged.Sub(healedAt).Round(time.Second))
		// The healed domain must never route to the old copy again.
		for end := time.Now().Add(time.Minute); time.Now().Before(end); time.Sleep(3 * time.Second) {
			if p := chaosProbeCopy(hc, url); p.copyID == oldCopy {
				inv.Violate("I7", "after convergence the domain still served the old copy at +%s after the heal", p.at.Sub(healedAt).Round(time.Second))
				break
			}
		}
	}
	if unobserved*5 > samples {
		t.Errorf("%d of %d runtime samples were incomplete; too few to stand for \"at no time two copies\"", unobserved, samples)
	}
	if dupSamples > 0 {
		inv.Violate("I1", "two copies ran at %d of %d samples (first %s)", dupSamples, samples, firstDup)
	} else {
		inv.Hold("I1", "at most %d running copy over %d samples (%s partition + %s after)", maxCopies, samples, partitionFor, time.Since(healedAt).Round(time.Second))
	}
}

// UC-471 — a returning node does not resurrect a deleted sandbox. A worker
// is partitioned from every other node; once its recreate-policy sandbox is
// reassigned, the sandbox is deleted; the worker heals and restarts
// sandboxd (its boot-time ownership replay is the C2 path).
//
// Guards plan C2 (a returning node brings a deleted sandbox back: its
// AssertOwnership replay re-places the old incarnation). Expected to FAIL on
// main until C2 lands. Also red until C4 lands if the cut-off worker's old
// copy, which never stopped, is still running when the window ends (I6).
//
// I3: for two reconcile intervals after the restart, the sandbox has no
// placement, the API answers 404, and no worker starts a copy after the
// census saw it gone. I6: by the end of the window no copy runs anywhere.
func TestClusterChaosReturningNodeDoesNotResurrect(t *testing.T) {
	harness.Require(t, sc, "UC-471")
	requireDisruptive(t, "this partitions a worker and restarts its daemon")
	tp := chaosTopology(t)
	inv := harness.TrackInvariants(t, "I3", "I6")
	tag := chaosTag(t)
	api := chaosAPI(t, tp.servers[0])
	ids := chaosNodeIDs(t, api, tp)

	cpu, mem := chaosSmallSize()
	id := chaosNewSandbox(t, operatorAPI(), chaosRequest(harness.UniqueName(sc, t), tag, true, cpu, mem, "", nil))
	ownerID := chaosOwner(t, api, id)
	w1, ok := chaosNodeByID(tp, ids, ownerID)
	if !ok || w1.Role != "worker" {
		t.Fatalf("owner %s of %s is not a worker", ownerID, id)
	}
	failover := chaosFailoverBound()
	bound := chaosConvergeBound(t, tp)
	heal := chaosPartition(t, []harness.IntegrationNode{w1}, chaosExcept(tp.all(), w1), failover+5*time.Minute)
	newOwner, at := chaosAwaitReassign(api, id, ownerID, failover, time.Second)
	if newOwner == "" {
		t.Fatalf("precondition: %s was not reassigned within %s of cutting off %s", id, failover, w1.Name)
	}
	t.Logf("%s reassigned from %s to %s", id, w1.Name, newOwner)

	var status int
	for attempt := 0; attempt < 6; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		st, err := chaosDelete(ctx, operatorAPI(), id)
		cancel()
		status = st
		if err == nil && (st/100 == 2 || st == http.StatusNotFound) {
			break
		}
		t.Logf("DELETE %s = %d %v; retrying", id, st, err)
		time.Sleep(5 * time.Second)
	}
	if status/100 != 2 && status != http.StatusNotFound {
		t.Fatalf("DELETE %s never succeeded (last %d)", id, status)
	}
	t.Logf("deleted %s (%d) %s after the reassign", id, status, time.Since(at).Round(time.Second))
	gone := false
	for end := time.Now().Add(time.Minute); time.Now().Before(end); time.Sleep(3 * time.Second) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		_, found, err := chaosPlacement(ctx, api, id)
		cancel()
		if err == nil && !found {
			gone = true
			break
		}
	}
	if !gone {
		inv.Violate("I3", "the placement of %s survived its own successful delete (%d) for a minute", id, status)
	}

	heal()
	chaosRestartDaemon(t, w1)
	samples := chaosWatchDeleted(t, inv, tp, api, []string{id}, bound, "after "+w1.Name+" returned")
	if !inv.Violated("I3") {
		inv.Hold("I3", "no placement, no 200 and no restarted copy over %d samples (%s) after %s returned", samples, bound, w1.Name)
	}
	if !inv.Violated("I6") {
		inv.Hold("I6", "no copy on any of %d workers %s after %s returned", len(tp.workers), bound, w1.Name)
	}
}

// UC-472 — delete during the failover window. The owner is killed for real
// (sandboxd, every container and the engine), and the sandbox is deleted the
// moment the placement moves, before the new owner has recreated it.
//
// Guards plan C3 (a delete during failover is lost: the new owner has no
// local row, answers 404, which SDKs treat as done, and its owner watcher
// recreates the sandbox seconds later). Expected to FAIL on main until C3
// lands. The second phase, after the old owner returns, also exercises C2.
//
// I3: the sandbox is never placed, answered or run again: for
// chaosConvergeBound with the old owner down, then for one more reconcile
// interval after it returns.
func TestClusterChaosDeleteDuringFailover(t *testing.T) {
	harness.Require(t, sc, "UC-472")
	requireDisruptive(t, "this kills a worker's daemon and container runtime")
	tp := chaosTopology(t)
	inv := harness.TrackInvariants(t, "I3")
	tag := chaosTag(t)
	api := chaosAPI(t, tp.servers[0])
	ids := chaosNodeIDs(t, api, tp)
	bound := chaosConvergeBound(t, tp)
	reconcile := chaosReconcileInterval(t, tp.workers[0])

	cpu, mem := chaosSmallSize()
	id := chaosNewSandbox(t, operatorAPI(), chaosRequest(harness.UniqueName(sc, t), tag, true, cpu, mem, "", nil))
	ownerID := chaosOwner(t, api, id)
	w1, ok := chaosNodeByID(tp, ids, ownerID)
	if !ok || w1.Role != "worker" {
		t.Fatalf("owner %s of %s is not a worker", ownerID, id)
	}
	restore := chaosHardKill(t, w1, false)
	killed := time.Now()
	newOwner, at := chaosAwaitReassign(api, id, ownerID, chaosFailoverBound(), 500*time.Millisecond)
	if newOwner == "" {
		t.Fatalf("precondition: %s was not reassigned within %s of killing %s", id, chaosFailoverBound(), w1.Name)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	status, err := chaosDelete(ctx, operatorAPI(), id)
	cancel()
	t.Logf("killed %s; reassigned to %s at +%s; DELETE %s at +%s = %d %v",
		w1.Name, newOwner, at.Sub(killed).Round(time.Second), id, time.Since(killed).Round(time.Second), status, err)
	if err != nil || (status/100 != 2 && status != http.StatusNotFound) {
		t.Fatalf("DELETE right after the reassign = %d %v; a delete that fails says nothing about a lost one", status, err)
	}

	n := chaosWatchDeleted(t, inv, tp, api, []string{id}, bound, "while "+w1.Name+" was down")
	restore()
	m := chaosWatchDeleted(t, inv, tp, api, []string{id}, reconcile+30*time.Second, "after "+w1.Name+" returned")
	if !inv.Violated("I3") && !inv.Violated("I6") {
		inv.Hold("I3", "the delete (%d) held over %d samples with the owner down and %d after it returned", status, n, m)
	}
}

// UC-473 — kill the Raft leader during AEROL_CHAOS_CREATES (default 200)
// concurrent creates.
//
// Guards plan C5 (a promote that fails during an election leaves a billed
// sandbox) and C1 (reserve conflicts and expiry read the wall clock, so
// servers can disagree on a reservation after an election); the capacity
// half watches for C7. Partly red on main depending on where the kill lands.
//
// I8: every create ends fully created (placed, running once on its owner)
// or fully absent; no name has two sandboxes; no container runs without a
// placement. I6: no reservation outlives its TTL, nothing stuck deleting.
// I4: no worker runs more of the batch than its CPU budget holds.
func TestClusterChaosLeaderKilledDuringCreates(t *testing.T) {
	harness.Require(t, sc, "UC-473")
	requireDisruptive(t, "this kills the Raft leader during a create burst")
	tp := chaosTopology(t)
	inv := harness.TrackInvariants(t, "I8", "I6", "I4")
	tag := chaosTag(t)
	probe := chaosAPI(t, tp.servers[0])
	ids := chaosNodeIDs(t, probe, tp)
	leaderID := chaosLeaderID(t, probe)
	observerNode := tp.servers[0]
	if ids[observerNode.Name] == leaderID {
		observerNode = tp.servers[1]
	}
	observer := chaosAPI(t, observerNode)
	budgets := chaosBudgets(t, chaosWorkerAPIs(t, tp))
	baseline := chaosCensusAll(t, tp.workers)
	if !baseline.complete() {
		t.Fatalf("baseline census incomplete: %s", baseline.errSummary())
	}
	bound := chaosConvergeBound(t, tp)

	n := envInt("AEROL_CHAOS_CREATES", 200)
	killAfter := time.Duration(envInt("AEROL_CHAOS_KILL_AFTER_MS", 1500)) * time.Millisecond
	ramp := 3 * time.Second
	cpu, mem := chaosSmallSize()
	prefix := fmt.Sprintf("chaos473-%d-", time.Now().Unix())
	results := make([]chaosCreateResult, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			time.Sleep(time.Duration(i) * ramp / time.Duration(n))
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
			defer cancel()
			results[i] = chaosCreate(ctx, operatorAPI(), chaosRequest(fmt.Sprintf("%s%03d", prefix, i), tag, false, cpu, mem, "", nil))
		}(i)
	}
	time.Sleep(killAfter)
	victim, restore := chaosKillLeader(t, tp, ids, leaderID)
	killedAt := time.Now()
	wg.Wait()
	restore()
	tally := map[string]int{}
	for _, r := range results {
		tally[r.describe()]++
	}
	t.Logf("%d creates with the leader %s killed %s in: %v", n, victim.Name, killAfter, tally)

	settle := chaosReservationTTL + 30*time.Second
	if bound > settle {
		settle = bound
	}
	if wait := settle - time.Since(killedAt); wait > 0 {
		t.Logf("waiting %s for reservations to expire and reconcile to converge", wait.Round(time.Second))
		time.Sleep(wait)
	}
	res := chaosCheckCreates(t, inv, tp, observer, ids, results, prefix, baseline, cpu, budgets)
	t.Logf("outcome: %d created, %d failed (%d absent, %d applied anyway), %d orphan containers", res.created, res.failed, res.absent, res.appliedAnyway, res.orphanContainers)
	if !inv.Violated("I8") {
		inv.Hold("I8", "%d creates (leader killed mid-burst): %d created, %d failed and left nothing, %d applied after an error", n, res.created, res.absent, res.appliedAnyway)
	}
	if !inv.Violated("I6") {
		inv.Hold("I6", "no reservation or deleting row left %s after the kill", settle.Round(time.Second))
	}
	if !inv.Violated("I4") {
		inv.Hold("I4", "every worker within its CPU budget")
	}
}

// UC-474 — the leader goes away while creates are between reserve and
// promote. A single leader kill opens an election window of a second or
// two, too short to land a promote in from the operator's laptop, so the
// case stops the leader AND a second voter: no new leader can be elected for
// AEROL_CHAOS_PROMOTE_WINDOW_SECONDS (default 30), and every promote in
// flight, and its rollback, fail. Each worker first drops the create image
// (AEROL_CHAOS_PROMOTE_IMAGE, default python:3.12-slim), so a create spends
// seconds pulling between its reserve and its promote.
//
// Guards plan C5 (a failed rollback leaves a billed sandbox: the rollback
// also needs the leader, fails, keeps the local row, and nothing retries
// it). Expected to FAIL on main until C5 lands, when the window is hit.
//
// I8: every create that failed leaves no placement, no reservation and no
// container once the servers are back and converged; every create that
// answered 2xx is placed and running once. When no create failed, the
// window was missed and the case skips, saying so.
func TestClusterChaosLeaderLostDuringPromote(t *testing.T) {
	harness.Require(t, sc, "UC-474")
	requireDisruptive(t, "this stops two of the three Raft voters while creates are in flight")
	tp := chaosTopology(t)
	inv := harness.TrackInvariants(t, "I8")
	tag := chaosTag(t)
	probe := chaosAPI(t, tp.servers[0])
	ids := chaosNodeIDs(t, probe, tp)
	leaderID := chaosLeaderID(t, probe)
	leader, ok := chaosNodeByID(tp, ids, leaderID)
	if !ok {
		t.Fatalf("the leader %s is not a provisioned node", leaderID)
	}
	var second, observerNode harness.IntegrationNode
	for _, s := range tp.servers {
		switch {
		case s.Name == leader.Name:
		case second.Name == "":
			second = s
		default:
			observerNode = s
		}
	}
	if observerNode.Name == "" {
		t.Skip("needs three servers: two to stop and one to read from")
	}
	observer := chaosAPI(t, observerNode)
	budgets := chaosBudgets(t, chaosWorkerAPIs(t, tp))
	baseline := chaosCensusAll(t, tp.workers)
	if !baseline.complete() {
		t.Fatalf("baseline census incomplete: %s", baseline.errSummary())
	}
	bound := chaosConvergeBound(t, tp)

	image := chaosString("AEROL_CHAOS_PROMOTE_IMAGE", "python:3.12-slim")
	for _, w := range tp.workers {
		target, _ := harness.SSHTarget(w)
		if out, err := harness.SSHRun(t, target, chaosPurgeImageScript(image)); err != nil || !strings.Contains(out, "PURGED") {
			t.Logf("purge %s on %s: %v %s (the create may not have to pull)", image, w.Name, err, out)
		}
	}
	m := envInt("AEROL_CHAOS_PROMOTE_CREATES", 12)
	window := chaosSeconds("AEROL_CHAOS_PROMOTE_WINDOW_SECONDS", 30)
	stopAfter := time.Duration(envInt("AEROL_CHAOS_PROMOTE_STOP_AFTER_MS", 2500)) * time.Millisecond
	cpu, mem := chaosSmallSize()
	prefix := fmt.Sprintf("chaos474-%d-", time.Now().Unix())
	results := make([]chaosCreateResult, m)
	var wg sync.WaitGroup
	for i := 0; i < m; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			time.Sleep(time.Duration(i) * 40 * time.Millisecond)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			results[i] = chaosCreate(ctx, operatorAPI(), chaosRequest(fmt.Sprintf("%s%02d", prefix, i), tag, false, cpu, mem, image, []string{"sleep", "infinity"}))
		}(i)
	}
	time.Sleep(stopAfter)
	restore := chaosStopVoters(t, []harness.IntegrationNode{leader, second})
	stoppedAt := time.Now()
	t.Logf("stopped the leader %s and %s %s after the first create; no quorum for %s", leader.Name, second.Name, stopAfter, window)
	time.Sleep(window)
	restore()
	wg.Wait()
	tally := map[string]int{}
	failed := 0
	for _, r := range results {
		tally[r.describe()]++
		if !r.ok() {
			failed++
		}
	}
	t.Logf("%d creates around a %s quorum loss: %v", m, window, tally)

	settle := chaosReservationTTL + 30*time.Second
	if bound > settle {
		settle = bound
	}
	if wait := settle - time.Since(stoppedAt); wait > 0 {
		time.Sleep(wait)
	}
	res := chaosCheckCreates(t, inv, tp, observer, ids, results, prefix, baseline, cpu, budgets)
	if failed == 0 {
		t.Skipf("the promote window was missed: all %d creates answered 2xx before the voters stopped %s in; lower AEROL_CHAOS_PROMOTE_STOP_AFTER_MS or use a larger AEROL_CHAOS_PROMOTE_IMAGE", m, stopAfter)
	}
	if !inv.Violated("I8") {
		inv.Hold("I8", "%d of %d creates failed across the quorum loss and left nothing (%d applied after an error, converged to fully created)", res.absent, m, res.appliedAnyway)
	}
}

// UC-475 — concurrent create, destroy, stop and start on the same names.
// AEROL_CHAOS_LIFECYCLE_NAMES names (default 6), three actors per name, each
// running AEROL_CHAOS_LIFECYCLE_ROUNDS rounds (default 8) of a create (by
// name), then a random stop, start or destroy of whatever sandbox now holds
// the name.
//
// Guards the lifecycle fences behind plan C2 and C3 (a delete must stay a
// delete whatever runs at the same time). Not expected to fail on main
// unless a start or a stop racing a destroy brings the sandbox back.
//
// I3: a destroyed sandbox id (destroy answered 2xx) is never answered 200
// by a get, start or stop that began after the destroy returned, never
// handed back by a create or a name lookup, and never runs again on any
// worker; and no name ever holds two live placements.
func TestClusterChaosConcurrentLifecycleSameNames(t *testing.T) {
	harness.Require(t, sc, "UC-475")
	requireDisruptive(t, "this races lifecycle calls on shared names")
	tp := chaosTopology(t)
	inv := harness.TrackInvariants(t, "I3")
	tag := chaosTag(t)
	api := operatorAPI()
	observer := chaosAPI(t, tp.servers[0])
	bound := chaosConvergeBound(t, tp)
	c := client(t)

	names := envInt("AEROL_CHAOS_LIFECYCLE_NAMES", 6)
	rounds := envInt("AEROL_CHAOS_LIFECYCLE_ROUNDS", 8)
	const actors = 3
	cpu, mem := chaosSmallSize()
	prefix := fmt.Sprintf("chaos475-%d-", time.Now().Unix())

	var mu sync.Mutex
	deleted := map[string]time.Time{} // id -> when its destroy returned 2xx
	everIDs := map[string]bool{}
	ops := map[string]int{}
	deletedAt := func(id string) (time.Time, bool) {
		mu.Lock()
		defer mu.Unlock()
		at, ok := deleted[id]
		return at, ok
	}
	deletedBefore := func(id string, start time.Time) bool {
		at, ok := deletedAt(id)
		return ok && at.Before(start)
	}
	record := func(op string, status int) {
		mu.Lock()
		ops[fmt.Sprintf("%s %d", op, status)]++
		mu.Unlock()
	}

	stop := make(chan struct{})
	var sampled atomic.Int64
	var samplerWG sync.WaitGroup
	samplerWG.Add(1)
	go func() {
		defer samplerWG.Done()
		for {
			select {
			case <-stop:
				return
			case <-time.After(5 * time.Second):
			}
			start := time.Now()
			fc := chaosCensusAll(t, tp.workers)
			for id, on := range fc.running() {
				// Ten seconds of grace: a container that dies a moment after
				// its destroy answered is teardown lag, not a resurrection;
				// one still running after the race is chaosWatchDeleted's.
				if at, ok := deletedAt(id); ok && at.Before(start.Add(-10*time.Second)) {
					inv.Violate("I3", "destroyed sandbox %s runs on %v (sampled %s after its destroy returned)", id, on, start.Sub(at).Round(time.Second))
				}
			}
			sampled.Add(1)
		}
	}()

	var wg sync.WaitGroup
	for ni := 0; ni < names; ni++ {
		name := fmt.Sprintf("%s%02d", prefix, ni)
		for a := 0; a < actors; a++ {
			wg.Add(1)
			go func(a int) {
				defer wg.Done()
				for r := 0; r < rounds; r++ {
					ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
					start := time.Now()
					cr := chaosCreate(ctx, api, chaosRequest(name, tag, false, cpu, mem, "", nil))
					record("create", cr.Status)
					id := cr.ID
					if !cr.ok() {
						if sb, err := c.SDK().GetByName(ctx, name); err == nil {
							id = sb.ID
						}
					}
					if id == "" {
						cancel()
						continue
					}
					if deletedBefore(id, start) {
						inv.Violate("I3", "create or lookup of %s handed back %s, destroyed before the call began", name, id)
					}
					mu.Lock()
					everIDs[id] = true
					mu.Unlock()
					opStart := time.Now()
					var op, path, method string
					switch (a + r) % 3 {
					case 0:
						op, method, path = "stop", http.MethodPost, "/v1/sandboxes/"+id+"/stop"
					case 1:
						op, method, path = "start", http.MethodPost, "/v1/sandboxes/"+id+"/start"
					default:
						op, method, path = "destroy", http.MethodDelete, "/v1/sandboxes/"+id
					}
					resp, err := api.Do(ctx, method, path, nil)
					if err == nil {
						record(op, resp.Status)
						switch {
						case op == "destroy" && resp.Status/100 == 2:
							mu.Lock()
							if _, ok := deleted[id]; !ok {
								deleted[id] = time.Now()
							}
							mu.Unlock()
						case op != "destroy" && resp.Status/100 == 2 && deletedBefore(id, opStart):
							inv.Violate("I3", "%s of %s answered %d although its destroy had returned before the call began", op, id, resp.Status)
						}
					}
					if st, _, gerr := chaosGetStatus(ctx, api, id); gerr == nil && st == http.StatusOK && deletedBefore(id, time.Now().Add(-time.Second)) {
						inv.Violate("I3", "get of %s answered 200 after its destroy returned", id)
					}
					cancel()
				}
			}(a)
		}
	}
	wg.Wait()
	close(stop)
	samplerWG.Wait()
	t.Logf("lifecycle answers: %v", ops)

	// No name with two live placements, before the cleanup.
	byName := map[string][]string{}
	for _, r := range chaosIndexEventually(t, observer) {
		if strings.HasPrefix(r.Name, prefix) && r.State != "deleting" {
			byName[r.Name] = append(byName[r.Name], r.SandboxID)
		}
	}
	for name, sbs := range byName {
		if len(sbs) > 1 {
			inv.Violate("I3", "name %s holds %d live placements at once: %v", name, len(sbs), sbs)
		}
	}

	// Delete what is left, then watch every id that ever existed.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	gone, err := c.SDK().DestroyAll(ctx, map[string]string{"chaos-run": tag})
	cancel()
	if err != nil {
		t.Fatalf("delete the survivors: %v (%d deleted)", err, len(gone))
	}
	all := make([]string, 0, len(everIDs))
	for id := range everIDs {
		all = append(all, id)
	}
	sort.Strings(all)
	samples := chaosWatchDeleted(t, inv, tp, observer, all, bound, "after the race")
	if !inv.Violated("I3") && !inv.Violated("I6") {
		inv.Hold("I3", "%d sandbox ids across %d names: no destroyed id answered, was handed back or ran again (%d census samples during the race, %d after)", len(all), names, sampled.Load(), samples)
	}
}

// UC-476 — 5% packet loss and 200 ms delay between every pair of nodes
// (AEROL_CHAOS_NETEM_LOSS / _DELAY) for AEROL_CHAOS_NETEM_SECONDS (default
// 180), while AEROL_CHAOS_NETEM_CREATES (default 30) recreate-policy creates
// run five at a time. Heartbeats arrive late and some not at all, so SWIM
// may suspect healthy nodes and the dead-owner path may fire on one.
//
// Guards plan C4 (a falsely-dead owner keeps running while its sandbox is
// recreated elsewhere), C6 (eviction has no owner fence) and C7 (capacity
// under-count). Red on main if the impairment triggers a false failover.
//
// I1: no sandbox runs on two workers at any ~5 s sample. I4: no worker runs
// more of the batch than its budget at any sample. I8 (and I6) after the
// impairment clears and the cluster converges: chaosCheckCreates.
func TestClusterChaosPacketLossAndDelay(t *testing.T) {
	harness.Require(t, sc, "UC-476")
	requireDisruptive(t, "this delays and drops packets between every node")
	tp := chaosTopology(t)
	inv := harness.TrackInvariants(t, "I1", "I4", "I8")
	tag := chaosTag(t)
	observer := chaosAPI(t, tp.servers[0])
	ids := chaosNodeIDs(t, observer, tp)
	budgets := chaosBudgets(t, chaosWorkerAPIs(t, tp))
	baseline := chaosCensusAll(t, tp.workers)
	if !baseline.complete() {
		t.Fatalf("baseline census incomplete: %s", baseline.errSummary())
	}
	bound := chaosConvergeBound(t, tp)
	before := baseline.running()

	delay := chaosString("AEROL_CHAOS_NETEM_DELAY", "200ms")
	loss := chaosString("AEROL_CHAOS_NETEM_LOSS", "5%")
	dur := chaosSeconds("AEROL_CHAOS_NETEM_SECONDS", 180)
	creates := envInt("AEROL_CHAOS_NETEM_CREATES", 30)
	cpu, mem := chaosSmallSize()
	prefix := fmt.Sprintf("chaos476-%d-", time.Now().Unix())

	clear := chaosNetem(t, tp.all(), delay, loss, dur+bound+10*time.Minute)
	start := time.Now()
	stop := make(chan struct{})
	var (
		smu                 sync.Mutex
		samples, dupSamples int
		overSamples         int
		firstDup, firstOver string
		maxLoad             = map[string]int{}
		samplerWG           sync.WaitGroup
	)
	samplerWG.Add(1)
	go func() {
		defer samplerWG.Done()
		for {
			select {
			case <-stop:
				return
			case <-time.After(5 * time.Second):
			}
			fc := chaosCensusAll(t, tp.workers)
			load := map[string]int{}
			smu.Lock()
			for id, on := range fc.running() {
				if _, old := before[id]; old {
					continue
				}
				for _, n := range on {
					load[n]++
				}
				if len(on) > 1 {
					dupSamples++
					if firstDup == "" {
						firstDup = fmt.Sprintf("%s on %v at +%s", id, on, time.Since(start).Round(time.Second))
					}
				}
			}
			for name, n := range load {
				if n > maxLoad[name] {
					maxLoad[name] = n
				}
				if float64(n)*cpu > budgets[name].CPUBudget {
					overSamples++
					if firstOver == "" {
						firstOver = fmt.Sprintf("%s ran %d (%.2f CPU of %.2f) at +%s", name, n, float64(n)*cpu, budgets[name].CPUBudget, time.Since(start).Round(time.Second))
					}
				}
			}
			samples++
			smu.Unlock()
		}
	}()

	results := make([]chaosCreateResult, creates)
	sem := make(chan struct{}, 5)
	var wg sync.WaitGroup
	for i := 0; i < creates && time.Since(start) < dur; i++ {
		sem <- struct{}{}
		wg.Add(1)
		go func(i int) {
			defer func() { <-sem; wg.Done() }()
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
			defer cancel()
			results[i] = chaosCreate(ctx, operatorAPI(), chaosRequest(fmt.Sprintf("%s%03d", prefix, i), tag, true, cpu, mem, "", nil))
		}(i)
	}
	wg.Wait()
	if wait := dur - time.Since(start); wait > 0 {
		time.Sleep(wait)
	}
	clear()
	clearedAt := time.Now()
	// Keep sampling through the recovery: the late duplicates show up here.
	time.Sleep(time.Minute)
	close(stop)
	samplerWG.Wait()

	var attempted []chaosCreateResult
	tally := map[string]int{}
	for _, r := range results {
		if r.Name != "" {
			attempted = append(attempted, r)
			tally[r.describe()]++
		}
	}
	t.Logf("%d creates under %s delay and %s loss: %v", len(attempted), delay, loss, tally)

	settle := chaosReservationTTL + 30*time.Second
	if bound > settle {
		settle = bound
	}
	if wait := settle - time.Since(clearedAt); wait > 0 {
		time.Sleep(wait)
	}
	res := chaosCheckCreates(t, inv, tp, observer, ids, attempted, prefix, baseline, cpu, budgets)

	smu.Lock()
	defer smu.Unlock()
	if dupSamples > 0 {
		inv.Violate("I1", "a sandbox ran on two workers at %d of %d samples (first %s)", dupSamples, samples, firstDup)
	} else {
		inv.Hold("I1", "no sandbox on two workers over %d samples (%s impaired + 1m)", samples, dur)
	}
	if overSamples > 0 {
		inv.Violate("I4", "a worker ran over its budget at %d samples (first %s)", overSamples, firstOver)
	} else if !inv.Violated("I4") {
		inv.Hold("I4", "peak batch load per worker %v, every one within budget", maxLoad)
	}
	if !inv.Violated("I8") {
		inv.Hold("I8", "%d created, %d failed and left nothing, %d applied after an error", res.created, res.absent, res.appliedAnyway)
	}
}

// UC-477 — restart every server one at a time, the leader last.
//
// Guards plan C1 (the Raft state machine reads the wall clock, so a server
// replaying its log after a restart can rebuild a different owner or
// incarnation than the one committed). Expected to pass on main unless a
// replay diverges.
//
// I6: after each restart a leader is back and the restarted server, read on
// its own loopback, names the same owner for every placement as before the
// restarts, with the same incarnation; every sandbox still runs once, on its
// owner; and after the last restart the cluster takes a new create and a
// delete.
func TestClusterChaosRollingServerRestart(t *testing.T) {
	harness.Require(t, sc, "UC-477")
	requireDisruptive(t, "this restarts every Raft voter in turn")
	tp := chaosTopology(t)
	inv := harness.TrackInvariants(t, "I6")
	tag := chaosTag(t)
	api := operatorAPI()
	ids := chaosNodeIDs(t, chaosAPI(t, tp.servers[0]), tp)

	k := envInt("AEROL_CHAOS_RESTART_SANDBOXES", 6)
	cpu, mem := chaosSmallSize()
	var sbs []string
	for i := 0; i < k; i++ {
		sbs = append(sbs, chaosNewSandbox(t, api, chaosRequest(fmt.Sprintf("%s-%d", harness.UniqueName(sc, t), i), tag, i%2 == 0, cpu, mem, "", nil)))
	}
	type committed struct{ owner, incarnation string }
	snapshot := func(view *harness.APIClient) map[string]committed {
		out := map[string]committed{}
		for _, r := range chaosIndexEventually(t, view) {
			out[r.SandboxID] = committed{owner: r.OwnerNodeID, incarnation: r.IncarnationID}
		}
		return out
	}
	before := snapshot(api)
	for _, id := range sbs {
		if before[id].owner == "" || before[id].incarnation == "" {
			t.Fatalf("no committed placement for %s before the restarts: %+v", id, before[id])
		}
	}

	leaderID := chaosLeaderID(t, api)
	order := append([]harness.IntegrationNode(nil), tp.servers...)
	sort.SliceStable(order, func(i, j int) bool { return ids[order[j].Name] == leaderID && ids[order[i].Name] != leaderID })
	for _, s := range order {
		t.Logf("restarting %s (leader: %v)", s.Name, ids[s.Name] == leaderID)
		chaosRestartDaemon(t, s)
		if chaosLeaderID(t, api) == "" {
			inv.Violate("I6", "no leader after restarting %s", s.Name)
		}
		view := chaosAPI(t, s)
		after := snapshot(view)
		for _, id := range sbs {
			if got, want := after[id], before[id]; got != want {
				inv.Violate("I6", "after its restart %s reads %s as owner %q incarnation %q; committed was %q %q", s.Name, id, got.owner, got.incarnation, want.owner, want.incarnation)
			}
		}
		fc := chaosCensusAll(t, tp.workers)
		if !fc.complete() {
			t.Errorf("census after restarting %s is incomplete: %s", s.Name, fc.errSummary())
		}
		for _, id := range sbs {
			owner, _ := chaosNodeByID(tp, ids, before[id].owner)
			if on := fc.runningOn(id); len(on) != 1 || on[0] != owner.Name {
				inv.Violate("I6", "after restarting %s, %s runs on %v; its owner is %s", s.Name, id, on, owner.Name)
			}
		}
	}

	// The last restart was the leader's. Its replacement answers placement
	// reads at once but places nothing until each worker's next capacity
	// report reaches it, about 20 s (UC-481 measures the same gap), and says
	// so with a retryable 503. So the create retries a 503 for a bounded
	// time, as a client would, and the wait is logged.
	afterReq := chaosRequest(harness.UniqueName(sc, t)+"-after", tag, false, cpu, mem, "", nil)
	createStart := time.Now()
	var made chaosCreateResult
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		made = chaosCreate(ctx, api, afterReq)
		cancel()
		if made.ok() || made.Status != http.StatusServiceUnavailable || time.Since(createStart) > 90*time.Second {
			break
		}
		time.Sleep(3 * time.Second)
	}
	if !made.ok() {
		t.Fatalf("create %s after the restarts: %s %v %s (retried 503s for %s)", afterReq.Name, made.describe(), made.Err, made.Body, time.Since(createStart).Round(time.Second))
	}
	t.Logf("the first create after the restarts succeeded %s after the leader's restart", time.Since(createStart).Round(time.Second))
	chaosAwaitStarted(t, api, made.ID, 3*time.Minute)
	fresh := made.ID
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	st, err := chaosDelete(ctx, api, fresh)
	cancel()
	if err != nil || st/100 != 2 {
		inv.Violate("I6", "after the restarts a delete answered %d %v", st, err)
	}
	if !inv.Violated("I6") {
		inv.Hold("I6", "%d placements kept owner and incarnation through %d server restarts (leader last); one copy each throughout; a new create and delete worked", len(sbs), len(order))
	}
}

// UC-478 — mass failover capacity. Every recreate-policy sandbox the case
// makes (AEROL_CHAOS_MASS_SANDBOXES, default 12, at
// AEROL_CHAOS_MASS_CPU, default 1.0 CPU) lands on one worker (the others
// drained for the create), the survivors are filled until each has only
// AEROL_CHAOS_MASS_SURVIVOR_FREE_CPU (default 4) left, and the loaded worker
// is killed for real. The survivors can take fewer sandboxes than it held.
//
// Guards plan C7 (right after a promote or reassign the leader under-counts
// a worker's load, so a mass failover assigns against one stale snapshot).
// On main the worker's own admitter refuses the overflow, so I4 should hold
// but sandboxes placed on a survivor may never run there (I6): red until C7
// lands if that happens.
//
// I4: at every ~5 s sample, no survivor runs more sandboxes than its budget
// holds and no survivor's admitter reserves past its budget. I6: by
// AEROL_CHAOS_FAILOVER_BOUND_SECONDS (default 300) every sandbox placed on a
// survivor runs there, and every one that is not placed on a live node runs
// nowhere; after the dead worker returns it runs none of them.
func TestClusterChaosMassFailoverCapacity(t *testing.T) {
	harness.Require(t, sc, "UC-478")
	requireDisruptive(t, "this kills a loaded worker's daemon and container runtime")
	tp := chaosTopology(t)
	inv := harness.TrackInvariants(t, "I4", "I6")
	tag := chaosTag(t)
	api := chaosAPI(t, tp.servers[0])
	ids := chaosNodeIDs(t, api, tp)
	wapis := chaosWorkerAPIs(t, tp)
	budgets := chaosBudgets(t, wapis)
	victim, survivors := tp.workers[0], tp.workers[1:]

	h := envInt("AEROL_CHAOS_MASS_SANDBOXES", 12)
	cpu := chaosFloat("AEROL_CHAOS_MASS_CPU", 1.0)
	mem := envInt("AEROL_CHAOS_MASS_MEMORY_MB", 256)
	free := chaosFloat("AEROL_CHAOS_MASS_SURVIVOR_FREE_CPU", 4)
	if fit := int((budgets[victim.Name].CPUBudget - budgets[victim.Name].ReservedCPU) / cpu); fit < h {
		h = fit
	}
	if h < 2 {
		t.Fatalf("precondition: %s fits only %d sandboxes of %.2f CPU", victim.Name, h, cpu)
	}

	drain := func(n harness.IntegrationNode, on bool) {
		verb := "uncordon"
		if on {
			verb = "drain"
		}
		resp := statusAs(t, api, http.MethodPost, "/v1/cluster/nodes/"+ids[n.Name]+"/"+verb, nil)
		if resp.Status/100 != 2 {
			t.Fatalf("%s %s: %s", verb, n.Name, resp)
		}
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		for _, w := range tp.workers {
			_, _ = api.Do(ctx, http.MethodPost, "/v1/cluster/nodes/"+ids[w.Name]+"/uncordon", nil)
		}
	})
	// Placement reads capacity from heartbeats, so give each drain a beat
	// to reach the leader's view.
	settleDrain := func() { time.Sleep(chaosSeconds("AEROL_CHAOS_DRAIN_SETTLE_SECONDS", 10)) }

	for _, s := range survivors {
		drain(s, true)
	}
	settleDrain()
	var ha []string
	for i := 0; i < h; i++ {
		id := chaosNewSandbox(t, operatorAPI(), chaosRequest(fmt.Sprintf("%s-ha-%02d", harness.UniqueName(sc, t), i), tag, true, cpu, mem, "", nil))
		if o := chaosOwner(t, api, id); o != ids[victim.Name] {
			t.Fatalf("precondition: %s landed on %s, not the only undrained worker %s", id, o, victim.Name)
		}
		ha = append(ha, id)
	}
	for _, s := range survivors {
		drain(s, false)
	}
	// Fill each survivor in turn, the others drained.
	fillers := 0
	ours := map[string]bool{}
	for _, id := range ha {
		ours[id] = true
	}
	for _, s := range survivors {
		for _, other := range chaosExcept(tp.workers, s) {
			drain(other, true)
		}
		settleDrain()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		c, err := chaosCapacityOf(ctx, wapis[s.Name])
		cancel()
		if err != nil {
			t.Fatalf("capacity of %s: %v", s.Name, err)
		}
		for i := 0; c.ReservedCPU+float64(i+1)*cpu <= c.CPUBudget-free; i++ {
			id := chaosNewSandbox(t, operatorAPI(), chaosRequest(fmt.Sprintf("%s-fill-%s-%02d", harness.UniqueName(sc, t), s.Name, i), tag, false, cpu, mem, "", nil))
			if o := chaosOwner(t, api, id); o != ids[s.Name] {
				t.Fatalf("precondition: filler %s landed on %s, not %s", id, o, s.Name)
			}
			ours[id] = true
			fillers++
		}
		for _, other := range chaosExcept(tp.workers, s) {
			drain(other, false)
		}
	}
	room := 0
	for _, s := range survivors {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		c, err := chaosCapacityOf(ctx, wapis[s.Name])
		cancel()
		if err != nil {
			t.Fatalf("capacity of %s: %v", s.Name, err)
		}
		room += int((c.CPUBudget - c.ReservedCPU) / cpu)
	}
	t.Logf("%d recreate-policy sandboxes on %s; %d fillers; the survivors have room for %d", h, victim.Name, fillers, room)
	settleDrain()

	restore := chaosHardKill(t, victim, false)
	killedAt := time.Now()
	bound := chaosFailoverBound()
	runningSince := map[string]time.Duration{}
	var (
		samples, overSamples int
		firstOver            string
		peak                 = map[string]int{}
	)
	var final chaosFleetCensus
	for time.Since(killedAt) < bound {
		fc := chaosCensusAll(t, survivors)
		final = fc
		load := map[string]int{}
		for id, on := range fc.running() {
			if !ours[id] {
				continue // not this case's; the admitter check below covers it
			}
			for _, n := range on {
				load[n]++
			}
		}
		for _, s := range survivors {
			if load[s.Name] > peak[s.Name] {
				peak[s.Name] = load[s.Name]
			}
			// Every sandbox this case made asks for cpu (fillers and the
			// reassigned alike), so the count is their load.
			if used := float64(load[s.Name]) * cpu; used > budgets[s.Name].CPUBudget {
				overSamples++
				if firstOver == "" {
					firstOver = fmt.Sprintf("%s ran %d (%.2f of %.2f CPU) at +%s", s.Name, load[s.Name], used, budgets[s.Name].CPUBudget, time.Since(killedAt).Round(time.Second))
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			c, err := chaosCapacityOf(ctx, wapis[s.Name])
			cancel()
			if err == nil && c.ReservedCPU > c.CPUBudget+1e-9 {
				overSamples++
				if firstOver == "" {
					firstOver = fmt.Sprintf("%s's admitter reserved %.2f of %.2f CPU at +%s", s.Name, c.ReservedCPU, c.CPUBudget, time.Since(killedAt).Round(time.Second))
				}
			}
		}
		for _, id := range ha {
			if _, done := runningSince[id]; done {
				continue
			}
			if len(fc.runningOn(id)) > 0 {
				runningSince[id] = time.Since(killedAt)
			}
		}
		samples++
		time.Sleep(5 * time.Second)
	}

	// Where every sandbox ended up, at the bound.
	landed, unplaced := 0, 0
	var times []time.Duration
	for _, id := range ha {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		pv, found, err := chaosPlacement(ctx, api, id)
		cancel()
		if err != nil {
			t.Errorf("placement of %s at the bound: %v", id, err)
			continue
		}
		on := final.runningOn(id)
		owner, onSurvivor := chaosNodeByID(tp, ids, pv.Owner.NodeID)
		onSurvivor = onSurvivor && found && !pv.Orphaned && owner.Name != victim.Name
		switch {
		case onSurvivor && (len(on) != 1 || on[0] != owner.Name):
			inv.Violate("I6", "%s is placed on %s but runs on %v %s after the kill", id, owner.Name, on, bound)
		case onSurvivor:
			landed++
			times = append(times, runningSince[id])
		case len(on) > 0:
			inv.Violate("I6", "%s is not placed on a live node (owner %q, orphaned %v) yet runs on %v", id, pv.Owner.NodeID, pv.Orphaned, on)
		default:
			unplaced++
		}
	}
	sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
	if overSamples > 0 {
		inv.Violate("I4", "a survivor ran or reserved over its budget at %d of %d samples (first %s)", overSamples, samples, firstOver)
	} else {
		inv.Hold("I4", "peak survivor load %v sandboxes of %.2f CPU over %d samples, every one within budget", peak, cpu, samples)
	}
	if len(times) > 0 {
		t.Logf("%d of %d landed (room %d), %d left unplaced; time to running p50 %s max %s", landed, h, room, unplaced, times[len(times)/2].Round(time.Second), times[len(times)-1].Round(time.Second))
	}

	// The dead worker returns and must run none of them.
	restore()
	returned := time.Now()
	convBound := chaosConvergeBound(t, tp)
	for time.Since(returned) < convBound {
		c, err := chaosCensus(t, victim)
		if err == nil {
			var stale []string
			for _, id := range ha {
				if c.Running(id) {
					stale = append(stale, id)
				}
			}
			if len(stale) == 0 {
				break
			}
			if time.Since(returned)+10*time.Second >= convBound {
				inv.Violate("I6", "%s, back for %s, still runs %v", victim.Name, convBound, stale)
				break
			}
		}
		time.Sleep(10 * time.Second)
	}
	if !inv.Violated("I6") && len(times) > 0 {
		inv.Hold("I6", "%d of %d landed and ran within %s (max %s), %d left unplaced and not running; %s ran none after returning", landed, h, bound, times[len(times)-1].Round(time.Second), unplaced, victim.Name)
	} else if !inv.Violated("I6") {
		inv.Hold("I6", "none of %d landed within %s and none runs anywhere", h, bound)
	}
}

// UC-479 — the old copy dies. The owner is killed for real (sandboxd, every
// container, the engine), the sandbox fails over and runs on a new owner,
// then the old node returns.
//
// Guards plan C4 (the old owner stops its copy only in reconcile, which
// needs a leader) and C2 (the returning node's boot replay re-asserts
// ownership of what its store still lists). Its containers were killed, so a
// copy on it after it returns is one its own boot path started.
//
// I1: sampled from the moment the old node starts coming back until
// chaosConvergeBound after it is back, it never runs the sandbox. I6: at the
// end exactly one copy runs, on the placement's owner.
func TestClusterChaosOldCopyDiesAfterReturn(t *testing.T) {
	harness.Require(t, sc, "UC-479")
	requireDisruptive(t, "this kills a worker's daemon and container runtime")
	tp := chaosTopology(t)
	inv := harness.TrackInvariants(t, "I1", "I6")
	tag := chaosTag(t)
	api := chaosAPI(t, tp.servers[0])
	ids := chaosNodeIDs(t, api, tp)
	bound := chaosConvergeBound(t, tp)

	cpu, mem := chaosSmallSize()
	id := chaosNewSandbox(t, operatorAPI(), chaosRequest(harness.UniqueName(sc, t), tag, true, cpu, mem, "", nil))
	ownerID := chaosOwner(t, api, id)
	w1, ok := chaosNodeByID(tp, ids, ownerID)
	if !ok || w1.Role != "worker" {
		t.Fatalf("owner %s of %s is not a worker", ownerID, id)
	}
	restore := chaosHardKill(t, w1, false)
	newOwnerID, _ := chaosAwaitReassign(api, id, ownerID, chaosFailoverBound(), time.Second)
	if newOwnerID == "" {
		t.Fatalf("precondition: %s was not reassigned within %s of killing %s", id, chaosFailoverBound(), w1.Name)
	}
	w2, ok := chaosNodeByID(tp, ids, newOwnerID)
	if !ok {
		t.Fatalf("new owner %s is not a provisioned node", newOwnerID)
	}
	running := false
	for end := time.Now().Add(chaosFailoverBound()); time.Now().Before(end); time.Sleep(5 * time.Second) {
		if c, err := chaosCensus(t, w2); err == nil && c.Running(id) {
			running = true
			break
		}
	}
	if !running {
		t.Fatalf("precondition: %s never ran on its new owner %s", id, w2.Name)
	}

	stop := make(chan struct{})
	var (
		smu            sync.Mutex
		samples, onOld int
		firstOld       string
		sampleStart    = time.Now()
		samplerWG      sync.WaitGroup
	)
	samplerWG.Add(1)
	go func() {
		defer samplerWG.Done()
		for {
			if c, err := chaosCensus(t, w1); err == nil {
				smu.Lock()
				samples++
				if c.Running(id) {
					onOld++
					if firstOld == "" {
						firstOld = fmt.Sprintf("+%s", time.Since(sampleStart).Round(time.Second))
					}
				}
				smu.Unlock()
			}
			select {
			case <-stop:
				return
			case <-time.After(3 * time.Second):
			}
		}
	}()
	restore()
	returned := time.Now()
	t.Logf("%s back after %s", w1.Name, returned.Sub(sampleStart).Round(time.Second))
	if wait := bound - time.Since(returned); wait > 0 {
		time.Sleep(wait)
	}
	close(stop)
	samplerWG.Wait()

	fc := chaosCensusAll(t, tp.workers)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	pv, found, err := chaosPlacement(ctx, api, id)
	cancel()
	on := fc.runningOn(id)
	owner, _ := chaosNodeByID(tp, ids, pv.Owner.NodeID)
	if err != nil || !found || !fc.complete() || len(on) != 1 || on[0] != owner.Name {
		inv.Violate("I6", "%s after %s returned: runs on %v, placement owner %q (found %v, err %v, census %s)", bound, w1.Name, on, owner.Name, found, err, fc.errSummary())
	} else {
		inv.Hold("I6", "one copy, on %s, %s after %s returned", owner.Name, bound, w1.Name)
	}
	smu.Lock()
	defer smu.Unlock()
	switch {
	case samples == 0:
		t.Errorf("%s never answered a census after the kill, so I1 was not observed", w1.Name)
	case onOld > 0:
		inv.Violate("I1", "the returned %s ran the sandbox at %d of %d samples (first %s after it started coming back), while %s owned it", w1.Name, onOld, samples, firstOld, w2.Name)
	default:
		inv.Hold("I1", "the returned %s ran no copy over %d samples (%s)", w1.Name, samples, time.Since(sampleStart).Round(time.Second))
	}
}

// UC-480 — a worker crashes between starting a sandbox and storing its row.
// The failpoint internal/failpoint.CreateBeforePersist is armed on every
// worker for this case's unique name; the one worker the create lands on
// parks it with the container running, its route and network slot held,
// its placement reserved, and no row; the case SIGKILLs sandboxd there
// (systemd restarts it at once, as on a real node).
//
// I8: once the reservation TTL and chaosConvergeBound have passed, the
// create is fully created (an answered 2xx: placed, and running once on its
// owner) or fully absent: the crashed attempt runs on no worker, has no
// placement, the API answers 404 for it, the worker holds no extra netns
// slot, and no container runs without a placement (chaosCheckCreates). I6:
// no reservation outlives its TTL.
//
// Needs sandboxd built with -tags itest_failpoints: run.sh's local build of
// cluster-chaos adds it (caps go_tags). On a binary without it the
// failpoint never fires and the create succeeds; the case then skips.
func TestClusterChaosCrashBeforeCreatePersists(t *testing.T) {
	harness.Require(t, sc, "UC-480")
	requireDisruptive(t, "this SIGKILLs a worker's sandboxd in the middle of a create")
	tp := chaosTopology(t)
	inv := harness.TrackInvariants(t, "I8", "I6")
	tag := chaosTag(t)
	observer := chaosAPI(t, tp.servers[0])
	ids := chaosNodeIDs(t, observer, tp)
	wapis := chaosWorkerAPIs(t, tp)
	budgets := chaosBudgets(t, wapis)
	bound := chaosConvergeBound(t, tp)
	baseline := chaosCensusAll(t, tp.workers)
	if !baseline.complete() {
		t.Fatalf("baseline census incomplete: %s", baseline.errSummary())
	}
	slotsBefore := map[string]int{}
	for name, api := range wapis {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		n, ok, err := chaosNetnsInUse(ctx, api)
		cancel()
		if err != nil {
			t.Fatalf("read %s's netns pool: %v", name, err)
		}
		if ok {
			slotsBefore[name] = n
		}
	}

	name := harness.UniqueName(sc, t)
	chaosArmFailpoint(t, tp.workers, failpoint.CreateBeforePersist, name)
	cpu, mem := chaosSmallSize()
	done := make(chan chaosCreateResult, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		done <- chaosCreate(ctx, operatorAPI(), chaosRequest(name, tag, false, cpu, mem, "", nil))
	}()

	// Wait for the hit, or for the create to answer without one. The create
	// is read before the markers in each round, so the round that sees it
	// answered still checks every worker once more after it.
	var (
		victim   harness.IntegrationNode
		res      chaosCreateResult
		answered bool
	)
	for deadline := time.Now().Add(4 * time.Minute); victim.Name == ""; time.Sleep(time.Second) {
		select {
		case res = <-done:
			answered = true
		default:
		}
		for _, w := range tp.workers {
			key, hit, err := chaosFailpointHit(t, w, failpoint.CreateBeforePersist)
			if err != nil {
				t.Logf("failpoint check: %v", err)
				continue
			}
			if hit {
				victim = w
				t.Logf("the create of %q parked on %s before its row was stored", key, w.Name)
			}
		}
		if victim.Name != "" || answered {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("neither did the failpoint fire nor did the create of %s answer within 4m", name)
		}
	}
	if victim.Name == "" {
		if res.ok() {
			t.Skipf("the failpoint never fired and the create succeeded (%s): sandboxd on the workers has no failpoints. "+
				"run.sh builds cluster-chaos with -tags itest_failpoints (caps go_tags; the build id ends -tags-itest_failpoints, this run's is %q); "+
				"a --released or --version run installs release binaries without them", res.ID, os.Getenv("AEROL_BUILD_ID"))
		}
		t.Fatalf("precondition: the create failed before it reached the failpoint: %s %v %s", res.describe(), res.Err, res.Body)
	}

	// Which sandbox: the reservation the leader holds for the name, and the
	// new task the victim runs. Either may be missing; each found one is
	// checked.
	var crashed []string
	for _, r := range chaosIndexEventually(t, observer) {
		if r.Name == name {
			crashed = append(crashed, r.SandboxID)
		}
	}
	if c, err := chaosCensus(t, victim); err == nil {
		for _, id := range c.RunningIDs() {
			if !baseline.byNode[victim.Name].Running(id) && !slices.Contains(crashed, id) {
				crashed = append(crashed, id)
			}
		}
	} else {
		t.Logf("census of %s before the kill: %v", victim.Name, err)
	}
	t.Logf("the parked create is %v on %s", crashed, victim.Name)

	// The victim is a worker and the seed is a server, so this never skips;
	// it states the choice for restart_node_test.go's seed guard.
	requireNonSeedVictim(t, victim)
	target, _ := harness.SSHTarget(victim)
	var once sync.Once
	restore := func() { once.Do(func() { restoreNodeDaemon(t, victim, target) }) }
	t.Cleanup(restore)
	out, err := harness.SSHRun(t, target, harness.KillSandboxdScript)
	harness.MarkNodeDown(victim.PublicIP)
	killedAt := time.Now()
	if err != nil || !strings.Contains(out, "KILLED") {
		t.Fatalf("SIGKILL sandboxd on %s: %v %s", victim.Name, err, out)
	}
	// systemd restarts it (Restart=always); restore only waits for the
	// rejoin, its start being a no-op on a unit that is back.
	restore()
	t.Logf("SIGKILLed sandboxd on %s; back after %s", victim.Name, time.Since(killedAt).Round(time.Second))
	if !answered {
		select {
		case res = <-done:
		case <-time.After(3 * time.Minute):
			t.Errorf("the create of %s was still unanswered 3m after its worker died", name)
			// Judged as a failed create below: it must still leave nothing.
			res = chaosCreateResult{Name: name, Err: fmt.Errorf("unanswered 3m after its worker died")}
		}
	}
	t.Logf("the create answered %s %v %s", res.describe(), res.Err, res.Body)

	settle := chaosReservationTTL + 30*time.Second
	if bound > settle {
		settle = bound
	}
	if wait := settle - time.Since(killedAt); wait > 0 {
		t.Logf("waiting %s for the reservation to expire and reconcile to converge", wait.Round(time.Second))
		time.Sleep(wait)
	}
	chaosCheckCreates(t, inv, tp, observer, ids, []chaosCreateResult{res}, name, baseline, cpu, budgets)

	// The crashed attempt itself, unless the create answered with it (a
	// replay that finished the create elsewhere is fully created, which
	// chaosCheckCreates just checked).
	fc := chaosCensusAll(t, tp.workers)
	if !fc.complete() {
		t.Fatalf("census after convergence is incomplete: %s", fc.errSummary())
	}
	for _, id := range crashed {
		if res.ok() && res.ID == id {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		pv, found, perr := chaosPlacement(ctx, observer, id)
		st, _, gerr := chaosGetStatus(ctx, operatorAPI(), id)
		cancel()
		switch {
		case perr != nil:
			t.Errorf("placement of %s: %v", id, perr)
		case found:
			inv.Violate("I8", "the crashed create %s still has a placement (owner %q, state %q) %s after the kill", id, pv.Owner.NodeID, pv.OwnerState, time.Since(killedAt).Round(time.Second))
		}
		switch {
		case gerr != nil:
			t.Errorf("get %s: %v", id, gerr)
		case st != http.StatusNotFound:
			inv.Violate("I8", "the crashed create %s answers %d on the API, not 404", id, st)
		}
		if on := fc.runningOn(id); len(on) > 0 {
			inv.Violate("I8", "the crashed create %s still runs on %v %s after the kill", id, on, time.Since(killedAt).Round(time.Second))
		}
	}

	// Its netns slot: the victim may hold one more only for a sandbox of
	// this create that is placed and running there.
	if before, ok := slotsBefore[victim.Name]; ok {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		after, _, err := chaosNetnsInUse(ctx, wapis[victim.Name])
		cancel()
		legit := 0
		if res.ok() && slices.Contains(fc.runningOn(res.ID), victim.Name) {
			legit = 1
		}
		switch {
		case err != nil:
			t.Errorf("read %s's netns pool after the crash: %v", victim.Name, err)
		case after > before+legit:
			inv.Violate("I8", "%s holds %d netns slots, %d before the crashed create (%d for a sandbox it now runs)", victim.Name, after, before, legit)
		}
	} else {
		t.Logf("%s reports no containerd netns pool; the slot check does not apply", victim.Name)
	}

	if !inv.Violated("I8") {
		inv.Hold("I8", "a create SIGKILLed on %s between the runtime start and the store write (%v) left no placement, no container and no netns slot %s after the kill; the create answered %s",
			victim.Name, crashed, settle.Round(time.Second), res.describe())
	}
	if !inv.Violated("I6") {
		inv.Hold("I6", "no reservation or stray copy left %s after the kill", settle.Round(time.Second))
	}
}

// UC-481 — control-plane recovery time. sandboxd is SIGKILLed on all three
// servers at once (AEROL_CHAOS_RTO_MODE=leader kills only the Raft leader),
// and systemd restarts them as it would after a crash. A prober sends,
// every second, through the API domain: GET /v1/cluster/leader (it must
// name a leader), a placement read for a sandbox made before the kill (it
// must name the owner it had), and a create. Each signal's recovery is the
// answer time of its first success after its last failure
// (harness.RecoveredAt); the control plane's recovery time is the latest of
// the three, logged and put in the report's detail.
//
// I6: recovery within AEROL_CHAOS_RTO_BUDGET_SECONDS (default 55: about 1.5
// times the first measured run, 34.5 s on 2026-11-08 with t3.medium servers;
// leader and placement reads were back at 13.3 s, and creates waited for the
// new leader's first worker capacity reports), and afterwards every placement made before
// the kill has the owner and incarnation it had, read on every server, and
// still runs once on that owner. I8, I4: the creates the prober sent during
// the outage end as chaosCheckCreates expects.
func TestClusterChaosControlPlaneRecoveryTime(t *testing.T) {
	harness.Require(t, sc, "UC-481")
	requireDisruptive(t, "this SIGKILLs sandboxd on the Raft servers")
	tp := chaosTopology(t)
	inv := harness.TrackInvariants(t, "I6", "I8", "I4")
	tag := chaosTag(t)
	observer := chaosAPI(t, tp.servers[0])
	ids := chaosNodeIDs(t, observer, tp)
	budgets := chaosBudgets(t, chaosWorkerAPIs(t, tp))
	bound := chaosConvergeBound(t, tp)
	budget := chaosSeconds("AEROL_CHAOS_RTO_BUDGET_SECONDS", 55)
	mode := chaosString("AEROL_CHAOS_RTO_MODE", "all")
	if mode != "all" && mode != "leader" {
		t.Fatalf("AEROL_CHAOS_RTO_MODE=%q: want all or leader", mode)
	}
	api := operatorAPI()
	cpu, mem := chaosSmallSize()

	k := envInt("AEROL_CHAOS_RTO_SANDBOXES", 3)
	var sbs []string
	for i := 0; i < k; i++ {
		sbs = append(sbs, chaosNewSandbox(t, api, chaosRequest(fmt.Sprintf("%s-%d", harness.UniqueName(sc, t), i), tag, false, cpu, mem, "", nil)))
	}
	type committed struct{ owner, incarnation string }
	snapshot := func(view *harness.APIClient) map[string]committed {
		out := map[string]committed{}
		for _, r := range chaosIndexEventually(t, view) {
			out[r.SandboxID] = committed{owner: r.OwnerNodeID, incarnation: r.IncarnationID}
		}
		return out
	}
	before := snapshot(observer)
	for _, id := range sbs {
		if before[id].owner == "" || before[id].incarnation == "" {
			t.Fatalf("no committed placement for %s before the kill: %+v", id, before[id])
		}
	}
	probeID, wantOwner := sbs[0], before[sbs[0]].owner
	baseline := chaosCensusAll(t, tp.workers)
	if !baseline.complete() {
		t.Fatalf("baseline census incomplete: %s", baseline.errSummary())
	}

	victims := tp.servers
	if mode == "leader" {
		leader, ok := chaosNodeByID(tp, ids, chaosLeaderID(t, observer))
		if !ok {
			t.Fatal("the Raft leader is not a provisioned node")
		}
		victims = []harness.IntegrationNode{leader}
	}

	var (
		mu                           sync.Mutex
		leaderP, placeP, createP     []harness.RecoveryProbe
		results                      []chaosCreateResult
		probes, creates              sync.WaitGroup
		createsSent, createsInFlight atomic.Int64
	)
	prefix := fmt.Sprintf("chaos481-%d-", time.Now().Unix())
	maxCreates := int64(envInt("AEROL_CHAOS_RTO_MAX_CREATES", 120))
	record := func(dst *[]harness.RecoveryProbe, sent time.Time, ok bool) {
		mu.Lock()
		*dst = append(*dst, harness.RecoveryProbe{Sent: sent, Answered: time.Now(), OK: ok})
		mu.Unlock()
	}
	streaks := func() (l, p, c int) {
		mu.Lock()
		defer mu.Unlock()
		return harness.RecoveryStreak(leaderP), harness.RecoveryStreak(placeP), harness.RecoveryStreak(createP)
	}
	// Five in a row: one success can be a cache or a lucky retry.
	const stable = 5

	restore := chaosKillVoters(t, victims)
	killedAt := time.Now()
	t.Logf("SIGKILLed sandboxd on %v (mode %s)", chaosNames(victims), mode)
	deadline := killedAt.Add(budget + 3*time.Minute)
	for tick := time.NewTicker(time.Second); ; <-tick.C {
		now := time.Now()
		l, p, c := streaks()
		// At least ten seconds: the servers come back no sooner than
		// RestartSec (5 s), and the first answers may still be cached.
		if (now.Sub(killedAt) >= 10*time.Second && l >= stable && p >= stable && c >= stable) || now.After(deadline) {
			tick.Stop()
			break
		}
		probes.Add(2)
		go func(sent time.Time) {
			defer probes.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			resp, err := api.Do(ctx, http.MethodGet, "/v1/cluster/leader", nil)
			record(&leaderP, sent, err == nil && resp.Status == http.StatusOK && harness.ParseLeaderJSON(string(resp.Body)) != "")
		}(now)
		go func(sent time.Time) {
			defer probes.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			pv, found, err := chaosPlacement(ctx, api, probeID)
			record(&placeP, sent, err == nil && found && pv.Owner.NodeID == wantOwner)
		}(now)
		// A create a second until creates are stably back, at most 16 in
		// flight: during the outage they hang, and a pile of them would
		// measure the client, not the cluster.
		if c < stable && createsSent.Load() < maxCreates && createsInFlight.Load() < 16 {
			i := createsSent.Add(1)
			createsInFlight.Add(1)
			creates.Add(1)
			go func(sent time.Time, i int64) {
				defer creates.Done()
				defer createsInFlight.Add(-1)
				ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
				defer cancel()
				r := chaosCreate(ctx, api, chaosRequest(fmt.Sprintf("%s%03d", prefix, i), tag, false, cpu, mem, "", nil))
				mu.Lock()
				results = append(results, r)
				mu.Unlock()
				record(&createP, sent, r.ok())
			}(now, i)
		}
	}
	probes.Wait()
	creates.Wait()
	restore()

	mu.Lock()
	lAt, lOut, lOK := harness.RecoveredAt(leaderP)
	pAt, pOut, pOK := harness.RecoveredAt(placeP)
	cAt, cOut, cOK := harness.RecoveredAt(createP)
	batch := append([]chaosCreateResult(nil), results...)
	mu.Unlock()
	since := func(at time.Time, ok bool) string {
		if !ok {
			return "never"
		}
		return at.Sub(killedAt).Round(100 * time.Millisecond).String()
	}
	signals := fmt.Sprintf("leader %s, placement read %s, create %s; outage seen: leader %v, placement %v, create %v",
		since(lAt, lOK), since(pAt, pOK), since(cAt, cOK), lOut, pOut, cOut)
	recovery := time.Duration(-1)
	if lOK && pOK && cOK {
		recovery = max(lAt.Sub(killedAt), pAt.Sub(killedAt), cAt.Sub(killedAt))
	}
	t.Logf("rto mode=%s recovery_seconds=%.1f budget_seconds=%.0f (%s)", mode, recovery.Seconds(), budget.Seconds(), signals)
	if mode == "all" && !cOut {
		t.Errorf("precondition: no create failed after every server was SIGKILLed, so the kill did not take effect (%s)", signals)
	}
	switch {
	case recovery < 0:
		inv.Violate("I6", "the control plane had not recovered %s after the kill (mode %s; %s)", deadline.Sub(killedAt).Round(time.Second), mode, signals)
	case recovery > budget:
		inv.Violate("I6", "control-plane recovery took %s, over the %s budget (mode %s; %s)", recovery.Round(100*time.Millisecond), budget, mode, signals)
	}

	settle := chaosReservationTTL + 30*time.Second
	if bound > settle {
		settle = bound
	}
	if wait := settle - time.Since(killedAt); wait > 0 {
		t.Logf("waiting %s for reservations to expire and reconcile to converge", wait.Round(time.Second))
		time.Sleep(wait)
	}
	res := chaosCheckCreates(t, inv, tp, observer, ids, batch, prefix, baseline, cpu, budgets)
	t.Logf("%d creates sent across the outage: %d created, %d failed (%d absent, %d applied anyway)", len(batch), res.created, res.failed, res.absent, res.appliedAnyway)

	// Every placement made before the kill, read on every server.
	for _, s := range tp.servers {
		view := chaosAPI(t, s)
		after := snapshot(view)
		for _, id := range sbs {
			if got, want := after[id], before[id]; got != want {
				inv.Violate("I6", "after the kill %s reads %s as owner %q incarnation %q; before it was %q %q", s.Name, id, got.owner, got.incarnation, want.owner, want.incarnation)
			}
		}
	}
	fc := chaosCensusAll(t, tp.workers)
	if !fc.complete() {
		t.Errorf("census after the recovery is incomplete: %s", fc.errSummary())
	}
	for _, id := range sbs {
		owner, _ := chaosNodeByID(tp, ids, before[id].owner)
		if on := fc.runningOn(id); len(on) != 1 || on[0] != owner.Name {
			inv.Violate("I6", "after the kill %s runs on %v; its owner is %s", id, on, owner.Name)
		}
	}

	if !inv.Violated("I6") {
		inv.Hold("I6", "control plane recovered in %s, within the %s budget (mode %s; %s); %d placements kept owner and incarnation on every server",
			recovery.Round(100*time.Millisecond), budget, mode, signals, len(sbs))
	}
	if !inv.Violated("I8") {
		inv.Hold("I8", "%d creates across the outage: %d created, %d failed and left nothing, %d applied after an error", len(batch), res.created, res.absent, res.appliedAnyway)
	}
	if !inv.Violated("I4") {
		inv.Hold("I4", "every worker within its CPU budget")
	}
}

// UC-484 — a paused sandbox answers on every public address at once (#1050,
// the follow-up to #1028). The owner worker is cut off from the servers only:
// its ownership lease runs out and it pauses its recreate-policy sandbox,
// while the other workers keep it alive in gossip, so the placement normally
// stays put and the resume can be checked on the same node. The probes run
// on the worker over SSH against its own Caddy, because the ingress (#1027)
// would answer for a cut-off owner before a request ever reached it.
//
// I7: while paused, the toolbox URL and the HTTP port answer 503 within
// seconds and the raw TCP port closes the connection (or refuses it) within
// seconds. A hang (curl giving up, the TCP read timing out) or a live answer
// is the violation. After the heal, if the placement did not move, every
// address answers as before.
func TestClusterChaosPausedSandboxAnswersEveryAddress(t *testing.T) {
	harness.Require(t, sc, "UC-484")
	requireDisruptive(t, "this cuts a worker off from the servers")
	tp := chaosTopology(t)
	inv := harness.TrackInvariants(t, "I7")
	tag := chaosTag(t)
	api := chaosAPI(t, tp.servers[len(tp.servers)-1])
	ids := chaosNodeIDs(t, api, tp)

	cpu, mem := chaosSmallSize()
	id := chaosNewSandbox(t, operatorAPI(), chaosRequest(harness.UniqueName(sc, t), tag, true, cpu, mem,
		"python:3.12-alpine", []string{"python3", "-c", chaosBannerServer}))
	ownerID := chaosOwner(t, api, id)
	owner, ok := chaosNodeByID(tp, ids, ownerID)
	if !ok || owner.Role != "worker" {
		t.Fatalf("owner %s of %s is not a worker", ownerID, id)
	}
	hc := chaosProbeClient()
	chaosAwaitServed(t, hc, chaosExpose(t, operatorAPI(), id), 3*time.Minute)
	resp := statusAs(t, operatorAPI(), http.MethodPost, "/v1/sandboxes/"+id+"/ports/9000", models.ExposePortRequest{Protocol: "tcp"})
	var tcp models.ExposePortResponse
	if resp.Status/100 != 2 || resp.JSON(&tcp) != nil || tcp.HostPort == 0 {
		t.Fatalf("expose tcp 9000 on %s: %s", id, resp)
	}
	probe := chaosPausedProbeScript(id+"."+sc.Domain, fmt.Sprintf("%s-8080.%s", id, sc.Domain), tcp.HostPort)
	target, _ := harness.SSHTarget(owner)
	run := func() chaosAddressProbe {
		out, err := harness.SSHRun(t, target, probe)
		if err != nil {
			t.Logf("probe on %s: %v %s", owner.Name, err, strings.TrimSpace(out))
		}
		return parseChaosAddressProbe(out)
	}

	var before chaosAddressProbe
	for end := time.Now().Add(2 * time.Minute); time.Now().Before(end); time.Sleep(3 * time.Second) {
		if before = run(); before.live() {
			break
		}
	}
	if !before.live() {
		t.Fatalf("precondition: before the cut %s did not answer live on %s: %s", id, owner.Name, before)
	}
	t.Logf("before the cut, on %s: %s", owner.Name, before)

	heal := chaosPartition(t, []harness.IntegrationNode{owner}, tp.servers, 4*time.Minute)
	cut := time.Now()
	var paused chaosAddressProbe
	for time.Since(cut) < 75*time.Second {
		if paused = run(); paused.toolbox.code == 503 && paused.port.code == 503 {
			break
		}
		time.Sleep(2 * time.Second)
	}
	heal()
	healedAt := time.Now()
	t.Logf("paused (+%s after the cut), on %s: %s", healedAt.Sub(cut).Round(time.Second), owner.Name, paused)
	switch {
	case paused.port.code != 503:
		t.Errorf("precondition: %s never paused within 75 s of the cut (its HTTP port answered %s), so nothing was exercised", id, paused.port)
	default:
		bad := paused.pausedProblems()
		if len(bad) > 0 {
			inv.Violate("I7", "while paused on %s: %s", owner.Name, strings.Join(bad, "; "))
		} else {
			inv.Hold("I7", "while paused on %s: toolbox %s, port %s, tcp %s", owner.Name, paused.toolbox, paused.port, paused.tcp)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	pv, found, err := chaosPlacement(ctx, api, id)
	cancel()
	if err != nil || !found || pv.Owner.NodeID != ownerID {
		t.Logf("the placement of %s moved during the cut (now %q, err %v); the resume on %s is not checked here (UC-470 and UC-479 cover a move)", id, pv.Owner.NodeID, err, owner.Name)
		return
	}
	var after chaosAddressProbe
	for end := time.Now().Add(90 * time.Second); time.Now().Before(end); time.Sleep(3 * time.Second) {
		if after = run(); after.live() {
			break
		}
	}
	if !after.live() {
		inv.Violate("I7", "%s after the heal %s still answers as paused on %s: %s", time.Since(healedAt).Round(time.Second), id, owner.Name, after)
		return
	}
	t.Logf("after the heal (+%s), on %s: %s", time.Since(healedAt).Round(time.Second), owner.Name, after)
}
