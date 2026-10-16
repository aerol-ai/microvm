//go:build integration

package suite

// Group E, disruptive half — UC-132, 134, 135, the witness boot gate UC-144
// and the local-evidence tamper cases UC-264 and UC-265. Each corrupts
// evidence or kills a node, so they sort last.
//
// Nothing in the suite calls t.Parallel, so these run one after another in
// file order. UC-144, UC-264 and UC-265 refuse the boot of the same victim
// (pickTamperVictim) and depend on that: each starts from a node the one
// before it has put back and restarted.

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// UC-132 — tamper detection. A single altered line must fail verification and
// the report must name the break.
//
// "Names the break" is not decoration: a verifier that says only "invalid"
// leaves an operator unable to tell a hand-edit from a torn tail after a
// crash, which are very different incidents.
func TestTamperedAuditLineFailsVerificationAndNamesTheBreak(t *testing.T) {
	harness.Require(t, sc, "UC-132")
	if !harness.DisruptiveAllowed() {
		t.Skip("disruptive tests disabled: this corrupts a node's audit log")
	}
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	c := client(t)

	// Make sure there is a chain to break, and that it verifies first.
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Name: harness.UniqueName(sc, t),
		Env:  map[string]string{"UC132_TOKEN": secretValue(t, "132")},
	})
	waitRunning(t, sb)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for i := 0; i < 3; i++ {
		if err := c.GetJSON(ctx, "/v1/sandboxes/"+sb.ID+"?include_env=true", nil); err != nil {
			t.Fatalf("read env: %v", err)
		}
	}
	// Tamper with the chain that holds these records — the sandbox owner's —
	// and verify on THAT node. PickSSHNode prefers the seed, which on the
	// hetero topology owns no sandboxes: its chain was too short to tamper
	// with and the case skipped (T18). On the mixed topology it only worked
	// because the seed is also the public entry point.
	var node harness.IntegrationNode
	ok := false
	if sc.Has(harness.CapCluster) {
		if owner := resolvePlacementOwner(t, c, sb.ID); owner != "" {
			node, ok = nodeForClusterID(t, c, targets, owner)
		}
	}
	if !ok {
		node, ok = harness.PickSSHNode(targets)
		if !ok {
			t.Skip("no SSH-reachable node")
		}
	}
	target, _ := harness.SSHTarget(node)
	if pre := verifyAuditChainOn(t, target); !pre.OK {
		t.Fatalf("the chain on %s was already broken before the tamper (%s); this case would prove nothing", node.Name, pre.Error)
	}

	// Alter a line in the MIDDLE of the file. A tail edit is
	// indistinguishable from a torn write; a middle edit can only be a
	// tamper, which is what the verifier must say.
	out, err := harness.SSHRun(t, target, tamperMiddleAuditLineScript)
	// A missing log is a FAILURE, not a skip: this node served audited reads
	// a moment ago, so no evidence file means either the harness is looking
	// in the wrong place (it was, until T18) or the evidence is gone.
	if strings.Contains(out, "NOLOG") {
		t.Fatalf("no audit log on %s where one must exist: %s", node.Name, strings.TrimSpace(out))
	}
	if err != nil || strings.Contains(out, "TOOSHORT") {
		t.Skipf("could not tamper with the audit log on %s (%v): %s", node.Name, err, strings.TrimSpace(out))
	}
	t.Cleanup(func() {
		// Restore the untouched copy: leaving a broken chain behind would
		// fail every later verification in the run for the wrong reason.
		if rout, rerr := harness.SSHRun(t, target, restoreTamperedAuditLogScript); rerr != nil {
			t.Errorf("RESTORE FAILED: the audit log on %s is left tampered and every later verification in this run is suspect: %v\n%s",
				node.Name, rerr, rout)
		}
	})

	report := verifyAuditChainOn(t, target)
	if report.OK {
		t.Fatalf("verification on %s PASSED over its hand-edited audit log: the chain does not detect tampering", node.Name)
	}
	if strings.TrimSpace(report.Error) == "" {
		t.Fatal("verification failed but named no reason; an operator cannot tell a tamper from a torn tail")
	}
	t.Logf("UC-132 PASS: tamper detected: %s", report.Error)
}

// UC-134 — coverage is honest. With a node down, the read must report it as
// missing rather than quietly returning a shorter history.
//
// A silently short answer is the worst outcome for an investigation: it says
// "this access did not happen" when it means "I could not ask".
func TestAuditCoverageReportsUnreachableNodes(t *testing.T) {
	harness.Require(t, sc, "UC-134")
	if !harness.DisruptiveAllowed() {
		t.Skip("disruptive tests disabled: this stops a node")
	}
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	c := client(t)

	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Name: harness.UniqueName(sc, t),
		Env:  map[string]string{"UC134_TOKEN": secretValue(t, "134")},
	})
	waitRunning(t, sb)

	full := harness.AuditEvents(t, c, sb.ID, harness.AuditQuery{Limit: 100})
	if full.Coverage.Partial {
		t.Fatalf("coverage was already partial before anything was stopped: %+v", full.Coverage)
	}
	if len(full.Coverage.Answered) < 2 {
		t.Skipf("only %v answered; there is no peer whose absence could be reported", full.Coverage.Answered)
	}

	owner := resolvePlacementOwner(t, c, sb.ID)

	// The exclusion below compares a PLACEMENT owner id against COVERAGE node
	// ids. If those two id spaces ever drift apart the comparison silently
	// never matches, the loop picks the owner as its victim, and the case
	// stops the very node it is trying to keep alive — which reads as a
	// three-minute wall of 502s from a route that forwards to the owner, and
	// looks like an audit bug.
	//
	// A vacuous exclusion is worse than no exclusion, so assert the spaces
	// overlap instead of trusting them to.
	if !slices.Contains(full.Coverage.Answered, owner) {
		t.Fatalf("placement owner %q does not appear in the coverage answered set %v: the two id spaces have drifted, so the non-owner exclusion below is vacuous and this case would stop the owner",
			owner, full.Coverage.Answered)
	}

	var victim harness.IntegrationNode
	found := false
	for _, id := range full.Coverage.Answered {
		if id == owner {
			continue // stopping the owner is UC-135's experiment
		}
		if n, ok := nodeForClusterID(t, c, targets, id); ok {
			// Never the seed, and never the ingress. UC-134 is about whether
			// a read ADMITS it could not reach a peer; it needs one absent
			// peer, not an absent front door. Stopping the only ingress (T18,
			// hetero) made the read itself 502 for the whole poll, and
			// stopping the seed used to strand it outside the cluster on
			// restart (fixed since, UC-170) — either way the case could not
			// answer its own question.
			if n.Seed || strings.EqualFold(strings.TrimSpace(n.Role), "ingress") {
				continue
			}
			if _, sshOK := harness.SSHTarget(n); sshOK {
				victim, found = n, true
				break
			}
		}
	}
	if !found {
		t.Skip("no SSH-reachable non-owner, non-seed peer to stop")
	}

	target, _ := harness.SSHTarget(victim)
	if out, err := harness.SSHRun(t, target, "sudo systemctl stop sandboxd"); err != nil {
		t.Fatalf("stop sandboxd on %s: %v\n%s", victim.Name, err, out)
	}
	t.Cleanup(func() { restoreNodeDaemon(t, victim, target) })

	// Give gossip a moment, then read again.
	deadline := time.Now().Add(3 * time.Minute)
	var lastErr error
	for time.Now().Before(deadline) {
		page, err := harness.TryAuditEvents(c, sb.ID, harness.AuditQuery{Limit: 100})
		if err != nil {
			// We just stopped a node. A gateway that still holds a route to
			// it answers 502 for a few seconds; that is the fault we
			// injected talking, not the audit read. Keep polling — if it
			// never clears, the deadline below fails with this error.
			lastErr = err
			time.Sleep(10 * time.Second)
			continue
		}
		lastErr = nil
		if page.Coverage.Partial && len(page.Coverage.Missing) > 0 {
			t.Logf("UC-134 PASS: coverage reports %v missing while %v answered", page.Coverage.Missing, page.Coverage.Answered)
			return
		}
		if !page.Coverage.Partial && len(page.Coverage.Answered) < len(full.Coverage.Answered) {
			t.Fatalf("a node dropped out of the answered set (%v -> %v) WITHOUT coverage.partial being set: the read is silently short",
				full.Coverage.Answered, page.Coverage.Answered)
		}
		time.Sleep(10 * time.Second)
	}
	if lastErr != nil {
		t.Fatalf("the audit read never succeeded after stopping %s (last error: %v): coverage honesty could not be observed because the read itself never came back",
			victim.Name, lastErr)
	}
	t.Fatalf("a stopped node never appeared in coverage.missing; the read never admitted it could not ask everyone")
}

// UC-135 — evidence survives the owner's death. After a failover the history
// must still be complete: the records the dead owner wrote are exactly the
// ones an incident investigation needs.
func TestAuditEvidenceSurvivesOwnerDeath(t *testing.T) {
	harness.Require(t, sc, "UC-135")
	if !harness.DisruptiveAllowed() {
		t.Skip("disruptive tests disabled: this kills the owner")
	}
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	c := client(t)

	sb := harness.CreateHASandbox(t, c, harness.HASandboxSpec{
		Env: map[string]string{"UC135_TOKEN": secretValue(t, "135")},
	})
	waitRunning(t, sb)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for i := 0; i < 3; i++ {
		if err := c.GetJSON(ctx, "/v1/sandboxes/"+sb.ID+"?include_env=true", nil); err != nil {
			t.Fatalf("read env: %v", err)
		}
	}
	before := harness.AllAuditEvents(t, c, sb.ID, 100, 20)
	if len(before) == 0 {
		t.Fatal("no pre-failover history; the survival assertion would be vacuous")
	}

	view := harness.AwaitSecretHolders(t, c, sb.ID, resealTimeout, func(v harness.SecretHoldersView) bool {
		return len(v.Holders) >= 2
	})
	owner := resolvePlacementOwner(t, c, sb.ID)
	if len(withoutString(view.Holders, owner)) == 0 {
		t.Skipf("holder set %v is owner-only; nothing to fail over to", view.Holders)
	}
	victim, ok := nodeForClusterID(t, c, targets, owner)
	if !ok || victim.InstanceID == "" {
		t.Skipf("owner %s is not an EC2 node this suite can kill", owner)
	}
	requireNonSeedVictim(t, victim)
	t.Cleanup(harness.KillNodeDaemon(t, victim))
	awaitNewOwner(t, c, sb.ID, owner, failoverOpenTimeout)

	// What "survives" means here, precisely.
	//
	// internal/cluster/audit_replication.go is a query-time FETCH across
	// peers, not record replication: a node's audit records live only on the
	// node that wrote them. So with the owner down, its slice is unreachable
	// until it returns, and durability across node loss is the off-node
	// EXPORTER's job (UC-139/140/141), not the read path's.
	//
	// The first version of this case asserted the records were still
	// returned, which demanded a replication mechanism the product does not
	// have and never claimed to. What the read path must guarantee is the
	// same honesty property as UC-134: it may return less, but it must SAY
	// so. A silently short history is the failure — it reads as "this access
	// never happened" when it means "I could not ask the node that knows".
	page := harness.AuditEvents(t, c, sb.ID, harness.AuditQuery{Limit: 200})
	missing := missingEventIDs(before, page.Events)

	if len(missing) == 0 {
		t.Logf("UC-135 PASS: all %d pre-failover records are still readable after the owner died", len(before))
		return
	}
	if !page.Coverage.Partial {
		t.Fatalf("%d of %d pre-failover records are gone after the owner died (e.g. %v) and coverage does NOT report partial: the history came back silently short, which reads as 'this access never happened'",
			len(missing), len(before), firstN(missing, 5))
	}
	if len(page.Coverage.Missing) == 0 {
		t.Fatalf("coverage is partial but names no missing node; an investigator cannot tell WHICH node's evidence is absent")
	}
	t.Logf("UC-135 PASS: %d of %d records are unreachable with the owner down, and coverage declares it (missing=%v, answered=%v). Durability across node loss is the exporter's job, not the read path's.",
		len(missing), len(before), page.Coverage.Missing, page.Coverage.Answered)
}

// UC-144 — the witness boot gate fails CLOSED. A witnessed head that the
// local chain cannot account for must stop an enterprise node from starting.
//
// Fail-open here defeats the whole mechanism: an attacker who can edit the
// local log would simply have the node ignore the external record of what the
// log used to say.
//
// The fault is injected AT THE WITNESS, which is where it has to be — the
// gate calls Witness.LastWitnessedHead at boot. It is a new version on the
// victim's key for today in the real S3 Object Lock bucket, written with the
// operator's credentials. An invented env knob would have produced a case
// that skips forever, which the plan calls the worst of the available options.
func TestWitnessDisagreementRefusesEnterpriseBoot(t *testing.T) {
	harness.Require(t, sc, "UC-144")
	if !harness.DisruptiveAllowed() {
		t.Skip("disruptive tests disabled: this deliberately refuses a node's boot")
	}
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	witness := harness.RequireWitnessBucket(t)
	c := client(t)

	victim, ok := pickTamperVictim(targets)
	if !ok {
		t.Skip("no SSH-reachable node to refuse")
	}
	// Resolved while the API still answers: on a single server, stopping the
	// victim below takes the API down with it.
	victimNodeID := heteroNodeID(t, c, targets, victim.Name)
	victimTarget, _ := harness.SSHTarget(victim)
	witnessVictim(t, c, victim, victimNodeID)

	// Stop the victim BEFORE planting. Its ship loop reads the witness before
	// every ship, and a head it did not ship is counted as foreign and then
	// buried under its own head on that same tick (D23). A plant made while it
	// runs therefore lasts at most one interval, and when that tick lands
	// before the restart below, the victim boots against its own head and the
	// case reports a gate that failed open. Stopped, only this case writes the
	// victim's key; the loop does not ship on shutdown, so the stop writes
	// nothing either. Registered first so it runs last: whatever fails below,
	// the head is restored before the victim is started again.
	t.Cleanup(harness.KillNodeDaemon(t, victim))

	// The head to restore with, read while the daemon is stopped so it cannot
	// move: the last head the victim shipped (witness_tip.json), which its own
	// chain contains. Read BEFORE planting, because Object Lock means a plant
	// is never deleted, only buried under a newer version: without a head to
	// bury it under, the victim could never boot under its node id again.
	out, err := harness.SSHRun(t, victimTarget, nodeWitnessTipScript)
	ownHead := lastNonEmptyLineSuite(out)
	if err != nil || len(ownHead) != 64 {
		t.Skipf("%s has no witness tip to restore with (%v): %q. It has never shipped a head (an empty chain), and planting one it could never bury would leave it unbootable under its node id",
			victim.Name, err, strings.TrimSpace(out))
	}

	// A head that is well-formed but cannot be anywhere in the node's chain.
	const plantedHead = "0000000000000000000000000000000000000000000000000000000000000000"
	planted, restored := false, false
	restoreHead := func() {
		if !planted || restored {
			return
		}
		restored = true
		// Only the newest version counts at boot, so burying the plant under
		// the victim's own head is a full restore; the planted version stays
		// locked in the bucket's history. A refused boot never re-ships over
		// the witness (that was the bug this case caught), so skipping this
		// refuses every later boot of this node.
		if rerr := harness.PlantWitnessHead(t, witness, victimNodeID, ownHead); rerr != nil {
			t.Errorf("RESTORE FAILED: the newest witnessed head for %s is still the planted one, and every later boot of that node will refuse: %v", victimNodeID, rerr)
		}
	}
	t.Cleanup(restoreHead)

	if err := harness.PlantWitnessHead(t, witness, victimNodeID, plantedHead); err != nil {
		t.Fatalf("plant a disagreeing head: %v", err)
	}
	planted = true
	// Prove the plant is the newest head, read the way the victim's boot reads
	// it. A plant that did not land, or landed under a prefix that drifted from
	// the node's, would let the boot succeed, and this case would report a gate
	// that failed open for a reason unrelated to the gate. (What this cannot
	// see is this machine and the node disagreeing about the UTC date at
	// midnight; PlantWitnessHead says why that window is accepted.)
	if got, present, rerr := harness.WitnessedHeadFor(t, witness, victimNodeID); rerr != nil || !present || got != plantedHead {
		t.Fatalf("the planted head is not the newest the witness holds for %s (got %q, present=%v, err=%v); the boot below would test nothing",
			victimNodeID, got, present, rerr)
	}

	// WithNodeEnv with no variables starts the node and always puts it back —
	// including when the boot is refused, which is the expected outcome.
	harness.WithNodeEnv(t, victim, nil, func(res harness.NodeBootResult) {
		// Un-plant BEFORE WithNodeEnv's restore restarts the node, even if an
		// assertion below fails. From t.Cleanup it ran after that restart,
		// which then booted against the planted head, was (correctly)
		// refused, and left worker-w down for the rest of T18 round 2.
		defer restoreHead()
		if res.Started {
			t.Fatalf("node %s started although the witness holds a head (%s) that its chain cannot account for: the boot gate failed OPEN, which defeats the witness entirely",
				victim.Name, plantedHead)
		}
		if !res.RefusedWith("witness") && !res.RefusedWith("audit") && !res.RefusedWith("chain") {
			t.Fatalf("node %s refused to start, but for a reason unrelated to the witness — a boot-gate assertion must not be satisfied by an unrelated failure:\n%s",
				victim.Name, tailLines(res.Journal, 40))
		}
		t.Logf("UC-144 PASS: enterprise boot refused on witness disagreement")
	})
}

// pickTamperVictim chooses the node whose boot the witness and tamper cases
// refuse (UC-144, UC-264, UC-265). A non-seed node where there is one:
// refusing the seed's boot on a cluster costs the rendezvous every joiner
// needs. A single server has no rendezvous to lose, and the single-node
// enterprise scenario exists to prove these gates on one box, so there the
// seed is the victim.
func pickTamperVictim(targets *harness.IntegrationTargets) (harness.IntegrationNode, bool) {
	victim, ok := pickNonSeedNode(targets)
	if !ok && !sc.Has(harness.CapCluster) {
		victim, ok = harness.PickRestartableNode(targets)
	}
	return victim, ok
}

// witnessVictim makes sure the victim has shipped a head before a case
// tampers with it. These cases used to rely on earlier cases having put
// audit records on the victim, so run on their own (AEROL_TEST_RUN) against
// a fresh cluster they found an empty chain, nothing witnessed, and could
// only skip. Records come from sandboxes the victim owns: on a cluster,
// sandboxes are created until placement lands one there. Call it while the
// victim is still serving.
func witnessVictim(t *testing.T, c *harness.Client, victim harness.IntegrationNode, victimNodeID string) {
	t.Helper()
	target, _ := harness.SSHTarget(victim)
	if victimHasWitnessTip(t, target) {
		return
	}
	owned := false
	for attempt := 0; attempt < 8 && !owned; attempt++ {
		sandboxID, _ := generateAuditRecords(t, c, fmt.Sprintf("witness-seed-%d", attempt), 2)
		owned = !sc.Has(harness.CapCluster) || resolvePlacementOwner(t, c, sandboxID) == victimNodeID
	}
	if !owned {
		t.Skipf("placement never put an audit sandbox on %s in 8 tries, so it has no records to tamper with", victim.Name)
	}
	// The ship loop runs every SB_SECRET_AUDIT_WITNESS_INTERVAL (30s by
	// default); allow several ticks for the first head and its receipt.
	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		if victimHasWitnessTip(t, target) {
			return
		}
		time.Sleep(10 * time.Second)
	}
	t.Fatalf("%s owns fresh audit records but shipped no head to the witness within 3m", victim.Name)
}

func victimHasWitnessTip(t *testing.T, target string) bool {
	t.Helper()
	out, err := harness.SSHRun(t, target, nodeWitnessTipScript)
	return err == nil && len(lastNonEmptyLineSuite(out)) == 64
}

// UC-264 — editing a record the witness has already vouched for refuses the
// boot, and the untouched log boots again.
//
// The record edited is the one whose hash is this node's last witnessed head,
// so the edit rewrites history an external store holds a fingerprint of. The
// boot's full chain scan finds the record no longer hashes to its event_hash
// and strict boot refuses before the witness is even consulted: a node that
// started on an edited log would be serving evidence it can no longer prove.
func TestEditedWitnessedAuditRecordRefusesBoot(t *testing.T) {
	harness.Require(t, sc, "UC-264")
	runAuditTamperBootCase(t, "uc264", editWitnessedAuditRecordScript, "EDITED", func(res harness.NodeBootResult) {
		if !res.RefusedWith("secret audit chain") {
			t.Fatalf("the node refused to start, but not on the audit chain check — an edited log must be refused for the edit, not for an unrelated failure:\n%s",
				tailLines(res.Journal, 40))
		}
		t.Logf("UC-264 PASS: an edited witnessed record refused the boot")
	})
}

// UC-265 — deleting the local audit log refuses the boot, and the refusal
// names the recovery: a node whose log is gone comes back under a new
// SB_NODE_ID, because the Object Lock witness keeps its old heads.
//
// An empty log is the cheapest tamper there is. The node still holds its
// witness tip and the bucket still holds its heads, so either one proves a
// chain existed (the erasure rule), and the daemon must say what to do about
// it: the generic mismatch text once sent operators to clear the witnessed
// head, which a locked bucket forbids.
func TestDeletedAuditLogRefusesBootNamingNewNodeID(t *testing.T) {
	harness.Require(t, sc, "UC-265")
	runAuditTamperBootCase(t, "uc265", deleteAuditLogScript, "DELETED", func(res harness.NodeBootResult) {
		if !res.RefusedWith("secret audit witness mismatch") {
			t.Fatalf("the node refused to start, but not on the witness check — a deleted log must be refused as erased evidence:\n%s",
				tailLines(res.Journal, 40))
		}
		if !res.RefusedWith("new SB_NODE_ID") {
			t.Fatalf("the boot was refused, but the error does not name the new-SB_NODE_ID recovery, so an operator is left to try clearing a head the bucket will not let go of:\n%s",
				tailLines(res.Journal, 40))
		}
		t.Logf("UC-265 PASS: a deleted log refused the boot and named the new-SB_NODE_ID recovery")
	})
}

// runAuditTamperBootCase stops the victim, snapshots its audit directory,
// applies tamperScript, starts the node and hands the refused boot to
// assertRefusal; then it puts the snapshot back, starts the node again and
// requires it to boot and serve with a chain that verifies.
//
// The restore is never skipped. A node left with an edited or empty log can
// never boot under its node id again: the witness remembers what the log used
// to say, and Object Lock forbids forgetting it. So the restore is registered
// as a cleanup the moment the snapshot exists, runs again from inside the
// boot callback before WithNodeEnv restarts the node, and reports a failure
// as RESTORE FAILED, the way UC-144 does. It stops sandboxd first every time,
// because a daemon that came up would keep writing to the directory being
// swapped out.
func runAuditTamperBootCase(t *testing.T, tag, tamperScript, tampered string, assertRefusal func(harness.NodeBootResult)) {
	t.Helper()
	if !harness.DisruptiveAllowed() {
		t.Skip("disruptive tests disabled: this deliberately refuses a node's boot")
	}
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	victim, ok := pickTamperVictim(targets)
	if !ok {
		t.Skip("no SSH-reachable node to refuse")
	}
	harness.RequireNodeSSH(t, victim)
	target, _ := harness.SSHTarget(victim)
	c := client(t)
	witnessVictim(t, c, victim, heteroNodeID(t, c, targets, victim.Name))

	// The chain must verify before the tamper, or a refusal could be for a
	// break that was already there.
	if pre := verifyAuditChainOn(t, target); !pre.OK {
		t.Fatalf("the audit chain on %s was already broken before the tamper (%s); this case would prove nothing", victim.Name, pre.Error)
	}

	// Stopped for everything below, so the directory holds still while it is
	// copied and changed. Registered first so it runs last: the node is only
	// started again once the evidence is back.
	t.Cleanup(harness.KillNodeDaemon(t, victim))

	out, err := harness.SSHRun(t, target, auditDirSnapshotScript(tag))
	switch {
	case strings.Contains(out, "STALE"):
		t.Fatalf("an earlier run's snapshot of %s's audit directory is still there (%s): that run's restore failed, so it may be the only good copy. Put it back as the audit directory by hand, then re-run",
			victim.Name, strings.TrimSpace(out))
	case strings.Contains(out, "NOLOG"):
		// The node served audited reads a moment ago (the verify above), so a
		// missing log is the harness looking in the wrong place or lost
		// evidence; either way, not a skip.
		t.Fatalf("no audit log on %s where one must exist: %s", victim.Name, strings.TrimSpace(out))
	case err != nil || !strings.Contains(out, "SNAPSHOT"):
		t.Fatalf("snapshot %s's audit directory before tampering: %v (%s)", victim.Name, err, strings.TrimSpace(out))
	}

	restored := false
	restore := func() bool {
		if restored {
			return true
		}
		rout, rerr := harness.SSHRun(t, target,
			"sudo systemctl stop sandboxd && { sudo systemctl reset-failed sandboxd 2>/dev/null || true; } && "+auditDirRestoreScript(tag))
		if rerr != nil || !strings.Contains(rout, "RESTORED") {
			t.Errorf("RESTORE FAILED: %s's audit directory is still tampered and the node can never boot under its id until the snapshot (audit.itest-%s next to it) is put back by hand: %v\n%s",
				victim.Name, tag, rerr, strings.TrimSpace(rout))
			return false
		}
		restored = true
		return true
	}
	t.Cleanup(func() { restore() })

	out, err = harness.SSHRun(t, target, tamperScript)
	if strings.Contains(out, "NOTIP") || strings.Contains(out, "NOTFOUND") {
		// Not a product failure: a node that never shipped a head has no
		// witnessed history to tamper with. The cleanups put the untouched
		// snapshot back and start it.
		t.Skipf("%s has no witnessed record to tamper with: %s", victim.Name, strings.TrimSpace(out))
	}
	if err != nil || !strings.Contains(out, tampered) {
		t.Fatalf("tamper with %s's audit evidence: %v (%s)", victim.Name, err, strings.TrimSpace(out))
	}
	t.Logf("tampered with %s: %s", victim.Name, lastNonEmptyLineSuite(out))

	// WithNodeEnv with no variables starts the node and always restarts it
	// afterwards. The restore runs inside the callback, before that restart,
	// so the restart is the second boot this case asserts on.
	harness.WithNodeEnv(t, victim, nil, func(res harness.NodeBootResult) {
		defer restore()
		if res.Started {
			t.Fatalf("node %s started on tampered audit evidence: the boot gate failed OPEN", victim.Name)
		}
		assertRefusal(res)
	})

	// Boots and serves: the node answers its own audit verify, on the chain
	// that was put back.
	if !restored {
		t.Fatalf("%s's audit directory was not restored; see RESTORE FAILED above", victim.Name)
	}
	if post := verifyAuditChainOn(t, target); !post.OK {
		t.Fatalf("%s came back on its restored audit directory, but the chain does not verify (%s)", victim.Name, post.Error)
	}
}
