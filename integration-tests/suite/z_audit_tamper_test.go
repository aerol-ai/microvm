//go:build integration

package suite

// Group E, disruptive half — UC-132, 134, 135, and the witness boot gate
// UC-144. Each corrupts evidence or kills a node, so they sort last.

import (
	"context"
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
	if pre := verifyAuditChain(t, c); !pre.OK {
		t.Fatalf("the chain was already broken before the tamper (%s); this case would prove nothing", pre.Error)
	}

	node, ok := harness.PickSSHNode(targets)
	if !ok {
		t.Skip("no SSH-reachable node")
	}
	target, _ := harness.SSHTarget(node)

	// Alter a line in the MIDDLE of the file. A tail edit is
	// indistinguishable from a torn write; a middle edit can only be a
	// tamper, which is what the verifier must say.
	out, err := harness.SSHRun(t, target, tamperMiddleAuditLineScript)
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

	report := verifyAuditChain(t, c)
	if report.OK {
		t.Fatal("verification PASSED over a hand-edited audit log: the chain does not detect tampering")
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
	var victim harness.IntegrationNode
	found := false
	for _, id := range full.Coverage.Answered {
		if id == owner {
			continue // stopping the owner is UC-135's experiment
		}
		if n, ok := nodeForClusterID(t, c, targets, id); ok {
			if _, sshOK := harness.SSHTarget(n); sshOK {
				victim, found = n, true
				break
			}
		}
	}
	if !found {
		t.Skip("no SSH-reachable non-owner peer to stop")
	}

	target, _ := harness.SSHTarget(victim)
	if out, err := harness.SSHRun(t, target, "sudo systemctl stop sandboxd"); err != nil {
		t.Fatalf("stop sandboxd on %s: %v\n%s", victim.Name, err, out)
	}
	t.Cleanup(func() {
		if out, err := harness.SSHRun(t, target, "sudo systemctl start sandboxd"); err != nil {
			t.Errorf("RESTORE FAILED: sandboxd is left stopped on %s and the rest of this run is suspect: %v\n%s", victim.Name, err, out)
		}
	})

	// Give gossip a moment, then read again.
	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		page := harness.AuditEvents(t, c, sb.ID, harness.AuditQuery{Limit: 100})
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
	t.Cleanup(func() {
		if state := harness.EC2InstanceState(t, victim.InstanceID); state != "running" {
			harness.SetEC2InstanceRunning(t, victim.InstanceID, true)
		}
	})
	harness.SetEC2InstanceRunning(t, victim.InstanceID, false)
	awaitNewOwner(t, c, sb.ID, owner, failoverOpenTimeout)

	after := harness.AllAuditEvents(t, c, sb.ID, 100, 20)
	missing := missingEventIDs(before, after)
	if len(missing) > 0 {
		t.Fatalf("%d of %d pre-failover audit records are gone after the owner died (e.g. %v): the evidence died with the node",
			len(missing), len(before), firstN(missing, 5))
	}
	t.Logf("UC-135 PASS: all %d pre-failover records survived the owner's death", len(before))
}

// UC-144 — the witness boot gate fails CLOSED. A witnessed head that the
// local chain cannot account for must stop an enterprise node from starting.
//
// Fail-open here defeats the whole mechanism: an attacker who can edit the
// local log would simply have the node ignore the external record of what the
// log used to say.
//
// The fault is injected AT THE WITNESS, which is where it has to be — the
// gate calls Witness.LastWitnessedHead at boot. An invented env knob would
// have produced a case that skips forever, which the plan calls the worst of
// the available options.
func TestWitnessDisagreementRefusesEnterpriseBoot(t *testing.T) {
	harness.Require(t, sc, "UC-144")
	if !harness.DisruptiveAllowed() {
		t.Skip("disruptive tests disabled: this deliberately refuses a node's boot")
	}
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	receiver, ok := harness.FindReceiverNode(t, targets)
	if !ok {
		t.Skip("no audit receiver provisioned in this scenario")
	}
	c := client(t)

	// Pick a non-seed victim where possible: refusing the seed's boot on a
	// cluster costs the rendezvous every joiner needs.
	victim, ok := pickNonSeedNode(targets)
	if !ok {
		t.Skip("no SSH-reachable non-seed node to refuse")
	}
	victimNodeID := heteroNodeID(t, c, targets, victim.Name)

	previous, hadPrevious, err := harness.WitnessedHeadFor(t, receiver, victimNodeID)
	if err != nil {
		t.Fatalf("read the current witnessed head for %s: %v", victimNodeID, err)
	}

	// A head that is well-formed but cannot be anywhere in the node's chain.
	const plantedHead = "0000000000000000000000000000000000000000000000000000000000000000"
	if err := harness.PlantWitnessHead(t, receiver, victimNodeID, plantedHead); err != nil {
		t.Fatalf("plant a disagreeing head: %v", err)
	}
	t.Cleanup(func() {
		if !hadPrevious {
			// Nothing to put back; the node will re-ship its real head on the
			// next witness interval once it is up.
			return
		}
		if rerr := harness.PlantWitnessHead(t, receiver, victimNodeID, previous); rerr != nil {
			t.Errorf("RESTORE FAILED: the witness still holds a planted head for %s and later boots of that node may refuse: %v", victimNodeID, rerr)
		}
	})

	// WithNodeEnv with no variables restarts the node and always puts it back
	// — including when the boot is refused, which is the expected outcome.
	harness.WithNodeEnv(t, victim, nil, func(res harness.NodeBootResult) {
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
