//go:build integration

package suite

// Group B — cross-node failover open, the critical path (§7 group B, F3).
// UC-117..120. Disruptive: every case here kills a node, so the z_ prefix
// keeps them after the rest of the suite (Go runs test files in lexical
// order; see z_disruptive_cluster_test.go:5-7).

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	"github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// failoverOpenTimeout bounds the whole detect-reassign-recreate sequence.
// Generous on purpose: SWIM has to notice the death, Raft has to commit the
// reassignment, and the new owner has to pull an image and boot.
const failoverOpenTimeout = 8 * time.Minute

// UC-117 — THE critical path. Kill the owner of an HA sandbox carrying real
// credentials; it must recreate on a node that held a sealed copy, and the
// credentials must still WORK inside the new sandbox.
//
// "Still work" is the whole point and is why this reads the value back from
// inside the guest rather than checking status=running. A sandbox that boots
// with an empty environment is running, and is exactly the silent failure the
// sealing subsystem exists to prevent — plans §0's probe found precisely that
// shape. status=running would pass against it.
//
// Deliberately NOT hetero-only and not a stub (§6.2b): it resolves the victim
// from the live placement on whatever cluster it is given, so it runs and
// PASSES on cluster-3-mixed-secrets.
func TestOwnerDeathKeepsCredentialsWorking(t *testing.T) {
	harness.Require(t, sc, "UC-117")
	if !harness.DisruptiveAllowed() {
		t.Skip("disruptive tests disabled (set disruptive: true in the scenario caps, or drop --no-disruptive)")
	}
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	c := client(t)
	secret := secretValue(t, "117")

	sb := harness.CreateHASandbox(t, c, harness.HASandboxSpec{
		Env: map[string]string{"UC117_TOKEN": secret},
	})
	waitRunning(t, sb)

	view := harness.AwaitSecretHolders(t, c, sb.ID, 3*time.Minute, func(v harness.SecretHoldersView) bool {
		return len(v.Holders) >= 2
	})
	originalOwner := resolvePlacementOwner(t, c, sb.ID)
	if originalOwner == "" {
		t.Fatal("no placement owner recorded; there is nothing to kill")
	}
	// A recipient OTHER than the owner must exist, or "recreates on a
	// recipient" has no possible subject and the case would pass vacuously.
	peers := withoutString(view.Holders, originalOwner)
	if len(peers) == 0 {
		t.Fatalf("holder set %v contains only the owner; there is nowhere to fail over to", view.Holders)
	}

	victim, ok := nodeForClusterID(t, c, targets, originalOwner)
	if !ok || victim.InstanceID == "" {
		t.Skipf("owner %s is not an EC2 node this suite can kill", originalOwner)
	}

	t.Cleanup(func() {
		if state := harness.EC2InstanceState(t, victim.InstanceID); state != "running" {
			harness.SetEC2InstanceRunning(t, victim.InstanceID, true)
		}
	})
	t.Logf("killing owner %s (%s / %s); recipients that can take over: %v", originalOwner, victim.Name, victim.InstanceID, peers)
	harness.SetEC2InstanceRunning(t, victim.InstanceID, false)

	newOwner := awaitNewOwner(t, c, sb.ID, originalOwner, failoverOpenTimeout)
	if !slices.Contains(peers, newOwner) {
		t.Fatalf("sandbox recreated on %s, which held no sealed copy (recipients were %v). It cannot have opened its credentials legitimately.",
			newOwner, peers)
	}

	// The assertion that matters: the secret is readable INSIDE the sandbox.
	got := execEnvValue(t, c, sb.ID, "UC117_TOKEN", 4*time.Minute)
	if got != secret {
		t.Fatalf("after failover to %s the sandbox's credential is %q, want the sealed value. A sandbox that boots with an empty environment is still 'running' — this is the silent failure the subsystem exists to prevent.",
			newOwner, got)
	}
	t.Logf("UC-117 PASS: sandbox %s recreated on recipient %s and its credentials still work", sb.ID, newOwner)
}

// UC-118 — the recreated sandbox's env is intact, not merely present.
//
// Parametrized over the runtimes the scenario actually advertises (§7.3):
// sealing is runtime-agnostic but the RESTORE path is not — a docker recreate
// and a wasm recreate rebuild the sandbox very differently, and PR #432 found
// a durable-WASM recreate that lost the sealed env entirely because the store
// rows carry no env.
func TestRecreatedSandboxEnvIsIntactAcrossRuntimes(t *testing.T) {
	harness.Require(t, sc, "UC-118")
	if !harness.DisruptiveAllowed() {
		t.Skip("disruptive tests disabled (set disruptive: true in the scenario caps, or drop --no-disruptive)")
	}
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	c := client(t)

	runtimes := advertisedRuntimesForFailover(sc)
	if len(runtimes) == 0 {
		t.Skip("no failover-capable runtime advertised by this scenario")
	}

	for _, rt := range runtimes {
		t.Run(rt, func(t *testing.T) {
			secret := secretValue(t, "118-"+rt)
			// Several keys, because "the env survived" must mean the whole map
			// and not just whichever key the restore path happened to carry.
			env := map[string]string{
				"UC118_TOKEN": secret,
				"UC118_PLAIN": "kept-" + rt,
				"UC118_EMPTY": "",
			}
			sb := harness.CreateHASandbox(t, c, harness.HASandboxSpec{Env: env, Image: harness.DefaultImage})
			waitRunning(t, sb)

			view := harness.AwaitSecretHolders(t, c, sb.ID, 3*time.Minute, func(v harness.SecretHoldersView) bool {
				return len(v.Holders) >= 2
			})
			owner := resolvePlacementOwner(t, c, sb.ID)
			peers := withoutString(view.Holders, owner)
			if len(peers) == 0 {
				t.Skipf("holder set %v has no peer; nothing to fail over to", view.Holders)
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

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			var withEnv struct {
				Env map[string]string `json:"env"`
			}
			if err := c.GetJSON(ctx, "/v1/sandboxes/"+sb.ID+"?include_env=true", &withEnv); err != nil {
				t.Fatalf("read env after failover: %v", err)
			}
			for k, want := range env {
				got, present := withEnv.Env[k]
				if !present {
					t.Fatalf("key %q vanished across the %s failover; the restore path dropped part of the sealed env", k, rt)
				}
				if got != want {
					t.Fatalf("key %q = %q after the %s failover, want %q", k, got, rt, want)
				}
			}
		})
	}
}

// UC-119 — a node that holds no sealed copy must fail LEGIBLY if it somehow
// acquires ownership. A silent empty-env boot is the worst outcome: the
// sandbox looks healthy and its application fails somewhere far away.
//
// The fault is injected honestly: drain every recipient peer so the only
// schedulable target for the recreate is a node outside the recipient set.
func TestNonRecipientOwnerFailsLegibly(t *testing.T) {
	harness.Require(t, sc, "UC-119")
	if !harness.DisruptiveAllowed() {
		t.Skip("disruptive tests disabled (set disruptive: true in the scenario caps, or drop --no-disruptive)")
	}
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	c := client(t)

	sb := harness.CreateHASandbox(t, c, harness.HASandboxSpec{
		Env: map[string]string{"UC119_TOKEN": secretValue(t, "119")},
	})
	waitRunning(t, sb)
	view := harness.AwaitSecretHolders(t, c, sb.ID, 3*time.Minute, func(v harness.SecretHoldersView) bool {
		return len(v.Holders) >= 2
	})
	owner := resolvePlacementOwner(t, c, sb.ID)

	all := clusterNodeIDs(t, c)
	outsiders := withoutAll(all, view.Holders)
	if len(outsiders) == 0 {
		t.Skipf("every node (%v) holds a copy; there is no non-recipient to hand ownership to", all)
	}

	// Drain the recipients other than the owner so the recreate cannot land on
	// one of them, then kill the owner.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	drained := withoutString(view.Holders, owner)
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer ccancel()
		for _, id := range drained {
			_ = c.PostJSON(cctx, "/v1/cluster/nodes/"+id+"/uncordon", nil, nil)
		}
	})
	for _, id := range drained {
		if err := c.PostJSON(ctx, "/v1/cluster/nodes/"+id+"/drain", nil, nil); err != nil {
			t.Fatalf("drain recipient %s: %v", id, err)
		}
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

	// Either it never opens (fine — fail closed), or it opens somewhere that
	// held a copy. What it must NOT do is come up on an outsider and serve an
	// empty environment.
	deadline := time.Now().Add(failoverOpenTimeout)
	for time.Now().Before(deadline) {
		newOwner := resolvePlacementOwner(t, c, sb.ID)
		if newOwner == "" || newOwner == owner {
			time.Sleep(10 * time.Second)
			continue
		}
		if slices.Contains(view.Holders, newOwner) {
			t.Logf("recreated on recipient %s despite the drain; nothing to assert about non-recipients here", newOwner)
			return
		}
		// An outsider took ownership. It must not be serving an empty env.
		status, env := sandboxStatusAndEnv(t, c, sb.ID)
		if strings.EqualFold(status, "started") && env["UC119_TOKEN"] == "" {
			t.Fatalf("non-recipient %s booted the sandbox to %q with an EMPTY UC119_TOKEN — a silent empty-env boot, the exact failure this case exists to catch",
				newOwner, status)
		}
		t.Logf("non-recipient %s took ownership and did not serve an empty env (status=%q)", newOwner, status)
		return
	}
	t.Logf("sandbox never reassigned within %s; fail-closed is an accepted outcome for UC-119", failoverOpenTimeout)
}

// UC-120 — killing the owner MID fan-out must never leave a half-sealed
// sandbox. Two outcomes are acceptable and one is not.
func TestOwnerKilledMidFanoutIsNeverHalfSealed(t *testing.T) {
	harness.Require(t, sc, "UC-120")
	if !harness.DisruptiveAllowed() {
		t.Skip("disruptive tests disabled (set disruptive: true in the scenario caps, or drop --no-disruptive)")
	}
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	c := client(t)
	secret := secretValue(t, "120")

	// Start the create and kill the owner while it is still in flight. The
	// create call itself carries the fan-out, so "in flight" is simply "before
	// Create returns".
	type createResult struct {
		sb  *microvm.Sandbox
		err error
	}
	name := harness.UniqueName(sc, t)
	done := make(chan createResult, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), failoverOpenTimeout)
		defer cancel()
		public := true
		sb, err := c.SDK().Create(ctx, sdktypes.CreateSandboxOptions{
			Name:               name,
			Image:              harness.DefaultImage,
			AllowPublicTraffic: &public,
			Env:                map[string]string{"UC120_TOKEN": secret},
			Failover:           &sdktypes.Failover{Policy: sdktypes.FailoverPolicyRecreate},
		})
		done <- createResult{sb: sb, err: err}
	}()

	// Give the create long enough to reserve a placement and begin sealing,
	// then kill whichever node owns it.
	var victim harness.IntegrationNode
	killed := false
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) && !killed {
		select {
		case res := <-done:
			// It finished before we could inject the fault; re-deliver and
			// fall through to the outcome check.
			done <- res
			deadline = time.Now()
		default:
		}
		if id := sandboxIDByName(t, c, name); id != "" {
			if owner := resolvePlacementOwner(t, c, id); owner != "" {
				if node, ok := nodeForClusterID(t, c, targets, owner); ok && node.InstanceID != "" {
					victim = node
					harness.SetEC2InstanceRunning(t, node.InstanceID, false)
					killed = true
					break
				}
			}
		}
		time.Sleep(3 * time.Second)
	}
	if killed {
		t.Cleanup(func() {
			if state := harness.EC2InstanceState(t, victim.InstanceID); state != "running" {
				harness.SetEC2InstanceRunning(t, victim.InstanceID, true)
			}
		})
	}

	res := <-done
	if res.sb != nil {
		t.Cleanup(func() {
			cctx, ccancel := context.WithTimeout(context.Background(), time.Minute)
			defer ccancel()
			_ = c.SDK().Destroy(cctx, res.sb.ID)
		})
	}

	if res.err != nil {
		// Loud failure. It must also have left nothing behind.
		t.Logf("create failed during the mid-fan-out kill, as permitted: %v", res.err)
		assertNoSandboxNamed(t, c, name)
		return
	}

	// It succeeded. Then it must be genuinely whole: a converged holder set,
	// and an env that actually reads back.
	view := harness.AwaitSecretHolders(t, c, res.sb.ID, failoverOpenTimeout, func(v harness.SecretHoldersView) bool {
		return len(v.Holders) >= 1
	})
	if !view.Converged() {
		t.Fatalf("create succeeded but the fan-out never settled: put=%v delete=%v — a half-sealed sandbox", view.PendingPut, view.PendingDelete)
	}
	if got := execEnvValue(t, c, res.sb.ID, "UC120_TOKEN", 4*time.Minute); got != secret {
		t.Fatalf("create succeeded but the credential reads back as %q; half-sealed and reporting healthy", got)
	}
}
