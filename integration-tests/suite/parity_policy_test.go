//go:build integration

package suite

// Live checks for the policy and storage lane of
// plans/agent-sandbox-feature-parity.md (T3, T4, V1). T3 and T4 are server
// settings, so their cases set them on every node for the length of the
// case (harness.WithClusterEnv restarts sandboxd with the override and
// restores it afterwards) instead of needing a scenario of their own.

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// policyTargets returns the SSH-reachable nodes, or skips: a server setting
// can only be changed on a node the suite can reach (not in local mode).
func policyTargets(t *testing.T) *harness.IntegrationTargets {
	t.Helper()
	targets := harness.LoadIntegrationTargets()
	if targets == nil || len(seedFirstNodeNames(targets)) == 0 {
		t.Skip("no SSH-reachable nodes (run via integration-tests/run.sh, not in local mode)")
	}
	return targets
}

// writeOnEveryNode writes body to path on every SSH-reachable node, and
// removes it when the test ends.
func writeOnEveryNode(t *testing.T, targets *harness.IntegrationTargets, path, body string) {
	t.Helper()
	for _, n := range targets.Nodes {
		target, ok := harness.SSHTarget(n)
		if !ok {
			continue
		}
		if out, err := harness.SSHRunStdin(t, target, "sudo tee "+path+" >/dev/null && sudo chmod 0644 "+path, body); err != nil {
			t.Fatalf("write %s on %s: %v\n%s", path, n.Name, err, out)
		}
	}
	t.Cleanup(func() {
		for _, n := range targets.Nodes {
			if target, ok := harness.SSHTarget(n); ok {
				_, _ = harness.SSHRun(t, target, "sudo rm -f "+path)
			}
		}
	})
}

// requireStarted fails unless every node came back up with the override.
func requireStarted(t *testing.T, res map[string]harness.NodeBootResult) {
	t.Helper()
	for name, r := range res {
		if !r.Started {
			t.Fatalf("node %s did not start with the override: %s", name, r.Status)
		}
	}
}

// requirePolicyRefusal asserts err is the create policy's 403 naming rule.
func requirePolicyRefusal(t *testing.T, err error, rule string) {
	t.Helper()
	var apiErr *microvm.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("create = %v, want a 403 refusal by %q", err, rule)
	}
	if apiErr.StatusCode != http.StatusForbidden || apiErr.Code != "create_policy_denied" || !strings.Contains(apiErr.Message, `"`+rule+`"`) {
		t.Fatalf("refusal = %d %q %q, want 403 create_policy_denied naming %q", apiErr.StatusCode, apiErr.Code, apiErr.Message, rule)
	}
}

const createPolicyPath = "/etc/sandboxd/itest-create-policy.yaml"

// UC-410 — the operator create policy (T3). With SB_CREATE_POLICY_FILE on
// every node capping a sandbox at 16 CPUs and refusing GPUs, a create past
// either is refused with 403 create_policy_denied naming the rule, and one
// inside the limits still runs. An edit to the file is picked up without a
// restart: once it allows only Firecracker, a container create is refused by
// the runtimes rule.
func TestParityCreatePolicyRefusesLive(t *testing.T) {
	harness.Require(t, sc, "UC-410")
	targets := policyTargets(t)
	writeOnEveryNode(t, targets, createPolicyPath, "version: 1\nlimits:\n  max_cpu: 16\nallow_gpu: false\n")
	c := client(t)

	harness.WithClusterEnv(t, targets, map[string]string{"SB_CREATE_POLICY_FILE": createPolicyPath}, func(res map[string]harness.NodeBootResult) {
		requireStarted(t, res)
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
		defer cancel()

		_, err := c.SDK().Create(ctx, sdktypes.CreateSandboxOptions{Image: "alpine:3.20", Name: harness.UniqueName(sc, t) + "-cpu", CPU: 32})
		requirePolicyRefusal(t, err, "limits.max_cpu")
		_, err = c.SDK().Create(ctx, sdktypes.CreateSandboxOptions{
			Image: "alpine:3.20", Name: harness.UniqueName(sc, t) + "-gpu", GPUs: &sdktypes.GPURequest{Count: 1},
		})
		requirePolicyRefusal(t, err, "allow_gpu")

		// Inside the limits: the policy is not a blanket refusal.
		sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t), CPU: 1})
		waitRunning(t, sb)

		// A reload, no restart: every node polls the file every 10 seconds.
		// A create that lands on a node before its poll is cleaned up and
		// tried again.
		writeOnEveryNode(t, targets, createPolicyPath, "version: 1\nruntimes: [firecracker]\n")
		deadline := time.Now().Add(45 * time.Second)
		for attempt := 0; ; attempt++ {
			var made *microvm.Sandbox
			made, err = c.SDK().Create(ctx, sdktypes.CreateSandboxOptions{Image: "alpine:3.20", Name: harness.UniqueName(sc, t) + "-rt" + strconv.Itoa(attempt), Runtime: "docker"})
			if err != nil || time.Now().After(deadline) {
				if made != nil {
					_ = made.Destroy(ctx)
				}
				break
			}
			_ = made.Destroy(ctx)
			time.Sleep(3 * time.Second)
		}
		requirePolicyRefusal(t, err, "runtimes")
	})
}

// privateProbeTargets are private addresses a sandbox on an AWS node can
// normally reach: Amazon's link-local DNS on TCP 53, and each other node's
// private address on the ingress port.
func privateProbeTargets(targets *harness.IntegrationTargets) [][2]string {
	out := [][2]string{{"169.254.169.253", "53"}}
	for _, n := range targets.Nodes {
		if n.PrivateIP != "" {
			out = append(out, [2]string{n.PrivateIP, "443"})
		}
	}
	return out
}

// reachablePrivate returns the private targets sb reaches. Its own node's
// address is left out: that traffic is the node's input, which the
// per-sandbox egress rules do not govern, so it proves nothing either way.
func reachablePrivate(t *testing.T, c *harness.Client, sb *microvm.Sandbox, cands [][2]string) map[[2]string]bool {
	t.Helper()
	self := sandboxNode(t, c, sb).PrivateIP
	out := map[[2]string]bool{}
	for _, cand := range cands {
		if cand[0] == self {
			continue
		}
		port, _ := strconv.Atoi(cand[1])
		out[cand] = tcpProbe(t, sb, cand[0], port)
	}
	return out
}

// UC-411 — block private networks by default (T4). Without the flag a
// no-policy sandbox reaches a private address; with
// SB_EGRESS_BLOCK_PRIVATE_BY_DEFAULT on every node, a new no-policy sandbox
// gets the private-range deny list on its record, cannot reach any private
// address that answered with the flag off, still resolves names and reaches
// the internet; a sandbox that sets its own policy keeps it and still
// reaches them; and destroying the default sandbox leaves no egress rule for
// its address on its node.
func TestParityBlockPrivateByDefaultLive(t *testing.T) {
	harness.Require(t, sc, "UC-411")
	targets := policyTargets(t)
	c := client(t)

	// The private addresses this deployment answers on, flag off.
	before := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t) + "-before"})
	waitRunning(t, before)
	var open [][2]string
	for cand, ok := range reachablePrivate(t, c, before, privateProbeTargets(targets)) {
		if ok {
			open = append(open, cand)
		}
	}
	if len(open) == 0 {
		t.Skip("no private address answers a sandbox here, so a block can't be told from a closed port")
	}

	harness.WithClusterEnv(t, targets, map[string]string{"SB_EGRESS_BLOCK_PRIVATE_BY_DEFAULT": "true"}, func(res map[string]harness.NodeBootResult) {
		requireStarted(t, res)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t)})
		waitRunning(t, sb)
		got, err := c.SDK().Get(ctx, sb.ID)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(got.NetworkDenyOut, "10.0.0.0/8") || !slices.Contains(got.NetworkDenyOut, "169.254.0.0/16") {
			t.Fatalf("the default sandbox's record has deny %v, want the private ranges", got.NetworkDenyOut)
		}
		for cand, ok := range reachablePrivate(t, c, sb, open) {
			if ok {
				t.Fatalf("%s:%s is private and must be blocked for a no-policy sandbox", cand[0], cand[1])
			}
		}
		if !tcpProbe(t, sb, cloudflareDNS, 443) {
			t.Fatal("the internet must stay open")
		}
		if out := egressExec(t, sb, "getent hosts example.com >/dev/null; echo dns_rc=$?"); !strings.Contains(out, "dns_rc=0") {
			t.Fatalf("name lookups must keep working (the resolver stays open):\n%s", out)
		}

		own := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t) + "-own", NetworkDenyOut: []string{"203.0.113.0/24"}})
		waitRunning(t, own)
		ownProbes := reachablePrivate(t, c, own, open)
		reached := false
		for _, ok := range ownProbes {
			reached = reached || ok
		}
		if len(ownProbes) > 0 && !reached {
			t.Fatal("a sandbox that sets its own policy keeps it: the flag is a default, not a floor")
		}

		node := sandboxNode(t, c, sb)
		ip := containerIP(t, c, sb)
		if err := sb.Destroy(ctx); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(30 * time.Second)
		for {
			rules := hostEgressRules(t, node, ip)
			if len(rules) == 0 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("egress rules left for %s after destroy:\n%s", ip, strings.Join(rules, "\n"))
			}
			time.Sleep(2 * time.Second)
		}
	})
}

// volumeStatus is the Daytona facade's answer for a platform volume by name:
// the one place the live API reads a volume's record (200 or 404).
func volumeStatus(t *testing.T, name string) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, _ := fcDo(t, ctx, http.MethodGet, "", "/daytona/volumes/by-name/"+name, nil, nil)
	return st
}

// UC-412 — a delete_with_sandbox volume goes with its sandbox (V1): it is
// made on first use, holds what the sandbox writes, and its record is gone
// once the sandbox is destroyed.
func TestParityVolumeDeletedWithSandboxLive(t *testing.T) {
	harness.Require(t, sc, "UC-412")
	c := client(t)
	vol := volumeName(t)
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Name:            harness.UniqueName(sc, t),
		PlatformVolumes: []sdktypes.PlatformVolumeMount{{Name: vol, Path: "/work", DeleteWithSandbox: true}},
	})
	waitRunning(t, sb)
	execOK(t, sb, "echo scratch > /work/job.txt")
	if st := volumeStatus(t, vol); st != http.StatusOK {
		t.Fatalf("volume %s while in use = %d, want 200", vol, st)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := c.SDK().Destroy(ctx, sb.ID); err != nil {
		t.Fatalf("destroy: %v", err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for volumeStatus(t, vol) != http.StatusNotFound {
		if time.Now().After(deadline) {
			t.Fatalf("volume %s still has a record 30 s after its only sandbox was destroyed", vol)
		}
		time.Sleep(2 * time.Second)
	}
}

// UC-413 — a normal volume survives (V1): on a sandbox that also has a
// delete_with_sandbox volume, destroying it removes only that one; the
// normal volume keeps its record and its file for the next sandbox, and a
// create that names it with delete_with_sandbox is refused with 409.
func TestParityNormalVolumeSurvivesLive(t *testing.T) {
	harness.Require(t, sc, "UC-413")
	c := client(t)
	keep, scratch := volumeName(t), volumeName(t)+"-s"
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Name: harness.UniqueName(sc, t),
		PlatformVolumes: []sdktypes.PlatformVolumeMount{
			{Name: keep, Path: "/keep"},
			{Name: scratch, Path: "/scratch", DeleteWithSandbox: true},
		},
	})
	waitRunning(t, sb)
	execOK(t, sb, "echo kept-bytes > /keep/data.txt")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := c.SDK().Destroy(ctx, sb.ID); err != nil {
		t.Fatalf("destroy: %v", err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for volumeStatus(t, scratch) != http.StatusNotFound {
		if time.Now().After(deadline) {
			t.Fatalf("delete_with_sandbox volume %s still has a record after destroy", scratch)
		}
		time.Sleep(2 * time.Second)
	}
	if st := volumeStatus(t, keep); st != http.StatusOK {
		t.Fatalf("normal volume %s after destroy = %d, want 200", keep, st)
	}

	_, err := c.SDK().Create(ctx, sdktypes.CreateSandboxOptions{
		Image: "alpine:3.20", Name: harness.UniqueName(sc, t) + "-flip",
		PlatformVolumes: []sdktypes.PlatformVolumeMount{{Name: keep, Path: "/keep", DeleteWithSandbox: true}},
	})
	var apiErr *microvm.APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusConflict || !strings.Contains(apiErr.Message, "delete_with_sandbox") {
		t.Fatalf("naming a kept volume with delete_with_sandbox = %v, want 409", err)
	}

	next := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Name:            harness.UniqueName(sc, t),
		PlatformVolumes: []sdktypes.PlatformVolumeMount{{Name: keep, Path: "/keep"}},
	})
	waitRunning(t, next)
	readBackWithRetry(t, next, "/keep/data.txt", "kept-bytes")
}
