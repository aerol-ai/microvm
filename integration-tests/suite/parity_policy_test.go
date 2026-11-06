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
