//go:build integration

package suite

// Early gateway attach (perf/egress-attach-early): a hostname-filtered
// create's gateway attach starts as soon as the runtime knows the sandbox's
// address, overlapping the runtime create. These use cases check, on live
// nodes, that the overlap never opens a sandbox and never leaves gateway or
// firewall state behind: the workload is shut from its first instruction,
// a create that fails after the attach leaves nothing for the next owner of
// the address, and churn leaves the gateway's sets and the host firewall
// flat.

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// skipPlainDocker skips where the engine is Docker without the pause-netns
// pool: Docker learns that sandbox's address only from the started
// container, so its block-all goes on a few milliseconds after the workload
// starts (unchanged by the early attach, a known gap).
func skipPlainDocker(t *testing.T) {
	t.Helper()
	if sc.Has(harness.CapDockerEngine) && !sc.Has(harness.CapDockerNetnsPool) {
		t.Skip("Docker without the pause-netns pool installs the block-all after the workload starts (known gap, see plans/egress-domain-filtering.md §8.2 amendment)")
	}
}

// earlyProbeScript hammers an arbitrary outside address from the moment
// the workload starts: every 10 ms a background fetch of Cloudflare's trace
// page by IP, logged with the time it started (the node's uptime clock in
// a container, the guest's in a VM). An answer can only come from a direct,
// unfiltered connection: the gateway's proxy refuses an IP-literal host
// outside the allowlist, and a shut sandbox gets nothing.
const earlyProbeScript = `n=0
while [ $n -lt 500 ]; do
  t0=$(cut -d' ' -f1 /proc/uptime)
  ( r=$(wget -q -O - -T 2 http://1.1.1.1/cdn-cgi/trace 2>&1 | tr '\n' ' ' | head -c 120); echo "probe $n $t0 $r" >> /tmp/early-probe.log ) &
  n=$((n+1))
  sleep 0.01
done
wait
echo done >> /tmp/early-probe.log
exec sleep 3600`

// UC-341 — a hostname-allowlisted sandbox has no unfiltered egress at any
// moment of its create or after: its workload starts already shut (the
// driver's block-all is on before the workload runs, and lifts only once the
// gateway enforces for its address), probes started from the workload's
// first instruction never reach an outside address directly, and after the
// create only the allowlist is reachable.
func TestEgressNothingOpenFromTheFirstInstruction(t *testing.T) {
	harness.Require(t, sc, "UC-341")
	skipPlainDocker(t)
	c := client(t)
	runtimes := []string{""}
	if sc.Has(harness.CapGvisor) {
		runtimes = append(runtimes, "gvisor")
	}
	if sc.Has(harness.CapFirecracker) {
		runtimes = append(runtimes, "firecracker")
	}
	for _, rt := range runtimes {
		name := rt
		if name == "" {
			name = "default"
		}
		t.Run(name, func(t *testing.T) {
			sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
				Image:            harness.DefaultImage,
				Name:             harness.UniqueName(sc, t),
				Runtime:          rt,
				NetworkAllowOut:  []string{"pypi.org"},
				ContainerCommand: []string{"sh", "-c", earlyProbeScript},
			})
			returned := egressExec(t, sb, "cut -d' ' -f1 /proc/uptime")
			tRet, err := strconv.ParseFloat(strings.TrimSpace(returned), 64)
			if err != nil {
				t.Fatalf("uptime after create: %q", returned)
			}
			var log string
			if !eventually(30*time.Second, func() bool {
				log = egressExec(t, sb, "cat /tmp/early-probe.log 2>/dev/null")
				return strings.Contains(log, "done")
			}) {
				t.Fatalf("probes did not finish:\n%s", lastLines(log, 20))
			}
			before, total := 0, 0
			for _, line := range strings.Split(log, "\n") {
				f := strings.Fields(line)
				if len(f) < 3 || f[0] != "probe" {
					continue
				}
				total++
				if t0, err := strconv.ParseFloat(f[2], 64); err == nil && t0 <= tRet {
					before++
				}
				if strings.Contains(line, "fl=") || strings.Contains(line, "visit_scheme=") {
					t.Fatalf("a probe reached 1.1.1.1 directly (unfiltered egress):\n%s", line)
				}
			}
			t.Logf("%d probes, %d started before the create returned", total, before)
			if total == 0 {
				t.Fatal("no probe ran")
			}
			if before == 0 {
				t.Log("no probe started before the create returned: the window was not exercised on this run")
			}
			// After the create: the allowlist and nothing else.
			if rc, _ := timedRC(t, sb, "wget -q -T 20 -O /dev/null https://pypi.org/simple/requests/"); rc != 0 {
				t.Fatalf("the allowed name must be fetchable after the create (rc=%d)", rc)
			}
			if out := egressExec(t, sb, "wget -q -O - -T 5 http://1.1.1.1/cdn-cgi/trace 2>&1; true"); strings.Contains(out, "fl=") {
				t.Fatalf("an address outside the allowlist is reachable after the create:\n%s", out)
			}
		})
	}
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// egressNodeState is what a node holds per sandbox address: the gateway's
// set elements and the host firewall's per-IP rules.
type egressNodeState map[string]bool

var (
	setElemRe = regexp.MustCompile(`\b(\d{1,3}(?:\.\d{1,3}){3})\b`)
	ruleIPRe  = regexp.MustCompile(`-s (\d{1,3}(?:\.\d{1,3}){3})(?:/32)?\b`)
)

// gatewaySets are the gateway's per-source sets.
var gatewaySets = []string{"fqdn_src", "src_deny_default", "src_accept", "learn_src", "blocked_src"}

// snapshotEgressNode reads every per-address entry a node holds: each
// gateway set's elements ("set fqdn_src 10.88.0.5") and each per-IP rule of
// the sandbox chains ("rule AEROLVM-USER -s 10.88.0.5/32 -j DROP").
func snapshotEgressNode(t *testing.T, node harness.IntegrationNode) egressNodeState {
	t.Helper()
	var script strings.Builder
	for _, s := range gatewaySets {
		fmt.Fprintf(&script, "echo '## set %s'; sudo nft list set inet aerolvm_egress %s 2>/dev/null | sed -n '/elements/,$p'; ", s, s)
	}
	for _, ch := range []string{"AEROLVM-USER", "AEROLVM-INPUT", "DOCKER-USER", "AEROLVM-FC"} {
		fmt.Fprintf(&script, "echo '## chain %s'; sudo iptables -w -S %s 2>/dev/null; ", ch, ch)
	}
	script.WriteString("true")
	out := nodeSSH(t, node, script.String())
	st := egressNodeState{}
	section := ""
	for _, line := range strings.Split(out, "\n") {
		if rest, ok := strings.CutPrefix(line, "## "); ok {
			section = rest
			continue
		}
		switch {
		case strings.HasPrefix(section, "set "):
			for _, m := range setElemRe.FindAllStringSubmatch(line, -1) {
				st[section+" "+m[1]] = true
			}
		case strings.HasPrefix(section, "chain "):
			if ruleIPRe.MatchString(line) {
				st["rule "+strings.TrimSpace(line)] = true
			}
		}
	}
	return st
}

// snapshotEgressNodes reads every SSH-reachable node.
func snapshotEgressNodes(t *testing.T) map[string]egressNodeState {
	t.Helper()
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	out := map[string]egressNodeState{}
	for _, n := range targets.Nodes {
		if _, ok := harness.SSHTarget(n); !ok {
			continue
		}
		out[n.Name] = snapshotEgressNode(t, n)
	}
	if len(out) == 0 {
		t.Skip("no SSH-reachable node in the integration targets")
	}
	return out
}

// newEgressEntries lists what after holds that before didn't.
func newEgressEntries(before, after map[string]egressNodeState) []string {
	var added []string
	for node, st := range after {
		for k := range st {
			if !before[node][k] {
				added = append(added, node+": "+k)
			}
		}
	}
	sort.Strings(added)
	return added
}

// requireNoNewEgressState waits up to d for every node to hold nothing per
// address that it didn't hold before (asynchronous cleanup included).
func requireNoNewEgressState(t *testing.T, before map[string]egressNodeState, d time.Duration) {
	t.Helper()
	var added []string
	if !eventually(d, func() bool {
		added = newEgressEntries(before, snapshotEgressNodes(t))
		return len(added) == 0
	}) {
		t.Fatalf("state left behind per address:\n  %s", strings.Join(added, "\n  "))
	}
}

// UC-342 — a hostname-filtered create that fails after the runtime built
// the sandbox (and the early attach ran) leaves no gateway element and no
// firewall rule for the address on any node, and the next sandboxes, which
// get freed addresses, get only their own policy.
func TestEgressFailedCreateLeavesNoGatewayState(t *testing.T) {
	harness.Require(t, sc, "UC-342")
	c := client(t)
	before := snapshotEgressNodes(t)
	// 1 MiB of memory: the container exists and the address was reported,
	// then the task can't start (runc: "container init was OOM-killed";
	// Firecracker refuses the machine config). Docker refuses it at the
	// container create, before any report, which is still a no-state check.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	sb, err := c.SDK().Create(ctx, sdktypes.CreateSandboxOptions{
		Image:           harness.DefaultImage,
		Name:            harness.UniqueName(sc, t),
		NetworkAllowOut: []string{"pypi.org"},
		MemoryMB:        1,
	})
	cancel()
	if err == nil {
		destroyBest(c, sb.ID)
		t.Skip("this runtime starts a 1 MiB sandbox; no live trigger for a failure after the attach here")
	}
	t.Logf("create failed as intended: %v", err)
	requireNoNewEgressState(t, before, 60*time.Second)

	// The freed addresses go to the next creates: a plain one must be
	// neither filtered nor shut, a hostname one only filtered by its own.
	plain := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Image: harness.DefaultImage, Name: harness.UniqueName(sc, t) + "-plain"})
	if out := egressExec(t, plain, "wget -q -O - -T 10 http://1.1.1.1/cdn-cgi/trace 2>&1; true"); !strings.Contains(out, "fl=") {
		t.Fatalf("a plain sandbox after the failed create is not open (inherited state?):\n%s", out)
	}
	node := sandboxNode(t, c, plain)
	if ip := containerIP(t, c, plain); inGatewaySet(t, node, "fqdn_src", ip) {
		t.Fatalf("plain sandbox %s at %s is in the gateway's fqdn_src", plain.ID, ip)
	}
	gw := newEgressSandbox(t, c, []string{"files.pythonhosted.org"}, nil)
	if rc, _ := timedRC(t, gw, "wget -q -T 20 -O /dev/null https://pypi.org/simple/requests/"); rc == 0 {
		t.Fatal("a hostname sandbox reached pypi.org, which only the failed create allowed")
	}
}

// UC-343 — churn of hostname-rule sandboxes (create, use, destroy, N
// times; AEROL_EGRESS_CHURN, default 20) leaves the gateway's sets and the
// host firewall's per-address rules on every node where they were.
func TestEgressChurnLeavesStateFlat(t *testing.T) {
	harness.Require(t, sc, "UC-343")
	c := client(t)
	n := benchEnvInt("AEROL_EGRESS_CHURN", 20)
	before := snapshotEgressNodes(t)
	for i := 0; i < n; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		sb, err := c.SDK().Create(ctx, sdktypes.CreateSandboxOptions{
			Image:           harness.DefaultImage,
			Name:            fmt.Sprintf("%s-%d", harness.UniqueName(sc, t), i),
			NetworkAllowOut: []string{"pypi.org"},
		})
		cancel()
		if err != nil {
			t.Fatalf("churn %d: create: %v", i, err)
		}
		if rc, _ := timedRC(t, sb, "wget -q -T 20 -O /dev/null https://pypi.org/simple/requests/"); rc != 0 {
			destroyBest(c, sb.ID)
			t.Fatalf("churn %d: the allowed name is not fetchable (rc=%d)", i, rc)
		}
		ctx, cancel = context.WithTimeout(context.Background(), time.Minute)
		err = c.SDK().Destroy(ctx, sb.ID)
		cancel()
		if err != nil {
			t.Fatalf("churn %d: destroy: %v", i, err)
		}
	}
	requireNoNewEgressState(t, before, 90*time.Second)
}
