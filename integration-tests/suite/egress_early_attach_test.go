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
	"encoding/base64"
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

// skipGvisorOnDocker skips gVisor on the Docker engine, the one runtime
// that still learns a restricted sandbox's address only from its started
// container: runsc builds its own network stack and doesn't join a pause
// container's namespace, so its block-all goes on a few milliseconds after
// the workload starts (plans/egress-domain-filtering.md §8.2 amendment).
// runc on the Docker engine is asserted with or without the pause pool: a
// restricted create gets a pause container of its own when the pool has no
// slot for it.
func skipGvisorOnDocker(t *testing.T, runtime string) {
	t.Helper()
	if runtime == "gvisor" && sc.Has(harness.CapDockerEngine) {
		t.Skip("gVisor on the Docker engine installs the block-all after the workload starts (known gap, see plans/egress-domain-filtering.md §8.2 amendment)")
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
//
// A Firecracker guest runs no workload command: its PID 1 is toolboxd, and
// the create's ContainerCommand is not run (the driver boots the agent
// only). No user code runs there before the create returns, so the subtest
// checks exactly that, then starts the probes with the first exec, the
// guest's first user instruction.
func TestEgressNothingOpenFromTheFirstInstruction(t *testing.T) {
	harness.Require(t, sc, "UC-341")
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
			skipGvisorOnDocker(t, rt)
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
			if rt == "firecracker" && !strings.Contains(egressExec(t, sb, "cat /tmp/early-probe.log 2>/dev/null; true"), "probe") {
				if init := egressExec(t, sb, "tr '\\0' ' ' < /proc/1/cmdline"); !strings.Contains(init, "toolboxd") {
					t.Fatalf("the guest ran no probe and its PID 1 is %q, not the agent: something else ran before the create returned", init)
				}
				t.Log("Firecracker ran no workload command (PID 1 is toolboxd): starting the probes with the first exec")
				script := base64.StdEncoding.EncodeToString([]byte(earlyProbeScript))
				egressExec(t, sb, "echo "+script+" | base64 -d > /tmp/early-probe.sh && (nohup sh /tmp/early-probe.sh >/dev/null 2>&1 &); true")
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
// set elements, the host firewall's per-IP rules and, on the Docker engine,
// the pause containers that hold restricted sandboxes' addresses.
type egressNodeState map[string]bool

var (
	setElemRe = regexp.MustCompile(`\b(\d{1,3}(?:\.\d{1,3}){3})\b`)
	ruleIPRe  = regexp.MustCompile(`-s (\d{1,3}(?:\.\d{1,3}){3})(?:/32)?\b`)
)

// gatewaySets are the gateway's per-source sets.
var gatewaySets = []string{"fqdn_src", "src_deny_default", "src_accept", "learn_src", "blocked_src"}

// snapshotEgressNode reads every per-address entry a node holds: each
// gateway set's elements ("set fqdn_src 10.88.0.5"), each per-IP rule of
// the sandbox chains ("rule AEROLVM-USER -s 10.88.0.5/32 -j DROP") and each
// sandbox's pause container ("pause aerolvm-netns-sb-<id>").
func snapshotEgressNode(t *testing.T, node harness.IntegrationNode) egressNodeState {
	t.Helper()
	var script strings.Builder
	for _, s := range gatewaySets {
		fmt.Fprintf(&script, "echo '## set %s'; sudo nft list set inet aerolvm_egress %s 2>/dev/null | sed -n '/elements/,$p'; ", s, s)
	}
	for _, ch := range []string{"AEROLVM-USER", "AEROLVM-INPUT", "DOCKER-USER", "AEROLVM-FC"} {
		fmt.Fprintf(&script, "echo '## chain %s'; sudo iptables -w -S %s 2>/dev/null; ", ch, ch)
	}
	// A sandbox's pause is named for it (the pool's free slots are not).
	script.WriteString("echo '## pause'; command -v docker >/dev/null && sudo docker ps -a --filter label=aerolvm.netns-pause=true --format '{{.Names}}' 2>/dev/null | grep '^aerolvm-netns-sb-'; ")
	// Parked warm-pool containers hold their own addresses, with the park
	// block on them by design (pkg/docker parkContainer): a refill during a
	// test parks a new one, which is not something left behind.
	script.WriteString("echo '## park'; command -v docker >/dev/null && for id in $(sudo docker ps -q --filter label=aerol.pool=park 2>/dev/null); do sudo docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' \"$id\" 2>/dev/null; done; ")
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
		case section == "pause":
			if name := strings.TrimSpace(line); name != "" {
				st["pause "+name] = true
			}
		case section == "park":
			for _, ip := range strings.Fields(line) {
				st[heldPrefix+ip] = true
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
			if before[node][k] || strings.HasPrefix(k, heldPrefix) || parkBlock(st, k) {
				continue
			}
			added = append(added, node+": "+k)
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
	// workload's container create, after the sandbox's pause started and
	// before any report: the pause must be gone afterwards too.
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

// pauseFor is the name of the pause container that holds a Docker
// sandbox's address (pkg/docker netnsAdoptedName).
func pauseFor(id string) string { return "pause aerolvm-netns-sb-" + id }

// onSomeNode reports whether any node's snapshot holds key.
func onSomeNode(nodes map[string]egressNodeState, key string) bool {
	for _, st := range nodes {
		if st[key] {
			return true
		}
	}
	return false
}

// UC-346 — on the Docker engine, a create with network rules (block-all, a
// CIDR allow list, a CIDR deny list, and a hostname allowlist where the
// gateway runs) runs in a pause container named for it, whether the pause
// pool had a slot or not; probes its workload starts from its first
// instruction never reach an outside address directly; and its destroy
// leaves no pause, firewall rule or gateway entry behind.
func TestDockerRestrictedCreateRunsInItsPause(t *testing.T) {
	harness.Require(t, sc, "UC-346")
	if !sc.Has(harness.CapDockerEngine) {
		t.Skip("the Docker engine's create path; this scenario runs containerd")
	}
	c := client(t)
	before := snapshotEgressNodes(t)
	kinds := []struct {
		name string
		opts sdktypes.CreateSandboxOptions
	}{
		{"block-all", sdktypes.CreateSandboxOptions{NetworkBlockAll: true}},
		{"allow-out", sdktypes.CreateSandboxOptions{NetworkAllowOut: []string{"9.9.9.9/32"}}},
		{"deny-out", sdktypes.CreateSandboxOptions{NetworkDenyOut: []string{"1.1.1.1/32"}}},
	}
	if sc.Has(harness.CapEgressFQDN) {
		kinds = append(kinds, struct {
			name string
			opts sdktypes.CreateSandboxOptions
		}{"hostname", sdktypes.CreateSandboxOptions{NetworkAllowOut: []string{"pypi.org"}}})
	}
	for _, k := range kinds {
		t.Run(k.name, func(t *testing.T) {
			opts := k.opts
			opts.Image = harness.DefaultImage
			opts.Name = harness.UniqueName(sc, t)
			opts.ContainerCommand = []string{"sh", "-c", earlyProbeScript}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			sb, err := c.SDK().Create(ctx, opts)
			cancel()
			// With no host firewall (local mode) there is no pause to run in:
			// the node refuses the policy it cannot enforce (#846), which is
			// the fail-closed answer this case exists to protect.
			if sc.Has(harness.CapNoHostFirewall) {
				if err == nil {
					destroyBest(c, sb.ID)
					t.Fatalf("a %s create was accepted on a node with no host firewall; it must be refused as unenforced", k.name)
				}
				if !harness.IsUnenforcedPolicyRefusal(err) {
					t.Fatalf("a %s create on a node with no host firewall failed, but not as the unenforced-policy refusal: %s", k.name, harness.DescribeAPIError(err))
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer destroyBest(c, sb.ID)
			if !onSomeNode(snapshotEgressNodes(t), pauseFor(sb.ID)) {
				t.Fatalf("no pause container holds sandbox %s's address", sb.ID)
			}
			var log string
			if !eventually(30*time.Second, func() bool {
				log = egressExec(t, sb, "cat /tmp/early-probe.log 2>/dev/null")
				return strings.Contains(log, "done")
			}) {
				t.Fatalf("probes did not finish:\n%s", lastLines(log, 20))
			}
			for _, line := range strings.Split(log, "\n") {
				if strings.Contains(line, "fl=") || strings.Contains(line, "visit_scheme=") {
					t.Fatalf("a probe reached 1.1.1.1 directly (unfiltered egress):\n%s", line)
				}
			}
		})
	}
	requireNoNewEgressState(t, before, 60*time.Second)
}

// UC-347 — on the Docker engine, a create without network rules keeps
// Docker's own path: it pays no docker_pause stage and, without the pause
// pool, gets no pause container.
func TestDockerOpenCreateKeepsDockersPath(t *testing.T) {
	harness.Require(t, sc, "UC-347")
	if !sc.Has(harness.CapDockerEngine) {
		t.Skip("the Docker engine's create path; this scenario runs containerd")
	}
	c := client(t)
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Image: harness.DefaultImage, Name: harness.UniqueName(sc, t)})
	if stages, ok := c.LastServerCreateStages(); ok {
		if ms, present := stages["docker_pause"]; present {
			t.Fatalf("an open create paid docker_pause (%.1f ms)", ms)
		}
	}
	if !sc.Has(harness.CapDockerNetnsPool) && onSomeNode(snapshotEgressNodes(t), pauseFor(sb.ID)) {
		t.Fatalf("an open create on a node without the pool got a pause container")
	}
}

// heldPrefix marks an address a parked warm-pool container holds; such
// keys describe the node, they are never "left behind".
const heldPrefix = "held-by-park "

// parkBlock reports whether k is the park block (the block-all pair) of an
// address a parked warm-pool container holds: the park's own rules, which
// go when the park does.
func parkBlock(st egressNodeState, k string) bool {
	rule, ok := strings.CutPrefix(k, "rule ")
	if !ok {
		return false
	}
	m := ruleIPRe.FindStringSubmatch(rule)
	if m == nil || !st[heldPrefix+m[1]] {
		return false
	}
	return strings.HasSuffix(rule, "-s "+m[1]+"/32 -j DROP") ||
		strings.HasSuffix(rule, "-s "+m[1]+"/32 -m comment --comment sbx-input-block -j DROP")
}
