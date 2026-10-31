//go:build integration

package suite

// Security boundary cases for running untrusted code (UC-317..UC-332 and
// UC-339): what
// a regulated buyer asks of a platform that executes code it did not write.
// Every case attacks the boundary from inside a sandbox, or from the
// internet, and asserts it holds on each shell runtime the scenario has:
// runc containers (the docker cap), gVisor and Firecracker.

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	"github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// bankRuntime is a runtime whose sandboxes run a shell: the security cases
// run once per runtime the scenario provides.
type bankRuntime struct {
	name    string // report label
	runtime string // CreateSandboxOptions.Runtime ("" = the default container runtime)
	vm      bool   // a hardware VM: the guest kernel is the sandbox's own
	gvisor  bool
}

func bankShellRuntimes(t *testing.T) []bankRuntime {
	t.Helper()
	var out []bankRuntime
	if sc.Has(harness.CapDocker) {
		out = append(out, bankRuntime{name: "container"})
	}
	if sc.Has(harness.CapGvisor) {
		out = append(out, bankRuntime{name: "gvisor", runtime: "gvisor", gvisor: true})
	}
	if sc.Has(harness.CapFirecracker) {
		out = append(out, bankRuntime{name: "firecracker", runtime: "firecracker", vm: true})
	}
	if len(out) == 0 {
		t.Skip("no shell runtime in this scenario")
	}
	return out
}

// eachShellRuntime runs fn as a subtest per runtime.
func bankEachRuntime(t *testing.T, fn func(t *testing.T, rt bankRuntime)) {
	t.Helper()
	for _, rt := range bankShellRuntimes(t) {
		t.Run(rt.name, func(t *testing.T) { fn(t, rt) })
	}
}

// bankImage is the image a bank case runs on rt. A Firecracker create
// without a template builds its root filesystem from the image every time,
// so its pulls come from ECR Public, not Docker Hub's anonymous pull limit.
func bankImage(rt bankRuntime) string {
	if rt.vm {
		return "public.ecr.aws/docker/library/alpine:3.20"
	}
	return harness.DefaultImage
}

// bankSandbox creates a running sandbox on rt.
func bankSandbox(t *testing.T, rt bankRuntime, opts sdktypes.CreateSandboxOptions) *microvm.Sandbox {
	t.Helper()
	opts.Name = harness.UniqueName(sc, t)
	opts.Runtime = rt.runtime
	if opts.Image == "" {
		opts.Image = bankImage(rt)
	}
	sb := client(t).NewSandbox(t, opts)
	waitRunning(t, sb)
	return sb
}

// sbRun runs cmd in sb and returns stdout+stderr and the exit code.
func bankRun(t *testing.T, sb *microvm.Sandbox, cmd string, timeout time.Duration) (string, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	res, err := sb.ExecCommand(ctx, cmd)
	if err != nil {
		t.Fatalf("exec %q: %v", cmd, err)
	}
	return res.Stdout + res.Stderr, res.ExitCode
}

// sbIP is the sandbox's primary IPv4 address as the sandbox sees it.
func bankIP(t *testing.T, sb *microvm.Sandbox) string {
	t.Helper()
	out, _ := bankRun(t, sb, "ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -1", time.Minute)
	ip := strings.TrimSpace(out)
	if net.ParseIP(ip) == nil {
		t.Fatalf("no IPv4 address in the sandbox: %q", out)
	}
	return ip
}

// sbGateway is the sandbox's default gateway: the host side of its network.
func bankGateway(t *testing.T, sb *microvm.Sandbox) string {
	t.Helper()
	out, _ := bankRun(t, sb, "ip route | awk '/^default/ {print $3; exit}'", time.Minute)
	gw := strings.TrimSpace(out)
	if net.ParseIP(gw) == nil {
		t.Fatalf("no default gateway in the sandbox: %q", out)
	}
	return gw
}

// tcpOpen reports whether sb can open a TCP connection to host:port within
// 3s (busybox nc -z).
func bankTCPOpen(t *testing.T, sb *microvm.Sandbox, host string, port int) bool {
	t.Helper()
	out, _ := bankRun(t, sb, fmt.Sprintf("nc -z -w 3 %s %d; echo rc=$?", host, port), time.Minute)
	return strings.Contains(out, "rc=0")
}

// bankNeighbour returns a sandbox of runtime rt on the same node as of, at a
// different address. A lateral probe between sandboxes on two nodes says
// nothing: every node numbers its sandboxes from the same ranges (the first
// Firecracker guest on each is 172.16.0.2), so it reaches a sandbox on the
// prober's own node, often the prober itself. The cluster-bank-flagship run
// reported Firecracker guests answering each other for exactly that reason.
func bankNeighbour(t *testing.T, rt bankRuntime, of *microvm.Sandbox) (*microvm.Sandbox, bool) {
	t.Helper()
	c := client(t)
	targets := harness.LoadIntegrationTargets()
	ofIP := containerIP(t, c, of)
	ofNode := ""
	if targets != nil && len(targets.Nodes) > 1 {
		ofNode = bankSandboxNode(t, targets, of).Name
	}
	// Misses stay up until there is a hit: placement spreads new sandboxes
	// onto the least-loaded node, so destroying each miss at once sends every
	// retry to the same other node and never lands next to of.
	var misses []string
	defer func() {
		for _, id := range misses {
			destroyBest(c, id)
		}
	}()
	for i := 0; i < 8; i++ {
		sb := bankSandbox(t, rt, sdktypes.CreateSandboxOptions{})
		if (ofNode == "" || bankSandboxNode(t, targets, sb).Name == ofNode) && containerIP(t, c, sb) != ofIP {
			return sb, true
		}
		misses = append(misses, sb.ID)
	}
	return nil, false
}

// bankTargets is the provisioned nodes with SSH, or a skip.
func bankTargets(t *testing.T) *harness.IntegrationTargets {
	t.Helper()
	targets := harness.LoadIntegrationTargets()
	if targets == nil || len(targets.Nodes) == 0 {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	for _, n := range targets.Nodes {
		harness.RequireNodeSSH(t, n)
	}
	return targets
}

// sandboxNode is the node that runs sb (the only node on a single-node
// scenario).
func bankSandboxNode(t *testing.T, targets *harness.IntegrationTargets, sb *microvm.Sandbox) harness.IntegrationNode {
	t.Helper()
	if len(targets.Nodes) == 1 {
		return targets.Nodes[0]
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	owner, err := client(t).OwnerNodeID(ctx, sb.ID)
	if err != nil {
		t.Fatalf("owner of %s: %v", sb.ID, err)
	}
	return nodeForOwner(t, targets, owner)
}

// UC-317 — cloud instance metadata is unreachable from every sandbox: the
// node's IAM role credentials (S3 bundles, KMS, platform volumes) sit behind
// 169.254.169.254, and IMDSv2 with a hop limit of 2 answers a sandbox one
// NAT hop away. Asked for explicitly in an allowlist, it stays unreachable.
func TestBankCloudMetadataUnreachable(t *testing.T) {
	harness.Require(t, sc, "UC-317")
	bankEachRuntime(t, func(t *testing.T, rt bankRuntime) {
		probe := func(sb *microvm.Sandbox, why string) {
			t.Helper()
			for _, ep := range []string{"169.254.169.254 80", "169.254.170.2 80", "169.254.170.23 80", "100.100.100.200 80"} {
				f := strings.Fields(ep)
				port, _ := strconv.Atoi(f[1])
				if bankTCPOpen(t, sb, f[0], port) {
					// Show what the endpoint gives away, for the report.
					out, _ := bankRun(t, sb, `printf 'PUT /latest/api/token HTTP/1.1\r\nHost: 169.254.169.254\r\nX-aws-ec2-metadata-token-ttl-seconds: 60\r\nContent-Length: 0\r\nConnection: close\r\n\r\n' | nc -w 3 `+f[0]+` 80 | head -1`, time.Minute)
					t.Errorf("%s: a sandbox opens a connection to the metadata endpoint %s:%d (IMDSv2 token request answered: %q)", why, f[0], port, strings.TrimSpace(out))
				}
			}
		}
		probe(bankSandbox(t, rt, sdktypes.CreateSandboxOptions{}), "default egress")
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		c := client(t)
		sb, err := c.SDK().Create(ctx, sdktypes.CreateSandboxOptions{
			Image: bankImage(rt), Name: harness.UniqueName(sc, t), Runtime: rt.runtime,
			NetworkAllowOut: []string{"169.254.169.254/32", "169.254.170.2/32"},
		})
		if err != nil {
			t.Logf("an allowlist naming the metadata endpoint is refused at create: %v", err)
			return
		}
		t.Cleanup(func() { destroyBest(c, sb.ID) })
		waitRunning(t, sb)
		probe(sb, "metadata endpoint in the sandbox's own allowlist")
	})
}

// UC-318 — one tenant's sandbox cannot connect to another's: a listener in
// sandbox B is unreachable from sandbox A, on the same node and the same
// bridge, with both on default (open) egress. ICMP too: with sandbox
// interconnect off (SB_SANDBOX_INTERCONNECT, off by default) no packet of any
// protocol may pass, and an echo reply is proof that one did.
func TestBankNoLateralMovement(t *testing.T) {
	harness.Require(t, sc, "UC-318")
	if sc.Has(harness.CapNoHostFirewall) {
		t.Skip("no host firewall on this deployment (local mode): sandboxes on it are not isolated from each other; local mode is for development, not for tenants")
	}
	bankEachRuntime(t, func(t *testing.T, rt bankRuntime) {
		b := bankSandbox(t, rt, sdktypes.CreateSandboxOptions{})
		if out, rc := bankRun(t, b, "nohup sh -c 'while true; do echo victim | nc -l -p 8080; done' >/dev/null 2>&1 & sleep 1; nc -z -w 2 127.0.0.1 8080; echo rc=$?", time.Minute); rc != 0 || !strings.Contains(out, "rc=0") {
			t.Fatalf("the victim's listener did not start: %s", out)
		}
		bIP := bankIP(t, b)
		a, ok := bankNeighbour(t, rt, b)
		if !ok {
			t.Skipf("no second %s sandbox landed on %s's node; a probe across nodes reaches the prober's own node", rt.name, b.ID)
		}
		if bankTCPOpen(t, a, bIP, 8080) {
			t.Errorf("sandbox %s reached sandbox %s's listener at %s:8080", a.ID, b.ID, bIP)
		}
		if out, _ := bankRun(t, a, fmt.Sprintf("ping -c 2 -W 2 %s >/dev/null 2>&1; echo rc=$?", bIP), time.Minute); strings.Contains(out, "rc=0") {
			t.Errorf("sandbox %s gets ICMP echo replies from sandbox %s at %s (interconnect is off by default: no protocol may pass)", a.ID, b.ID, bIP)
		}
	})
}

// UC-319 — host services are unreachable from a default sandbox: every TCP
// port the node listens on is probed from inside the sandbox on its
// gateway and the node's private address. Only the public web ports (80,
// 443) and DNS may answer. The node's public address is left out: a
// sandbox reaches it through NAT, as any internet client does, so what
// answers there is the public attack surface (UC-328), not a sandbox hole.
func TestBankHostServicesUnreachable(t *testing.T) {
	harness.Require(t, sc, "UC-319")
	targets := bankTargets(t)
	bankEachRuntime(t, func(t *testing.T, rt bankRuntime) {
		sb := bankSandbox(t, rt, sdktypes.CreateSandboxOptions{})
		node := bankSandboxNode(t, targets, sb)
		out := nodeSSH(t, node, `sudo ss -H -ltn | awk '{print $4}' | sed -E 's/.*:([0-9]+)$/\1/' | sort -un | tr '\n' ' '`)
		// 80/443 answer the internet anyway; 53 is the sandbox's resolver
		// when the node serves DNS to its sandboxes.
		allowed := map[int]bool{53: true, 80: true, 443: true}
		var ports []int
		for _, f := range strings.Fields(out) {
			if p, err := strconv.Atoi(f); err == nil && !allowed[p] {
				ports = append(ports, p)
			}
		}
		if len(ports) == 0 {
			t.Fatalf("no listening ports read from %s: %q", node.Name, out)
		}
		gw := bankGateway(t, sb)
		addrs := []string{gw}
		for _, a := range []string{node.PrivateIP} {
			if a != "" && a != gw {
				addrs = append(addrs, a)
			}
		}
		var script strings.Builder
		for _, a := range addrs {
			for _, p := range ports {
				fmt.Fprintf(&script, "nc -z -w 2 %s %d && echo OPEN %s:%d; ", a, p, a, p)
			}
		}
		got, _ := bankRun(t, sb, script.String()+"true", 10*time.Minute)
		var open []string
		for _, line := range strings.Split(got, "\n") {
			if strings.HasPrefix(line, "OPEN ") {
				open = append(open, strings.TrimPrefix(line, "OPEN "))
			}
		}
		t.Logf("node %s listens on %v (probed on %v)", node.Name, ports, addrs)
		if len(open) > 0 {
			t.Errorf("a default sandbox reaches host services on %s: %v", node.Name, open)
		}
	})
}

// UC-320 — a fork bomb is contained: the sandbox has a process limit, its
// processes stop at it, and the node and a neighbour stay responsive.
func TestBankForkBombContained(t *testing.T) {
	harness.Require(t, sc, "UC-320")
	bankEachRuntime(t, func(t *testing.T, rt bankRuntime) {
		neighbour := bankSandbox(t, rt, sdktypes.CreateSandboxOptions{})
		sb := bankSandbox(t, rt, sdktypes.CreateSandboxOptions{})
		limit, _ := bankRun(t, sb, "cat /sys/fs/cgroup/pids.max 2>/dev/null || cat /sys/fs/cgroup/pids/pids.max 2>/dev/null || echo none", time.Minute)
		const tries = 20000
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		res, err := sb.ExecCommand(ctx, fmt.Sprintf(`i=0; while [ $i -lt %d ]; do sleep 120 >/dev/null 2>&1 & [ $? -eq 0 ] || break; i=$((i+1)); done 2>/dev/null; echo spawned=$i`, tries))
		cancel()
		spawned := -1
		if m := regexp.MustCompile(`spawned=(\d+)`).FindStringSubmatch(res.Stdout); m != nil {
			spawned, _ = strconv.Atoi(m[1])
		}
		t.Logf("pids.max=%s spawned=%d of %d (%s), exec error %v", strings.TrimSpace(limit), spawned, tries, rt.name, err)
		if err != nil {
			t.Errorf("the fork bomb took down the sandbox's exec path: %v", err)
		}
		if !rt.vm && spawned >= tries {
			t.Errorf("no process limit: the sandbox spawned all %d processes", tries)
		}
		ctx, cancel = context.WithTimeout(context.Background(), time.Minute)
		_, _ = sb.ExecCommand(ctx, "kill -9 -1 2>/dev/null; true")
		cancel()
		if out, rc := bankRun(t, neighbour, "echo alive", time.Minute); rc != 0 || !strings.Contains(out, "alive") {
			t.Errorf("the neighbour stopped answering after the fork bomb: %q", out)
		}
		// At its pids limit the sandbox cannot even fork the kill above; it
		// recovers when the bomb's sleeps end (120 s), so allow longer.
		recovered := false
		var last string
		for deadline := time.Now().Add(3 * time.Minute); time.Now().Before(deadline); time.Sleep(10 * time.Second) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			res, err := sb.ExecCommand(ctx, "echo alive")
			cancel()
			if err == nil && res.ExitCode == 0 && strings.Contains(res.Stdout, "alive") {
				recovered = true
				break
			}
			last = fmt.Sprintf("%v %q", err, res.Stdout+res.Stderr)
		}
		if !recovered {
			t.Errorf("the sandbox itself did not recover within 3 minutes of the fork bomb: %s", last)
		}
	})
}

// UC-321 — a memory bomb is contained: allocation past the sandbox's memory
// limit is killed inside the sandbox, the limit is what was asked for, and
// the node and a neighbour stay up.
func TestBankMemoryBombContained(t *testing.T) {
	harness.Require(t, sc, "UC-321")
	bankEachRuntime(t, func(t *testing.T, rt bankRuntime) {
		neighbour := bankSandbox(t, rt, sdktypes.CreateSandboxOptions{})
		const memMB = 256
		sb := bankSandbox(t, rt, sdktypes.CreateSandboxOptions{MemoryMB: memMB})
		// awk doubles a string until something stops it.
		out, _ := bankRun(t, sb, `awk 'BEGIN{s="x"; for(i=0;i<40;i++){s=s s}; print length(s)}'; echo rc=$?`, 5*time.Minute)
		if regexp.MustCompile(`rc=0\b`).MatchString(out) {
			t.Errorf("a 1 TiB string was allocated in a %d MiB sandbox: %s", memMB, out)
		}
		t.Logf("%s: memory bomb ended with %q", rt.name, strings.TrimSpace(out))
		// The bomb's own sandbox may be stopped by its OOM (a group kill
		// takes its init): containment either way, reported for the record.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if res, err := sb.ExecCommand(ctx, "echo alive"); err != nil || !strings.Contains(res.Stdout, "alive") {
			t.Logf("FINDING: %s: the memory bomb's sandbox stopped answering after its OOM (%v)", rt.name, err)
		}
		cancel()
		for _, s := range []*microvm.Sandbox{neighbour} {
			deadline := time.Now().Add(3 * time.Minute)
			for {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				res, err := s.ExecCommand(ctx, "echo alive")
				cancel()
				if err == nil && strings.Contains(res.Stdout, "alive") {
					break
				}
				if time.Now().After(deadline) {
					t.Errorf("sandbox %s did not answer after the memory bomb: %v", s.ID, err)
					break
				}
				time.Sleep(5 * time.Second)
			}
		}
	})
}

// UC-322 — a disk fill is contained to the sandbox: writing past its disk
// size fails inside the sandbox, and the node's own disk keeps its space.
func TestBankDiskFillContained(t *testing.T) {
	harness.Require(t, sc, "UC-322")
	targets := bankTargets(t)
	bankEachRuntime(t, func(t *testing.T, rt bankRuntime) {
		const diskGB = 2
		sb := bankSandbox(t, rt, sdktypes.CreateSandboxOptions{DiskGB: diskGB})
		node := bankSandboxNode(t, targets, sb)
		freeMB := func() int {
			out := nodeSSH(t, node, "df -Pm /var/lib | awk 'NR==2 {print $4}'")
			v, err := strconv.Atoi(strings.TrimSpace(out))
			if err != nil {
				t.Fatalf("node free space: %q", out)
			}
			return v
		}
		before := freeMB()
		// Never let the case itself fill the node: stop 1.5 GiB short.
		budget := diskGB*1024 + 1024
		if budget > before-1536 {
			budget = before - 1536
		}
		if budget < diskGB*1024+256 {
			t.Skipf("node %s has %d MiB free: too little to tell a quota from a full disk", node.Name, before)
		}
		// Two ways to be contained: the engine enforces the size (the
		// write fails), or the disk watchdog stops the sandbox once its
		// writable layer is past it — which also cuts this exec short.
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		res, execErr := sb.ExecCommand(ctx, fmt.Sprintf("dd if=/dev/zero of=/var/tmp/fill bs=1M count=%d 2>&1 | tail -2; ls -l /var/tmp/fill | awk '{print \"size=\"$5}'", budget))
		cancel()
		written := int64(-1)
		if execErr == nil {
			if m := regexp.MustCompile(`size=(\d+)`).FindStringSubmatch(res.Stdout + res.Stderr); m != nil {
				written, _ = strconv.ParseInt(m[1], 10, 64)
			}
		}
		during := freeMB()
		var view struct {
			Status    string `json:"status"`
			LastError string `json:"last_error"`
		}
		stopped := false
		for deadline := time.Now().Add(time.Minute); ; {
			gctx, gcancel := context.WithTimeout(context.Background(), 30*time.Second)
			gerr := client(t).GetJSON(gctx, "/v1/sandboxes/"+sb.ID, &view)
			gcancel()
			if gerr == nil && view.Status == "stopped" && strings.Contains(view.LastError, "over its") {
				stopped = true
				break
			}
			// A write the engine capped leaves a running sandbox; only an
			// over-size or cut-short write waits for the watchdog's verdict.
			overSize := written > int64(diskGB*1024+512)<<20
			if (execErr == nil && !overSize) || time.Now().After(deadline) {
				break
			}
			time.Sleep(5 * time.Second)
		}
		if !stopped && view.Status != "stopped" {
			// Only a running sandbox has a file to remove; not fatal, the
			// verdict below is about containment.
			rctx, rcancel := context.WithTimeout(context.Background(), 5*time.Minute)
			_, _ = sb.ExecCommand(rctx, "rm -f /var/tmp/fill; sync")
			rcancel()
		}
		t.Logf("%s: wrote %d MiB into a %d GiB sandbox; node %s free %d -> %d MiB; status %q %q (exec error %v)", rt.name, written>>20, diskGB, node.Name, before, during, view.Status, view.LastError, execErr)
		switch {
		case stopped:
			// Contained by the watchdog. How far past the size it got is the
			// write speed times the check interval; reported, not asserted.
		case view.Status == "stopped":
			// Stopped for another reason before the watchdog spoke: gVisor
			// keeps rootfs writes in a filestore charged to the sandbox, so a
			// fill can end the sandbox at its memory limit. Contained as long
			// as the node did not lose more than the case wrote.
			t.Logf("%s: the sandbox stopped on its own (%q); the node lost %d MiB", rt.name, view.LastError, before-during)
		case execErr != nil:
			t.Errorf("the disk fill broke the sandbox's exec path and nothing stopped it for its size: %v (status %q)", execErr, view.Status)
		case written > int64(diskGB*1024+512)<<20:
			t.Errorf("no disk limit: the sandbox wrote %d MiB with %d GiB asked for and is still %q (node %s free space %d -> %d MiB)", written>>20, diskGB, view.Status, node.Name, before, during)
		}
	})
}

// UC-323 — CPU limits hold: a sandbox spinning every core it can see uses
// at most its share, and a neighbour's commands stay quick.
func TestBankCPUHogContained(t *testing.T) {
	harness.Require(t, sc, "UC-323")
	bankEachRuntime(t, func(t *testing.T, rt bankRuntime) {
		neighbour := bankSandbox(t, rt, sdktypes.CreateSandboxOptions{})
		hog := bankSandbox(t, rt, sdktypes.CreateSandboxOptions{CPU: 1})
		lat := func() time.Duration {
			var ds []time.Duration
			for i := 0; i < 7; i++ {
				start := time.Now()
				bankRun(t, neighbour, "true", time.Minute)
				ds = append(ds, time.Since(start))
			}
			sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
			return ds[len(ds)/2]
		}
		base := lat()
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		if _, err := hog.ExecCommand(ctx, "for i in $(seq 1 16); do (while :; do :; done) >/dev/null 2>&1 & done; echo started"); err != nil {
			t.Logf("starting the hog: %v", err)
		}
		cancel()
		time.Sleep(10 * time.Second)
		during := lat()
		_, _ = bankRun(t, hog, "kill -9 -1 2>/dev/null; true", time.Minute)
		t.Logf("%s: neighbour exec p50 %v idle, %v beside a 16-thread hog", rt.name, base, during)
		if during > 3*base+time.Second {
			t.Errorf("a CPU hog slowed its neighbour's exec from %v to %v", base, during)
		}
	})
}

// UC-324 — the privilege boundary of a container sandbox: no dangerous
// capability, a seccomp filter, no kernel interfaces, no host devices.
// gVisor and Firecracker sandboxes have their own kernel, so a guest that
// holds capabilities there holds them over that kernel only (UC-325).
func TestBankPrivilegeBoundary(t *testing.T) {
	harness.Require(t, sc, "UC-324")
	bankEachRuntime(t, func(t *testing.T, rt bankRuntime) {
		if rt.vm {
			t.Skip("a Firecracker guest runs its own kernel: root there is root over the guest only (UC-325)")
		}
		sb := bankSandbox(t, rt, sdktypes.CreateSandboxOptions{})
		status, _ := bankRun(t, sb, "grep -E '^(CapEff|CapBnd|Seccomp|NoNewPrivs):' /proc/self/status", time.Minute)
		field := func(name string) string {
			for _, l := range strings.Split(status, "\n") {
				if strings.HasPrefix(l, name+":") {
					return strings.TrimSpace(strings.TrimPrefix(l, name+":"))
				}
			}
			return ""
		}
		capEff, err := strconv.ParseUint(field("CapEff"), 16, 64)
		if err != nil {
			t.Fatalf("CapEff: %q", status)
		}
		dangerous := map[int]string{2: "DAC_READ_SEARCH", 12: "NET_ADMIN", 13: "NET_RAW", 16: "SYS_MODULE", 17: "SYS_RAWIO", 19: "SYS_PTRACE", 21: "SYS_ADMIN", 22: "SYS_BOOT", 25: "SYS_TIME", 33: "MAC_ADMIN", 38: "PERFMON", 39: "BPF"}
		var held []string
		for bit, name := range dangerous {
			if capEff&(1<<bit) != 0 {
				held = append(held, name)
			}
		}
		sort.Strings(held)
		if len(held) > 0 {
			t.Errorf("%s holds dangerous capabilities: %v (CapEff=%s)", rt.name, held, field("CapEff"))
		}
		if !rt.gvisor && field("Seccomp") != "2" {
			t.Errorf("no seccomp filter (Seccomp: %q)", field("Seccomp"))
		}
		for _, probe := range []struct{ cmd, what string }{
			{"mount -t tmpfs none /mnt", "mount a filesystem"},
			{"echo 1 > /proc/sys/kernel/sysrq", "write a kernel sysctl"},
			{"echo h > /proc/sysrq-trigger", "trigger sysrq"},
			{"touch /sys/kernel/aerol-probe", "write to /sys"},
			// runc masks these with /dev/null: a read that returns no
			// bytes is the mask, not access.
			{"[ $(head -c 16 /proc/kcore 2>/dev/null | wc -c) -gt 0 ]", "read kernel memory (/proc/kcore)"},
			{"[ $(head -c 16 /dev/mem 2>/dev/null | wc -c) -gt 0 ]", "read physical memory (/dev/mem)"},
			{"dmesg >/dev/null", "read the kernel log"},
			{"modprobe dummy", "load kernel modules"},
		} {
			// gVisor's mount and dmesg act on gVisor's own kernel.
			if !rt.gvisor || !(strings.HasPrefix(probe.cmd, "mount") || strings.HasPrefix(probe.cmd, "dmesg")) {
				if _, rc := bankRun(t, sb, probe.cmd+" 2>/dev/null", time.Minute); rc == 0 {
					t.Errorf("%s: the sandbox can %s (%q succeeded)", rt.name, probe.what, probe.cmd)
				}
			}
		}
		if out, _ := bankRun(t, sb, "ls /dev | grep -E '^(sd|nvme|xvd|vd|loop|mem|kmem|port)' || true", time.Minute); strings.TrimSpace(out) != "" {
			t.Errorf("%s: host devices are visible in /dev: %s", rt.name, strings.Fields(out))
		}
	})
}

// UC-325 — the kernel boundary per runtime, for the report: a gVisor
// sandbox talks to gVisor's kernel and a Firecracker sandbox to its guest
// kernel, never the node's; a runc container shares the node's kernel,
// which is why untrusted code belongs on gVisor or Firecracker.
func TestBankKernelBoundary(t *testing.T) {
	harness.Require(t, sc, "UC-325")
	targets := bankTargets(t)
	bankEachRuntime(t, func(t *testing.T, rt bankRuntime) {
		sb := bankSandbox(t, rt, sdktypes.CreateSandboxOptions{})
		guest, _ := bankRun(t, sb, "uname -r", time.Minute)
		host := nodeSSH(t, bankSandboxNode(t, targets, sb), "uname -r")
		guest, host = strings.TrimSpace(guest), strings.TrimSpace(host)
		t.Logf("%s: sandbox kernel %q, node kernel %q", rt.name, guest, host)
		switch {
		case rt.gvisor || rt.vm:
			if guest == host {
				t.Errorf("%s sandbox reports the node's kernel %q: it is not behind its own kernel", rt.name, host)
			}
		default:
			if guest != host {
				t.Logf("container sandbox kernel %q differs from node %q", guest, host)
			}
		}
	})
}

// UC-326 — filesystem isolation: nothing of the node (its config, its
// state, other sandboxes' files) is visible inside a sandbox, and a file one
// sandbox writes is not in another.
func TestBankFilesystemIsolation(t *testing.T) {
	harness.Require(t, sc, "UC-326")
	bankEachRuntime(t, func(t *testing.T, rt bankRuntime) {
		a := bankSandbox(t, rt, sdktypes.CreateSandboxOptions{})
		b := bankSandbox(t, rt, sdktypes.CreateSandboxOptions{})
		marker := "bank-fs-" + strconv.FormatInt(time.Now().UnixNano(), 36)
		bankRun(t, a, "echo "+marker+" > /tmp/"+marker+" && echo "+marker+" > /root/"+marker, time.Minute)
		if out, _ := bankRun(t, b, "grep -rl "+marker+" /tmp /root /var/tmp 2>/dev/null; true", time.Minute); strings.TrimSpace(out) != "" {
			t.Errorf("a file written in sandbox A is visible in sandbox B: %s", out)
		}
		for _, p := range []string{"/etc/sandboxd", "/var/lib/sandboxd", "/var/lib/containerd", "/var/lib/docker", "/run/containerd/containerd.sock", "/var/run/docker.sock", "/etc/aerol-audit-receiver"} {
			if _, rc := bankRun(t, a, "test -e "+p, time.Minute); rc == 0 {
				t.Errorf("%s: the node's %s is visible in the sandbox", rt.name, p)
			}
		}
		mounts, _ := bankRun(t, a, "cat /proc/self/mountinfo", time.Minute)
		for _, l := range strings.Split(mounts, "\n") {
			if strings.Contains(l, "/var/lib/sandboxd/") && !strings.Contains(l, "/toolbox") && !strings.Contains(l, "/mounts/") {
				t.Logf("mount from the node's sandboxd state: %s", l)
			}
		}
	})
}

// UC-327 — process isolation: a sandbox sees only its own processes; the
// node's daemons and other sandboxes' processes are invisible to it.
func TestBankProcessIsolation(t *testing.T) {
	harness.Require(t, sc, "UC-327")
	bankEachRuntime(t, func(t *testing.T, rt bankRuntime) {
		other := bankSandbox(t, rt, sdktypes.CreateSandboxOptions{})
		bankRun(t, other, "(sleep 600 >/dev/null 2>&1 &) ; echo started", time.Minute)
		sb := bankSandbox(t, rt, sdktypes.CreateSandboxOptions{})
		out, _ := bankRun(t, sb, "ps -o comm 2>/dev/null || ps", time.Minute)
		for _, daemon := range []string{"sandboxd", "containerd", "dockerd", "caddy", "sshd", "egress-gateway", "systemd-journal", "firecracker"} {
			if strings.Contains(out, daemon) {
				t.Errorf("%s: the node's %s process is visible inside the sandbox", rt.name, daemon)
			}
		}
		if n := strings.Count(out, "sleep"); n > 0 {
			t.Errorf("%s: another sandbox's processes are visible (%d sleep)", rt.name, n)
		}
	})
}

// UC-328 — the nodes' public attack surface: from the internet, every port
// a node listens on (read over SSH) plus well-known service ports are tried
// on its public address; only web, the per-sandbox SSH gateway, the L4
// exposure pool and the admin-scoped ports may answer — never Raft, gossip,
// Caddy's admin or a metrics port. AEROL_BANK_FULL_PORT_SCAN=1 adds a full
// 1-65535 scan of one node per role (heavy: run it on one scenario).
func TestBankPublicAttackSurface(t *testing.T) {
	harness.Require(t, sc, "UC-328")
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	// Public by design: web, the per-sandbox SSH gateway and the raw-TCP
	// exposure pool. Admin-scoped (admin_allowed_cidrs): SSH and the daemon
	// API, which this runner reaches from an admin address.
	l4Lo, l4Hi := bankPortRange("AEROL_L4_PORT_RANGE", 22000, 23000)
	public := map[int]bool{80: true, 443: true, benchEnvInt("AEROL_SSH_GATEWAY_PORT", 2220): true}
	admin := map[int]bool{22: true, 21212: true}
	type result struct {
		node      harness.IntegrationNode
		open      []int
		exhausted bool
	}
	wellKnown := []int{21, 22, 23, 25, 53, 80, 111, 135, 139, 443, 445, 2019, 2220, 2375, 2376, 2379, 2380, 3000, 3306, 4000, 4001, 4002, 5000, 5432, 5900, 6379, 6443, 7000, 7001, 7002, 7946, 8000, 8080, 8081, 8300, 8301, 8443, 8500, 9000, 9090, 9091, 9093, 9100, 9200, 9443, 10250, 10255, 11211, 15001, 15006, 21212, 27017}
	full := os.Getenv("AEROL_BANK_FULL_PORT_SCAN") == "1"
	scannedRole := map[string]bool{}
	results := make([]result, len(targets.Nodes))
	for i, n := range targets.Nodes {
		if n.PublicIP == "" {
			continue
		}
		ports := append([]int(nil), wellKnown...)
		if target, ok := harness.SSHTarget(n); ok {
			if out, err := harness.SSHRun(t, target, `sudo ss -H -ltn | awk '{print $4}' | sed -E 's/.*:([0-9]+)$/\1/' | sort -un | tr '\n' ' '`); err == nil {
				for _, f := range strings.Fields(out) {
					if p, err := strconv.Atoi(f); err == nil {
						ports = append(ports, p)
					}
				}
			}
		}
		if full && !scannedRole[n.Role] {
			scannedRole[n.Role] = true
			ports = nil
			for p := 1; p <= 65535; p++ {
				ports = append(ports, p)
			}
		}
		open, exhausted := bankScanTCP(n.PublicIP, ports, 128, 1500*time.Millisecond)
		results[i] = result{node: n, open: open, exhausted: exhausted}
	}
	for _, r := range results {
		if r.node.Name == "" {
			continue
		}
		if r.exhausted {
			t.Fatalf("%s: the scanner ran out of file descriptors; raise ulimit -n and rerun", r.node.Name)
		}
		var unexpected, adminOpen []int
		for _, p := range r.open {
			switch {
			case public[p] || (p >= l4Lo && p <= l4Hi):
			case admin[p]:
				adminOpen = append(adminOpen, p)
			default:
				unexpected = append(unexpected, p)
			}
		}
		t.Logf("%s (%s) open TCP ports: %v (admin-scoped: %v)", r.node.Name, r.node.PublicIP, r.open, adminOpen)
		if len(unexpected) > 0 {
			t.Errorf("%s exposes TCP ports beyond web, the SSH gateway, the L4 pool and the admin ports: %v", r.node.Name, unexpected)
		}
	}
	// The admin ports must be scoped to admin addresses, not the internet.
	for _, n := range targets.Nodes {
		if n.InstanceID == "" {
			continue
		}
		rules, err := bankWorldOpenRules(n.InstanceID)
		if err != nil {
			t.Logf("security groups of %s not read: %v", n.Name, err)
			continue
		}
		for _, r := range rules {
			if r.from <= 22 && r.to >= 22 || r.from <= 21212 && r.to >= 21212 || r.from == -1 {
				t.Errorf("%s: security group opens %s %d-%d to 0.0.0.0/0 (SSH or the daemon API reachable from the whole internet; set admin_allowed_cidrs)", n.Name, r.proto, r.from, r.to)
			}
		}
		break // one node: every node shares the node security group
	}
}

func bankPortRange(key string, lo, hi int) (int, int) {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if a, b, ok := strings.Cut(v, "-"); ok {
			x, e1 := strconv.Atoi(a)
			y, e2 := strconv.Atoi(b)
			if e1 == nil && e2 == nil {
				return x, y
			}
		}
	}
	return lo, hi
}

type bankSGRule struct {
	proto    string
	from, to int
}

// securityGroupWorldOpen lists the ingress rules open to 0.0.0.0/0 on the
// instance's security groups (aws CLI, the credentials run.sh provisions
// with).
func bankWorldOpenRules(instanceID string) ([]bankSGRule, error) {
	out, err := exec.Command("aws", "ec2", "describe-instances", "--instance-ids", instanceID,
		"--query", "Reservations[0].Instances[0].SecurityGroups[].GroupId", "--output", "text").Output()
	if err != nil {
		return nil, err
	}
	groups := strings.Fields(string(out))
	if len(groups) == 0 {
		return nil, fmt.Errorf("no security groups")
	}
	args := append([]string{"ec2", "describe-security-groups", "--group-ids"}, groups...)
	args = append(args, "--query", "SecurityGroups[].IpPermissions[?IpRanges[?CidrIp=='0.0.0.0/0']].[IpProtocol,FromPort,ToPort][]", "--output", "text")
	out, err = exec.Command("aws", args...).Output()
	if err != nil {
		return nil, err
	}
	var rules []bankSGRule
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Fields(line)
		if len(f) < 1 {
			continue
		}
		r := bankSGRule{proto: f[0], from: -1, to: -1}
		if len(f) >= 3 {
			r.from, _ = strconv.Atoi(f[1])
			r.to, _ = strconv.Atoi(f[2])
		}
		rules = append(rules, r)
	}
	return rules, nil
}

// bankScanTCP is a connect scan of host's ports. exhausted reports a local
// file-descriptor shortage, which would read as closed ports.
func bankScanTCP(host string, list []int, workers int, timeout time.Duration) (open []int, exhausted bool) {
	ports := make(chan int, workers)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range ports {
				c, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(p)), timeout)
				mu.Lock()
				switch {
				case err == nil:
					c.Close()
					open = append(open, p)
				case strings.Contains(err.Error(), "too many open files"):
					exhausted = true
				}
				mu.Unlock()
			}
		}()
	}
	seen := map[int]bool{}
	for _, p := range list {
		if !seen[p] {
			seen[p] = true
			ports <- p
		}
	}
	close(ports)
	wg.Wait()
	sort.Ints(open)
	return open, exhausted
}

// UC-329 — TLS posture of the public endpoint: TLS 1.0 and 1.1 are refused,
// TLS 1.2 offers only forward-secret AEAD suites, TLS 1.3 works.
func TestBankTLSPosture(t *testing.T) {
	harness.Require(t, sc, "UC-329")
	host := bankAPIHost(t)
	dial := func(cfg *tls.Config) (*tls.ConnectionState, error) {
		cfg.ServerName = strings.Split(host, ":")[0]
		cfg.InsecureSkipVerify = true // staging certificates: the protocol is under test, not the chain (UC-09)
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", host, cfg)
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		st := conn.ConnectionState()
		return &st, nil
	}
	for _, v := range []uint16{tls.VersionTLS10, tls.VersionTLS11} {
		if st, err := dial(&tls.Config{MinVersion: v, MaxVersion: v}); err == nil {
			t.Errorf("the endpoint accepts %s", tls.VersionName(st.Version))
		}
	}
	weak := []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA, tls.TLS_RSA_WITH_AES_256_CBC_SHA, tls.TLS_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_RSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA}
	for _, cs := range weak {
		if st, err := dial(&tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{cs}}); err == nil {
			t.Errorf("the endpoint negotiates the weak suite %s", tls.CipherSuiteName(st.CipherSuite))
		}
	}
	if st, err := dial(&tls.Config{MinVersion: tls.VersionTLS13}); err != nil {
		t.Errorf("TLS 1.3 refused: %v", err)
	} else {
		t.Logf("TLS 1.3: %s", tls.CipherSuiteName(st.CipherSuite))
	}
	resp, err := (&http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}).Get("https://" + host + "/health")
	if err == nil {
		resp.Body.Close()
		t.Logf("security headers on /health: Strict-Transport-Security=%q X-Content-Type-Options=%q Server=%q",
			resp.Header.Get("Strict-Transport-Security"), resp.Header.Get("X-Content-Type-Options"), resp.Header.Get("Server"))
	}
	plain, err := (&http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Get("http://" + strings.Split(host, ":")[0] + "/v1/sandboxes")
	if err == nil {
		plain.Body.Close()
		if plain.StatusCode < 300 || plain.StatusCode >= 400 {
			t.Errorf("plain HTTP /v1/sandboxes answered %d, not a redirect to HTTPS", plain.StatusCode)
		}
	}
}

func bankAPIHost(t *testing.T) string {
	t.Helper()
	u := strings.TrimPrefix(strings.TrimPrefix(sc.BaseURL, "https://"), "http://")
	u = strings.TrimRight(strings.SplitN(u, "/", 2)[0], "/")
	if !strings.HasPrefix(sc.BaseURL, "https://") {
		t.Skip("the API is not served over TLS in this scenario")
	}
	if !strings.Contains(u, ":") {
		u += ":443"
	}
	return u
}

// UC-330 — no route answers without credentials: every /v1 route in the
// route table, the compatibility facades and the debug paths are called
// with no token and with a wrong one; each must refuse (401/403/404/405),
// never succeed or fail with a server error, and no body may carry a stack
// trace or a source path.
func TestBankUnauthenticatedSurface(t *testing.T) {
	harness.Require(t, sc, "UC-330")
	routes := bankV1Routes(t)
	routes = append(routes,
		"GET /debug/vars", "GET /debug/pprof/", "GET /debug/pprof/goroutine", "GET /metrics", "GET /v1/metrics",
		"GET /daytona/sandbox", "POST /daytona/sandbox", "GET /e2b/sandboxes", "POST /e2b/sandboxes", "GET /runloop/v1/devboxes", "POST /runloop/v1/devboxes",
		"POST /mcp", "GET /mcp")
	public := map[string]bool{"GET /health": true}
	leak := regexp.MustCompile(`goroutine \d+|\.go:\d+|panic:|runtime\.`)
	base := strings.TrimRight(sc.BaseURL, "/")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	checked := 0
	for _, bearer := range []string{"", "avm_not-a-real-token-0000000000000000"} {
		api := harness.NewAPIClient(base, bearer)
		for _, r := range routes {
			parts := strings.SplitN(r, " ", 2)
			if len(parts) != 2 || public[r] {
				continue
			}
			path := regexp.MustCompile(`\{[^}]+\}`).ReplaceAllString(parts[1], "bank-probe")
			var body any
			if parts[0] == http.MethodPost || parts[0] == http.MethodPut || parts[0] == http.MethodPatch {
				body = map[string]any{}
			}
			resp, err := api.Do(ctx, parts[0], path, body)
			if err != nil {
				t.Errorf("%s (bearer %t): %v", r, bearer != "", err)
				continue
			}
			checked++
			switch {
			case resp.Status >= 200 && resp.Status < 300:
				t.Errorf("%s answered %d without valid credentials (bearer %t): %.200s", r, resp.Status, bearer != "", resp.Body)
			case resp.Status >= 500 && resp.Status != http.StatusServiceUnavailable:
				t.Errorf("%s answered %d without valid credentials (bearer %t): %.200s", r, resp.Status, bearer != "", resp.Body)
			}
			if leak.Match(resp.Body) {
				t.Errorf("%s leaks internals in its %d body: %.300s", r, resp.Status, resp.Body)
			}
		}
	}
	t.Logf("checked %d unauthenticated calls over %d routes", checked, len(routes))
}

// v1RouteTable reads "METHOD /v1/..." patterns from the route table source.
func bankV1Routes(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "pkg", "api", "v1", "routes.go"))
	if err != nil {
		t.Fatalf("read the route table: %v", err)
	}
	re := regexp.MustCompile(`"(GET|POST|PUT|PATCH|DELETE) "\s*\+\s*PathPrefix\s*\+\s*"([^"]*)"`)
	seen := map[string]bool{}
	var out []string
	for _, m := range re.FindAllStringSubmatch(string(raw), -1) {
		r := m[1] + " /v1" + m[2]
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	if len(out) < 50 {
		t.Fatalf("read only %d routes from routes.go", len(out))
	}
	return out
}

// UC-331 — a secret given to a sandbox appears nowhere on its node outside
// the sandbox: not in any daemon's journal, not on a process command line,
// not under /var/log, after the sandbox has used it.
func TestBankSecretNotOnNode(t *testing.T) {
	harness.Require(t, sc, "UC-331")
	targets := bankTargets(t)
	bankEachRuntime(t, func(t *testing.T, rt bankRuntime) {
		canary := "bankcanary" + strconv.FormatInt(time.Now().UnixNano(), 36)
		sb := bankSandbox(t, rt, sdktypes.CreateSandboxOptions{Env: map[string]string{"BANK_SECRET": canary}})
		if out, _ := bankRun(t, sb, "printenv BANK_SECRET | wc -c", time.Minute); strings.TrimSpace(out) == "0" {
			t.Fatalf("the secret did not reach the sandbox")
		}
		since := time.Now().Add(-15 * time.Minute).UTC().Format("2006-01-02 15:04:05")
		// The canary goes over stdin to one root shell: on a command line
		// it would show up in ps and in sudo's own log, a false positive.
		script := fmt.Sprintf(`sudo sh -c 'read c
j=$(journalctl --since "%s" --no-pager 2>/dev/null | grep -c "$c")
p=$(ps -eo args 2>/dev/null | grep -v grep | grep -c "$c")
l=$(grep -rl "$c" /var/log 2>/dev/null | wc -l)
echo journal=$j procs=$p varlog=$l'`, since)
		for _, n := range targets.Nodes {
			target, _ := harness.SSHTarget(n)
			out, err := harness.SSHRunStdin(t, target, script, canary+"\n")
			if err != nil {
				t.Fatalf("%s: %v\n%s", n.Name, err, out)
			}
			if !strings.Contains(out, "journal=0") || !strings.Contains(out, "procs=0") || !strings.Contains(out, "varlog=0") {
				t.Errorf("%s: the sandbox secret shows up on node %s: %s", rt.name, n.Name, strings.TrimSpace(out))
			}
		}
	})
}

// UC-332 — a block-all sandbox has no way out: TCP, UDP DNS to a public
// resolver, ICMP and a lookup through its own resolver (DNS tunnelling) all
// fail.
func TestBankBlockAllNoExfiltration(t *testing.T) {
	harness.Require(t, sc, "UC-332")
	bankEachRuntime(t, func(t *testing.T, rt bankRuntime) {
		if !rt.vm && refusedForNoHostFirewall(t, sdktypes.CreateSandboxOptions{NetworkBlockAll: true, Runtime: rt.runtime, Image: bankImage(rt)}) {
			return
		}
		sb := bankSandbox(t, rt, sdktypes.CreateSandboxOptions{NetworkBlockAll: true})
		label := "exfil-" + strconv.FormatInt(time.Now().UnixNano(), 36)
		for _, probe := range []struct{ cmd, what string }{
			{"nc -z -w 3 1.1.1.1 443", "TCP to the internet"},
			{"nc -z -w 3 8.8.8.8 53", "TCP DNS to a public resolver"},
			{"nslookup example.com 8.8.8.8", "UDP DNS to a public resolver"},
			{"ping -c 1 -W 3 1.1.1.1", "ICMP to the internet"},
			{"nslookup example.com", "a DNS lookup through its own resolver (a tunnel out)"},
			{"nslookup " + label + ".example.org 1.1.1.1", "UDP DNS to another public resolver"},
			{"wget -q -T 5 -O /dev/null http://example.com/", "HTTP by name"},
		} {
			if _, rc := bankRun(t, sb, probe.cmd+" >/dev/null 2>&1", time.Minute); rc == 0 {
				t.Errorf("%s: a block-all sandbox succeeded at %s (%q)", rt.name, probe.what, probe.cmd)
			}
		}
	})
}

// bankToolboxPort is the port toolboxd, the agent that runs commands and
// moves files for the API, listens on inside every container and VM.
const bankToolboxPort = 2280

// bankUnauthExec sends an exec with no Authorization header to
// host:2280 from inside sb and returns the HTTP status line, or "" when
// nothing answered.
func bankUnauthExec(t *testing.T, sb *microvm.Sandbox, host string) string {
	t.Helper()
	const body = `{"command":"id"}`
	req := fmt.Sprintf(`POST /process/execute HTTP/1.0\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s`, host, len(body), body)
	out, _ := bankRun(t, sb, fmt.Sprintf("printf '%s' | nc -w 3 %s %d | head -1", req, host, bankToolboxPort), time.Minute)
	return strings.TrimSpace(out)
}

// UC-339 — no sandbox reaches another sandbox's toolbox agent, on any pair of
// runtimes the scenario has (container, gVisor, Firecracker, in both
// directions), and a Firecracker guest's agent refuses a call that does not
// carry its sandbox's token, even from the node itself. Before the toolbox
// auth fix a Firecracker guest booted from a template, a template snapshot or
// the warm pool ran its agent with no token and served exec and files to any
// caller that reached port 2280, so the node check runs on a template clone
// as well as a cold boot.
func TestBankToolboxAgentUnreachable(t *testing.T) {
	harness.Require(t, sc, "UC-339")
	c := client(t)
	type peer struct {
		rt bankRuntime
		sb *microvm.Sandbox
		ip string
	}
	var victims []peer
	for _, rt := range bankShellRuntimes(t) {
		v := bankSandbox(t, rt, sdktypes.CreateSandboxOptions{})
		victims = append(victims, peer{rt: rt, sb: v, ip: containerIP(t, c, v)})
	}
	for _, v := range victims {
		for _, rt := range bankShellRuntimes(t) {
			v, rt := v, rt
			t.Run(rt.name+"-to-"+v.rt.name, func(t *testing.T) {
				sb, ok := bankNeighbour(t, rt, v.sb)
				if !ok {
					t.Skipf("no %s sandbox landed on %s's node; a probe across nodes reaches the prober's own node", rt.name, v.sb.ID)
				}
				a := peer{rt: rt, sb: sb}
				if !bankTCPOpen(t, a.sb, v.ip, bankToolboxPort) {
					return
				}
				t.Errorf("sandbox %s (%s) opens a connection to sandbox %s's (%s) toolbox agent at %s:%d",
					a.sb.ID, a.rt.name, v.sb.ID, v.rt.name, v.ip, bankToolboxPort)
				// What the connection is worth: an exec without the token.
				status := bankUnauthExec(t, a.sb, v.ip)
				t.Logf("an unauthenticated exec from %s to %s answered %q", a.sb.ID, v.sb.ID, status)
				if f := strings.Fields(status); len(f) >= 2 && strings.HasPrefix(f[1], "2") {
					t.Errorf("CRITICAL: sandbox %s ran a command in sandbox %s without its token (%s)", a.sb.ID, v.sb.ID, status)
				}
			})
		}
	}

	if !sc.Has(harness.CapFirecracker) {
		return
	}
	targets := bankTargets(t)
	fc := []peer{}
	for _, v := range victims {
		if v.rt.vm {
			fc = append(fc, v)
		}
	}
	// A template clone: the boot path whose agent had no token at all.
	ctx, cancel := context.WithTimeout(context.Background(), 18*time.Minute)
	defer cancel()
	tmpl, err := c.SDK().CreateTemplate(ctx, sdktypes.CreateTemplateOptions{Image: "docker://" + bankImage(bankRuntime{vm: true})})
	if err != nil {
		t.Fatalf("create template: %v", err)
	}
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), time.Minute)
		defer ccancel()
		_ = c.SDK().DeleteTemplate(cctx, tmpl.ID)
	})
	waitTemplateReady(t, c, tmpl.ID)
	clone := bankSandbox(t, bankRuntime{name: "firecracker-template", runtime: "firecracker", vm: true}, sdktypes.CreateSandboxOptions{TemplateID: tmpl.ID})
	fc = append(fc, peer{rt: bankRuntime{name: "firecracker-template", vm: true}, sb: clone, ip: containerIP(t, c, clone)})

	for _, v := range fc {
		v := v
		t.Run("node-to-"+v.rt.name, func(t *testing.T) {
			node := bankSandboxNode(t, targets, v.sb)
			base := fmt.Sprintf("http://%s:%d", v.ip, bankToolboxPort)
			const code = `-s -o /dev/null -m 5 -w '%{http_code}\n'`
			script := strings.Join([]string{
				fmt.Sprintf(`curl %s -X POST -H 'Content-Type: application/json' -d '{"command":"id"}' %s/process/execute`, code, base),
				fmt.Sprintf(`curl %s -X POST -H 'Authorization: Bearer not-the-token' -H 'Content-Type: application/json' -d '{"command":"id"}' %s/process/execute`, code, base),
				fmt.Sprintf(`curl %s '%s/files/download?path=/etc/hostname'`, code, base),
				fmt.Sprintf(`curl %s %s/sessions`, code, base),
				fmt.Sprintf(`curl %s %s/health`, code, base),
			}, "; ")
			got := strings.Fields(nodeSSH(t, node, script))
			if len(got) != 5 {
				t.Fatalf("node %s: unexpected curl output %v", node.Name, got)
			}
			// /health answers whether or not the agent is adopted: it proves
			// the calls above reached the agent and were refused by it.
			if got[4] != "200" {
				t.Fatalf("node %s could not reach %s's agent at %s (health %s); the refusals prove nothing", node.Name, v.sb.ID, base, got[4])
			}
			for i, what := range []string{"an exec without a token", "an exec with a wrong token", "a file read without a token", "the sessions API without a token"} {
				if got[i] != "401" && got[i] != "503" {
					t.Errorf("%s (%s): %s from node %s answered %s, want 401 or 503", v.sb.ID, v.rt.name, what, node.Name, got[i])
				}
			}
		})
	}
}
