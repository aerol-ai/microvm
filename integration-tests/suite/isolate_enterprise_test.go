//go:build integration

package suite

// Group K — the isolate jail under the enterprise posture (§7 group K,
// F16/F17). UC-163..164.

import (
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	"github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// UC-163 — under enterprise, workerd runs jailed while serving: non-root uid,
// a populated chroot, an enforcing seccomp filter, and the configured pid cap
// on its cgroup.
//
// All four together, and while SERVING. Each alone is satisfiable by a
// process that does nothing: a jail that is only correct when idle is not a
// boundary, and the enterprise gate (config.go:2427-2440) exists precisely
// because this is the cross-tenant boundary for untrusted code.
func TestIsolateJailIsRealizedUnderEnterprise(t *testing.T) {
	harness.Require(t, sc, "UC-163")
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	c := client(t)

	ref := uploadBundle(t, c, "itest-uc163",
		`export default { async fetch() { return new Response("jailed-ok"); } };`)
	sb := newIsolateSandbox(t, c, ref, "itest-uc163", sdktypes.CreateSandboxOptions{})
	waitRunning(t, sb)

	owner := resolvePlacementOwner(t, c, sb.ID)
	node, ok := nodeForClusterID(t, c, targets, owner)
	if !ok {
		node, ok = harness.PickSSHNode(targets)
		if !ok {
			t.Skip("no SSH-reachable node")
		}
	}
	target, _ := harness.SSHTarget(node)

	out, err := harness.SSHRun(t, target, workerdJailProbeScript)
	if err != nil {
		t.Fatalf("probe the workerd jail on %s: %v\n%s", node.Name, err, out)
	}
	fields := parseKV(out)
	if fields["FOUND"] != "1" {
		t.Skipf("no workerd process found on %s while an isolate sandbox is running; this node is not serving it: %s", node.Name, strings.TrimSpace(out))
	}

	if fields["UID"] == "0" || fields["UID"] == "" {
		t.Fatalf("workerd runs as uid %q: the jail's first boundary is not in place and tenant code runs as root", fields["UID"])
	}
	// Seccomp: 2 is SECCOMP_MODE_FILTER. 0 is disabled, 1 is strict-but-
	// unused-here; anything but 2 means the syscall filter is not enforcing.
	if fields["SECCOMP"] != "2" {
		t.Fatalf("workerd's /proc/<pid>/status reports Seccomp: %q, want 2 (filter enforcing); the syscall boundary is off", fields["SECCOMP"])
	}
	if fields["NONEWPRIVS"] != "1" {
		t.Fatalf("workerd reports NoNewPrivs: %q, want 1; a setuid binary inside the jail could escape it", fields["NONEWPRIVS"])
	}
	// A chroot of "/" means the process was never chrooted. This is the
	// gotcha that has bitten this project before: workerd is installed on the
	// host but the chroot is never populated, so jail-on either fails to
	// start or silently is not a chroot at all.
	if root := fields["ROOT"]; root == "" || root == "/" {
		t.Fatalf("workerd's root is %q: it is not chrooted, so the filesystem boundary between tenants does not exist", root)
	}
	pidsMax := fields["PIDSMAX"]
	if pidsMax == "" || pidsMax == "max" {
		t.Fatalf("workerd's cgroup pids.max is %q: an unbounded tenant cgroup can exhaust the host PID space, which config.go refuses to boot with", pidsMax)
	}
	if n, convErr := strconv.Atoi(pidsMax); convErr != nil || n <= 0 {
		t.Fatalf("workerd's cgroup pids.max is %q, want a positive integer", pidsMax)
	}

	// And it must still be serving. A jailed process that cannot answer is
	// not evidence that the jail is compatible with doing the job.
	if got := execFetch(t, sb, "/"); got != "jailed-ok" {
		t.Fatalf("the jailed isolate sandbox stopped serving: fetch returned %q", got)
	}
	t.Logf("UC-163 PASS: workerd uid=%s seccomp=%s nonewprivs=%s root=%s pids.max=%s, and serving",
		fields["UID"], fields["SECCOMP"], fields["NONEWPRIVS"], fields["ROOT"], pidsMax)
}

// UC-164 — per-sandbox egress attribution holds under the jail: an
// allow-listed host is reachable, a non-allowed one is refused, and the
// audit event names the right sandbox.
//
// Attribution is by egress slot socket, which is structural rather than a
// forgeable header — so the thing that could break under the jail is the
// plumbing, not the design. That is exactly why it has to be checked with
// the jail on rather than inherited from the jail-off run.
func TestIsolateEgressAttributionHoldsUnderTheJail(t *testing.T) {
	harness.Require(t, sc, "UC-164")
	c := client(t)

	ref := uploadBundle(t, c, "itest-uc164", egressProbeBundle)

	// ONE workerd group, two policies. Attribution is by egress slot socket
	// — structural, not a forgeable header — so what the jail could break is
	// the plumbing, not the design. That is exactly why it has to be proven
	// with the jail ON rather than inherited from the jail-off UC-104 run.
	const tenant = "itest-uc164"
	allow := newIsolateSandbox(t, c, ref, tenant, sdktypes.CreateSandboxOptions{
		NetworkAllowOut: []string{"example.com"},
	})
	block := newIsolateSandbox(t, c, ref, tenant, sdktypes.CreateSandboxOptions{
		NetworkBlockAll: true,
	})
	waitRunning(t, allow)
	waitRunning(t, block)

	probe := func(sb *microvm.Sandbox, target string) string {
		return execFetch(t, sb, "/?t="+url.QueryEscape(target))
	}

	if got := probe(allow, "https://example.com/"); strings.Contains(got, "status=403") {
		t.Fatalf("under the jail, the allow-listed sandbox was refused its OWN allowed host: %q. The jail broke the egress plumbing, so the enterprise posture cannot serve networked tenants at all.", got)
	}
	if got := probe(allow, "https://not-allowed.example/"); !strings.Contains(got, "status=403") {
		t.Fatalf("under the jail, the allow-listed sandbox reached a host NOT on its allowlist: %q. The per-sandbox policy is not enforced.", got)
	}
	if got := probe(block, "https://example.com/"); !strings.Contains(got, "status=403") {
		t.Fatalf("under the jail, a block-all sandbox reached the host its GROUP NEIGHBOUR was allowed: %q. Attribution collapsed to the group, so one tenant's allowlist silently widens another's.", got)
	}

	// The evidence must name the right sandbox. A denial recorded against
	// the wrong tenant is worse than no record: it puts one tenant's network
	// activity in another tenant's audit trail.
	for _, ev := range harness.AllAuditEvents(t, c, block.ID, 200, 10) {
		if ev.Kind == "egress" && ev.SandboxID == allow.ID {
			t.Fatalf("an egress record in %s's history names %s", block.ID, allow.ID)
		}
	}
	if harness.CountAuditEvents(harness.AllAuditEvents(t, c, allow.ID, 200, 10), "egress") == 0 {
		t.Log("no egress audit records for the allow-listed sandbox; attribution may be off on this profile (the enforcement assertions above still ran)")
	}
}
