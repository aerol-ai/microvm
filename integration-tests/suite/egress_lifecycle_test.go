//go:build integration

package suite

// Egress lifecycle use cases (PR #622, plans/egress-domain-filtering.md
// §5.7-5.8): what a sandbox's egress enforcement does across stop and start,
// live mode changes, destroy, an egress gateway restart or outage, and a
// sandboxd restart, checked through the sandbox and on its node. The node
// checks read the host firewall and the gateway's nft sets over SSH, so they
// see what an API answer can't: rules left behind at an address.

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// Destinations every scenario's nodes can reach. CIDR checks use DNS over
// TCP on 53, which answers on both. A gateway-mode sandbox's port 53, to any
// address, is the gateway's filtering DNS (and 80 and 443 its proxy), so in
// that mode a probe proves nothing about CIDR rules: those steps read the
// node's firewall instead.
const (
	cloudflareDNS = "1.1.1.1"
	googleDNS     = "8.8.8.8"
)

// sandboxNode returns the node that runs sb, for host-side checks: its
// cluster owner, or the only node. It skips when the node can't be reached
// over SSH.
func sandboxNode(t *testing.T, c *harness.Client, sb *microvm.Sandbox) harness.IntegrationNode {
	t.Helper()
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	var node harness.IntegrationNode
	if sc.Has(harness.CapCluster) {
		id := resolveOwnerNode(t, c, sb.ID)
		n, ok := harness.IntegrationNodeForClusterID(targets, id)
		if !ok {
			t.Fatalf("owner node %q of %s is not in the integration targets", id, sb.ID)
		}
		node = n
	} else {
		n, ok := harness.PickSSHNode(targets)
		if !ok {
			t.Skip("no SSH-reachable node in the integration targets")
		}
		node = n
	}
	harness.RequireNodeSSH(t, node)
	return node
}

func nodeSSH(t *testing.T, node harness.IntegrationNode, script string) string {
	t.Helper()
	target, _ := harness.SSHTarget(node)
	out, err := harness.SSHRun(t, target, script)
	if err != nil {
		t.Fatalf("ssh %s: %v\n%s", node.Name, err, out)
	}
	return out
}

// ipOnLine matches ip as a whole address, so 10.0.0.5 doesn't match
// 10.0.0.50.
func ipOnLine(ip string) *regexp.Regexp {
	return regexp.MustCompile(`(^|[^0-9.])` + regexp.QuoteMeta(ip) + `([^0-9.]|$)`)
}

// hostEgressRules returns the node's selective-egress and hold rules
// (comment-tagged sbx-egress, sbx-egress-hold) whose source is ip, in
// whichever form the node keeps them: iptables (nft or legacy) or native nft.
func hostEgressRules(t *testing.T, node harness.IntegrationNode, ip string) []string {
	t.Helper()
	out := nodeSSH(t, node, "sudo iptables-save 2>/dev/null; sudo iptables-legacy-save 2>/dev/null; sudo nft list ruleset 2>/dev/null; true")
	re := ipOnLine(ip)
	var rules []string
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "sbx-egress") && re.MatchString(line) {
			rules = append(rules, strings.TrimSpace(line))
		}
	}
	return rules
}

// inGatewaySet reports whether ip is an element of the egress gateway's nft
// set (fqdn_src: attached sandboxes; blocked_src: shut ones).
func inGatewaySet(t *testing.T, node harness.IntegrationNode, set, ip string) bool {
	t.Helper()
	out := nodeSSH(t, node, "sudo nft list set inet aerolvm_egress "+set+" 2>/dev/null; true")
	i := strings.Index(out, "elements")
	return i >= 0 && ipOnLine(ip).MatchString(out[i:])
}

// eventually polls cond for up to d.
func eventually(d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for {
		if cond() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(3 * time.Second)
	}
}

// containerIP is sb's address as the API reports it.
func containerIP(t *testing.T, c *harness.Client, sb *microvm.Sandbox) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	got, err := c.SDK().Get(ctx, sb.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ContainerIP == "" {
		t.Fatalf("sandbox %s has no container_ip", sb.ID)
	}
	return got.ContainerIP
}

func egressStatus(t *testing.T, c *harness.Client, id string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	got, err := c.SDK().Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	return got.EgressStatus
}

// stopSandbox stops sb and waits until the API reports it stopped.
func stopSandbox(t *testing.T, sb *microvm.Sandbox) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := sb.Stop(ctx); err != nil {
		t.Fatalf("stop %s: %v", sb.ID, err)
	}
	if !eventually(90*time.Second, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return sb.Refresh(ctx) == nil && string(sb.Status) == "stopped"
	}) {
		t.Fatalf("sandbox %s never reported stopped (status %q)", sb.ID, sb.Status)
	}
}

func startSandbox(t *testing.T, sb *microvm.Sandbox) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if err := sb.Start(ctx); err != nil {
		t.Fatalf("start %s: %v", sb.ID, err)
	}
	waitRunning(t, sb)
}

// refusedFast asserts a name outside the list is refused, and quickly: the
// gateway answers NXDOMAIN and ends a TLS handshake for a name it doesn't
// admit, so the 20s client timeout must not be what stops it.
func refusedFast(t *testing.T, sb *microvm.Sandbox, url string) {
	t.Helper()
	if rc, secs := timedRC(t, sb, "wget -q -T 20 -O /dev/null "+url); rc == 0 || secs >= 10 {
		t.Fatalf("%s must be refused fast (rc=%d after %ds)", url, rc, secs)
	}
}

// UC-205 — a hostname allowlist is enforced again after a stop and start:
// the start re-attaches the sandbox to its node's gateway before it reports
// started.
func TestEgressHostnamePolicySurvivesStopStart(t *testing.T) {
	harness.Require(t, sc, "UC-205")
	c := client(t)
	sb := newEgressSandbox(t, c, []string{"example.com"}, nil)
	if !fetches(t, sb, "https://example.com/") {
		t.Fatal("the allowed name must be reachable before the stop")
	}
	stopSandbox(t, sb)
	startSandbox(t, sb)
	if !fetches(t, sb, "https://example.com/") {
		t.Fatal("the allowed name must be reachable after the start")
	}
	refusedFast(t, sb, "https://pypi.org/simple/")
	if st := egressStatus(t, c, sb.ID); st != "active" {
		t.Fatalf("egress_status after the start = %q, want active", st)
	}
}

// UC-206 — a CIDR allowlist across a stop and start: the stop removes the
// sandbox's rules from the address it leaves, and the start enforces the
// list at the address it gets, leaving nothing at the old one.
func TestEgressCIDRStopStartLeavesNoRulesBehind(t *testing.T) {
	harness.Require(t, sc, "UC-206")
	c := client(t)
	sb := newEgressSandbox(t, c, []string{cloudflareDNS + "/32"}, nil)
	node := sandboxNode(t, c, sb)
	ip1 := containerIP(t, c, sb)
	if len(hostEgressRules(t, node, ip1)) == 0 {
		t.Fatalf("setup: no egress rules for %s on %s", ip1, node.Name)
	}

	stopSandbox(t, sb)
	if !eventually(60*time.Second, func() bool { return len(hostEgressRules(t, node, ip1)) == 0 }) {
		t.Fatalf("a stopped sandbox's rules must leave its address %s:\n%s", ip1, strings.Join(hostEgressRules(t, node, ip1), "\n"))
	}

	startSandbox(t, sb)
	if !tcpProbe(t, sb, cloudflareDNS, 53) {
		t.Fatal("the allowed CIDR must be reachable after the start")
	}
	if tcpProbe(t, sb, googleDNS, 53) {
		t.Fatal("a destination outside the list must stay dropped after the start")
	}
	node = sandboxNode(t, c, sb)
	ip2 := containerIP(t, c, sb)
	if len(hostEgressRules(t, node, ip2)) == 0 {
		t.Fatalf("no egress rules for the new address %s on %s", ip2, node.Name)
	}
	if ip2 != ip1 {
		if left := hostEgressRules(t, node, ip1); len(left) > 0 {
			t.Fatalf("rules left at the old address %s:\n%s", ip1, strings.Join(left, "\n"))
		}
	}
}

// UC-207 (review 6 finding 2) — a policy changed while the sandbox is
// stopped is the policy its start enforces, and the old list's rules are
// gone by the time the start reports success.
func TestEgressPolicyChangedWhileStoppedIsWhatStartEnforces(t *testing.T) {
	harness.Require(t, sc, "UC-207")
	c := client(t)
	sb := newEgressSandbox(t, c, []string{cloudflareDNS + "/32"}, nil)
	stopSandbox(t, sb)
	setPolicy(t, sb, sdktypes.NetworkPolicyOptions{NetworkAllowOut: []string{googleDNS + "/32"}})
	startSandbox(t, sb)
	if !tcpProbe(t, sb, googleDNS, 53) {
		t.Fatal("the list set while stopped must be enforced: its CIDR is unreachable")
	}
	if tcpProbe(t, sb, cloudflareDNS, 53) {
		t.Fatal("the list replaced while stopped must not be enforced after the start")
	}
	node := sandboxNode(t, c, sb)
	for _, r := range hostEgressRules(t, node, containerIP(t, c, sb)) {
		if strings.Contains(r, cloudflareDNS) {
			t.Fatalf("a rule of the replaced list is still installed: %s", r)
		}
	}
}

// UC-208 (§5.8) — a running sandbox moves CIDR → hostname → CIDR in place;
// each step enforces its own list and removes the previous step's, from the
// sandbox's view and from its node's firewall and gateway sets.
func TestEgressLiveModeTransitions(t *testing.T) {
	harness.Require(t, sc, "UC-208")
	c := client(t)
	sb := newEgressSandbox(t, c, []string{cloudflareDNS + "/32"}, nil)
	if !tcpProbe(t, sb, cloudflareDNS, 53) || tcpProbe(t, sb, googleDNS, 53) {
		t.Fatal("step 1 (CIDR): only the listed address may be reachable")
	}
	node, ip := sandboxNode(t, c, sb), containerIP(t, c, sb)
	namesCIDR := func(cidr string) bool {
		for _, r := range hostEgressRules(t, node, ip) {
			if strings.Contains(r, cidr) {
				return true
			}
		}
		return false
	}

	pol := setPolicy(t, sb, sdktypes.NetworkPolicyOptions{NetworkAllowOut: []string{"example.com"}})
	if pol.EgressStatus != "active" {
		t.Fatalf("step 2 (hostname): egress_status = %q, want active", pol.EgressStatus)
	}
	if !fetches(t, sb, "https://example.com/") {
		t.Fatal("step 2 (hostname): the listed name must be reachable")
	}
	refusedFast(t, sb, "https://pypi.org/simple/")
	if namesCIDR(cloudflareDNS) {
		t.Fatalf("step 2 (hostname): step 1's CIDR rules must be gone from %s:\n%s", node.Name, strings.Join(hostEgressRules(t, node, ip), "\n"))
	}
	if !inGatewaySet(t, node, "fqdn_src", ip) {
		t.Fatalf("step 2 (hostname): %s must be attached to the gateway on %s", ip, node.Name)
	}

	setPolicy(t, sb, sdktypes.NetworkPolicyOptions{NetworkAllowOut: []string{googleDNS + "/32"}})
	if !tcpProbe(t, sb, googleDNS, 53) {
		t.Fatal("step 3 (CIDR): the listed address must be reachable")
	}
	if tcpProbe(t, sb, cloudflareDNS, 53) || fetches(t, sb, "https://example.com/") {
		t.Fatal("step 3 (CIDR): earlier steps' lists must be gone")
	}
	if inGatewaySet(t, node, "fqdn_src", ip) {
		t.Fatalf("step 3 (CIDR): %s must have left the gateway on %s", ip, node.Name)
	}
	if st := egressStatus(t, c, sb.ID); st != "" {
		t.Fatalf("step 3 (CIDR): egress_status = %q, want none (no gateway)", st)
	}
}

// UC-209 — block-all shuts a hostname sandbox completely, DNS included, and
// lifting it restores the list through the gateway.
func TestEgressBlockAllToggle(t *testing.T) {
	harness.Require(t, sc, "UC-209")
	c := client(t)
	sb := newEgressSandbox(t, c, []string{"example.com"}, nil)
	setPolicy(t, sb, sdktypes.NetworkPolicyOptions{NetworkBlockAll: true})
	if fetches(t, sb, "https://example.com/") {
		t.Fatal("block-all must shut the listed name")
	}
	// busybox nslookup prints a "Name:" line only for an answer.
	if out := egressExec(t, sb, "timeout 15 nslookup example.com 2>&1; true"); strings.Contains(out, "Name:") {
		t.Fatalf("block-all must shut DNS too:\n%s", out)
	}
	if tcpProbe(t, sb, cloudflareDNS, 53) {
		t.Fatal("block-all must drop every destination")
	}
	pol := setPolicy(t, sb, sdktypes.NetworkPolicyOptions{NetworkAllowOut: []string{"example.com"}})
	if pol.EgressStatus != "active" {
		t.Fatalf("egress_status after lifting block-all = %q, want active", pol.EgressStatus)
	}
	if !fetches(t, sb, "https://example.com/") {
		t.Fatal("lifting block-all must restore the listed name")
	}
	refusedFast(t, sb, "https://pypi.org/simple/")
}

// UC-210 (review 5 findings 5-6, review 6 finding 3) — a destroy leaves
// nothing on the node: no CIDR or hold rules at a CIDR sandbox's address,
// and a hostname sandbox's address is out of the gateway's sets.
func TestEgressDestroyLeavesNothingOnTheNode(t *testing.T) {
	harness.Require(t, sc, "UC-210")
	c := client(t)
	cidr := newEgressSandbox(t, c, []string{cloudflareDNS + "/32"}, nil)
	host := newEgressSandbox(t, c, []string{"example.com"}, nil)
	cidrNode, hostNode := sandboxNode(t, c, cidr), sandboxNode(t, c, host)
	cidrIP, hostIP := containerIP(t, c, cidr), containerIP(t, c, host)
	if len(hostEgressRules(t, cidrNode, cidrIP)) == 0 {
		t.Fatalf("setup: no egress rules for %s", cidrIP)
	}
	if !inGatewaySet(t, hostNode, "fqdn_src", hostIP) {
		t.Fatalf("setup: %s is not in the gateway's fqdn_src on %s", hostIP, hostNode.Name)
	}

	for _, sb := range []*microvm.Sandbox{cidr, host} {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		err := sb.Destroy(ctx)
		cancel()
		if err != nil {
			t.Fatalf("destroy %s: %v", sb.ID, err)
		}
	}
	if !eventually(60*time.Second, func() bool { return len(hostEgressRules(t, cidrNode, cidrIP)) == 0 }) {
		t.Fatalf("a destroyed sandbox's rules are left at %s:\n%s", cidrIP, strings.Join(hostEgressRules(t, cidrNode, cidrIP), "\n"))
	}
	if !eventually(60*time.Second, func() bool {
		return !inGatewaySet(t, hostNode, "fqdn_src", hostIP) && !inGatewaySet(t, hostNode, "blocked_src", hostIP)
	}) {
		t.Fatalf("a destroyed sandbox's address %s is still in the gateway's sets on %s", hostIP, hostNode.Name)
	}
}

// UC-211 (review 5 finding 2) — restarting the node's egress gateway: the
// gateway rebuilds its sets from sandboxd, so a sandbox it was filtering
// reaches its listed name again and is still refused another.
func TestEgressGatewayRestartRebuildsEnforcement(t *testing.T) {
	harness.Require(t, sc, "UC-211")
	c := client(t)
	sb := newEgressSandbox(t, c, []string{"example.com"}, nil)
	node := sandboxNode(t, c, sb)
	ip := containerIP(t, c, sb)
	harness.RestartSystemdUnit(t, node, "aerolvm-egress-gateway.service")
	if !eventually(90*time.Second, func() bool { return inGatewaySet(t, node, "fqdn_src", ip) }) {
		t.Fatalf("the restarted gateway never took %s back", ip)
	}
	if !eventually(90*time.Second, func() bool { return fetches(t, sb, "https://example.com/") }) {
		t.Fatal("the listed name must be reachable again after the gateway restart")
	}
	refusedFast(t, sb, "https://pypi.org/simple/")
	if !eventually(60*time.Second, func() bool { return egressStatus(t, c, sb.ID) == "active" }) {
		t.Fatalf("egress_status = %q after the gateway restart, want active", egressStatus(t, c, sb.ID))
	}
}

// UC-212 — restarting sandboxd on the sandbox's node leaves its filtering
// as it was (the gateway is its own process), and the restarted daemon can
// change the policy: its first Sync carries a fresh token.
func TestEgressSurvivesSandboxdRestart(t *testing.T) {
	harness.Require(t, sc, "UC-212")
	c := client(t)
	sb := newEgressSandbox(t, c, []string{"example.com"}, nil)
	node := sandboxNode(t, c, sb)
	harness.RestartSystemdUnit(t, node, "sandboxd")
	if !eventually(3*time.Minute, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_, err := sb.ExecCommand(ctx, "true")
		return err == nil
	}) {
		t.Fatal("the sandbox never answered exec after the sandboxd restart")
	}
	if !fetches(t, sb, "https://example.com/") {
		t.Fatal("the listed name must stay reachable across a sandboxd restart")
	}
	refusedFast(t, sb, "https://pypi.org/simple/")
	if !eventually(90*time.Second, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		pol, err := sb.SetNetworkPolicy(ctx, sdktypes.NetworkPolicyOptions{NetworkAllowOut: []string{"pypi.org"}})
		return err == nil && pol.EgressStatus == "active"
	}) {
		t.Fatal("the restarted sandboxd must apply a policy change")
	}
	if !fetches(t, sb, "https://pypi.org/simple/") {
		t.Fatal("the new list must be enforced after the restart")
	}
	refusedFast(t, sb, "https://example.com/")
}

// UC-213 (CEO D16) — with the node's egress gateway down, a hostname
// sandbox is shut, not open, and a policy change can't claim to be live;
// when the gateway is back, the sandbox recovers on the newest policy.
func TestEgressGatewayOutageFailsClosedAndRecovers(t *testing.T) {
	harness.Require(t, sc, "UC-213")
	c := client(t)
	sb := newEgressSandbox(t, c, []string{"example.com"}, nil)
	node := sandboxNode(t, c, sb)
	units := "aerolvm-egress-gateway.socket aerolvm-egress-gateway.service"
	// The socket goes too: socket activation would start the service again
	// on sandboxd's next probe.
	nodeSSH(t, node, "sudo systemctl stop "+units)
	restarted := false
	restart := func() {
		if !restarted {
			restarted = true
			nodeSSH(t, node, "sudo systemctl start "+units)
		}
	}
	t.Cleanup(restart)

	if fetches(t, sb, "https://example.com/") {
		t.Fatal("with the gateway down, the listed name must not be reachable")
	}
	if tcpProbe(t, sb, cloudflareDNS, 53) {
		t.Fatal("with the gateway down, nothing may bypass it")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	pol, err := sb.SetNetworkPolicy(ctx, sdktypes.NetworkPolicyOptions{NetworkAllowOut: []string{"pypi.org"}})
	cancel()
	if err == nil && pol.EgressStatus == "active" {
		t.Fatal("a policy change with the gateway down must not report itself active")
	}
	if fetches(t, sb, "https://pypi.org/simple/") {
		t.Fatal("the new list must not open anything while the gateway is down")
	}

	restart()
	if err != nil {
		// The change was refused, not stored: apply it now the gateway is back.
		if !eventually(2*time.Minute, func() bool {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			pol, err := sb.SetNetworkPolicy(ctx, sdktypes.NetworkPolicyOptions{NetworkAllowOut: []string{"pypi.org"}})
			return err == nil && pol.EgressStatus == "active"
		}) {
			t.Fatal("the policy change never applied after the gateway came back")
		}
	}
	if !eventually(3*time.Minute, func() bool { return egressStatus(t, c, sb.ID) == "active" }) {
		t.Fatalf("egress_status = %q after the gateway came back, want active", egressStatus(t, c, sb.ID))
	}
	if !eventually(90*time.Second, func() bool { return fetches(t, sb, "https://pypi.org/simple/") }) {
		t.Fatal("the newest list must be enforced once the gateway is back")
	}
	refusedFast(t, sb, "https://example.com/")
}

// UC-214 (P2-9) — the policy check endpoint answers the matcher's verdict
// for hosts, ports and addresses without creating a sandbox.
func TestEgressPolicyCheckAPI(t *testing.T) {
	harness.Require(t, sc, "UC-214")
	c := client(t)
	cases := []struct {
		name        string
		opts        sdktypes.NetworkPolicyCheckOptions
		allowed     bool
		matched     string
		defaultVerd string
	}{
		{"listed host", sdktypes.NetworkPolicyCheckOptions{NetworkAllowOut: []string{"pypi.org"}, Destination: "pypi.org"}, true, "pypi.org", "deny"},
		{"unlisted host", sdktypes.NetworkPolicyCheckOptions{NetworkAllowOut: []string{"pypi.org"}, Destination: "example.com"}, false, "", "deny"},
		{"wildcard subdomain", sdktypes.NetworkPolicyCheckOptions{NetworkAllowOut: []string{"*.github.com"}, Destination: "api.github.com"}, true, "*.github.com", "deny"},
		{"wildcard not apex", sdktypes.NetworkPolicyCheckOptions{NetworkAllowOut: []string{"*.github.com"}, Destination: "github.com"}, false, "", "deny"},
		{"bare host is web ports only", sdktypes.NetworkPolicyCheckOptions{NetworkAllowOut: []string{"pypi.org"}, Destination: "pypi.org:8080"}, false, "", "deny"},
		{"port entry", sdktypes.NetworkPolicyCheckOptions{NetworkAllowOut: []string{"git.example.com:22"}, Destination: "git.example.com:22"}, true, "git.example.com:22", "deny"},
		{"cidr", sdktypes.NetworkPolicyCheckOptions{NetworkAllowOut: []string{"203.0.113.0/24"}, Destination: "203.0.113.9:5432"}, true, "203.0.113.0/24", "deny"},
		{"deny list", sdktypes.NetworkPolicyCheckOptions{NetworkDenyOut: []string{"198.51.100.0/24"}, Destination: "198.51.100.4"}, false, "198.51.100.0/24", "allow"},
		{"deny list default", sdktypes.NetworkPolicyCheckOptions{NetworkDenyOut: []string{"198.51.100.0/24"}, Destination: "example.com"}, true, "", "allow"},
		{"block-all", sdktypes.NetworkPolicyCheckOptions{NetworkBlockAll: true, Destination: "example.com"}, false, "network_block_all", "deny"},
	}
	for _, tc := range cases {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		res, err := c.SDK().CheckNetworkPolicy(ctx, tc.opts)
		cancel()
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if res.Allowed != tc.allowed || res.MatchedRule != tc.matched || res.DefaultVerdict != tc.defaultVerd {
			t.Errorf("%s: got allowed=%v matched=%q default=%q, want %v %q %q", tc.name, res.Allowed, res.MatchedRule, res.DefaultVerdict, tc.allowed, tc.matched, tc.defaultVerd)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := c.SDK().CheckNetworkPolicy(ctx, sdktypes.NetworkPolicyCheckOptions{NetworkAllowOut: []string{"pypi.org"}, Destination: "bad name!"}); err == nil {
		t.Error("an invalid destination must be refused")
	}
}

// placedSandboxes creates hostname sandboxes, alternating two allowlists,
// until want(byNode) holds or max creates are spent, and returns them by
// owner node ("" on a single node).
func placedSandboxes(t *testing.T, c *harness.Client, lists [2][]string, max int, want func(map[string][2][]*microvm.Sandbox) bool) map[string][2][]*microvm.Sandbox {
	t.Helper()
	byNode := map[string][2][]*microvm.Sandbox{}
	for i := 0; i < max; i++ {
		k := i % 2
		sb := newEgressSandbox(t, c, lists[k], nil)
		node := ""
		if sc.Has(harness.CapCluster) {
			node = resolveOwnerNode(t, c, sb.ID)
		}
		b := byNode[node]
		b[k] = append(b[k], sb)
		byNode[node] = b
		if want(byNode) {
			break
		}
	}
	return byNode
}

// assertOwnList checks a sandbox reaches its own name and is refused the
// other list's.
func assertOwnList(t *testing.T, sb *microvm.Sandbox, own, other string) {
	t.Helper()
	if !fetches(t, sb, "https://"+own+"/") {
		t.Fatalf("sandbox %s must reach its own name %s", sb.ID, own)
	}
	refusedFast(t, sb, "https://"+other+"/")
}

// UC-215 — two sandboxes on the same node, with different allowlists, go
// through the same gateway and are filtered apart: each reaches only its
// own names.
func TestEgressNeighboursOnOneNodeAreFilteredApart(t *testing.T) {
	harness.Require(t, sc, "UC-215")
	c := client(t)
	lists := [2][]string{{"example.com"}, {"pypi.org"}}
	byNode := placedSandboxes(t, c, lists, 8, func(m map[string][2][]*microvm.Sandbox) bool {
		for _, b := range m {
			if len(b[0]) > 0 && len(b[1]) > 0 {
				return true
			}
		}
		return false
	})
	for node, b := range byNode {
		if len(b[0]) > 0 && len(b[1]) > 0 {
			t.Logf("neighbours on %q: %s (example.com) and %s (pypi.org)", node, b[0][0].ID, b[1][0].ID)
			assertOwnList(t, b[0][0], "example.com", "pypi.org")
			assertOwnList(t, b[1][0], "pypi.org", "example.com")
			return
		}
	}
	t.Fatalf("no node got sandboxes of both lists in 8 creates: %v", fmt.Sprint(byNode))
}

// UC-216 — every worker runs its own egress gateway: sandboxes on two
// different workers are each filtered by their node, and a policy change
// sent through the API reaches the sandbox on whichever node owns it.
func TestEgressEachWorkerFiltersItsOwnSandboxes(t *testing.T) {
	harness.Require(t, sc, "UC-216")
	c := client(t)
	lists := [2][]string{{"example.com"}, {"example.com"}}
	byNode := placedSandboxes(t, c, lists, 8, func(m map[string][2][]*microvm.Sandbox) bool { return len(m) >= 2 })
	if len(byNode) < 2 {
		t.Fatalf("8 creates all landed on one node: %v", fmt.Sprint(byNode))
	}
	n := 0
	for node, b := range byNode {
		if n == 2 {
			break
		}
		sb := append(b[0], b[1]...)[0]
		t.Logf("checking %s on %s", sb.ID, node)
		assertOwnList(t, sb, "example.com", "pypi.org")
		pol := setPolicy(t, sb, sdktypes.NetworkPolicyOptions{NetworkAllowOut: []string{"pypi.org"}})
		if pol.EgressStatus != "active" {
			t.Fatalf("egress_status on %s after the change = %q, want active", node, pol.EgressStatus)
		}
		assertOwnList(t, sb, "pypi.org", "example.com")
		n++
	}
}
