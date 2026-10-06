//go:build integration

package suite

// Private-cloud egress use cases (plans/egress-domain-filtering.md §5.10,
// P1-20). They run only on single-node-private-cloud, whose bootstrap builds
// node-local stand-ins for a bank network and an operator file around them:
//
//   - dnsmasq on 127.0.0.1:5353 is the gateway's upstream resolver. It
//     answers privateCloudInternalName and privateCloudRebindName with the
//     node's private address and forwards everything else to the VPC
//     resolver.
//   - An HTTP server on the node's :8081 stands in for an internal service.
//   - squid on :3128 is the upstream proxy.
//   - /etc/sandboxd/egress-policy.yaml sets internal_zone
//     (corp.itest.internal → the VPC CIDR), deny_cidrs [1.0.0.1/32],
//     node_control_port_guard true and upstream_proxy → squid.
//
// The default policy stays open there, because a non-open default or a
// ceiling would apply to every create in the scenario. Those two are covered
// by the service tests (TestOperatorDefaultPolicyIsStored,
// TestOperatorCeiling).

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

const (
	privateCloudInternalName = "svc.corp.itest.internal"
	privateCloudRebindName   = "rebind.itest.example"
	privateCloudInternalPort = "8081"
)

var syntheticRange = netip.MustParsePrefix("198.18.0.0/15")

// UC-186 (EF-82) — an allowed outside name gets a synthetic answer and is
// still fetched: only the operator's proxy could have carried it, since the
// synthetic range is never routed.
func TestPrivateCloudUpstreamProxy(t *testing.T) {
	harness.Require(t, sc, "UC-186")
	c := client(t)
	sb := newEgressSandbox(t, c, []string{"pypi.org"}, nil)
	out := egressExec(t, sb, "nslookup pypi.org 2>&1; true")
	found := false
	for _, f := range strings.Fields(out) {
		if ip, err := netip.ParseAddr(f); err == nil && syntheticRange.Contains(ip) {
			found = true
		}
	}
	if !found {
		t.Fatalf("a proxied name must get a synthetic answer from %s:\n%s", syntheticRange, out)
	}
	if rc, _ := timedRC(t, sb, "wget -q -T 30 -O /dev/null https://pypi.org/simple/requests/"); rc != 0 {
		t.Fatalf("the fetch must succeed through the upstream proxy (rc=%d)", rc)
	}
}

// UC-187 (EF-79) — the internal zone: an internal name reaches its port,
// and a name outside the zone that resolves to the same internal address is
// refused (rebinding protection).
func TestPrivateCloudInternalZone(t *testing.T) {
	harness.Require(t, sc, "UC-187")
	c := client(t)
	sb := newEgressSandbox(t, c, []string{
		privateCloudInternalName + ":" + privateCloudInternalPort,
		privateCloudRebindName + ":" + privateCloudInternalPort,
	}, nil)
	if rc, _ := timedRC(t, sb, "wget -q -T 15 -O /dev/null http://"+privateCloudInternalName+":"+privateCloudInternalPort+"/"); rc != 0 {
		t.Fatalf("an internal-zone name must reach its internal port (rc=%d)", rc)
	}
	if out := egressExec(t, sb, "nc -z -w 8 "+privateCloudRebindName+" "+privateCloudInternalPort+"; echo probe_rc=$?"); strings.Contains(out, "probe_rc=0") {
		t.Fatalf("a name outside the zone must not reach an internal address:\n%s", out)
	}
}

// UC-188 (EF-80) — the operator floor drops a deny CIDR for a sandbox that
// set no policy at all, while a neighbouring address still answers.
func TestPrivateCloudDenyFloor(t *testing.T) {
	harness.Require(t, sc, "UC-188")
	c := client(t)
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t)})
	waitRunning(t, sb)
	if tcpProbe(t, sb, "1.0.0.1", 443) {
		t.Fatal("the deny floor must drop 1.0.0.1 for every sandbox")
	}
	if !tcpProbe(t, sb, "1.1.1.1", 443) {
		t.Fatal("the floor must not drop more than its CIDRs")
	}
}

// UC-189 (EF-80) — the control-port guard: a sandbox with no policy can't
// reach the node's API port, while ingress 443 stays open.
func TestPrivateCloudControlPortGuard(t *testing.T) {
	harness.Require(t, sc, "UC-189")
	c := client(t)
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t)})
	waitRunning(t, sb)
	out := egressExec(t, sb, "gw=$(ip route | awk '/default/ {print $3}'); nc -z -w 4 $gw 21212; echo api_rc=$?; nc -z -w 4 $gw 443; echo ingress_rc=$?")
	if strings.Contains(out, "api_rc=0") {
		t.Fatalf("the guard must refuse the node's API port:\n%s", out)
	}
	if !strings.Contains(out, "ingress_rc=0") {
		t.Fatalf("ingress 443 must stay reachable:\n%s", out)
	}
}
