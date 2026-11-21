//go:build linux

package rootd

// The helper's firewall calls on the real kernel, as root in a privileged
// container: the rules netrules renders land in the kernel's ruleset, and
// a release takes every one of them away. The ruleset is read back with
// nft(8) or iptables-save(8), whichever the container has.

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc/codes"

	"github.com/aerol-ai/microvm/internal/network/cni"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// leasingRunner writes a host-local style lease (<dir>/<ip>, the holder's
// id on its first line) for each address the stand-in runner gives, as the
// real IPAM plugin does, and removes it on DEL.
type leasingRunner struct {
	cni.Runner
	dir string
	mu  sync.Mutex
	ips map[string]string // id -> ip
}

func (r *leasingRunner) Add(ctx context.Context, path, id string) (cni.Result, error) {
	res, err := r.Runner.Add(ctx, path, id)
	if err == nil {
		r.mu.Lock()
		r.ips[id] = res.IP4
		r.mu.Unlock()
		err = os.WriteFile(filepath.Join(r.dir, res.IP4), []byte(id+"\neth0"), 0o644)
	}
	return res, err
}

func (r *leasingRunner) Del(ctx context.Context, path, id string) error {
	r.mu.Lock()
	ip := r.ips[id]
	delete(r.ips, id)
	r.mu.Unlock()
	if ip != "" {
		_ = os.Remove(filepath.Join(r.dir, ip))
	}
	return r.Runner.Del(ctx, path, id)
}

// ruleset is the kernel's ruleset as text, or "" with no tool to read it.
func ruleset(t *testing.T) string {
	t.Helper()
	var out strings.Builder
	// Stateless: no packet counters, which change between two reads.
	for _, cmd := range [][]string{{"nft", "-s", "list", "ruleset"}, {"iptables-save"}} {
		if _, err := exec.LookPath(cmd[0]); err != nil {
			continue
		}
		b, err := exec.Command(cmd[0], cmd[1:]...).CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %v: %s", cmd, err, b)
		}
		out.Write(b)
	}
	return out.String()
}

// TestKernelFirewallCalls runs on each rules backend: the production one
// (netlink, SB_NETRULES_BACKEND's default) and the iptables processes.
func TestKernelFirewallCalls(t *testing.T) {
	for _, backend := range []string{"netlink", "exec"} {
		t.Run(backend, func(t *testing.T) { kernelFirewallCalls(t, backend) })
	}
}

func kernelFirewallCalls(t *testing.T, backend string) {
	k, _ := kernelRig(t)
	if os.Getenv("AEROL_KT_CNI_DIR") == "" {
		// The stand-in runner leases nothing: lease files as host-local's.
		k.leases = filepath.Join(t.TempDir(), "leases")
		if err := os.MkdirAll(k.leases, 0o755); err != nil {
			t.Fatal(err)
		}
		k.steps = k.stepsWith(&leasingRunner{Runner: k.steps.Runner, dir: k.leases, ips: map[string]string{}})
	}
	r := newRig(t, func(c *Config, o *Options) {
		c.Policy.NetnsDir = k.netnsDir
		c.Firewall.Backend = backend
		o.Network = k
	})
	c := rootdpb.NewRootHelperClient(r.conn)
	ctx := callCtx(t)
	host, err := c.EnsureHost(ctx, &rootdpb.EnsureHostRequest{})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("IPv6 fence: %q", host.GetIpv6FenceError())

	cold, err := c.PrepareSandbox(ctx, &rootdpb.PrepareSandboxRequest{NetnsName: "sb-1",
		Parts:    []string{rootdpb.PartNetns, rootdpb.PartFirewall},
		Firewall: &rootdpb.SandboxFirewall{BlockAllEgress: true, AllowCidrs: []string{"192.0.2.7"}, DenyCidrs: []string{"198.51.100.0/24"}}})
	if err != nil {
		t.Fatal(err)
	}
	ip := cold.GetContainerIp()
	if !cold.GetBlockInserted() || ip == "" {
		t.Fatalf("cold create = %v", cold)
	}
	if _, err := c.SetNodeGuard(ctx, &rootdpb.SetNodeGuardRequest{Allow: []*rootdpb.NodePort{{Proto: "tcp", Port: 15080}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SetEgressFloor(ctx, &rootdpb.SetEgressFloorRequest{Cidrs: []string{"203.0.113.0/24"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SandboxRules(ctx, &rootdpb.SandboxRulesRequest{ContainerIp: ip, Op: rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_HOLD_EGRESS}); err != nil {
		t.Fatal(err)
	}
	rs := ruleset(t)
	if rs == "" {
		t.Skip("no nft or iptables-save here to read the ruleset back")
	}
	for _, want := range []string{ip, "192.0.2.7", "198.51.100.0/24", "203.0.113.0/24", "169.254.169.254", "15080"} {
		if !strings.Contains(rs, want) {
			t.Errorf("the ruleset lacks %s", want)
		}
	}

	// Another address in the range, that nobody holds, is refused for a
	// write, and the ruleset does not change.
	before := ruleset(t)
	b4 := k.Subnet().Addr().As4()
	unheld := netip.AddrFrom4([4]byte{b4[0], b4[1], 200, 200}).String()
	_, err = c.SandboxRules(ctx, &rootdpb.SandboxRulesRequest{ContainerIp: unheld, Op: rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_BLOCK_EGRESS})
	wantRefusal(t, r, err, codes.PermissionDenied, string(rootpolicy.RuleLease))
	if ruleset(t) != before {
		t.Fatal("a refused call changed the ruleset")
	}

	// The release takes every rule of the address away, then the slot.
	if _, err := c.ReleaseSandbox(ctx, &rootdpb.ReleaseSandboxRequest{NetnsName: "sb-1", ContainerIp: ip,
		Parts: []string{rootdpb.PartNetns, rootdpb.PartFirewall}}); err != nil {
		t.Fatal(err)
	}
	rs = ruleset(t)
	for _, gone := range []string{ip + " ", ip + "/", "192.0.2.7", "198.51.100.0/24"} {
		if strings.Contains(rs, gone) {
			t.Errorf("the ruleset still holds %q after the release:\n%s", gone, rs)
		}
	}
	// The node's own rules stay.
	if !strings.Contains(rs, "203.0.113.0/24") || !strings.Contains(rs, "15080") {
		t.Error("the release took the node's rules too")
	}
	if _, err := os.Stat(filepath.Join(k.netnsDir, "sb-1")); !os.IsNotExist(err) {
		t.Fatalf("the namespace is still there: %v", err)
	}
}
