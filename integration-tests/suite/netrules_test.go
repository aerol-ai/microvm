//go:build integration

package suite

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// tcpProbe attempts a TCP connect from inside the sandbox and reports whether
// it succeeded. The rc is echoed to stdout rather than read from ExitCode so
// the exec itself always exits 0 — a DROPped connect and a transport error
// stay distinguishable. busybox nc is on every alpine image (DefaultImage);
// -w bounds the connect so a DROP rule turns into a timeout, not a hang.
func tcpProbe(t *testing.T, sb *microvm.Sandbox, ip string, port int) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := fmt.Sprintf("nc -z -w 4 %s %d; echo probe_rc=$?", ip, port)
	res, err := sb.ExecCommand(ctx, cmd)
	if err != nil {
		t.Fatalf("exec %q: %v", cmd, err)
	}
	switch {
	case strings.Contains(res.Stdout, "probe_rc=0"):
		return true
	case strings.Contains(res.Stdout, "probe_rc="):
		return false
	default:
		t.Fatalf("probe %q produced no rc marker (stdout=%q stderr=%q)", cmd, res.Stdout, res.Stderr)
		return false
	}
}

// UC-98 — an egress deny rule must actually drop traffic, not merely echo
// back in the API response. This is the only check that exercises the full
// enforcement chain (create → ApplyEgressPolicy → DOCKER-USER rule → kernel)
// under whichever SB_NETRULES_BACKEND the nodes run — the netlink backend's
// unit tests prove iptables-argv translation, not that packets stop
// (plans/warm-create-latency-tier1.md Phase 1 follow-up from PR #306).
//
// Targets are stable public anycast services the nodes already need internet
// access to reach (image pulls): 1.1.1.1:443 (Cloudflare) as the denied
// destination, 8.8.8.8:53/tcp (Google DNS) as proof the deny is targeted.
func TestEgressDenyRuleDropsTraffic(t *testing.T) {
	harness.Require(t, sc, "UC-98")
	c := client(t)

	const deniedIP = "1.1.1.1"
	const controlIP = "8.8.8.8"

	// Control sandbox, no egress rules: the denied target must be reachable
	// from this cluster at all, or a "denied" failure below proves nothing.
	control := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t)})
	waitRunning(t, control)
	if !tcpProbe(t, control, deniedIP, 443) {
		t.Fatalf("control sandbox cannot reach %s:443 — cluster egress is broken, probe cannot prove enforcement", deniedIP)
	}

	denied := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Name:           harness.UniqueName(sc, t),
		NetworkDenyOut: []string{deniedIP + "/32"},
	})
	waitRunning(t, denied)

	if tcpProbe(t, denied, deniedIP, 443) {
		t.Errorf("egress deny rule NOT enforced: sandbox with deny %s/32 reached %s:443", deniedIP, deniedIP)
	}
	// The deny must be targeted: unrelated egress from the same sandbox flows.
	if !tcpProbe(t, denied, controlIP, 53) {
		t.Errorf("deny rule over-blocks: sandbox with deny %s/32 cannot reach %s:53", deniedIP, controlIP)
	}
}
