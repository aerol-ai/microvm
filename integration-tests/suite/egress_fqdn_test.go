//go:build integration

package suite

// Egress domain filtering use cases (plans/egress-domain-filtering.md P1-10).
// Every probe runs busybox tools from DefaultImage (alpine) inside the sandbox
// and echoes its own exit code, so a refusal and a transport error stay
// distinguishable, the same convention as tcpProbe (UC-98).

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// egressExec runs cmd in the sandbox and returns stdout, failing the test on a
// transport error.
func egressExec(t *testing.T, sb *microvm.Sandbox, cmd string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	res, err := sb.ExecCommand(ctx, cmd)
	if err != nil {
		t.Fatalf("exec %q: %v", cmd, err)
	}
	return res.Stdout
}

// timedRC runs cmd and reports its exit code and wall time in seconds,
// measured inside the sandbox so API latency doesn't count.
func timedRC(t *testing.T, sb *microvm.Sandbox, cmd string) (rc int, secs int) {
	t.Helper()
	out := egressExec(t, sb, fmt.Sprintf("s=$(date +%%s); %s >/dev/null 2>&1; r=$?; e=$(date +%%s); echo rc=$r secs=$((e-s))", cmd))
	for _, f := range strings.Fields(out) {
		if v, ok := strings.CutPrefix(f, "rc="); ok {
			rc, _ = strconv.Atoi(v)
		}
		if v, ok := strings.CutPrefix(f, "secs="); ok {
			secs, _ = strconv.Atoi(v)
		}
	}
	return rc, secs
}

func newEgressSandbox(t *testing.T, c *harness.Client, allow, deny []string) *microvm.Sandbox {
	t.Helper()
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Name:            harness.UniqueName(sc, t),
		NetworkAllowOut: allow,
		NetworkDenyOut:  deny,
	})
	waitRunning(t, sb)
	return sb
}

// UC-179 (EGR-01) — a CIDR allowlist: the listed range answers, anything
// else is dropped.
func TestEgressAllowCIDR(t *testing.T) {
	harness.Require(t, sc, "UC-179")
	c := client(t)
	sb := newEgressSandbox(t, c, []string{"1.1.1.0/24"}, nil)
	if !tcpProbe(t, sb, "1.1.1.1", 443) {
		t.Fatal("the allowed CIDR must be reachable")
	}
	if tcpProbe(t, sb, "8.8.8.8", 53) {
		t.Fatal("a destination outside the allowlist must be dropped")
	}
}

// UC-180 — hostname allowlist end to end through the egress gateway.
func TestEgressHostnameAllowlist(t *testing.T) {
	harness.Require(t, sc, "UC-180")
	c := client(t)
	sb := newEgressSandbox(t, c, []string{"pypi.org", "*.pythonhosted.org"}, nil)

	if rc, _ := timedRC(t, sb, "wget -q -T 20 -O /dev/null https://pypi.org/simple/requests/"); rc != 0 {
		t.Fatalf("an allowed name must be fetchable over HTTPS (rc=%d)", rc)
	}
	// A refusal is fast and explicit: the TLS alert ends the handshake, so
	// the 20s timeout must not be what stops it.
	rc, secs := timedRC(t, sb, "wget -q -T 20 -O /dev/null https://example.com/")
	if rc == 0 || secs >= 10 {
		t.Fatalf("a name outside the list must be refused fast (rc=%d after %ds)", rc, secs)
	}
	if out := egressExec(t, sb, "nslookup example.com 2>&1; true"); !strings.Contains(out, "NXDOMAIN") && !strings.Contains(out, "can't find") {
		t.Fatalf("DNS for a name outside the list must be NXDOMAIN:\n%s", out)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	got, err := c.SDK().Get(ctx, sb.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.EgressStatus != "active" {
		t.Fatalf("egress_status = %q, want active", got.EgressStatus)
	}
}

// UC-181 (EF-47, EF-56) — a denied plain-HTTP host is told why, and the
// denial lands in the sandbox's audit log.
func TestEgressExplainableDenials(t *testing.T) {
	harness.Require(t, sc, "UC-181")
	c := client(t)
	sb := newEgressSandbox(t, c, []string{"pypi.org"}, nil)

	// Any IP on port 80 lands on the gateway's proxy; the Host decides.
	out := egressExec(t, sb, `printf 'GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n' | nc -w 10 1.1.1.1 80; true`)
	if !strings.Contains(out, "403") || !strings.Contains(out, "aerolvm egress policy: host example.com not allowed") {
		t.Fatalf("the 403 must name the host and rule:\n%s", out)
	}
	_, _ = timedRC(t, sb, "nslookup evil.example")

	// Audit events are written asynchronously from the gateway's stream.
	deadline := time.Now().Add(45 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		page, err := sb.Audit(ctx, sdktypes.AuditOptions{Kind: "egress", Limit: 200})
		cancel()
		if err == nil {
			reasons := map[string]bool{}
			for _, e := range page.Events {
				if e.Result == "failure" {
					reasons[e.Reason] = true
				}
			}
			if reasons["host_not_allowed"] && reasons["dns_not_allowed"] {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("audit is missing the denials; failure reasons seen: %v", reasons)
			}
		} else if time.Now().After(deadline) {
			t.Fatalf("audit read: %v", err)
		}
		time.Sleep(3 * time.Second)
	}
}

// UC-182 — port semantics and wildcards: github.com:22 opens 22 only; a
// *. entry covers subdomains.
func TestEgressHostPortAndWildcard(t *testing.T) {
	harness.Require(t, sc, "UC-182")
	c := client(t)
	sb := newEgressSandbox(t, c, []string{"github.com:22", "*.githubusercontent.com"}, nil)
	if out := egressExec(t, sb, "nc -z -w 10 github.com 22; echo probe_rc=$?"); !strings.Contains(out, "probe_rc=0") {
		t.Fatalf("github.com:22 must open port 22:\n%s", out)
	}
	if rc, _ := timedRC(t, sb, "wget -q -T 15 -O /dev/null https://github.com/"); rc == 0 {
		t.Fatal("a port-only entry must not open the web ports")
	}
	if rc, _ := timedRC(t, sb, "wget -q -T 20 -O /dev/null https://raw.githubusercontent.com/github/gitignore/main/Go.gitignore"); rc != 0 {
		t.Fatalf("a subdomain must match the wildcard (rc=%d)", rc)
	}
}

// UC-183 (EF-51, P0-2) — CAP_NET_RAW (bit 13) is absent from every container
// sandbox's effective set, so it can't forge packets.
func TestSandboxHasNoNetRaw(t *testing.T) {
	harness.Require(t, sc, "UC-183")
	c := client(t)
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t)})
	waitRunning(t, sb)
	out := egressExec(t, sb, "grep CapEff /proc/self/status")
	fields := strings.Fields(out)
	if len(fields) < 2 {
		t.Fatalf("CapEff not found:\n%s", out)
	}
	caps, err := strconv.ParseUint(fields[1], 16, 64)
	if err != nil {
		t.Fatalf("parse %q: %v", fields[1], err)
	}
	if caps&(1<<13) != 0 {
		t.Fatalf("CAP_NET_RAW is in the effective set (CapEff=%s)", fields[1])
	}
}

// UC-184 (P0-5) — a block-all sandbox can't open a connection to sandboxd's
// API through its bridge gateway; the host stays reachable for the toolbox
// (this exec proves it).
func TestBlockAllGuardsHostServices(t *testing.T) {
	harness.Require(t, sc, "UC-184")
	c := client(t)
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t), NetworkBlockAll: true})
	waitRunning(t, sb)
	out := egressExec(t, sb, "gw=$(ip route | awk '/default/ {print $3}'); nc -z -w 4 $gw 21212; echo probe_rc=$?")
	if strings.Contains(out, "probe_rc=0") {
		t.Fatalf("a block-all sandbox reached the host API:\n%s", out)
	}
}

// UC-185 (EF-78) — gateway-mode creates carry the svc_egress_* stages and
// stay inside the §8.2 budgets: join (what the create actually waited for
// the gateway) ≤2 ms p50, attach ≤10 ms p99. AEROL_BENCH=1 only.
func TestBenchEgressCreateStages(t *testing.T) {
	harness.Require(t, sc, "UC-185")
	requireBenchEnabled(t)
	c := client(t)
	samples := benchEnvInt("AEROL_BENCH_SAMPLES", 20)
	joinBudget := time.Duration(benchEnvInt("AEROL_EGRESS_JOIN_P50_MS", 2)) * time.Millisecond
	attachBudget := time.Duration(benchEnvInt("AEROL_EGRESS_ATTACH_P99_MS", 10)) * time.Millisecond
	stages := map[string][]time.Duration{}
	for i := 0; i < samples+1; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		sb, err := c.SDK().Create(ctx, sdktypes.CreateSandboxOptions{
			Image:           harness.DefaultImage,
			Name:            harness.UniqueName(sc, t),
			NetworkAllowOut: []string{"pypi.org"},
		})
		cancel()
		if err != nil {
			t.Fatalf("sample %d: %v", i, err)
		}
		got, ok := c.LastServerCreateStages()
		destroyBest(c, sb.ID)
		if i == 0 || !ok {
			continue // the first create may pay the one-time gateway connect
		}
		for _, name := range []string{"svc_egress_prepare", "svc_egress_attach", "svc_egress_join"} {
			if ms, present := got[name]; present {
				stages[name] = append(stages[name], time.Duration(ms*float64(time.Millisecond)))
			}
		}
	}
	for _, name := range []string{"svc_egress_prepare", "svc_egress_attach", "svc_egress_join"} {
		if len(stages[name]) == 0 {
			t.Fatalf("no create reported %s in Server-Timing", name)
		}
	}
	join50 := percentile(stages["svc_egress_join"], 50)
	attach99 := percentile(stages["svc_egress_attach"], 99)
	t.Logf("egress stages over %d creates: prepare p50=%v attach p50=%v p99=%v join p50=%v",
		len(stages["svc_egress_join"]), percentile(stages["svc_egress_prepare"], 50),
		percentile(stages["svc_egress_attach"], 50), attach99, join50)
	if join50 > joinBudget {
		t.Errorf("svc_egress_join p50 %v over the %v budget", join50, joinBudget)
	}
	if attach99 > attachBudget {
		t.Errorf("svc_egress_attach p99 %v over the %v budget", attach99, attachBudget)
	}
}
