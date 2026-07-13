//go:build integration && linux

package suite

import (
	"context"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// TestSecuritySpecDiff is the permanent cross-engine security parity contract
// (plans/containerd-engine.md Phase 1 / §8). It creates a minimal sandbox via
// the daemon's configured engine and compares CapEff / NoNewPrivs / Seccomp /
// masked-path presence against a dockerd `docker run` baseline on the same
// host. containerd must not be strictly weaker than dockerd.
//
// Operator-run (needs Docker CLI + a live sandboxd). Example:
//
//	AEROL_SECURITY_SPEC_DIFF=1 go test -tags=integration \
//	  -run TestSecuritySpecDiff ./integration-tests/suite/...
func TestSecuritySpecDiff(t *testing.T) {
	if os.Getenv("AEROL_SECURITY_SPEC_DIFF") != "1" {
		t.Skip("set AEROL_SECURITY_SPEC_DIFF=1 to run cross-engine security spec-diff")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker CLI required for dockerd baseline probe")
	}
	// Env-gated operator probe — not a registered UC (no capability gate).
	// Requires a live sandboxd (AEROL_BASE_URL + PAT) like the rest of suite.
	dockerProbe := probeDockerSecurity(t)
	sandboxProbe := probeSandboxSecurity(t)

	if sandboxProbe.NoNewPrivs < dockerProbe.NoNewPrivs {
		t.Fatalf("NoNewPrivs weaker than docker: sandbox=%d docker=%d", sandboxProbe.NoNewPrivs, dockerProbe.NoNewPrivs)
	}
	if sandboxProbe.Seccomp == 0 && dockerProbe.Seccomp != 0 {
		t.Fatalf("Seccomp disabled on sandbox but enabled on docker baseline (docker=%d)", dockerProbe.Seccomp)
	}
	// CapEff: sandbox must not gain capabilities docker dropped. Compare as
	// sets — any bit set in sandbox but clear in docker is a regression.
	if sandboxProbe.CapEff&^dockerProbe.CapEff != 0 {
		t.Fatalf("CapEff has extra bits vs docker: sandbox=%#x docker=%#x extra=%#x",
			sandboxProbe.CapEff, dockerProbe.CapEff, sandboxProbe.CapEff&^dockerProbe.CapEff)
	}
	for _, path := range []string{"/proc/kcore", "/sys/firmware"} {
		if dockerProbe.Masked[path] && !sandboxProbe.Masked[path] {
			t.Fatalf("masked path %s present on docker baseline but missing in sandbox", path)
		}
	}
}

type securityProbe struct {
	CapEff     uint64
	NoNewPrivs int
	Seccomp    int
	Masked     map[string]bool
}

const securityProbeScript = `set -e
grep -E '^(CapEff|NoNewPrivs|Seccomp):' /proc/self/status
for p in /proc/kcore /sys/firmware; do
  if [ -e "$p" ]; then echo "MASKED_MISS $p"; else echo "MASKED_OK $p"; fi
done
`

func probeDockerSecurity(t *testing.T) securityProbe {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "run", "--rm", "alpine:3.20", "sh", "-c", securityProbeScript)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("docker run probe: %v\n%s", err, out)
	}
	return parseSecurityProbe(t, string(out))
}

func probeSandboxSecurity(t *testing.T) securityProbe {
	t.Helper()
	c := client(t)
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Name:  harness.UniqueName(sc, t),
		Image: "alpine:3.20",
	})
	waitRunning(t, sb)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	res, err := sb.ExecCommand(ctx, "sh -c "+strconv.Quote(securityProbeScript))
	if err != nil {
		t.Fatalf("sandbox exec probe: %v", err)
	}
	body := res.Stdout
	if body == "" {
		body = res.Stderr
	}
	return parseSecurityProbe(t, body)
}

var (
	reCapEff     = regexp.MustCompile(`(?m)^CapEff:\s*([0-9a-fA-F]+)`)
	reNoNewPrivs = regexp.MustCompile(`(?m)^NoNewPrivs:\s*(\d+)`)
	reSeccomp    = regexp.MustCompile(`(?m)^Seccomp:\s*(\d+)`)
)

func parseSecurityProbe(t *testing.T, body string) securityProbe {
	t.Helper()
	p := securityProbe{Masked: map[string]bool{}}
	if m := reCapEff.FindStringSubmatch(body); len(m) == 2 {
		v, err := strconv.ParseUint(m[1], 16, 64)
		if err != nil {
			t.Fatalf("CapEff %q: %v", m[1], err)
		}
		p.CapEff = v
	} else {
		t.Fatalf("CapEff missing in probe output:\n%s", body)
	}
	if m := reNoNewPrivs.FindStringSubmatch(body); len(m) == 2 {
		v, _ := strconv.Atoi(m[1])
		p.NoNewPrivs = v
	} else {
		t.Fatalf("NoNewPrivs missing in probe output:\n%s", body)
	}
	if m := reSeccomp.FindStringSubmatch(body); len(m) == 2 {
		v, _ := strconv.Atoi(m[1])
		p.Seccomp = v
	} else {
		t.Fatalf("Seccomp missing in probe output:\n%s", body)
	}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "MASKED_OK ") {
			p.Masked[strings.TrimPrefix(line, "MASKED_OK ")] = true
		}
		if strings.HasPrefix(line, "MASKED_MISS ") {
			p.Masked[strings.TrimPrefix(line, "MASKED_MISS ")] = false
		}
	}
	return p
}
