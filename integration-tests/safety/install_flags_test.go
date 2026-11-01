package safety

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// --no-start leaves sandboxd for cluster-join.sh to start; a --local
// install never joins a cluster, so the pair is refused before install.sh
// touches the machine.
func TestInstallRefusesNoStartWithLocal(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	script, err := filepath.Abs(filepath.Join("..", "..", "scripts", "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", script, "--local", "--no-start")
	cmd.Dir = t.TempDir()
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "--no-start is for a node cluster-join.sh will start") {
		t.Fatalf("install.sh --local --no-start = %v:\n%s", err, out)
	}
}

// --lb-health-port opens a listener Caddy must be able to bind: a port this
// node already uses fails Caddy's start and takes the API down with it, and
// outside domain mode there is no caddy-l4 :443 for the probe to walk. Every
// bad value is refused before install.sh touches the machine.
func TestInstallRefusesABadLBHealthPort(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	script, err := filepath.Abs(filepath.Join("..", "..", "scripts", "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	domain := []string{"--domain", "x.example.com", "--dns-provider", "cloudflare", "--dns-api-token", "t", "--pat-token", "p"}
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"no domain", []string{"--pat-token", "p", "--lb-health-port", "21280"}, "--lb-health-port requires domain mode"},
		{"local mode", []string{"--local", "--lb-health-port", "21280"}, "--lb-health-port requires domain mode"},
		{"the API port", append(append([]string{}, domain...), "--lb-health-port", "21212"), "is already used on this node"},
		{"the HTTPS site", append(append([]string{}, domain...), "--lb-health-port", "8443"), "is already used on this node"},
		{"the SSH gateway", append(append([]string{}, domain...), "--lb-health-port", "2220"), "is already used on this node"},
		{"inside the TCP pool", append(append([]string{}, domain...), "--lb-health-port", "22500"), "inside the raw-TCP port pool"},
		{"a privileged port", append(append([]string{}, domain...), "--lb-health-port", "443"), "must be a port from 1024 to 65535"},
		{"a leading zero", append(append([]string{}, domain...), "--lb-health-port", "08443"), "must be a port from 1024 to 65535"},
		{"too high", append(append([]string{}, domain...), "--lb-health-port", "70000"), "must be a port from 1024 to 65535"},
		{"not a number", append(append([]string{}, domain...), "--lb-health-port", "health"), "must be a port from 1024 to 65535"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("bash", append([]string{script}, tc.args...)...)
			cmd.Dir = t.TempDir()
			out, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(out), tc.want) {
				t.Fatalf("install.sh %v = %v, want refusal %q:\n%s", tc.args, err, tc.want, out)
			}
		})
	}
}
