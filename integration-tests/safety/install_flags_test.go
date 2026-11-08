package safety

import (
	"os"
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

// --with-containerd-engine is a server-node setting: only the server path
// writes SB_CONTAINER_ENGINE=containerd and installs the CNI plugins. With
// --local or --cli-only the flag used to be ignored, so a Linux --local node
// silently ran Docker. It is refused before install.sh touches the machine,
// like --with-firecracker.
func TestInstallRefusesContainerdEngineOutsideAServerInstall(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	script, err := filepath.Abs(filepath.Join("..", "..", "scripts", "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"--local", "--cli-only"} {
		t.Run(mode, func(t *testing.T) {
			cmd := exec.Command("bash", script, mode, "--with-containerd-engine")
			cmd.Dir = t.TempDir()
			cmd.Env = noInstallEnv(t)
			out, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(out), "--with-containerd-engine sets up a server node; it does not work with --cli-only or --local") {
				t.Fatalf("install.sh %s --with-containerd-engine = %v:\n%s", mode, err, out)
			}
		})
	}
}

// cloud-init runs EC2 user data without HOME. install.sh runs under set -u
// and used to read $HOME at the top, before any OS check, so a Linux install
// pasted into user data stopped with "HOME: unbound variable".
func TestInstallRunsWithoutHOME(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	script, err := filepath.Abs(filepath.Join("..", "..", "scripts", "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "HOME=") {
			env = append(env, kv)
		}
	}
	cmd := exec.Command("bash", script, "--help")
	cmd.Dir = t.TempDir()
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil || strings.Contains(string(out), "unbound variable") || !strings.Contains(string(out), "--with-containerd-engine") {
		t.Fatalf("install.sh --help without HOME = %v:\n%s", err, out)
	}
}

// noInstallEnv is an environment in which install.sh cannot change the
// machine running the test: HOME is a temp dir and every tool an install step
// reaches for (downloads, launchd, systemd, apt, sudo, docker) fails at once.
// A test that expects a refusal then fails harmlessly if the guard is gone:
// on macOS, --local and --cli-only install for the current user without sudo,
// so a real run would add a LaunchAgent and binaries under HOME.
func noInstallEnv(t *testing.T) []string {
	t.Helper()
	stubs := t.TempDir()
	for _, tool := range []string{"curl", "wget", "launchctl", "systemctl", "apt-get", "sudo", "docker", "brew", "go", "tar", "unzip"} {
		if err := os.WriteFile(filepath.Join(stubs, tool), []byte("#!/bin/sh\necho \"noInstallEnv: $0 blocked\" >&2\nexit 97\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	env := []string{"HOME=" + t.TempDir(), "PATH=" + stubs + string(os.PathListSeparator) + os.Getenv("PATH")}
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "HOME=") && !strings.HasPrefix(kv, "PATH=") {
			env = append(env, kv)
		}
	}
	return env
}
