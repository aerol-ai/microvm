package harness

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// SSHUser returns the OS login used for host-side integration SSH.
// Matches run.sh / common.sh (ubuntu@…).
func SSHUser() string {
	if u := strings.TrimSpace(os.Getenv("AEROL_SSH_USER")); u != "" {
		return u
	}
	return "ubuntu"
}

// SSHTarget builds user@host for a provisioned node. Prefers PublicIP.
func SSHTarget(n IntegrationNode) (string, bool) {
	host := strings.TrimSpace(n.PublicIP)
	if host == "" {
		host = strings.TrimSpace(n.PrivateIP)
	}
	if host == "" {
		return "", false
	}
	return SSHUser() + "@" + host, true
}

// PickSSHNode returns a node we can SSH into from IntegrationTargets.
// Prefers the seed (local-mode tunnel / single-node), else first public IP.
func PickSSHNode(targets *IntegrationTargets) (IntegrationNode, bool) {
	if targets == nil || len(targets.Nodes) == 0 {
		return IntegrationNode{}, false
	}
	for _, n := range targets.Nodes {
		if n.Seed {
			if _, ok := SSHTarget(n); ok {
				return n, true
			}
		}
	}
	for _, n := range targets.Nodes {
		if _, ok := SSHTarget(n); ok {
			return n, true
		}
	}
	return IntegrationNode{}, false
}

func sshBaseArgs() []string {
	args := []string{
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "ConnectTimeout=10",
		"-o", "BatchMode=yes",
	}
	if key := strings.TrimSpace(os.Getenv("AEROL_SSH_IDENTITY_FILE")); key != "" {
		args = append(args, "-i", key)
	}
	return args
}

// SSHRun runs a remote shell command via SSH. Returns combined stdout/stderr.
func SSHRun(t *testing.T, target, script string) (string, error) {
	t.Helper()
	args := append(sshBaseArgs(), target, script)
	cmd := exec.Command("ssh", args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

// RestartSystemdUnitOnAll restarts unit on every SSH-reachable node.
func RestartSystemdUnitOnAll(t *testing.T, targets *IntegrationTargets, unit string) {
	t.Helper()
	if targets == nil {
		t.Fatal("nil integration targets")
	}
	n := 0
	for _, node := range targets.Nodes {
		if _, ok := SSHTarget(node); !ok {
			continue
		}
		RestartSystemdUnit(t, node, unit)
		n++
	}
	if n == 0 {
		t.Fatal("no SSH-reachable nodes to restart " + unit)
	}
}

// RestartSystemdUnit restarts a unit on the node and waits until it is active.
func RestartSystemdUnit(t *testing.T, node IntegrationNode, unit string) {
	t.Helper()
	target, ok := SSHTarget(node)
	if !ok {
		t.Fatalf("node %s has no SSH address", node.Name)
	}
	script := fmt.Sprintf("sudo systemctl restart %s && sudo systemctl is-active %s", unit, unit)
	out, err := SSHRun(t, target, script)
	if err != nil {
		t.Fatalf("restart %s on %s: %v\n%s", unit, target, err, out)
	}
	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		out, err = SSHRun(t, target, "sudo systemctl is-active "+unit)
		if err == nil && strings.TrimSpace(out) == "active" {
			return
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("%s on %s did not become active after restart (last=%q)", unit, target, strings.TrimSpace(out))
}

// HostHasAEROLVMUserJump reports whether filter FORWARD jumps to AEROLVM-USER.
// Works for both iptables-nft and legacy (iptables -S).
func HostHasAEROLVMUserJump(t *testing.T, node IntegrationNode) bool {
	t.Helper()
	target, ok := SSHTarget(node)
	if !ok {
		t.Fatalf("node %s has no SSH address", node.Name)
	}
	out, err := SSHRun(t, target, "sudo iptables -S FORWARD 2>/dev/null || true; sudo iptables-legacy -S FORWARD 2>/dev/null || true")
	if err != nil {
		t.Logf("iptables probe on %s: %v (%s)", target, err, out)
		return false
	}
	return strings.Contains(out, "AEROLVM-USER")
}
