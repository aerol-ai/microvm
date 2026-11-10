package safety

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// upgrade-gate.sh judges a live upgrade from what its node-state.sh heredoc
// prints on each node. A slip in that script (a misread exit code, a
// version line cut wrong) fails or passes a paid AWS run for the wrong
// reason, so it runs here first against a fake node: /etc/sandboxd and the
// sandboxd binary moved under a temp dir, systemctl, curl, stat and pgrep
// stubbed.

func nodeStateScript(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "integration-tests", "upgrade-gate.sh"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?s)<<'NODESTATE'\n(.*?)\nNODESTATE\n`).FindStringSubmatch(string(raw))
	if m == nil {
		t.Fatal("upgrade-gate.sh has no <<'NODESTATE' heredoc")
	}
	return m[1]
}

// runNodeState runs the heredoc against a fake node and returns its
// key=value output.
func runNodeState(t *testing.T, phase, env, nodeJSON, binary string) map[string]string {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	dir := t.TempDir()
	etc := filepath.Join(dir, "etc")
	if err := os.MkdirAll(etc, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(etc, "sandboxd.env"), []byte(env), 0o600); err != nil {
		t.Fatal(err)
	}
	if nodeJSON != "" {
		if err := os.WriteFile(filepath.Join(etc, "node.json"), []byte(nodeJSON), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	bin := filepath.Join(dir, "sandboxd")
	if err := os.WriteFile(bin, []byte(binary), 0o755); err != nil {
		t.Fatal(err)
	}
	script := strings.NewReplacer("/etc/sandboxd", etc, "/usr/local/bin/sandboxd", bin).Replace(nodeStateScript(t))
	stubs := "systemctl() { echo 4242; }\n" +
		"curl() { echo '{\"status\":\"ok\",\"sandboxes\":0,\"version\":\"itest-abc\"}'; }\n" +
		"stat() { echo '600 root'; }\n" +
		"pgrep() { echo 0; return 1; }\n" +
		"timeout() { shift; \"$@\"; }\n"
	// The heredoc's first line is its shebang; the stubs go after it.
	script = strings.Replace(script, "set -u\n", "set -u\n"+stubs, 1)
	out, err := exec.Command("bash", "-c", script, "node-state.sh", phase).CombinedOutput()
	if err != nil {
		t.Fatalf("node-state.sh %s: %v\n%s", phase, err, out)
	}
	got := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		k, v, _ := strings.Cut(line, "=")
		got[k] = v
	}
	return got
}

func TestUpgradeGateNodeStateBeforeTheUpgrade(t *testing.T) {
	// The old release's binary must never be run: it would boot a daemon.
	got := runNodeState(t, "before", "SB_PAT_TOKEN=abc=def\nSB_DOMAIN=sb.example.com\nSB_NODE_NAME=n1\n", "",
		"#!/bin/sh\necho BOOTED A SECOND DAEMON\n")
	for k, want := range map[string]string{
		"pat": "abc=def", "env_SB_DOMAIN": "sb.example.com", "env_SB_NODE_NAME": "n1", "env_SB_PAT_SCOPE": "",
		"main_pid": "4242", "running_version": "itest-abc", "node_json": "absent",
	} {
		if got[k] != want {
			t.Errorf("%s = %q, want %q", k, got[k], want)
		}
	}
	if _, ran := got["version_line"]; ran {
		t.Fatalf("the before phase ran sandboxd --version: %v", got)
	}
}

func TestUpgradeGateNodeStateAfterTheUpgrade(t *testing.T) {
	nodeJSON := "{\n  \"format\": 1,\n  \"domain\": \"sb.example.com\"\n}\n"
	got := runNodeState(t, "after", "SB_PAT_TOKEN=tok\n", nodeJSON,
		"#!/bin/sh\nprintf 'sandboxd itest-abc\\ncommit:          deadbeef\\n'\n")
	for k, want := range map[string]string{
		"node_json": "600 root", "node_json_format": "1", "node_json_has_pat": "0",
		"version_exit": "0", "version_line": "sandboxd itest-abc", "main_pid_after_version": "4242", "stray_version_procs": "0",
	} {
		if got[k] != want {
			t.Errorf("%s = %q, want %q", k, got[k], want)
		}
	}

	// A PAT in node.json and a binary that fails are both reported.
	got = runNodeState(t, "after", "SB_PAT_TOKEN=tok\n", "{\n  \"format\": 1,\n  \"x\": \"tok\"\n}\n", "#!/bin/sh\necho boom >&2\nexit 3\n")
	if got["node_json_has_pat"] != "1" || got["version_exit"] != "3" || got["version_line"] != "boom" {
		t.Fatalf("a leaked PAT or a failing binary went unreported: %v", got)
	}
}

// run.sh --upgrade-from is the documented entry point; it must still reach
// the gate, and the gate must still upgrade through install.sh by default.
func TestUpgradeGateUpgradesThroughTheInstaller(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "integration-tests", "upgrade-gate.sh"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	for _, want := range []string{
		"SWAP_BINARY=0\n",
		"sudo bash $STAGE/install.sh --sandboxd-url file://$STAGE/sandboxd_linux_amd64 --toolboxd-url file://$STAGE/toolboxd_linux_amd64 --checksums-url file://$STAGE/checksums.txt --caddy-binary-url '$CADDY_URL'",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("upgrade-gate.sh lost %q", want)
		}
	}
	// No node flag on the re-run: each of these would hide a setting the
	// installer failed to remember.
	re := regexp.MustCompile(`sudo bash \$STAGE/install\.sh[^\n]*`)
	line := re.FindString(src)
	for _, flag := range []string{"--pat-token", "--domain", "--node-name", "--dns-api-token", "--public-host", "--local"} {
		if strings.Contains(line, flag) {
			t.Errorf("the gate's install.sh re-run passes %s; it must pass no node flags", flag)
		}
	}
	run, err := os.ReadFile(filepath.Join(repoRoot(t), "integration-tests", "run.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(run), `exec "${HERE}/upgrade-gate.sh" "$SCENARIO" --from "$UPGRADE_FROM"`) {
		t.Error("run.sh --upgrade-from no longer hands off to upgrade-gate.sh")
	}
}
