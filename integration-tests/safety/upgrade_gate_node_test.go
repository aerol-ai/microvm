package safety

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/nodeupgrade"
)

// upgrade-gate.sh --upgrade-node judges `sandboxd upgrade node` from what
// its upgrade-node.sh heredoc prints on each node. It runs here against a
// fake node first: the upgrader is a script that prints the record the
// real command prints (marshalled from nodeupgrade.State, so a renamed
// field fails here, not on AWS), and systemctl and curl are stubbed.

func upgradeNodeScript(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "integration-tests", "upgrade-gate.sh"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?s)<<'UPGNODE'\n(.*?)\nUPGNODE\n`).FindStringSubmatch(string(raw))
	if m == nil {
		t.Fatal("upgrade-gate.sh has no <<'UPGNODE' heredoc")
	}
	return m[1]
}

func TestUpgradeGateUpgradeNodeScript(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	dir := t.TempDir()
	bin, stage := filepath.Join(dir, "bin"), filepath.Join(dir, "stage")
	for _, d := range []string{bin, stage} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	backup := filepath.Join(dir, "op.state.db")
	record := func(result string) string {
		st := nodeupgrade.State{Format: 1, Op: "op-1", Version: "itest-abc", Phase: nodeupgrade.PhaseDone, Result: result,
			BackupPath: backup, Files: []nodeupgrade.FileState{{Role: "sandboxd", SHA256: "x", Changed: true}}}
		b, err := json.MarshalIndent(st, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	write := func(path, content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(stage, "checksums.txt"), "aaa  sandboxd_linux_amd64\nbbb  toolboxd_linux_amd64\n")
	write(filepath.Join(bin, "sandboxd"), "old sandboxd\n")
	write(filepath.Join(bin, "toolboxd"), "old toolboxd\n")
	write(filepath.Join(dir, "upgraded.json"), record(nodeupgrade.ResultUpgraded))
	write(filepath.Join(dir, "noop.json"), record(nodeupgrade.ResultNoop))
	// The fake upgrader: installs itself the first time, a noop after; the
	// installed one rolls back. Its arguments go to args.log.
	upgrader := "#!/usr/bin/env bash\necho \"$*\" >> " + dir + "/args.log\n" +
		"if [[ \"$*\" == *--rollback* ]]; then cp " + bin + "/sandboxd.prev " + bin + "/sandboxd; cp " + bin + "/toolboxd.prev " + bin + "/toolboxd; echo old > " + dir + "/running; cat " + dir + "/upgraded.json; exit 0; fi\n" +
		"if cmp -s \"$0\" " + bin + "/sandboxd; then cat " + dir + "/noop.json; exit 0; fi\n" +
		"cp " + bin + "/sandboxd " + bin + "/sandboxd.prev; cp " + bin + "/toolboxd " + bin + "/toolboxd.prev\n" +
		"cp \"$0\" " + bin + "/sandboxd; echo new > " + bin + "/toolboxd\n" +
		"echo db > " + backup + "\necho 'backed up /var/lib/sandboxd/state.db to x in 12ms' >&2\n" +
		"echo itest-abc > " + dir + "/running; echo $((RANDOM + 1)) > " + dir + "/pid\n" +
		"cat " + dir + "/upgraded.json\n"
	write(filepath.Join(stage, "sandboxd_linux_amd64"), upgrader)
	write(filepath.Join(dir, "pid"), "100\n")
	write(filepath.Join(dir, "running"), "v0.6.11\n")

	script := strings.ReplaceAll(upgradeNodeScript(t), "/usr/local/bin", bin)
	stubs := "systemctl() { cat " + dir + "/pid; }\n" +
		"curl() { printf '{\"status\":\"ok\",\"version\":\"%s\"}' \"$(cat " + dir + "/running)\"; }\n" +
		"sha256sum() { if command -v shasum >/dev/null; then shasum -a 256 \"$@\"; else command sha256sum \"$@\"; fi; }\n"
	script = strings.Replace(script, "set -u\n", "set -u\n"+stubs, 1)
	run := func(phase string) map[string]string {
		t.Helper()
		out, err := exec.Command("bash", "-c", script, "upgrade-node.sh", phase, stage, "itest-abc", "v0.6.11").CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v\n%s", phase, err, out)
		}
		got := map[string]string{}
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			k, v, _ := strings.Cut(line, "=")
			got[k] = v
		}
		return got
	}

	before := run("before")
	if before["running"] != "v0.6.11" || before["sha_sandboxd"] == "" {
		t.Fatalf("before = %v", before)
	}
	up := run("upgrade")
	for k, want := range map[string]string{
		"exit": "0", "result": "upgraded", "backup": backup, "backup_exists": "yes", "backup_took": "12ms", "backup_bytes": "3",
		"prev_sandboxd": "yes", "prev_toolboxd": "yes", "new_sandboxd": "yes", "pid_changed": "yes", "running": "itest-abc",
	} {
		if up[k] != want {
			t.Errorf("upgrade %s = %q, want %q", k, up[k], want)
		}
	}
	again := run("again")
	if again["exit"] != "0" || again["result"] != "noop" || again["pid_same"] != "yes" {
		t.Errorf("again = %v", again)
	}
	rb := run("rollback")
	if rb["exit"] != "0" || rb["result"] != "upgraded" || rb["sha_sandboxd"] != before["sha_sandboxd"] || rb["sha_toolboxd"] != before["sha_toolboxd"] {
		t.Errorf("rollback = %v, before = %v", rb, before)
	}
	args, _ := os.ReadFile(filepath.Join(dir, "args.log"))
	lines := strings.Split(strings.TrimSpace(string(args)), "\n")
	wantUp := "upgrade node itest-abc --from " + stage + " --sha256 sandboxd_linux_amd64=aaa --sha256 toolboxd_linux_amd64=bbb --allow-unversioned -o json"
	if len(lines) != 3 || lines[0] != wantUp || lines[1] != wantUp || lines[2] != "upgrade node v0.6.11 --rollback -o json" {
		t.Fatalf("upgrader calls:\n%s", args)
	}
}

// run.sh passes --upgrade-node through to the gate, only with --upgrade-from.
func TestRunShPassesUpgradeNodeToTheGate(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "integration-tests", "run.sh"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	for _, want := range []string{
		"--upgrade-node) UPGRADE_NODE=1 ;;",
		`[[ "$UPGRADE_NODE" == 1 ]] && GATE_ARGS+=(--upgrade-node)`,
		`exec "${HERE}/upgrade-gate.sh" "$SCENARIO" --from "$UPGRADE_FROM" ${GATE_ARGS[@]+"${GATE_ARGS[@]}"}`,
	} {
		if !strings.Contains(src, want) {
			t.Errorf("run.sh lost %q", want)
		}
	}
	gate, err := os.ReadFile(filepath.Join(repoRoot(t), "integration-tests", "upgrade-gate.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(gate), "--upgrade-node) UPGRADE_NODE=1; shift ;;") {
		t.Error("upgrade-gate.sh does not take --upgrade-node")
	}
}
