package safety

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// sandboxd-backup.sh, sandboxd-restore.sh and raft-lost-quorum-recover.sh
// are thin wrappers over `sandboxd backup`, `restore` and `recover-quorum`
// (plans/kubectl-style-cluster-ops.md Phase 5); the archive and key rules
// they used to carry are tested in internal/nodeops. What stays here is the
// wrapper's own job: hand every argument to the installed sandboxd, and
// never run a sandboxd too old to have the command, which would read the
// command as no argument and boot a second daemon on the live state
// directory.
func TestOpsWrappersHandOffToSandboxd(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	for script, cmd := range map[string]string{
		"sandboxd-backup.sh":          "backup",
		"sandboxd-restore.sh":         "restore",
		"raft-lost-quorum-recover.sh": "recover-quorum",
	} {
		t.Run(script, func(t *testing.T) {
			path := filepath.Join(repoRoot(t), "scripts", script)
			dir := t.TempDir()
			ran := filepath.Join(dir, "ran")
			fake := func(name, marker string) string {
				p := filepath.Join(dir, name)
				body := "#!/usr/bin/env bash\n# " + marker + "\nprintf '%s\\n' \"$@\" > " + ran + "\n"
				if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
					t.Fatal(err)
				}
				return p
			}
			run := func(bin string, args ...string) (string, error) {
				c := exec.Command("bash", append([]string{path}, args...)...)
				c.Env = append(os.Environ(), "SANDBOXD_BIN="+bin)
				out, err := c.CombinedOutput()
				return string(out), err
			}

			current := fake("sandboxd", "usage: sandboxd "+cmd+" --flags")
			args := []string{"--output", "/tmp/a b.tgz", "--force", "--node-id", "x"}
			if out, err := run(current, args...); err != nil {
				t.Fatalf("%s: %v\n%s", script, err, out)
			}
			got, err := os.ReadFile(ran)
			if err != nil {
				t.Fatal(err)
			}
			if want := cmd + "\n" + strings.Join(args, "\n") + "\n"; string(got) != want {
				t.Fatalf("sandboxd got %q, want %q", got, want)
			}

			if err := os.Remove(ran); err != nil {
				t.Fatal(err)
			}
			old := fake("sandboxd-old", "an old sandboxd")
			out, err := run(old, "--output", "x")
			if err == nil || !strings.Contains(out, "too old") {
				t.Fatalf("an old sandboxd: err %v\n%s", err, out)
			}
			if _, err := os.Stat(ran); !os.IsNotExist(err) {
				t.Fatal("the wrapper ran a sandboxd without the command: it would boot a second daemon")
			}
			if out, err := run(filepath.Join(dir, "missing")); err == nil || !strings.Contains(out, "too old") {
				t.Fatalf("no sandboxd: err %v\n%s", err, out)
			}
		})
	}
}
