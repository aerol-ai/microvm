package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestKubectlPluginName: called as kubectl-aerolvm (how `kubectl aerolvm`
// runs a Krew plugin), the binary behaves exactly as aerolvm: the same
// stdout, stderr and exit code for a verb, a usage error and the overview.
func TestKubectlPluginName(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the binary")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "aerolvm")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	plugin := filepath.Join(dir, "kubectl-aerolvm")
	if err := os.Symlink(bin, plugin); err != nil {
		t.Fatal(err)
	}
	copied := filepath.Join(dir, "copy", "kubectl-aerolvm")
	raw, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(copied), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(copied, raw, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"version"}, {"api-resources", "-o", "wide"}, {"get"}, {"--help"}, {"no-such-verb"}, {"get", "sb", "--json"}} {
		want := runBinary(t, bin, args...)
		for _, name := range []string{plugin, copied} {
			if got := runBinary(t, name, args...); got != want {
				t.Fatalf("%s %v:\n%s\nwant (as aerolvm):\n%s", filepath.Base(name), args, got, want)
			}
		}
	}
}

// runBinary runs a built aerolvm with no login and a dead API URL, and
// returns its transcript.
func runBinary(t *testing.T, bin string, args ...string) string {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = []string{"XDG_CONFIG_HOME=" + t.TempDir(), "SB_API_URL=http://127.0.0.1:1", "SB_PAT_TOKEN=x", "HOME=" + t.TempDir()}
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	code := 0
	if err := cmd.Run(); err != nil {
		exit, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("run %s: %v", bin, err)
		}
		code = exit.ExitCode()
	}
	return fmt.Sprintf("exit %d\n--- stdout\n%s--- stderr\n%s", code, stdout.String(), stderr.String())
}
