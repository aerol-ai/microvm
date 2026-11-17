// Offline tests for the local kind drills (k8s/drills-local.sh, issue
// #1343): they run the script with kubectl, kind, curl and docker stubbed,
// so nothing touches a cluster.
//
// Runs in the normal `go test ./...` / `make test` flow (no build tag).
package safety

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// drillStubs puts logging stand-ins for kubectl, kind, curl and docker on
// PATH and returns the environment and the log they write. kind lists one
// cluster, aerolvm-drills.
func drillStubs(t *testing.T) ([]string, string) {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "calls.log")
	for name, body := range map[string]string{
		"kubectl": `echo "kubectl $*" >> "$STUB_LOG"`,
		"curl":    `echo "curl $*" >> "$STUB_LOG"`,
		"docker":  `echo "docker $*" >> "$STUB_LOG"`,
		"kind":    `echo "kind $*" >> "$STUB_LOG"; [ "$1 $2" = "get clusters" ] && echo aerolvm-drills; exit 0`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	env := append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"), "STUB_LOG="+log)
	return env, log
}

func readLog(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return string(b)
}

// Every step deletes pods, fills workers or breaks a gateway: the script
// refuses any kubectl context but a local kind cluster's, before it calls
// kubectl or docker, whatever step was asked for (PR 3 review).
func TestDrillsLocalRefusesNonKindContexts(t *testing.T) {
	script := filepath.Join(integrationDir(t), "k8s", "drills-local.sh")
	for _, ctx := range []string{"arn:aws:eks:eu-west-1:111122223333:cluster/bank-prod", "prod", "kind-not-a-local-cluster"} {
		env, log := drillStubs(t)
		cmd := exec.Command("bash", script, t.TempDir(), "teardown")
		cmd.Env = append(env, "KUBECTL_CONTEXT="+ctx)
		out, err := cmd.CombinedOutput()
		if code := cmd.ProcessState.ExitCode(); err == nil || code != 2 || !strings.Contains(string(out), "refusing to run") {
			t.Errorf("context %q: exit %d, %s", ctx, code, out)
		}
		if calls := readLog(t, log); strings.Contains(calls, "kubectl") || strings.Contains(calls, "docker") {
			t.Errorf("context %q: the script ran commands before refusing:\n%s", ctx, calls)
		}
	}
	env, log := drillStubs(t)
	cmd := exec.Command("bash", script, t.TempDir(), "teardown")
	cmd.Env = append(env, "KUBECTL_CONTEXT=kind-aerolvm-drills")
	if out, err := cmd.CombinedOutput(); err != nil || !strings.Contains(readLog(t, log), "docker rm") {
		t.Fatalf("a local kind cluster is refused: %v %s\n%s", err, out, readLog(t, log))
	}
}

// A step that dies midway leaves the registry faulty, callers running and
// a gateway's Caddy admin API off its port. The EXIT trap puts all three
// back, best effort (PR 3 review).
func TestDrillsLocalExitPutsBackWhatAStepBroke(t *testing.T) {
	script := filepath.Join(integrationDir(t), "k8s", "drills-local.sh")
	env, log := drillStubs(t)
	// Sourced with a state dir and no step: the functions and the trap
	// exist, nothing runs. Then play a slo-breach step that dies.
	cmd := exec.Command("bash", "-c", `source "$0" "$1"; faults_set=1; storms=(hot-1 cold-1); caddy_moved_on=aerolvm-gateway-x; exit 3`,
		script, t.TempDir())
	cmd.Env = append(env, "KUBECTL_CONTEXT=kind-aerolvm-drills")
	if out, err := cmd.CombinedOutput(); cmd.ProcessState.ExitCode() != 3 {
		t.Fatalf("exit %d (%v): %s", cmd.ProcessState.ExitCode(), err, out)
	}
	calls := readLog(t, log)
	for _, want := range []string{
		"/mode/clear",
		"exec drills-client -- sh -c kill $(cat /work/hot-1.pid)",
		"exec drills-client -- sh -c kill $(cat /work/cold-1.pid)",
		"port-forward pod/aerolvm-gateway-x 12019:2020",
		`/config/admin/listen`,
		`"localhost:2019"`,
	} {
		if !strings.Contains(calls, want) {
			t.Errorf("the exit trap did not run %q; calls:\n%s", want, calls)
		}
	}

	// A step that ended cleanly leaves nothing to put back.
	env, log = drillStubs(t)
	cmd = exec.Command("bash", "-c", `source "$0" "$1"; exit 0`, script, t.TempDir())
	cmd.Env = append(env, "KUBECTL_CONTEXT=kind-aerolvm-drills")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if calls := readLog(t, log); strings.Contains(calls, "curl") || strings.Contains(calls, "kubectl") {
		t.Errorf("a clean exit still put things back:\n%s", calls)
	}
}

// The admin token and the scrape token the drills keep on disk are written
// readable by this user only.
func TestDrillsLocalTokensWrittenPrivately(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(integrationDir(t), "k8s", "drills-local.sh"))
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.Contains(line, `> "$sd/token"`) || strings.Contains(line, `> "$sd/scrape-token"`) {
			found++
			if !strings.Contains(line, "umask 077") {
				t.Errorf("a token file is written without umask 077: %s", strings.TrimSpace(line))
			}
		}
	}
	if found != 2 {
		t.Fatalf("found %d token writes, want 2 (the admin token, the scrape token)", found)
	}
}
