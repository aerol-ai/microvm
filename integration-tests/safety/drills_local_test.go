// Offline tests for the local kind drills (k8s/drills-local.sh, issue
// #1343): they run the script with kubectl, kind, curl and docker stubbed,
// so nothing touches a cluster.
//
// Runs in the normal `go test ./...` / `make test` flow (no build tag).
package safety

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
		// A port-forward says it forwards (pf_start waits for that line).
		"kubectl": `echo "kubectl $*" >> "$STUB_LOG"
case " $* " in *" port-forward "*) for a in "$@"; do last="$a"; done; echo "Forwarding from 127.0.0.1:${last%%:*} -> ${last#*:}" ;; esac`,
		"curl":   `echo "curl $*" >> "$STUB_LOG"`,
		"docker": `echo "docker $*" >> "$STUB_LOG"`,
		"kind":   `echo "kind $*" >> "$STUB_LOG"; [ "$1 $2" = "get clusters" ] && echo aerolvm-drills; exit 0`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	env := append(cleanEnviron(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"), "STUB_LOG="+log)
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

// The admin token, the API tokens and the scrape token the drills keep on
// disk are written readable by this user only, in every drill script.
func TestDrillsTokensWrittenPrivately(t *testing.T) {
	want := map[string]int{
		"drills-local.sh": 1, // the admin token
		"drills-lib.sh":   1, // the scrape token
		"drills-eks.sh":   2, // DRILL_TOKEN_FILE's copy, or one made for the run
		"eks-bank.sh":     2, // the run's API token (and a dry run's stand-in)
	}
	for file, n := range want {
		raw, err := os.ReadFile(filepath.Join(integrationDir(t), "k8s", file))
		if err != nil {
			t.Fatal(err)
		}
		found := 0
		for _, line := range strings.Split(string(raw), "\n") {
			if strings.Contains(line, `> "$sd/token"`) || strings.Contains(line, `> "$sd/scrape-token"`) || strings.Contains(line, `> "$sd/api-token"`) {
				found++
				if !strings.Contains(line, "umask 077") {
					t.Errorf("%s writes a token file without umask 077: %s", file, strings.TrimSpace(line))
				}
			}
		}
		if found != n {
			t.Errorf("%s: found %d token writes, want %d", file, found, n)
		}
	}
}

// Scorecard alert 1697 (Pinned-Dependencies, downloadThenRun): setup's wait
// for scraped AerolVM pods piped curl into python3, which Scorecard reads as
// a downloaded script being run. prom.py up fetches the targets itself now.
func TestDrillsPromUpCountsScrapedAerolVMTargets(t *testing.T) {
	needTools(t, "python3")
	targets := []map[string]any{
		{"labels": map[string]string{"aerolvm_component": "server"}, "health": "up"},
		{"labels": map[string]string{"aerolvm_component": "worker"}, "health": "up"},
		{"labels": map[string]string{"aerolvm_component": "worker"}, "health": "down"},
		{"labels": map[string]string{"aerolvm_component": "worker"}, "health": "unknown"},
		{"labels": map[string]string{"job": "kubelet"}, "health": "up"},
	}
	asked := make(chan string, 1)
	prom := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/targets" {
			http.NotFound(w, r)
			return
		}
		select {
		case asked <- r.URL.Query().Get("state"):
		default:
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "success",
			"data": map[string]any{"activeTargets": targets, "droppedTargets": []any{}}})
	}))
	upCmd := func() *exec.Cmd {
		return exec.Command("python3", "-I", k8sFile(t, "drills-local", "prom.py"), "--url", prom.URL, "up", "aerolvm_component")
	}
	// Only AerolVM targets whose last scrape worked count: not a down or
	// not-yet-scraped one, and not another job's.
	out, err := upCmd().CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "2" {
		t.Errorf("prom.py up: %v %q, want 2", err, out)
	}
	select {
	case st := <-asked:
		if st != "active" {
			t.Errorf("prom.py up asked for state=%q, want active", st)
		}
	default:
		t.Error("prom.py up never asked for the targets")
	}
	// A Prometheus that does not answer prints no count and fails, so
	// setup's `|| echo 0` counts 0 and keeps waiting.
	prom.Close()
	if out, err := upCmd().Output(); err == nil || len(out) != 0 {
		t.Errorf("prom.py up with Prometheus gone: %v %q, want a failure and no output", err, out)
	}

	src, err := os.ReadFile(k8sFile(t, "drills-lib.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if want := `up="$(prom up aerolvm_component 2>/dev/null || echo 0)"`; !strings.Contains(string(src), want) {
		t.Errorf("drills-lib.sh setup no longer counts scraped pods with %s", want)
	}
	// And no script here pipes a download into an interpreter.
	pipe := regexp.MustCompile(`\b(curl|wget)\b[^|\n]*\|[ \t]*(sudo[ \t]+)?(python3?|bash|sh|zsh|perl|ruby|node)\b`)
	err = filepath.WalkDir(integrationDir(t), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() == "node_modules" {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".sh") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(b), "\n") {
			if pipe.MatchString(line) {
				t.Errorf("%s:%d pipes a download into an interpreter (Scorecard Pinned-Dependencies): %s", path, i+1, strings.TrimSpace(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
