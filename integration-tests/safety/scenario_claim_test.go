package safety

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Every worktree of a clone shares one Terraform state key per scenario
// (integration/<scenario>/terraform.tfstate). Before claims, a second
// worktree that ran, kept or destroyed a scenario another worktree was live
// on applied over that stack or destroyed it. These tests run run.sh's own
// functions, or run.sh itself, in throwaway git repos with two worktrees.
// Nothing reaches AWS, Terraform, Cloudflare or DNS.

func claimFuncs(t *testing.T) string {
	t.Helper()
	src, err := os.ReadFile(runScript(t))
	if err != nil {
		t.Fatalf("read run.sh: %v", err)
	}
	var fns strings.Builder
	for _, name := range []string{
		"worktree_roots", "lease_lock_path", "lease_lock_acquire", "lease_lock_release",
		"scenario_holders", "refuse_if_scenario_held", "claim_scenario", "release_scenario_claim",
	} {
		fns.WriteString(extractShellFunc(t, string(src), name))
	}
	return fns.String()
}

func claimScript(fns, scenario string) string {
	return "set -euo pipefail\nREPO_ROOT=\"$1\"\n" + fns + "\nclaim_scenario " + scenario + "\n"
}

func claimPath(root, scenario string) string {
	return filepath.Join(root, "integration-tests", ".tf", scenario, ".state-claim")
}

func TestClaimScenarioRefusesANameAnotherWorktreeHolds(t *testing.T) {
	fns := claimFuncs(t)
	cases := []struct {
		name      string
		setup     func(t *testing.T, a, b string)
		wantClaim bool   // a ends up holding s
		wantNamed string // refusal names this file (relative to b)
	}{
		{
			name:      "b holds a claim on s",
			setup:     func(t *testing.T, a, b string) { writeClaim(t, b, "s") },
			wantNamed: filepath.Join("integration-tests", ".tf", "s", ".state-claim"),
		},
		{
			// A run.sh from before claims leaves only its domain pin.
			name:      "b holds a domain pin on s",
			setup:     func(t *testing.T, a, b string) { pinDomain(t, b, "s", "one.itest.example.com") },
			wantNamed: filepath.Join("integration-tests", ".tf", "s", ".leased-domain"),
		},
		{
			name:      "b holds a different scenario",
			setup:     func(t *testing.T, a, b string) { writeClaim(t, b, "t") },
			wantClaim: true,
		},
		{
			// A kept stack in a's own tree: a may run it again.
			name:      "a already holds s",
			setup:     func(t *testing.T, a, b string) { writeClaim(t, a, "s") },
			wantClaim: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, b := twoWorktrees(t)
			tc.setup(t, a, b)
			_, stderr, code := runBashScript(t, claimScript(fns, "s"), a, gitEnv())
			claim, claimErr := os.ReadFile(claimPath(a, "s"))
			if tc.wantClaim {
				if code != 0 {
					t.Fatalf("claim exited %d; want it granted", code)
				}
				if claimErr != nil || !strings.Contains(string(claim), "state_key=integration/s/terraform.tfstate") {
					t.Fatalf("claim file = %q (err %v)", claim, claimErr)
				}
				return
			}
			if code == 0 {
				t.Fatal("claim granted while worktree b holds s")
			}
			if claimErr == nil {
				t.Errorf("a refused claim wrote %q", claim)
			}
			if !strings.Contains(stderr, filepath.Join("b", tc.wantNamed)) {
				t.Errorf("the refusal does not name b's %s:\n%s", tc.wantNamed, stderr)
			}
			if _, err := os.Stat(filepath.Join(a, ".git", "aerol-itest-domain-lease.lock")); !os.IsNotExist(err) {
				t.Errorf("a refused claim left the lease lock behind (stat err %v)", err)
			}
		})
	}
}

func writeClaim(t *testing.T, root, scenario string) {
	t.Helper()
	mustMkdir(t, filepath.Dir(claimPath(root, scenario)))
	mustWrite(t, claimPath(root, scenario), "worktree="+root+"\nstate_key=integration/"+scenario+"/terraform.tfstate\n")
}

// Two worktrees that start the same scenario at the same moment: exactly one
// gets it. Without the lease lock both read "nobody holds s" before either
// wrote its claim.
func TestConcurrentClaimsOnOneScenarioGrantOne(t *testing.T) {
	a, b := twoWorktrees(t)
	fns := claimFuncs(t)
	for round := range 10 {
		for _, root := range []string{a, b} {
			if err := os.RemoveAll(filepath.Join(root, "integration-tests", ".tf")); err != nil {
				t.Fatal(err)
			}
		}
		cmds := make([]*exec.Cmd, 2)
		for i, root := range []string{a, b} {
			cmds[i] = exec.Command("bash", "-c", claimScript(fns, "s"), "bash", root)
			cmds[i].Env = gitEnv()
			if err := cmds[i].Start(); err != nil {
				t.Fatal(err)
			}
		}
		granted := 0
		for _, c := range cmds {
			if c.Wait() == nil {
				granted++
			}
		}
		if granted != 1 {
			t.Fatalf("round %d: %d worktrees got scenario s; want exactly 1", round, granted)
		}
	}
}

// stageRunSh copies run.sh into worktree root the way
// TestRunRefusesADomainScenarioWithNoDomainPool does: lib/provision.sh is a
// stub that records check-safety and stops the run (exit 97), and terraform,
// aws, curl and ssh on PATH record any call and fail. It returns the env, the
// gate log and the tool log.
func stageRunSh(t *testing.T, root string) (env []string, gateLog, toolLog string) {
	t.Helper()
	runSh, err := os.ReadFile(runScript(t))
	if err != nil {
		t.Fatal(err)
	}
	common, err := os.ReadFile(filepath.Join(filepath.Dir(runScript(t)), "lib", "common.sh"))
	if err != nil {
		t.Fatal(err)
	}
	it := filepath.Join(root, "integration-tests")
	scratch := t.TempDir()
	bin := filepath.Join(scratch, "bin")
	for _, d := range []string{filepath.Join(it, "lib"), filepath.Join(it, "scenarios"),
		filepath.Join(root, "config"), bin, filepath.Join(scratch, "tmp")} {
		mustMkdir(t, d)
	}
	gateLog, toolLog = filepath.Join(scratch, "gate-calls"), filepath.Join(scratch, "tool-calls")
	mustWrite(t, filepath.Join(it, "run.sh"), string(runSh))
	mustWrite(t, filepath.Join(it, "lib", "common.sh"), string(common))
	mustWrite(t, filepath.Join(it, "lib", "provision.sh"),
		"#!/usr/bin/env bash\nprintf '%s\\n' \"$*\" >>\""+gateLog+"\"\nexit 97\n")
	for _, tool := range []string{"terraform", "aws", "curl", "ssh"} {
		p := filepath.Join(bin, tool)
		mustWrite(t, p, "#!/usr/bin/env bash\necho \""+tool+" $*\" >>\""+toolLog+"\"\nexit 1\n")
		if err := os.Chmod(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite(t, filepath.Join(it, "scenarios", "s.tfvars"), "cluster_name = \"aerolvm-itest-s\"\n")
	mustWrite(t, filepath.Join(it, "scenarios", "s.caps.yml"), "name: s\ncapabilities: [docker]\n")
	mustWrite(t, filepath.Join(root, "config", "cluster.yml"), "ingress:\n  domain_name: prod.example.com\n")
	env = []string{
		"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"HOME=" + scratch,
		"TMPDIR=" + filepath.Join(scratch, "tmp"),
		"GIT_CONFIG_NOSYSTEM=1",
	}
	return env, gateLog, toolLog
}

// run.sh itself, in worktree a, while worktree b holds scenario s: a fresh
// run and --destroy-only are both refused before the safety gate and before
// any tool runs. With nobody else holding s, a run reaches the gate, and the
// claim it made is dropped again when the run stops there, since nothing was
// applied; a claim a kept stack already had stays.
func TestRunRefusesAScenarioAnotherWorktreeHolds(t *testing.T) {
	requireYQ(t)
	cases := []struct {
		name     string
		args     []string
		aHolds   bool // a kept stack in a's own tree
		bHolds   bool
		wantGate bool
	}{
		{name: "fresh run, b holds s", args: []string{"s"}, bHolds: true},
		{name: "--destroy-only, b holds s", args: []string{"s", "--destroy-only"}, bHolds: true},
		{name: "--collect-logs-only, b holds s", args: []string{"s", "--collect-logs-only"}, bHolds: true},
		{name: "fresh run, nobody else holds s", args: []string{"s"}, wantGate: true},
		{name: "--keep run of a's own kept stack", args: []string{"s", "--keep"}, aHolds: true, wantGate: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, b := twoWorktrees(t)
			env, gateLog, toolLog := stageRunSh(t, a)
			if tc.aHolds {
				writeClaim(t, a, "s")
			}
			if tc.bHolds {
				writeClaim(t, b, "s")
			}
			cmd := exec.Command("bash", append([]string{filepath.Join(a, "integration-tests", "run.sh")}, tc.args...)...)
			cmd.Env = env
			out, _ := cmd.CombinedOutput()
			t.Logf("run.sh %v -> %s", tc.args, out)
			gate, _ := os.ReadFile(gateLog)
			tools, _ := os.ReadFile(toolLog)
			if _, err := os.Stat(claimPath(a, "s")); tc.aHolds != (err == nil) {
				t.Errorf("a's claim on s after the run: stat err %v; want it kept only for a kept stack", err)
			}
			if tc.wantGate {
				if !strings.Contains(string(gate), "check-safety integration/s/terraform.tfstate") {
					t.Errorf("run.sh did not reach the safety gate: %q", gate)
				}
				return
			}
			if !strings.Contains(string(out), "another worktree holds it") ||
				!strings.Contains(string(out), filepath.Join("b", "integration-tests", ".tf", "s", ".state-claim")) {
				t.Error("run.sh did not refuse with b's claim named")
			}
			if len(gate) > 0 {
				t.Errorf("run.sh reached the safety gate: %s", gate)
			}
			if len(tools) > 0 {
				t.Errorf("run.sh reached a stubbed external tool:\n%s", tools)
			}
		})
	}
}
