package safety

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// On 2026-10-16 a live run of single-node-secrets-enterprise, started from a
// fresh git worktree with no scenarios/domains.yml (it is gitignored), got
// past the domain lease, the safety gate and the zone precheck with NO test
// domain, and was stopped by hand short of a Terraform apply. lease_domain had
// failed; nothing listened. Its caller runs inside $(…), where bash clears
// errexit, so the failure became an empty domain with status 0, and every
// later gate read "empty" as "no domain to check".
//
// These tests run run.sh's own functions, or run.sh itself, against throwaway
// trees under t.TempDir(). Nothing reaches AWS, Terraform, Cloudflare or DNS.

const leasePool = "itest:\n  domains:\n    - one.itest.example.com\n    - two.itest.example.com\n"

var leasePoolDomains = []string{"one.itest.example.com", "two.itest.example.com"}

func requireYQ(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("yq"); err != nil {
		t.Skip("yq not on PATH")
	}
}

// runBashScript runs script with root as $1 and returns stdout, stderr and the
// exit code separately: "no domain was echoed" is a claim about stdout alone.
func runBashScript(t *testing.T, script, root string, env []string) (string, string, int) {
	t.Helper()
	cmd := exec.Command("bash", "-c", script, "bash", root)
	cmd.Env = env
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	t.Logf("stdout=%q\nstderr:\n%s", stdout.String(), stderr.String())
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run bash: %v", err)
	}
	return stdout.String(), stderr.String(), code
}

// TestLeaseDomainForScenarioNeverHandsOutAnEmptyDomain lifts the lease
// functions out of run.sh and calls lease_domain_for_scenario exactly the way
// run_one does, inside $(…). Called directly under `set -e` the old code would
// have stopped on its own and this test would prove nothing.
func TestLeaseDomainForScenarioNeverHandsOutAnEmptyDomain(t *testing.T) {
	requireYQ(t)
	fns := leaseFuncs(t)

	str := func(s string) *string { return &s }
	cases := []struct {
		name    string
		domains *string // nil: no domains.yml at all
		keep    bool
		pin     *string // nil: no pin on disk before the lease
		wantIn  []string
		wantErr string // stderr substring; set means the lease must be refused
	}{
		{name: "missing domains.yml (a fresh worktree)", wantErr: "domains pool empty"},
		{name: "empty domains.yml", domains: str(""), wantErr: "domains pool empty"},
		{name: "pool with no entries", domains: str("itest:\n  domains: []\n"), wantErr: "domains pool empty"},
		{name: "blank pool entry", domains: str("itest:\n  domains:\n    - \"\"\n"), wantErr: "blank entry"},
		{name: "null pool entry", domains: str("itest:\n  domains:\n    -\n"), wantErr: "blank entry"},
		{name: "populated pool", domains: str(leasePool), wantIn: leasePoolDomains},
		{
			// The pre-fix bug left exactly this behind: a 1-byte pin holding a
			// newline. --keep must lease afresh rather than trust it.
			name: "kept run, empty pin, populated pool", keep: true,
			pin: str("\n"), domains: str(leasePool), wantIn: leasePoolDomains,
		},
		{
			name: "kept run, empty pin, no domains.yml", keep: true,
			pin: str("\n"), wantErr: "domains pool empty",
		},
		{
			// A kept scenario re-uses its own pin and needs no pool, so the
			// refusal must not break --keep for an operator without domains.yml.
			name: "kept run, real pin, no domains.yml", keep: true,
			pin: str("kept.itest.example.com\n"), wantIn: []string{"kept.itest.example.com"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			mustMkdir(t, filepath.Join(root, "integration-tests", "scenarios"))
			if tc.domains != nil {
				mustWrite(t, filepath.Join(root, "integration-tests", "scenarios", "domains.yml"), *tc.domains)
			}
			pin := filepath.Join(root, "integration-tests", ".tf", "s", ".leased-domain")
			if tc.pin != nil {
				mustMkdir(t, filepath.Dir(pin))
				mustWrite(t, pin, *tc.pin)
			}
			keep := "0"
			if tc.keep {
				keep = "1"
			}
			script := `set -euo pipefail
REPO_ROOT="$1"
HERE="${REPO_ROOT}/integration-tests"
DOMAINS_FILE="${HERE}/scenarios/domains.yml"
KEEP=` + keep + `
# No Terraform state: the --keep fallback must never reach a real backend.
terraform_state_domain() { return 1; }
` + fns + `
rc=0
leased=$(lease_domain_for_scenario s) || rc=$?
printf '%s' "$leased"
exit "$rc"
`
			stdout, stderr, code := runBashScript(t, script, root, os.Environ())
			pinBytes, pinErr := os.ReadFile(pin)

			if tc.wantErr != "" {
				if code == 0 {
					t.Errorf("lease exited 0 with %q; want a refusal", stdout)
				}
				if stdout != "" {
					t.Errorf("a refused lease still echoed %q", stdout)
				}
				if !strings.Contains(stderr, tc.wantErr) {
					t.Errorf("stderr lacks %q", tc.wantErr)
				}
				switch {
				case tc.pin == nil && pinErr == nil:
					t.Errorf("a refused lease left a pin holding %q", pinBytes)
				case tc.pin != nil && string(pinBytes) != *tc.pin:
					t.Errorf("a refused lease rewrote the pin from %q to %q", *tc.pin, pinBytes)
				}
				return
			}
			if code != 0 {
				t.Fatalf("lease exited %d; want a domain", code)
			}
			got := strings.TrimSpace(stdout)
			if !slices.Contains(tc.wantIn, got) {
				t.Errorf("leased %q; want one of %q", got, tc.wantIn)
			}
			if pinErr != nil || strings.TrimSpace(string(pinBytes)) != got {
				t.Errorf("pin holds %q (err %v); want the leased %q", pinBytes, pinErr, got)
			}
		})
	}
}

// leaseFuncs lifts the lease functions, and every helper they call, out of
// run.sh.
func leaseFuncs(t *testing.T) string {
	t.Helper()
	src, err := os.ReadFile(runScript(t))
	if err != nil {
		t.Fatalf("read run.sh: %v", err)
	}
	var fns strings.Builder
	for _, name := range []string{
		"worktree_roots", "domain_pins", "domains_in_use",
		"lease_lock_path", "lease_lock_acquire", "lease_lock_release",
		"lease_domain", "scenario_overlay_domain", "lease_domain_for_scenario",
	} {
		fns.WriteString(extractShellFunc(t, string(src), name))
	}
	return fns.String()
}

// leaseScript leases a domain for scenario from the tree at $1, as run_one
// does (inside $(…), KEEP=0), and prints it.
func leaseScript(fns, scenario string) string {
	return `set -euo pipefail
REPO_ROOT="$1"
HERE="${REPO_ROOT}/integration-tests"
DOMAINS_FILE="${HERE}/scenarios/domains.yml"
KEEP=0
terraform_state_domain() { return 1; }
` + fns + `
rc=0
leased=$(lease_domain_for_scenario ` + scenario + `) || rc=$?
printf '%s' "$leased"
exit "$rc"
`
}

// gitEnv keeps the operator's git config (signing, hooks) out of the
// throwaway repos.
func gitEnv() []string {
	return append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
}

// twoWorktrees makes a throwaway clone at a with a second worktree at b, both
// holding the two-domain pool, the way parallel lanes and agent sessions each
// run from their own worktree of one clone.
func twoWorktrees(t *testing.T) (a, b string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	dir := t.TempDir()
	a, b = filepath.Join(dir, "a"), filepath.Join(dir, "b")
	mustMkdir(t, a)
	for _, args := range [][]string{
		{"-C", a, "init", "-q"},
		{"-C", a, "commit", "-q", "--allow-empty", "-m", "init"},
		{"-C", a, "worktree", "add", "-q", b},
	} {
		cmd := exec.Command("git", args...)
		cmd.Env = gitEnv()
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	for _, root := range []string{a, b} {
		mustMkdir(t, filepath.Join(root, "integration-tests", "scenarios"))
		mustWrite(t, filepath.Join(root, "integration-tests", "scenarios", "domains.yml"), leasePool)
	}
	return a, b
}

func pinDomain(t *testing.T, root, scenario, domain string) {
	t.Helper()
	dir := filepath.Join(root, "integration-tests", ".tf", scenario)
	mustMkdir(t, dir)
	mustWrite(t, filepath.Join(dir, ".leased-domain"), domain+"\n")
}

// On 2026-11-07 a run in one worktree leased sandbox.aerol.live while another
// session's worktree was live on it: the lease read only its own tree's pins.
// Two stacks then sat behind one name, its A records round-robined between
// two ingresses, and the suite saw "sandbox not found" and invalid_signature.
func TestLeaseDomainSkipsPinsHeldInOtherWorktrees(t *testing.T) {
	requireYQ(t)
	a, b := twoWorktrees(t)
	fns := leaseFuncs(t)
	// b is live on one.itest under the SAME scenario name: a different pin
	// path, so a different holder.
	pinDomain(t, b, "s", "one.itest.example.com")
	// A lock left by a run killed mid-lease must not block the next one.
	lock := filepath.Join(a, ".git", "aerol-itest-domain-lease.lock")
	mustMkdir(t, lock)
	old := time.Now().Add(-2 * time.Minute)
	if err := os.Chtimes(lock, old, old); err != nil {
		t.Fatal(err)
	}

	// The random start lands on the held domain half the time, so eight
	// tries miss the old bug 1 time in 256.
	for i := range 8 {
		stdout, _, code := runBashScript(t, leaseScript(fns, "s"), a, gitEnv())
		if code != 0 || strings.TrimSpace(stdout) != "two.itest.example.com" {
			t.Fatalf("try %d: leased %q (exit %d); one.itest is held by worktree b", i, stdout, code)
		}
	}
	if _, err := os.Stat(lock); !os.IsNotExist(err) {
		t.Errorf("the lease lock is still there after the leases finished (stat err %v)", err)
	}

	// With two.itest held in a's own tree too, the pool is exhausted, and the
	// refusal names b's pin so the operator knows which worktree to tear down.
	pinDomain(t, a, "other", "two.itest.example.com")
	stdout, stderr, code := runBashScript(t, leaseScript(fns, "s"), a, gitEnv())
	if code == 0 || stdout != "" {
		t.Fatalf("leased %q (exit %d) with every domain held", stdout, code)
	}
	if !strings.Contains(stderr, "domain pool exhausted") ||
		!strings.Contains(stderr, filepath.Join("b", "integration-tests", ".tf", "s", ".leased-domain")) {
		t.Errorf("the refusal does not name worktree b's pin:\n%s", stderr)
	}
	if _, err := os.Stat(lock); !os.IsNotExist(err) {
		t.Errorf("a refused lease left the lock behind (stat err %v)", err)
	}
}

// A lease that finds the lock held by a live run waits for it instead of
// reading the pins mid-lease, and goes on once the lock is freed.
func TestLeaseWaitsForAHeldLock(t *testing.T) {
	requireYQ(t)
	a, b := twoWorktrees(t)
	fns := leaseFuncs(t)
	lock := filepath.Join(a, ".git", "aerol-itest-domain-lease.lock")
	mustMkdir(t, lock) // fresh: another run is mid-lease
	cmd := exec.Command("bash", "-c", leaseScript(fns, "s"), "bash", b)
	cmd.Env = gitEnv()
	var out strings.Builder
	cmd.Stdout = &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		t.Fatalf("the lease finished (%v, %q) while another run held the lock", err, out.String())
	case <-time.After(500 * time.Millisecond):
	}
	if err := os.Remove(lock); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil || !slices.Contains(leasePoolDomains, strings.TrimSpace(out.String())) {
			t.Fatalf("after the lock was freed: %v, leased %q", err, out.String())
		}
	case <-time.After(15 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("the lease did not go on after the lock was freed")
	}
}

// Two runs started at the same moment from two worktrees, with a two-domain
// pool, must each get a domain and never the same one. Without the lease lock
// both read "nothing held" before either wrote its pin, so they matched half
// the time.
func TestConcurrentLeasesFromTwoWorktreesNeverShareADomain(t *testing.T) {
	requireYQ(t)
	a, b := twoWorktrees(t)
	fns := leaseFuncs(t)
	for round := range 10 {
		for _, root := range []string{a, b} {
			if err := os.RemoveAll(filepath.Join(root, "integration-tests", ".tf")); err != nil {
				t.Fatal(err)
			}
		}
		type run struct {
			cmd *exec.Cmd
			out strings.Builder
		}
		runs := []*run{{}, {}}
		for i, root := range []string{a, b} {
			r := runs[i]
			r.cmd = exec.Command("bash", "-c", leaseScript(fns, "s"), "bash", root)
			r.cmd.Env = gitEnv()
			r.cmd.Stdout = &r.out
			var stderr strings.Builder
			r.cmd.Stderr = &stderr
			if err := r.cmd.Start(); err != nil {
				t.Fatal(err)
			}
		}
		for i, r := range runs {
			if err := r.cmd.Wait(); err != nil {
				t.Fatalf("round %d: lease %d failed: %v", round, i, err)
			}
		}
		got := []string{strings.TrimSpace(runs[0].out.String()), strings.TrimSpace(runs[1].out.String())}
		if got[0] == got[1] {
			t.Fatalf("round %d: both worktrees leased %q", round, got[0])
		}
		for _, d := range got {
			if !slices.Contains(leasePoolDomains, d) {
				t.Fatalf("round %d: leased %q, not a pool domain", round, d)
			}
		}
	}
}

// TestRunRefusesADomainScenarioWithNoDomainPool drives run.sh itself, copied
// into a throwaway tree, up to the safety gate. lib/provision.sh is a stub
// that records its arguments and stops the run, and terraform, aws, curl and
// ssh on PATH are stubs that record any call and fail, so a regression that
// slipped past the gate still could not reach AWS.
func TestRunRefusesADomainScenarioWithNoDomainPool(t *testing.T) {
	requireYQ(t)
	runSh, err := os.ReadFile(runScript(t))
	if err != nil {
		t.Fatalf("read run.sh: %v", err)
	}
	common, err := os.ReadFile(filepath.Join(filepath.Dir(runScript(t)), "lib", "common.sh"))
	if err != nil {
		t.Fatalf("read common.sh: %v", err)
	}

	const gatePrefix = "check-safety integration/s/terraform.tfstate "
	const gateSuffix = " prod.example.com aerolvm-itest-s"
	cases := []struct {
		name     string
		caps     string
		domains  string // empty: no domains.yml
		wantGate string // the one check-safety call expected; empty: the gate must not run
	}{
		{name: "domain scenario, no domains.yml", caps: "[docker, domain]"},
		{
			// The gate must see the domain DNS is about to point at, not the
			// placeholder.
			name: "domain scenario, populated pool", caps: "[docker, domain]",
			domains:  "itest:\n  domains:\n    - one.itest.example.com\n",
			wantGate: gatePrefix + "one.itest.example.com" + gateSuffix,
		},
		{
			// local-mode has no domain and must keep reaching the gate with the
			// placeholder, domains.yml or not.
			name: "scenario without a domain", caps: "[docker]",
			wantGate: gatePrefix + "none.itest.invalid" + gateSuffix,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			it := filepath.Join(root, "integration-tests")
			for _, d := range []string{filepath.Join(it, "lib"), filepath.Join(it, "scenarios"),
				filepath.Join(root, "config"), filepath.Join(root, "bin"), filepath.Join(root, "tmp")} {
				mustMkdir(t, d)
			}
			gateLog := filepath.Join(root, "gate-calls")
			toolLog := filepath.Join(root, "tool-calls")
			mustWrite(t, filepath.Join(it, "run.sh"), string(runSh))
			mustWrite(t, filepath.Join(it, "lib", "common.sh"), string(common))
			mustWrite(t, filepath.Join(it, "lib", "provision.sh"),
				"#!/usr/bin/env bash\nprintf '%s\\n' \"$*\" >>\""+gateLog+"\"\nexit 97\n")
			for _, tool := range []string{"terraform", "aws", "curl", "ssh"} {
				p := filepath.Join(root, "bin", tool)
				mustWrite(t, p, "#!/usr/bin/env bash\necho \""+tool+" $*\" >>\""+toolLog+"\"\nexit 1\n")
				if err := os.Chmod(p, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			mustWrite(t, filepath.Join(it, "scenarios", "s.tfvars"), "cluster_name = \"aerolvm-itest-s\"\n")
			mustWrite(t, filepath.Join(it, "scenarios", "s.caps.yml"), "name: s\ncapabilities: "+tc.caps+"\n")
			mustWrite(t, filepath.Join(root, "config", "cluster.yml"), "ingress:\n  domain_name: prod.example.com\n")
			if tc.domains != "" {
				mustWrite(t, filepath.Join(it, "scenarios", "domains.yml"), tc.domains)
			}

			// A fresh environment, not os.Environ(): no AWS credentials, no
			// operator HOME, and no inherited AEROL_RUNSH_PINNED to send HERE
			// back to the real tree.
			cmd := exec.Command("bash", filepath.Join(it, "run.sh"), "s")
			cmd.Env = []string{
				"PATH=" + filepath.Join(root, "bin") + string(os.PathListSeparator) + os.Getenv("PATH"),
				"HOME=" + root,
				"TMPDIR=" + filepath.Join(root, "tmp"),
			}
			out, err := cmd.CombinedOutput()
			t.Logf("run.sh s -> %s", out)
			code := 0
			if ee, ok := err.(*exec.ExitError); ok {
				code = ee.ExitCode()
			} else if err != nil {
				t.Fatalf("run bash: %v", err)
			}
			gate, _ := os.ReadFile(gateLog)
			if tools, _ := os.ReadFile(toolLog); len(tools) > 0 {
				t.Errorf("run.sh reached a stubbed external tool:\n%s", tools)
			}

			if tc.wantGate == "" {
				if code == 0 {
					t.Error("run.sh exited 0 for a domain scenario with no domain pool")
				}
				if len(gate) > 0 {
					t.Errorf("run.sh reached the safety gate with no test domain: %s", gate)
				}
				// yq's own "no such file" error already names domains.yml, so
				// look for the refusal itself as well.
				if !strings.Contains(string(out), "needs a test domain but none was leased") ||
					!strings.Contains(string(out), "domains.yml") {
					t.Error("run.sh did not refuse with a message naming domains.yml")
				}
				pin := filepath.Join(it, ".tf", "s", ".leased-domain")
				if b, err := os.ReadFile(pin); err == nil {
					t.Errorf("run.sh left a pin holding %q", b)
				}
				return
			}
			if got := strings.TrimSpace(string(gate)); got != tc.wantGate {
				t.Errorf("safety gate called with %q; want %q", got, tc.wantGate)
			}
			if code != 97 {
				t.Errorf("run.sh exited %d; want 97 from the stub gate", code)
			}
		})
	}
}

// verify_leased_zone is only called for domain scenarios, so an empty name is
// a lease that went wrong, not local-mode. It used to return 0 for it.
func TestVerifyLeasedZoneRefusesAnEmptyDomain(t *testing.T) {
	src, err := os.ReadFile(runScript(t))
	if err != nil {
		t.Fatalf("read run.sh: %v", err)
	}
	fn := extractShellFunc(t, string(src), "verify_leased_zone")

	cases := []struct {
		name, domain string
		wantCode     int
	}{
		{name: "empty domain", domain: "", wantCode: 1},
		// No config/secrets.yml means no Cloudflare token: the precheck stays
		// best-effort and lets a real domain through, as before.
		{name: "real domain, no token", domain: "one.itest.example.com", wantCode: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			mustMkdir(t, filepath.Join(root, "bin"))
			curlLog := filepath.Join(root, "curl-calls")
			curl := filepath.Join(root, "bin", "curl")
			mustWrite(t, curl, "#!/usr/bin/env bash\necho \"$*\" >>\""+curlLog+"\"\nexit 1\n")
			if err := os.Chmod(curl, 0o755); err != nil {
				t.Fatal(err)
			}
			script := "set -euo pipefail\nREPO_ROOT=\"$1\"\n" + fn + "\nverify_leased_zone '" + tc.domain + "'\n"
			env := append(os.Environ(), "PATH="+filepath.Join(root, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"))
			_, stderr, code := runBashScript(t, script, root, env)
			if code != tc.wantCode {
				t.Errorf("verify_leased_zone %q exited %d; want %d", tc.domain, code, tc.wantCode)
			}
			if tc.wantCode != 0 && !strings.Contains(stderr, "no leased domain") {
				t.Errorf("stderr does not say why: %q", stderr)
			}
			if calls, _ := os.ReadFile(curlLog); len(calls) > 0 {
				t.Errorf("verify_leased_zone called Cloudflare: %s", calls)
			}
		})
	}
}
