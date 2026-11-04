package safety

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
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
	src, err := os.ReadFile(runScript(t))
	if err != nil {
		t.Fatalf("read run.sh: %v", err)
	}
	var fns strings.Builder
	for _, name := range []string{"domains_in_use", "lease_domain", "scenario_overlay_domain", "lease_domain_for_scenario"} {
		fns.WriteString(extractShellFunc(t, string(src), name))
	}

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
` + fns.String() + `
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
