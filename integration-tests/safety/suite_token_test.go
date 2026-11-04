package safety

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// mint_suite_token (lib/common.sh) is how a pat-scope-host scenario gets the
// admin avm_ token every remote call presents (identity-and-access T12). It
// runs against a node over SSH, so these tests replace ssh with a bash
// function and check the two properties that matter offline: the PAT reaches
// curl on stdin and never in an argv, and a node that never answers with a
// token fails the mint rather than handing back an empty credential.

const fakePAT = "pat-secret-value-0123456789abcdef0123456789"

func runMint(t *testing.T, fakeSSH string, timeout string) (stdout, stderr string, code int, argvLog string) {
	t.Helper()
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq not on PATH")
	}
	common := filepath.Join(filepath.Dir(buildScript(t)), "common.sh")
	dir := t.TempDir()
	argv := filepath.Join(dir, "argv.log")
	script := `set -u
source "$1"
SSH_OPTS=()
sleep() { :; }
ssh() { printf '%s\n' "$*" >> "$ARGV_LOG"; ` + fakeSSH + `; }
mint_suite_token "ubuntu@203.0.113.10" "$PAT" "cluster-3-mixed-secrets-enterprise" "$TIMEOUT"
`
	cmd := exec.Command("bash", "-c", script, "bash", common)
	cmd.Env = append(os.Environ(), "ARGV_LOG="+argv, "PAT="+fakePAT, "TIMEOUT="+timeout)
	var out, errb strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(argv)
	return out.String(), errb.String(), code, string(raw)
}

func TestMintSuiteTokenPassesThePATOnStdinOnly(t *testing.T) {
	// The fake node checks the header it was handed on stdin and answers like
	// POST /v1/tokens.
	fake := `hdr=$(cat); [ "$hdr" = "Authorization: Bearer $PAT" ] || { echo '{"error":"unauthorized"}'; return 0; }; ` +
		`echo '{"id":"tok_abcdefghijkl","role":"admin","team":"*","token":"avm_abcdefghijkl_s3cr3t_xyz123"}'`
	stdout, stderr, code, argv := runMint(t, fake, "30")
	if code != 0 || strings.TrimSpace(stdout) != "avm_abcdefghijkl_s3cr3t_xyz123" {
		t.Fatalf("mint = %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if strings.Contains(argv, fakePAT) {
		t.Fatalf("the PAT appeared in ssh's argv, where the remote ps and sudo logs see it:\n%s", argv)
	}
	for _, want := range []string{"curl", "-H @-", "http://127.0.0.1:21212/v1/tokens", `"role":"admin"`, `"team":"*"`, "itest-harness-cluster-3-mixed-secrets-enterprise-"} {
		if !strings.Contains(argv, want) {
			t.Errorf("the remote command lacks %q:\n%s", want, argv)
		}
	}
}

func TestMintSuiteTokenFailsWithoutAToken(t *testing.T) {
	// A node answering 401 forever (the PAT is wrong, or the daemon refuses
	// it) must fail the mint, never yield an empty token the suite would then
	// present as its credential.
	stdout, stderr, code, _ := runMint(t, `cat >/dev/null; echo '{"error":"unauthorized"}'`, "0")
	if code == 0 || strings.TrimSpace(stdout) != "" {
		t.Fatalf("a mint with no token = %d, stdout %q", code, stdout)
	}
	if !strings.Contains(stderr, "no admin token") {
		t.Fatalf("the failure does not say what went wrong: %q", stderr)
	}
}
