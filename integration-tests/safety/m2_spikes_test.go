package safety

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The M2 spike kit (k8s/m2: spa.sh, spb.sh, leak-check.sh) spends real AWS
// money when it runs. These tests run the scripts for real around a fake
// `aws` that fails and records every call, and pin the guards that keep a
// run short and safe: nothing reaches AWS without --i-have-owner-approval,
// --dry-run prints every call and makes none, the cost is printed first and
// a run past its ceiling is refused, and every machine carries the spike's
// owner tag, a hard deadline and no inbound access. Offline: no AWS, no
// network.

// m2Run runs one kit script with a fake aws first on PATH and its state in
// a temp folder. It returns the combined output, the exit code and the
// calls the fake aws received.
func m2Run(t *testing.T, script string, env []string, args ...string) (string, int, string) {
	t.Helper()
	needTools(t, "python3", "git")
	bin := t.TempDir()
	calls := filepath.Join(t.TempDir(), "aws-calls")
	fake := "#!/bin/sh\necho \"$*\" >> \"$FAKE_AWS_CALLS\"\nexit 99\n"
	if err := os.WriteFile(filepath.Join(bin, "aws"), []byte(fake), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", append([]string{k8sFile(t, "m2", script)}, args...)...)
	cmd.Env = append(os.Environ(), append([]string{
		"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"FAKE_AWS_CALLS=" + calls,
		"M2_STATE=" + t.TempDir(),
		"AEROL_PYTHON=python3",
		"DRY_RUN=0",
	}, env...)...)
	out, err := cmd.CombinedOutput()
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("%s: %v", script, err)
	}
	got, _ := os.ReadFile(calls)
	return string(out), code, string(got)
}

func TestM2SpikeDryRunPrintsEveryCallAndMakesNone(t *testing.T) {
	cases := []struct {
		script string
		args   []string
		want   []string
	}{
		{"spa.sh", []string{"--dry-run", "--run", "m2t-spa"}, []string{
			"COST planned", `"NestedVirtualization": "enabled"`, `"InstanceType": "c5.metal"`,
			`"InstanceType": "m8i.4xlarge"`, "'FCK ' lines", "'SPA ' lines",
		}},
		{"spa.sh", []string{"--dry-run", "--run", "m2t-spa2", "--legs", "bench-m8i-redial"}, []string{
			`"InstanceType": "m8i.xlarge"`,
		}},
		{"spb.sh", []string{"--dry-run", "--run", "m2t-spb"}, []string{
			"COST planned", `"EnclaveOptions": {"Enabled": true}`, "al2023-ami-kernel-6.18-x86_64", "'SPB ' lines",
		}},
	}
	for _, c := range cases {
		out, code, calls := m2Run(t, c.script, nil, c.args...)
		if code != 0 {
			t.Fatalf("%s %v: exit %d\n%s", c.script, c.args, code, out)
		}
		if calls != "" {
			t.Fatalf("%s %v: a dry run called aws:\n%s", c.script, c.args, calls)
		}
		for _, w := range append(c.want,
			"dry-run: ec2.run_instances(",
			`"InstanceInitiatedShutdownBehavior": "terminate"`,
			`{"Key": "owner", "Value": "aerolvm-spike"}`,
			`{"Key": "itest", "Value": "true"}`,
			`"ResourceType": "volume"`, `"ResourceType": "network-interface"`,
			"create-security-group", "Value=aerolvm-spike-m2t-",
			"terminate-instances", "wait instance-terminated", "delete-security-group",
			"leak check instances", "leak check volumes", "leak check security groups",
		) {
			if !strings.Contains(out, w) {
				t.Errorf("%s %v: output lacks %q", c.script, c.args, w)
			}
		}
		// The machines get no inbound rule, and nothing is copied over SSH.
		for _, bad := range []string{"authorize-security-group-ingress", "KeyName", "ssh "} {
			if strings.Contains(out, bad) {
				t.Errorf("%s %v: output has %q", c.script, c.args, bad)
			}
		}
	}
}

func TestM2SpikeRefusesWithoutOwnerApproval(t *testing.T) {
	for _, script := range []string{"spa.sh", "spb.sh"} {
		out, code, calls := m2Run(t, script, nil, "--run", "m2t-refuse")
		if code != 4 {
			t.Fatalf("%s without approval: exit %d, want 4\n%s", script, code, out)
		}
		if calls != "" {
			t.Fatalf("%s without approval called aws:\n%s", script, calls)
		}
		if !strings.Contains(out, "COST planned") || !strings.Contains(out, "REFUSED") {
			t.Errorf("%s without approval: want the cost, then a refusal\n%s", script, out)
		}
	}
}

func TestM2SpikeRefusesPastTheCeilingOrWithNoPrice(t *testing.T) {
	cases := []struct {
		script string
		env    []string
		args   []string
		want   string
	}{
		{"spa.sh", nil, []string{"--i-have-owner-approval", "--run", "m2t-ceil", "--ceiling", "1"}, "passes the ceiling"},
		{"spb.sh", []string{"M2_SPB_TYPE=x9.unpriced"}, []string{"--i-have-owner-approval", "--run", "m2t-price"}, "no price for x9.unpriced"},
	}
	for _, c := range cases {
		out, code, calls := m2Run(t, c.script, c.env, c.args...)
		if code != 3 || calls != "" || !strings.Contains(out, c.want) {
			t.Fatalf("%s %v: exit %d (want 3), aws calls %q, output:\n%s", c.script, c.args, code, calls, out)
		}
	}
}

func TestM2SpikeRejectsBadInput(t *testing.T) {
	cases := []struct {
		script string
		env    []string
		args   []string
	}{
		{"spa.sh", nil, []string{"--dry-run", "--run", "m2t-bad", "--legs", "bench-x"}},
		{"spa.sh", nil, []string{"--dry-run", "--run", "m2t-bad", "--legs", "bench-m8i,bench-m8i"}},
		{"spa.sh", nil, []string{"--dry-run", "--run", "Bad Name"}},
		{"spb.sh", []string{"M2_SPB_STEPS=step1 rm"}, []string{"--dry-run", "--run", "m2t-bad"}},
		{"spb.sh", nil, []string{"--dry-run", "--run", "m2t-bad", "--legs", "x"}},
	}
	for _, c := range cases {
		out, code, calls := m2Run(t, c.script, c.env, c.args...)
		if code != 2 || calls != "" {
			t.Errorf("%s %v %v: exit %d (want 2), aws calls %q\n%s", c.script, c.env, c.args, code, calls, out)
		}
	}
}

func TestM2LeakCheckIsReadOnly(t *testing.T) {
	out, code, calls := m2Run(t, "leak-check.sh", nil, "--dry-run", "--all")
	if code != 0 || calls != "" {
		t.Fatalf("leak-check --dry-run: exit %d, aws calls %q\n%s", code, calls, out)
	}
	verbs := regexp.MustCompile(`leak check [a-z ]+: aws ec2 ([a-z-]+)`)
	found := verbs.FindAllStringSubmatch(out, -1)
	if len(found) != 4 {
		t.Fatalf("want 4 checks, got %d\n%s", len(found), out)
	}
	for _, m := range found {
		if !strings.HasPrefix(m[1], "describe-") {
			t.Errorf("leak check makes a call that is not read-only: %s", m[1])
		}
	}
}

// m2_follow reads each machine's serial console every 20 s; AWS returns its
// last 64 KB each time. Each line must reach the leg's file once: a line
// printed twice by the machine shows twice, a line that only contains the
// prefix is not taken, a console that rolled over is picked up after the
// last line seen, and a machine that ends before DONE stops the watch.
func TestM2FollowPrintsEachConsoleLineOnce(t *testing.T) {
	needTools(t)
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	// The fake answers call n for an instance with console-<id>-<n>, or the
	// last one there is; describe-instances says terminated once gone-<id>
	// exists.
	fake := `#!/bin/bash
id=""; prev=""
for a in "$@"; do [[ "$prev" == --instance-id || "$prev" == --instance-ids ]] && id="$a"; prev="$a"; done
case "$1 $2" in
  "ec2 get-console-output")
    n=$(cat "$FAKE/n-$id" 2>/dev/null || echo 0); n=$((n + 1)); echo $n > "$FAKE/n-$id"
    while [[ $n -gt 1 && ! -e "$FAKE/console-$id-$n" ]]; do n=$((n - 1)); done
    cat "$FAKE/console-$id-$n" ;;
  "ec2 describe-instances") if [[ -e "$FAKE/gone-$id" ]]; then echo terminated; else echo running; fi ;;
  *) exit 99 ;;
esac
`
	files := map[string]string{
		"bin/aws": fake,
		// a: one line more each call, a repeated line, CRLF endings.
		"console-i-a-1": "boot noise\r\nSPA start\r\n",
		"console-i-a-2": "boot noise\r\nSPA start\r\nSPA same\r\nSPA same\r\n",
		"console-i-a-3": "boot noise\r\nSPA start\r\nSPA same\r\nSPA same\r\nnoise SPA inside\r\nSPA DONE\r\n",
		// b: the console rolls over between calls.
		"console-i-b-1": "FCK one\nFCK two\nFCK three\n",
		"console-i-b-2": "FCK three\nFCK four\nFCK five\n",
		"console-i-b-3": "FCK five\nFCK DONE\n",
		// c: the machine is gone before DONE.
		"console-i-c-1": "SPB first\n",
		"gone-i-c":      "",
	}
	for name, body := range files {
		mode := os.FileMode(0o644)
		if strings.HasPrefix(name, "bin/") {
			mode = 0o755
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	script := `set -euo pipefail
. "$LIB"
sleep() { :; }
dry=0 sd="$FAKE" report="$FAKE/report.txt"
: >"$report"
leg_names=(a b c) leg_ids=(i-a i-b i-c) leg_prefix=(SPA FCK SPB)
leg_state=(open open open) leg_last=("" "" "") leg_seen=(0 0 0)
m2_follow 5
echo "states: ${leg_state[*]}"
`
	cmd := exec.Command("bash", "-c", script)
	cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"FAKE="+dir, "LIB="+k8sFile(t, "m2", "lib.sh"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("m2_follow: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "states: finished finished gone") {
		t.Fatalf("leg states: want finished finished gone\n%s", out)
	}
	want := map[string]string{
		"a.txt": "SPA start\nSPA same\nSPA same\nSPA DONE\n",
		"b.txt": "FCK one\nFCK two\nFCK three\nFCK four\nFCK five\nFCK DONE\n",
		"c.txt": "SPB first\n",
	}
	for f, w := range want {
		got, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != w {
			t.Errorf("%s:\ngot  %q\nwant %q", f, got, w)
		}
	}
}

// Every machine's user data puts it on a deadline that powers it off (and
// so terminates it), and its downloads are checked against the SHA-256
// the launching script took.
func TestM2SpikeUserDataHasADeadlineAndChecksums(t *testing.T) {
	for _, f := range []string{"spa-userdata.sh", "spb-userdata.sh"} {
		b, err := os.ReadFile(k8sFile(t, "m2", f))
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		for _, w := range []string{"@TTL_MIN@", "sha256sum -c", "@SRC_SHA@", "@KIT_SHA@", "poweroff"} {
			if !strings.Contains(s, w) {
				t.Errorf("%s lacks %q", f, w)
			}
		}
	}
	for _, f := range []string{"spa.sh", "spb.sh", "leak-check.sh", "lib.sh", "spa-userdata.sh", "spb-userdata.sh", "spb-run.sh", "spb-setup.sh"} {
		if out, err := exec.Command("bash", "-n", k8sFile(t, "m2", f)).CombinedOutput(); err != nil {
			t.Errorf("bash -n %s: %v\n%s", f, err, out)
		}
	}
}
