package safety

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
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
			`"ClientToken": "`,
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
	// Machines, disks, network interfaces, groups, and the kit in S3.
	verbs := regexp.MustCompile(`leak check [A-Za-z0-9 ]+: aws (ec2|s3api) ([a-z0-9-]+)`)
	found := verbs.FindAllStringSubmatch(out, -1)
	if len(found) != 5 {
		t.Fatalf("want 5 checks, got %d\n%s", len(found), out)
	}
	for _, m := range found {
		if !strings.HasPrefix(m[2], "describe-") && !strings.HasPrefix(m[2], "list-") {
			t.Errorf("leak check makes a call that is not read-only: %s %s", m[1], m[2])
		}
	}
	if !strings.Contains(out, "list-objects-v2") || !strings.Contains(out, "builds/spike-m2/") {
		t.Errorf("leak check does not look at the kit in S3\n%s", out)
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

// m2StandIn is a stand-in for sandboxd's v1 API, just enough for
// spa-bench.py's base phase. Every stop and start succeeds. A sandbox for
// which broken(its creation number) is true comes back from each start the
// way a rebooted guest would: a new boot ID and an empty /tmp.
type m2StandIn struct {
	mu     sync.Mutex
	n      int
	broken func(n int) bool
	sb     map[string]*m2Guest
}

type m2Guest struct {
	n       int
	boot    string
	marker  bool
	busy    bool
	counter int
}

func (s *m2StandIn) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	reply := func(code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	switch {
	case r.URL.Path == "/health":
		reply(200, map[string]bool{"ok": true})
	case r.Method == "POST" && r.URL.Path == "/v1/templates":
		reply(201, map[string]string{"id": "tpl-standin"})
	case r.Method == "GET" && len(parts) == 3 && parts[1] == "templates":
		reply(200, map[string]string{"id": parts[2], "status": "ready"})
	case r.Method == "POST" && r.URL.Path == "/v1/sandboxes":
		s.n++
		id := fmt.Sprintf("sb-standin-%04d", s.n)
		s.sb[id] = &m2Guest{n: s.n, boot: fmt.Sprintf("%032x", s.n*1000)}
		w.Header().Set("Server-Timing", "create;dur=50.0")
		reply(201, map[string]string{"id": id, "status": "started"})
	case len(parts) < 3 || parts[1] != "sandboxes" || s.sb[parts[2]] == nil:
		reply(404, map[string]string{"error": "not found"})
	case r.Method == "GET", r.Method == "DELETE":
		reply(200, map[string]string{"id": parts[2], "status": "started"})
	case len(parts) == 4 && parts[3] == "stop":
		reply(200, map[string]string{})
	case len(parts) == 4 && parts[3] == "start":
		g := s.sb[parts[2]]
		if s.broken(g.n) {
			g.boot = fmt.Sprintf("%032x", g.n*1000+g.counter+7)
			g.marker, g.counter = false, 0
		}
		reply(200, map[string]string{})
	case strings.HasSuffix(r.URL.Path, "/toolbox/process/execute"):
		g := s.sb[parts[2]]
		var body struct {
			Command string `json:"command"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		out := "agent-ok\n5.10.245"
		switch {
		case strings.Contains(body.Command, "setsid nohup"):
			g.busy, out = true, ""
		case strings.Contains(body.Command, "echo spa-marker"):
			g.marker, out = true, g.boot+"\n"
		case strings.Contains(body.Command, "cat /tmp/marker"):
			out = g.boot + "\n"
			if g.marker {
				out += "spa-marker\n"
			}
			if g.busy && g.marker {
				g.counter++
				out += fmt.Sprintf("%d\n", g.counter)
			} else if !g.busy {
				out += "0\n"
			}
		}
		reply(200, map[string]string{"stdout": out})
	default:
		reply(404, map[string]string{"error": "no route"})
	}
}

// The pause/resume verdict is every cycle intact, not only none lost: a
// start that works but hands back a rebooted guest must fail the bench and
// SP-A's verdict (review of #1483). Every third sandbox here comes back
// from each start with a new boot ID and an empty /tmp; the same run with
// no broken sandbox passes.
func TestM2BenchFailsWhenAResumeLosesTheGuestsMemory(t *testing.T) {
	needTools(t, "python3")
	cases := []struct {
		name    string
		broken  func(int) bool
		bench   string
		verdict string
	}{
		{"every third sandbox rebooted", func(n int) bool { return n%3 == 0 }, "-> FAIL", "VERDICT SP-A: NO GO"},
		{"every sandbox intact", func(int) bool { return false }, "-> PASS", "VERDICT SP-A: go"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(&m2StandIn{broken: c.broken, sb: map[string]*m2Guest{}})
			defer srv.Close()
			home := t.TempDir()
			if err := os.WriteFile(filepath.Join(home, "pat"), []byte("standin\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("python3", "-I", k8sFile(t, "m2", "spa-bench.py"), "base",
				"--samples", "2", "--cycles", "6", "--idle-cycles", "3", "--leg", "standin")
			cmd.Env = append(os.Environ(), "SPA_API="+srv.URL, "SPA_HOME="+home, "SPA_CYCLE_GAP=0", "SPA_EXEC_WAIT=0.2")
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("spa-bench.py: %v\n%s", err, out)
			}
			var spa []string
			for _, l := range strings.Split(string(out), "\n") {
				if strings.HasPrefix(l, "SPA ") {
					spa = append(spa, l)
				}
				if strings.HasPrefix(l, "SPA VERDICT pause/resume") && !strings.HasSuffix(l, c.bench) {
					t.Errorf("bench verdict: want %q at the end\n%s", c.bench, l)
				}
			}
			if !strings.Contains(string(out), "SPA VERDICT pause/resume") {
				t.Fatalf("no pause/resume verdict\n%s", out)
			}
			// verdict.py over the leg, with a passing warm row: the
			// pause/resume row alone decides.
			state := t.TempDir()
			leg := strings.Join(append(spa, "SPA VERDICT warm create p50 20.0 ms over 20 hits of 20 (go: under 100 ms) -> PASS", "SPA DONE"), "\n") + "\n"
			if err := os.WriteFile(filepath.Join(state, "bench-m8i.txt"), []byte(leg), 0o644); err != nil {
				t.Fatal(err)
			}
			vout, _ := exec.Command("python3", "-I", k8sFile(t, "m2", "verdict.py"), state).CombinedOutput()
			if !strings.Contains(string(vout), c.verdict) {
				t.Errorf("verdict.py: want %q\n%s", c.verdict, vout)
			}
		})
	}
}

// A hangup (the terminal closed) runs the cleanup to its end and reports the
// run's own exit code: stderr is gone, so every write to it fails, and the
// machines, the group and the kit must still be removed and the leak check
// run (review of #1483).
func TestM2CleanupFinishesAfterAHangupWithNoTerminal(t *testing.T) {
	needTools(t)
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	fake := "#!/bin/sh\necho \"$*\" >> \"$OUT/calls\"\ncase \"$2\" in describe-*|list-*) echo None ;; esac\nexit 0\n"
	if err := os.WriteFile(filepath.Join(bin, "aws"), []byte(fake), 0o755); err != nil {
		t.Fatal(err)
	}
	script := `set -euo pipefail
. "$LIB"
sleep() { :; }
dry=0 run=m2t-hup sd="$OUT" report="$OUT/report.txt"
m2_bucket=bkt m2_sg=sg-1 leg_ids=(i-1 i-2) m2_tmp_keys=(builds/spike-m2/m2t-hup/kit.tgz)
trap m2_finish EXIT
trap 'exit 129' HUP
exec 2>&-
kill -HUP $$
:
`
	cmd := exec.Command("bash", "-c", script)
	cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"OUT="+dir, "LIB="+k8sFile(t, "m2", "lib.sh"))
	err := cmd.Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 129 {
		t.Fatalf("exit: %v, want 129 (the hangup's own code)", err)
	}
	calls, _ := os.ReadFile(filepath.Join(dir, "calls"))
	for _, w := range []string{
		"ec2 terminate-instances --region us-east-1 --instance-ids i-1 i-2",
		"ec2 wait instance-terminated",
		"ec2 delete-security-group --region us-east-1 --group-id sg-1",
		"s3 rm --only-show-errors --region us-east-1 s3://bkt/builds/spike-m2/m2t-hup/kit.tgz",
		"ec2 describe-instances", "s3api list-objects-v2 --region us-east-1 --bucket bkt --prefix builds/spike-m2/m2t-hup/",
	} {
		if !strings.Contains(string(calls), w) {
			t.Errorf("cleanup did not call %q; calls:\n%s", w, calls)
		}
	}
	report, _ := os.ReadFile(filepath.Join(dir, "report.txt"))
	if !strings.Contains(string(report), "nothing of run m2t-hup is left") || !strings.Contains(string(report), "ended (exit 129)") {
		t.Errorf("report:\n%s", report)
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
	// The move leg runs fckind's user data: its source is checked too, and
	// fckind.sh fills the checksum in.
	for f, wants := range map[string][]string{
		"fckind/userdata.sh": {"'@SRC_SHA@  src.tgz' | sha256sum -c --quiet -"},
		"fckind.sh":          {`.replace("@SRC_SHA@", os.environ["SUM"])`},
		// The throwaway admin token stays out of spa.log, the console and
		// the results: the installer's output, the journal and the log
		// copy all go through mask.
		"m2/spa-userdata.sh": {"--build-from-source 2>&1 | mask", "| mask | gzip", "mask </var/log/spa.log"},
		// The same for the sandboxd step: its log and its setup log go
		// up masked, and so does a failed setup's tail on the console.
		"m2/spb-run.sh": {`for f in /var/log/sandboxd.log /root/spb-sandboxd-setup.log; do`, `sed "s/$(cat /root/pat 2>/dev/null || echo NOPAT)/<pat>/g" "$f" | gzip`, `tail -15 /root/spb-sandboxd-setup.log | sed "s/$(cat /root/pat`},
	} {
		b, err := os.ReadFile(k8sFile(t, f))
		if err != nil {
			t.Fatal(err)
		}
		for _, w := range wants {
			if !strings.Contains(string(b), w) {
				t.Errorf("%s lacks %q", f, w)
			}
		}
	}
	for _, f := range []string{"spa.sh", "spb.sh", "leak-check.sh", "lib.sh", "spa-userdata.sh", "spb-userdata.sh", "spb-run.sh", "spb-setup.sh", "spb-sandboxd.sh"} {
		if out, err := exec.Command("bash", "-n", k8sFile(t, "m2", f)).CombinedOutput(); err != nil {
			t.Errorf("bash -n %s: %v\n%s", f, err, out)
		}
	}
}

// nitroStandIn is sandboxd on a Nitro node, as far as the SP-B "sandboxd"
// step (spb_sandboxd.py, plan §4.3) asks it things. noEgress makes every
// guest fail to reach the internet; loseEnv makes a start come back
// without the sandbox's env.
type nitroStandIn struct {
	mu       sync.Mutex
	next     int
	noEgress bool
	loseEnv  bool
	// rawRefusal answers a create past the cap as Firecracker would without
	// AerolVM's budget (a 400 from InstanceStart), not with a capacity 503.
	rawRefusal bool
	sb         map[string]*nitroGuest
}

// nitroStandInCap is how many sandboxes the stand-in runs at once.
const nitroStandInCap = 6

type nitroGuest struct {
	env, file string
	boot      int
}

func (s *nitroStandIn) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	reply := func(code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	refuse := func(op string) {
		reply(http.StatusNotImplemented, map[string]string{"error": `runtime "firecracker-nitro" cannot ` + op + ` yet on this build: runtime not yet implemented on this build`})
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sb == nil {
		s.sb = map[string]*nitroGuest{}
	}
	parts := strings.Split(r.URL.Path, "/")
	var g *nitroGuest
	if len(parts) > 3 {
		g = s.sb[parts[3]]
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1/runtimes":
		reply(200, map[string]any{"runtimes": []map[string]any{
			{"name": "docker", "available": true},
			{"name": "firecracker", "backend": "kvm", "available": false},
			{"name": "firecracker-nitro", "backend": "nitro", "available": true},
		}})
	case r.Method == http.MethodPost && r.URL.Path == "/v1/sandboxes":
		if body["runtime"] != "firecracker-nitro" {
			reply(http.StatusNotImplemented, map[string]string{"error": fmt.Sprintf(`runtime %q is not offered here (offered: docker, firecracker-nitro)`, body["runtime"])})
			return
		}
		if len(s.sb) >= nitroStandInCap {
			if s.rawRefusal {
				reply(http.StatusBadRequest, map[string]string{"error": "firecracker runtime: action InstanceStart: A Nitro Enclave does not have enough vCPUs"})
				return
			}
			reply(http.StatusServiceUnavailable, map[string]string{"error": "Nitro vCPU budget: no free slot (host capacity exceeded)"})
			return
		}
		s.next++
		id := fmt.Sprintf("sb-%d", s.next)
		env, _ := body["env"].(map[string]any)
		val, _ := env["SPB_ENV"].(string)
		s.sb[id] = &nitroGuest{env: val}
		reply(http.StatusCreated, map[string]any{"id": id, "status": "started", "runtime": "firecracker-nitro", "backend": "nitro"})
	case strings.HasSuffix(r.URL.Path, "/toolbox/process/execute"):
		cmd, _ := body["command"].(string)
		out := ""
		switch {
		case strings.Contains(cmd, "ran-"):
			out = "ran-42"
		case strings.Contains(cmd, "nitro-file"):
			out = "nitro-file"
		case strings.Contains(cmd, "wget"):
			out = "net-ok"
			if s.noEgress {
				out = "net-fail"
			}
		case strings.Contains(cmd, "> /root/spb-keep.txt"):
			g.file = "persist"
		case cmd == "cat /root/spb-keep.txt":
			out = g.file
		case cmd == "echo $SPB_ENV":
			out = g.env
		case cmd == "cat /proc/sys/kernel/random/boot_id":
			out = fmt.Sprintf("boot-%d", g.boot)
		case strings.HasPrefix(cmd, "ip -4 -o addr show eth0"):
			out = "172.16.0.2/30"
		case cmd == "uname -r":
			out = "6.18.62"
		case cmd == "cat /proc/cmdline":
			out = "console=ttyS0 reboot=k panic=1 nomodules quiet ipv6.disable_ipv6=1 init=/usr/local/bin/toolboxd-init root=/dev/vda"
		default:
			out = "0"
		}
		reply(200, map[string]any{"stdout": out, "exit_code": 0})
	case strings.HasSuffix(r.URL.Path, "/stop"):
		reply(200, map[string]any{"status": "stopped"})
	case strings.HasSuffix(r.URL.Path, "/start"):
		g.boot++
		if s.loseEnv {
			g.env = ""
		}
		reply(200, map[string]any{"status": "started"})
	case strings.HasSuffix(r.URL.Path, "/snapshot"):
		refuse("take a snapshot")
	case r.Method == http.MethodDelete:
		delete(s.sb, parts[3])
		w.WriteHeader(http.StatusNoContent)
	default:
		reply(http.StatusNotFound, map[string]string{"error": "stand-in: " + r.Method + " " + r.URL.Path})
	}
}

// The SP-B "sandboxd" step (plan §4.3) judges AerolVM's own sandboxd on a
// Nitro node through its API: run against a stand-in that behaves, the
// verdict is go; with guests that cannot reach the internet it is NO GO.
// Only the steps asked for are judged, so a sandboxd-only run is not a
// failed SP-B for steps 1-4 it never ran.
func TestM2SPBSandboxdStepVerdict(t *testing.T) {
	needTools(t, "python3")
	for _, c := range []struct {
		name                          string
		noEgress, loseEnv, rawRefusal bool
		want                          string
	}{
		{"guests reach the internet and keep their env across a start", false, false, false, "VERDICT SP-B: go"},
		{"guests cannot reach the internet", true, false, false, "VERDICT SP-B: NO GO"},
		{"a start loses the env", false, true, false, "VERDICT SP-B: NO GO"},
		{"the budget is Firecracker's refusal, not AerolVM's", false, false, true, "VERDICT SP-B: NO GO"},
	} {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(&nitroStandIn{noEgress: c.noEgress, loseEnv: c.loseEnv, rawRefusal: c.rawRefusal})
			defer srv.Close()
			dir := t.TempDir()
			pat, results := filepath.Join(dir, "pat"), filepath.Join(dir, "results.jsonl")
			if err := os.WriteFile(pat, []byte("standin\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			spb := k8sFile(t, "m2", "spb.py")
			// Not -I: spb.py imports spb_sandboxd from its own folder, as
			// it does on the node (spb-run.sh).
			run := exec.Command("python3", spb, "sandboxd", "--samples", "3", "--results", results)
			run.Env = append(os.Environ(), "SPB_API="+srv.URL, "SPB_PAT_FILE="+pat)
			run.Dir = filepath.Dir(spb)
			if out, err := run.CombinedOutput(); err != nil {
				t.Fatalf("spb.py sandboxd: %v\n%s", err, out)
			}
			v := exec.Command("python3", spb, "verdict", "--results", results, "--steps", "sandboxd")
			v.Dir = filepath.Dir(spb)
			out, _ := v.CombinedOutput()
			if !strings.Contains(string(out), c.want) || strings.Contains(string(out), "VERDICT step1") {
				t.Fatalf("verdict: want %q and no step1 line\n%s", c.want, out)
			}
		})
	}
}
