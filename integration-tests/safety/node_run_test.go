package safety

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// lib/node-run.sh, scripts/run-on-node.sh and scripts/routing-ab.sh drive a
// kept scenario over SSH, so these tests run their pure helpers and their
// dry-run and refusal paths against fixture targets: no SSH, no terraform,
// no build, nothing that leaves this machine.

func integrationDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve test file path")
	}
	return filepath.Join(filepath.Dir(thisFile), "..")
}

func needTools(t *testing.T, tools ...string) {
	t.Helper()
	for _, tool := range append([]string{"bash"}, tools...) {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not on PATH", tool)
		}
	}
}

// nodeRun sources common.sh and node-run.sh and runs snippet. It returns
// stdout, stderr and the exit code.
func nodeRun(t *testing.T, snippet string, env ...string) (string, string, int) {
	t.Helper()
	lib := filepath.Join(integrationDir(t), "lib")
	cmd := exec.Command("bash", "-c", `set -u
source "$1/common.sh"
source "$1/node-run.sh"
`+snippet, "bash", lib)
	cmd.Env = append(os.Environ(), env...)
	var out, errb strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return out.String(), errb.String(), code
}

// The cluster-hetero-lite-routing shape: three servers (one the seed), one
// ingress, workers. Roles as Terraform renders them.
const heteroTargets = `{"base_url":"https://r.itest.example.com","domain":"r.itest.example.com","seed_ip":"203.0.113.1","nodes":[
 {"name":"server-1","role":"server","seed":true,"public_ip":"203.0.113.1"},
 {"name":"server-2","role":"server","seed":false,"public_ip":"203.0.113.2"},
 {"name":"server-3","role":"server","seed":false,"public_ip":"203.0.113.3"},
 {"name":"ingress-1","role":"ingress","seed":false,"public_ip":"203.0.113.4"},
 {"name":"worker-x","role":"worker","seed":false,"public_ip":"203.0.113.5"}]}`

func TestPickGateNode(t *testing.T) {
	needTools(t, "jq")
	cases := []struct {
		name, targets, want, wantErr string
		node                         string
	}{
		// Not the seed: it also mints the suite's token and answers the
		// harness's own checks.
		{name: "default is a non-seed server", targets: heteroTargets, want: "server-2\t203.0.113.2"},
		{name: "an explicit node wins", targets: heteroTargets, node: "worker-x", want: "worker-x\t203.0.113.5"},
		{name: "unknown node", targets: heteroTargets, node: "server-9", wantErr: "node server-9 is not in this scenario"},
		{name: "the seed when it is the only server", want: "s\t198.51.100.1", targets: `{"nodes":[
			{"name":"w","role":"worker","public_ip":"198.51.100.2"},{"name":"s","role":"server","seed":true,"public_ip":"198.51.100.1"}]}`},
		// A combined role serves traffic: not a quiet place to measure from.
		{name: "mixed and combined roles never default", wantErr: "no server-only node", targets: `{"nodes":[
			{"name":"node1","role":"mixed","seed":true,"public_ip":"198.51.100.1"},{"name":"node2","role":"server, ingress","public_ip":"198.51.100.2"}]}`},
		{name: "no public IP", wantErr: "has no public IP", targets: `{"nodes":[{"name":"s","role":"server","public_ip":""}]}`},
		// A blank node has no sandboxd to run from, even with role server.
		{name: "a blank server never defaults", want: "s\t198.51.100.1", targets: `{"nodes":[
			{"name":"a-spare","role":"server","blank":true,"public_ip":"198.51.100.9"},{"name":"s","role":"server","seed":true,"public_ip":"198.51.100.1"}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, errOut, code := nodeRun(t, `pick_gate_node "$TARGETS" "$NODE"`, "TARGETS="+tc.targets, "NODE="+tc.node)
			if tc.wantErr != "" {
				if code == 0 || !strings.Contains(errOut, tc.wantErr) {
					t.Fatalf("pick_gate_node = %d %q %q, want refusal %q", code, out, errOut, tc.wantErr)
				}
				return
			}
			if code != 0 || strings.TrimSpace(out) != tc.want {
				t.Fatalf("pick_gate_node = %d %q (stderr %q), want %q", code, out, errOut, tc.want)
			}
		})
	}
}

func TestNodesSeedFirst(t *testing.T) {
	needTools(t, "jq")
	targets := `{"nodes":[{"name":"b","role":"worker","public_ip":"1.1.1.2"},{"name":"a","role":"server, ingress","seed":true,"public_ip":"1.1.1.1"}]}`
	out, errOut, code := nodeRun(t, `nodes_seed_first "$TARGETS"`, "TARGETS="+targets)
	want := "a\tserver,ingress\tseed\t1.1.1.1\nb\tworker\t-\t1.1.1.2\n"
	if code != 0 || out != want {
		t.Fatalf("nodes_seed_first = %d %q (stderr %q), want %q", code, out, errOut, want)
	}
	// A blank node has not joined: nothing to restart on it.
	withBlank := `{"nodes":[{"name":"b","role":"worker","public_ip":"1.1.1.2"},{"name":"spare-server","role":"server","blank":true,"public_ip":"1.1.1.3"},{"name":"a","role":"server, ingress","seed":true,"public_ip":"1.1.1.1"}]}`
	if out, errOut, code := nodeRun(t, `nodes_seed_first "$TARGETS"`, "TARGETS="+withBlank); code != 0 || out != want {
		t.Fatalf("nodes_seed_first with a blank node = %d %q (stderr %q), want %q", code, out, errOut, want)
	}
}

func TestGoarchFor(t *testing.T) {
	needTools(t)
	for in, want := range map[string]string{"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"} {
		out, _, code := nodeRun(t, `goarch_for "$A"`, "A="+in)
		if code != 0 || strings.TrimSpace(out) != want {
			t.Errorf("goarch_for %s = %d %q, want %s", in, code, out, want)
		}
	}
	if _, errOut, code := nodeRun(t, `goarch_for riscv64`); code == 0 || !strings.Contains(errOut, "unsupported") {
		t.Errorf("goarch_for riscv64 = %d %q, want a refusal", code, errOut)
	}
}

// The env file carries the targets JSON (quotes everywhere) and the tokens;
// both must arrive byte for byte when the node sources it, and the file must
// be private.
func TestWriteEnvFileRoundTrips(t *testing.T) {
	needTools(t)
	file := filepath.Join(t.TempDir(), "suite.env")
	targets := `{"base_url":"https://x","nodes":[{"name":"a b","role":"server"}]}`
	token := `avm_x$HOME'"; rm -rf /tmp/nope`
	_, errOut, code := nodeRun(t, `write_env_file "$F" AEROL_INTEGRATION_TARGETS "$T" AEROL_PAT "$P" AEROL_EMPTY ""
set -a; . "$F"; set +a
[ "$AEROL_INTEGRATION_TARGETS" = "$T" ] || { echo targets differ >&2; exit 1; }
[ "$AEROL_PAT" = "$P" ] || { echo token differs >&2; exit 1; }
[ -z "$AEROL_EMPTY" ] || exit 1`, "F="+file, "T="+targets, "P="+token)
	if code != 0 {
		t.Fatalf("round trip failed: %s", errOut)
	}
	st, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		t.Fatalf("env file mode %v: it holds tokens and must be private", st.Mode().Perm())
	}
}

func TestAerolPassthroughNames(t *testing.T) {
	needTools(t)
	out, _, code := nodeRun(t, `aerol_passthrough_names AEROL_PAT AEROL_BASE_URL`,
		"AEROL_PAT=x", "AEROL_BASE_URL=y", "AEROL_OVERLOAD_SECONDS=30", "AEROL_SSH_IDENTITY_FILE=/k", "AEROL_RUNSH_PINNED=/r", "NOT_AEROL=1")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	names := strings.Fields(out)
	has := func(n string) bool {
		for _, x := range names {
			if x == n {
				return true
			}
		}
		return false
	}
	if !has("AEROL_OVERLOAD_SECONDS") {
		t.Errorf("a tuning knob was not passed through: %v", names)
	}
	for _, n := range []string{"AEROL_PAT", "AEROL_BASE_URL", "AEROL_SSH_IDENTITY_FILE", "AEROL_RUNSH_PINNED", "NOT_AEROL"} {
		if has(n) {
			t.Errorf("%s passed through: %v", n, names)
		}
	}
}

// The A/B override runs against a temp root with sudo and systemctl
// replaced, and must (off) set the flag false in a drop-in that wins over
// cluster-init's cluster.conf but loses to the suite's own override, and
// (on) leave no file behind.
func TestABApplyScript(t *testing.T) {
	needTools(t)
	root := t.TempDir()
	run := func(action string) {
		t.Helper()
		script, errOut, code := nodeRun(t, `ab_apply_script "$A"`, "A="+action)
		if code != 0 {
			t.Fatalf("ab_apply_script %s: %s", action, errOut)
		}
		script = strings.ReplaceAll(script, "/etc/", root+"/etc/")
		cmd := exec.Command("bash", "-c", "sudo() { \"$@\"; }\nsystemctl() { :; }\n"+script)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("apply %s: %v\n%s", action, err, out)
		}
	}
	envFile := filepath.Join(root, "etc/sandboxd/ab-routing.env")
	dropIn := filepath.Join(root, "etc/systemd/system/sandboxd.service.d/zz-ab-routing.conf")
	if err := os.MkdirAll(filepath.Dir(envFile), 0o755); err != nil {
		t.Fatal(err)
	}

	run("off")
	env, err := os.ReadFile(envFile)
	if err != nil || !strings.Contains(string(env), "\nSB_INGRESS_PROXY_ROUTING=false\n") {
		t.Fatalf("off: env file = %q (%v)", env, err)
	}
	// The temp root was spliced into every /etc/ path, the drop-in's own
	// EnvironmentFile= line included.
	unit, err := os.ReadFile(dropIn)
	if err != nil || string(unit) != "[Service]\nEnvironmentFile="+envFile+"\n" {
		t.Fatalf("off: drop-in = %q (%v), want it to load %s", unit, err, envFile)
	}
	name := filepath.Base(dropIn)
	if !(name > "cluster.conf" && name < "zz-itest-override.conf") {
		t.Fatalf("drop-in %q must sort after cluster.conf and before the suite's zz-itest-override.conf", name)
	}

	run("on")
	for _, f := range []string{envFile, dropIn} {
		if _, err := os.Stat(f); !os.IsNotExist(err) {
			t.Errorf("on: %s still exists (%v)", f, err)
		}
	}
	if _, _, code := nodeRun(t, `ab_apply_script sideways`); code == 0 {
		t.Error("ab_apply_script accepted an unknown action")
	}
}

func TestABNodeSettled(t *testing.T) {
	needTools(t)
	probe := func(override, marker, static string) string {
		return "override=" + override + "\nconfigured=x\nmarker=" + marker + "\nstatic_route=" + static + "\nactive=active\n"
	}
	cases := []struct {
		name, role, want, probe string
		settled                 bool
	}{
		{"off: rolled back", "worker", "off", probe("present", "false", "no"), true},
		{"off: never engaged", "ingress", "off", probe("present", "none", "no"), true},
		{"off: override set but still engaged", "worker", "off", probe("present", "true", "yes"), false},
		{"off: static route left behind", "worker", "off", probe("present", "false", "yes"), false},
		{"off: no override yet", "worker", "off", probe("absent", "false", "no"), false},
		{"on: engaged and committed", "worker", "on", probe("absent", "true", "yes"), true},
		// The refusal the A/B must catch: the node came back on Caddy routes.
		{"on: engage refused", "ingress", "on", probe("absent", "false", "no"), false},
		{"on: engaged, commit not in yet", "worker", "on", probe("absent", "true", "no"), false},
		{"on: override still there", "worker", "on", probe("present", "true", "yes"), false},
		// A pure server never engages, so only its override counts.
		{"server off", "server", "off", probe("present", "none", "unknown"), true},
		{"server on", "server", "on", probe("absent", "none", "unknown"), true},
		{"unreachable node", "worker", "on", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, code := nodeRun(t, `ab_node_settled "$R" "$W" "$P"`, "R="+tc.role, "W="+tc.want, "P="+tc.probe)
			if (code == 0) != tc.settled {
				t.Fatalf("ab_node_settled = exit %d, want settled=%v", code, tc.settled)
			}
		})
	}
}

// runHarnessScript runs one of integration-tests/scripts with targets from the
// environment, so it never reaches terraform.
func runHarnessScript(t *testing.T, script string, env []string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command("bash", append([]string{filepath.Join(integrationDir(t), "scripts", script)}, args...)...)
	cmd.Dir = t.TempDir()
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return string(out), code
}

func TestRunOnNodeDryRun(t *testing.T) {
	needTools(t, "jq", "yq")
	env := []string{"AEROL_INTEGRATION_TARGETS=" + heteroTargets, "AEROL_OVERLOAD_SECONDS=30", "AEROL_PAT=laptop-token"}
	out, code := runHarnessScript(t, "run-on-node.sh", env, "cluster-hetero-lite-routing",
		"-run", "^TestIngressRoutingChurnGate$", "--label", "on-1", "--timeout", "45m", "--dry-run", "--", "-test.short")
	if code != 0 {
		t.Fatalf("dry run = %d:\n%s", code, out)
	}
	for _, want := range []string{
		"node=server-2\n", "node_ip=203.0.113.2\n", "base_url=https://r.itest.example.com\n",
		// A compiled test binary only knows -test.* flags.
		`test_args=-test.run \^TestIngressRoutingChurnGate\$ -test.count=1 -test.timeout 45m -test.v=test2json -test.short`,
		"/reports/run-on-node/cluster-hetero-lite-routing/", "-on-1\n",
		"passthrough=AEROL_OVERLOAD_SECONDS \n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("dry run lacks %q:\n%s", want, out)
		}
	}
}

func TestRunOnNodeRefusals(t *testing.T) {
	needTools(t, "jq", "yq")
	env := []string{"AEROL_INTEGRATION_TARGETS=" + heteroTargets}
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"no selection", []string{"cluster-hetero-lite-routing", "--dry-run"}, "-run '<regex>' is required"},
		{"unknown scenario", []string{"no-such-scenario", "-run", "x", "--dry-run"}, "unknown scenario no-such-scenario"},
		{"unsafe scenario", []string{"a;b", "-run", "x", "--dry-run"}, "unsafe characters"},
		{"unsafe label", []string{"cluster-hetero-lite-routing", "-run", "x", "--label", "../x", "--dry-run"}, "--label may hold only"},
		{"bad timeout", []string{"cluster-hetero-lite-routing", "-run", "x", "--timeout", "1d", "--dry-run"}, "--timeout must be"},
		{"go test flag before --", []string{"cluster-hetero-lite-routing", "-run", "x", "-v", "--dry-run"}, "test-binary flags go after --"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, code := runHarnessScript(t, "run-on-node.sh", env, tc.args...)
			if code == 0 || !strings.Contains(out, tc.want) {
				t.Fatalf("run-on-node.sh %v = %d, want refusal %q:\n%s", tc.args, code, tc.want, out)
			}
		})
	}
	// Local mode has no public path to measure from a node.
	out, code := runHarnessScript(t, "run-on-node.sh", []string{`AEROL_INTEGRATION_TARGETS={"base_url":"http://localhost:21212","nodes":[]}`},
		"local-mode", "-run", "x", "--dry-run")
	if code == 0 || !strings.Contains(out, "no public base URL") {
		t.Fatalf("local-mode = %d:\n%s", code, out)
	}
}

// The A/B needs a scenario installed with routing on; anything else is
// refused before any node is touched (the targets here would fail loudly).
func TestRoutingABRefusesANonRoutingScenario(t *testing.T) {
	needTools(t, "jq", "yq")
	env := []string{`AEROL_INTEGRATION_TARGETS={"nodes":[{"name":"x","role":"mixed","public_ip":"192.0.2.1"}]}`}
	out, code := runHarnessScript(t, "routing-ab.sh", env, "cluster-3-mixed", "off")
	if code == 0 || !strings.Contains(out, "needs a -routing scenario") {
		t.Fatalf("routing-ab.sh cluster-3-mixed off = %d:\n%s", code, out)
	}
	for _, args := range [][]string{{"cluster-hetero-lite-routing"}, {"cluster-hetero-lite-routing", "sideways"}, {"a;b", "on"}} {
		if out, code := runHarnessScript(t, "routing-ab.sh", env, args...); code == 0 {
			t.Errorf("routing-ab.sh %v accepted:\n%s", args, out)
		}
	}
}
