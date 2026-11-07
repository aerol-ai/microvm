package nodeupgrade

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A script that knows these flags, as install.sh's case arms spell them.
const fakeInstallSh = "#!/usr/bin/env bash\nwhile [[ $# -gt 0 ]]; do\n\tcase \"$1\" in\n" +
	"\t\t--domain)\n\t\t\tshift 2 ;;\n" +
	"\t\t--node-name)\n\t\t\tshift 2 ;;\n" +
	"\t\t--with-gvisor)\n\t\t\tshift ;;\n" +
	"\t\t--with-isolate)\n\t\t\tshift ;;\n" +
	"\t\t--idle-timeout-min)\n\t\t\tshift 2 ;;\n" +
	"\t\t*)\n\t\t\tshift ;;\n" +
	"\tesac\ndone\n"

// host apply passes node.json's settings to install.sh --config-only as
// separate arguments (§8): a value with spaces, quotes or shell syntax is
// one argument and is never interpreted.
func TestHostApplyPassesNodeSettingsAsSeparateArguments(t *testing.T) {
	dir := t.TempDir()
	node := filepath.Join(dir, "node.json")
	writeFile(t, node, []byte(`{
  "format": 1,
  "domain": "sb.example.com",
  "node_name": "edge 1; rm -rf / \"$(id)\"",
  "with_gvisor": true,
  "with_isolate": false,
  "idle_timeout_min": 30,
  "unknown_to_this_script": "x",
  "public_host": ""
}`))
	var got []string
	h := &argHost{run: func(name string, args ...string) ([]byte, error) {
		got = append([]string{name}, args...)
		// The script is a real file while it runs.
		if b, err := os.ReadFile(args[0]); err != nil || string(b) != fakeInstallSh {
			t.Fatalf("script file: %q %v", b, err)
		}
		return []byte("re-rendered\n"), nil
	}}
	var out bytes.Buffer
	state := filepath.Join(dir, "upgrade")
	if err := HostApply(context.Background(), HostApplyOptions{Script: []byte(fakeInstallSh), NodeJSON: node, StateDir: state, Host: h, Out: &out}); err != nil {
		t.Fatal(err)
	}
	want := []string{"bash", "", "--config-only", "--domain", "sb.example.com", "--idle-timeout-min", "30",
		"--node-name", "edge 1; rm -rf / \"$(id)\"", "--with-gvisor"}
	got[1] = ""
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("args =\n%q\nwant\n%q", got, want)
	}
	if out.String() != "re-rendered\n" {
		t.Fatalf("output = %q", out.String())
	}
	if InstalledHostSetup(state, "") != sum([]byte(fakeInstallSh)) {
		t.Fatal("the applied script's hash was not recorded")
	}
	left, _ := filepath.Glob(filepath.Join(state, "install-*.sh"))
	if len(left) != 0 {
		t.Fatalf("the script file was left behind: %v", left)
	}
}

// The real thing: bash runs the written script, and each argument arrives
// as itself.
func TestHostApplyRunsTheScriptWithBash(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not found")
	}
	dir := t.TempDir()
	node := filepath.Join(dir, "node.json")
	writeFile(t, node, []byte(`{"format": 1, "node_name": "a b $(c)"}`))
	// It prints its arguments before its flag loop consumes them.
	script := "#!/usr/bin/env bash\nprintf '[%s]' \"$@\" > " + filepath.Join(dir, "argv") + "\n" + strings.TrimPrefix(fakeInstallSh, "#!/usr/bin/env bash\n")
	if err := HostApply(context.Background(), HostApplyOptions{Script: []byte(script), NodeJSON: node, StateDir: filepath.Join(dir, "upgrade"), Host: &SystemHost{}}); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, filepath.Join(dir, "argv")); got != "[--config-only][--node-name][a b $(c)]" {
		t.Fatalf("argv = %s", got)
	}
}

func TestHostApplyFailures(t *testing.T) {
	dir := t.TempDir()
	ok := &argHost{run: func(string, ...string) ([]byte, error) { return nil, nil }}
	cases := []struct {
		name string
		node string // "" leaves node.json absent
		host Host
		opts func(o *HostApplyOptions)
		want string
	}{
		{name: "no script", opts: func(o *HostApplyOptions) { o.Script = nil }, host: ok, want: "no install.sh"},
		{name: "script fails", host: &argHost{run: func(string, ...string) ([]byte, error) {
			return []byte("refusing: no sandboxd.env"), errors.New("exit status 1")
		}}, want: "refusing: no sandboxd.env"},
		{name: "broken node.json", node: "{", host: ok, want: "unexpected EOF"},
		{name: "bad key", node: `{"Domain": "x"}`, host: ok, want: "not a setting name"},
		{name: "control character", node: `{"domain": "a\nb"}`, host: ok, want: "control character"},
		{name: "fraction", node: `{"idle_timeout_min": 1.5}`, host: ok, want: "whole number"},
		{name: "a list", node: `{"domain": ["a"]}`, host: ok, want: "not a string, number"},
		{name: "state dir is a file", host: ok, opts: func(o *HostApplyOptions) {
			writeFile(t, filepath.Join(dir, "afile"), []byte("x"))
			o.StateDir = filepath.Join(dir, "afile")
		}, want: "not a directory"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			node := filepath.Join(t.TempDir(), "node.json")
			if tc.node != "" {
				writeFile(t, node, []byte(tc.node))
			}
			o := HostApplyOptions{Script: []byte(fakeInstallSh), NodeJSON: node, StateDir: filepath.Join(t.TempDir(), "u"), Host: tc.host}
			if tc.opts != nil {
				tc.opts(&o)
			}
			err := HostApply(context.Background(), o)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
	// No node.json: no flags; install.sh reads sandboxd.env back itself.
	var args []string
	h := &argHost{run: func(_ string, a ...string) ([]byte, error) { args = a; return nil, nil }}
	if err := HostApply(context.Background(), HostApplyOptions{Script: []byte(fakeInstallSh), NodeJSON: filepath.Join(dir, "none.json"), StateDir: filepath.Join(dir, "u2"), Host: h}); err != nil {
		t.Fatal(err)
	}
	if len(args) != 2 || args[1] != "--config-only" {
		t.Fatalf("args = %q", args)
	}
	if _, err := nodeSettingsArgs(dir, []byte(fakeInstallSh)); err == nil {
		t.Fatal("read a directory as node.json")
	}
}

// argHost is a Host whose Run is a function; the rest is unused here.
type argHost struct {
	fakeHost
	run func(name string, args ...string) ([]byte, error)
}

func (h *argHost) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	return h.run(name, args...)
}

// Launch starts the upgrader in its own transient unit, every value a
// separate argument.
func TestLaunchStartsTheUpgraderUnderSystemdRun(t *testing.T) {
	var name string
	var args []string
	h := &argHost{run: func(n string, a ...string) ([]byte, error) { name, args = n, a; return nil, nil }}
	req := Request{Version: "v0.6.12", SHA256: map[string]string{"sandboxd": strings.Repeat("a", 64), "toolboxd": strings.Repeat("b", 64)}, From: "/srv/rel ease", Op: "op-7"}
	op, err := Launch(context.Background(), h, "/usr/local/bin/sandboxd", req)
	if err != nil || op != "op-7" {
		t.Fatalf("%q %v", op, err)
	}
	want := []string{"--unit=aerolvm-upgrade-op-7", "--description=AerolVM node upgrade op-7", "--collect", "--quiet", "--",
		"/usr/local/bin/sandboxd", "upgrade", "node", "v0.6.12",
		"--sha256", "sandboxd=" + strings.Repeat("a", 64), "--sha256", "toolboxd=" + strings.Repeat("b", 64),
		"--from", "/srv/rel ease", "--op", "op-7"}
	if name != "systemd-run" || strings.Join(args, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("%s %q", name, args)
	}
	// An op ID is made up when none is given.
	req.Op = ""
	if op, err := Launch(context.Background(), h, "/usr/local/bin/sandboxd", req); err != nil || !opRe.MatchString(op) {
		t.Fatalf("generated op %q %v", op, err)
	}
	if _, err := Launch(context.Background(), h, "sandboxd", req); err == nil {
		t.Fatal("a relative binary was launched")
	}
	if _, err := Launch(context.Background(), h, "/x", Request{Version: "v1"}); !errors.Is(err, ErrUsage) {
		t.Fatalf("an invalid request was launched: %v", err)
	}
	failing := &argHost{run: func(string, ...string) ([]byte, error) { return []byte("unit exists"), errors.New("exit 1") }}
	if _, err := Launch(context.Background(), failing, "/x", Request{Version: "v1.0.0", Rollback: true, Op: "o"}); err == nil || !strings.Contains(err.Error(), "unit exists") {
		t.Fatalf("systemd-run failure: %v", err)
	}
}
