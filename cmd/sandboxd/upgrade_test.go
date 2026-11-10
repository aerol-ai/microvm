package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/nodeupgrade"
	"github.com/aerol-ai/microvm/pkg/daemon"
)

// cliHost is a machine for the command-line tests: sandboxd runs `target`
// once restarted.
type cliHost struct {
	running string
	target  string
	runs    []string
	runErr  error
}

func (h *cliHost) UnitActive(_ context.Context, unit string) bool { return unit == "sandboxd" }
func (h *cliHost) StopUnit(context.Context, string) error         { h.running = ""; return nil }
func (h *cliHost) StartUnit(context.Context, string) error        { return nil }
func (h *cliHost) RestartUnit(_ context.Context, unit string) error {
	if unit == "sandboxd" {
		h.running = h.target
	}
	return nil
}
func (h *cliHost) UnitControlGroup(context.Context, string) string { return "" }
func (h *cliHost) LookPath(name string) (string, error)            { return "/usr/bin/" + name, nil }
func (h *cliHost) FreeBytes(string) (uint64, uint64, error)        { return 1 << 40, 1, nil }
func (h *cliHost) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	h.runs = append(h.runs, filepath.Base(name)+" "+strings.Join(args, " "))
	return []byte("ran\n"), h.runErr
}
func (h *cliHost) Fetch(context.Context, string) (io.ReadCloser, int64, error) {
	return nil, 0, errors.New("offline")
}
func (h *cliHost) HealthVersion(context.Context, string) (string, error) {
	if h.running == "" {
		return "", errors.New("connection refused")
	}
	return h.running, nil
}
func (h *cliHost) GatewayProtocol(context.Context, string) (int, error) { return 0, errors.New("none") }
func (h *cliHost) StartDrain(string) (int, error)                       { return 0, errors.New("none") }

// cliNode is a node in a temp dir: installed binaries, the files of
// v0.6.12 in a --from directory, and the seams pointed at them.
type cliNode struct {
	paths nodeupgrade.Paths
	from  string
	sums  map[string]string
	host  *cliHost
}

func newCLINode(t *testing.T) *cliNode {
	t.Helper()
	dir := t.TempDir()
	n := &cliNode{
		paths: nodeupgrade.Paths{
			EnvFile: filepath.Join(dir, "sandboxd.env"), NodeJSON: filepath.Join(dir, "node.json"),
			StateDir: filepath.Join(dir, "upgrade"), DBPath: filepath.Join(dir, "state.db"),
			Sandboxd: filepath.Join(dir, "bin", "sandboxd"), Toolboxd: filepath.Join(dir, "bin", "toolboxd"),
			CgroupRoot: filepath.Join(dir, "cgroup"), ProcRoot: filepath.Join(dir, "proc"),
			HealthURL: "http://127.0.0.1:21212/health", ReleaseURL: "https://releases.example",
		},
		from: filepath.Join(dir, "from"),
		sums: map[string]string{},
		host: &cliHost{running: "v0.6.11", target: "v0.6.12"},
	}
	write := func(path, content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write(n.paths.Sandboxd, "old sandboxd\n")
	write(n.paths.Toolboxd, "old toolboxd\n")
	for name, content := range map[string]string{"sandboxd": "new sandboxd\n", "toolboxd": "new toolboxd\n"} {
		write(filepath.Join(n.from, name), content)
		s := sha256.Sum256([]byte(content))
		n.sums[name] = hex.EncodeToString(s[:])
	}
	origHost, origPaths, origSig := newUpgradeHost, resolveUpgradePaths, upgradeSignalContext
	t.Cleanup(func() { newUpgradeHost, resolveUpgradePaths, upgradeSignalContext = origHost, origPaths, origSig })
	newUpgradeHost = func() nodeupgrade.Host { return n.host }
	resolveUpgradePaths = func(string) (nodeupgrade.Paths, error) { return n.paths, nil }
	upgradeSignalContext = func() (context.Context, context.CancelFunc) {
		return context.WithTimeout(context.Background(), time.Minute)
	}
	return n
}

func (n *cliNode) args(version string, extra ...string) []string {
	args := []string{"node", version, "--from", n.from, "--health-timeout", "200ms"}
	for name, sum := range n.sums {
		args = append(args, "--sha256", name+"="+sum)
	}
	return append(args, extra...)
}

func TestParseUpgradeArgs(t *testing.T) {
	h := strings.Repeat("a", 64)
	cases := []struct {
		name    string
		args    []string
		want    nodeupgrade.Request
		output  string
		envFile string
		wantErr string
	}{
		{name: "version first", args: []string{"node", "v0.6.12", "--sha256", "sandboxd=" + h, "-o", "json"},
			want: nodeupgrade.Request{Version: "v0.6.12", SHA256: map[string]string{"sandboxd": h}}, output: "json", envFile: nodeupgrade.DefaultEnvFile},
		{name: "flags first", args: []string{"node", "--rollback", "--op", "x", "--env-file", "/e", "v0.6.11", "--health-timeout", "5s"},
			want: nodeupgrade.Request{Version: "v0.6.11", Rollback: true, Op: "x", HealthTimeout: 5 * time.Second}, output: "text", envFile: "/e"},
		{name: "every switch", args: []string{"node", "v1.0.0", "--allow-unversioned", "--skip-host-apply", "--from", "/d", "--output", "text"},
			want: nodeupgrade.Request{Version: "v1.0.0", AllowUnversioned: true, SkipHostApply: true, From: "/d"}, output: "text", envFile: nodeupgrade.DefaultEnvFile},
		{name: "not node", args: []string{"cluster"}, wantErr: "only upgrade command"},
		{name: "nothing", args: nil, wantErr: "only upgrade command"},
		{name: "no version", args: []string{"node", "--rollback"}, wantErr: "missing <version>"},
		{name: "two versions", args: []string{"node", "v1", "v2"}, wantErr: `unexpected argument "v2"`},
		{name: "bad output", args: []string{"node", "v1", "-o", "yaml"}, wantErr: "-o must be text or json"},
		{name: "bad sha256", args: []string{"node", "v1", "--sha256", "sandboxd"}, wantErr: "<file>=<hash>"},
		{name: "repeated sha256", args: []string{"node", "v1", "--sha256", "a=" + h, "--sha256", "a=" + h}, wantErr: "names a twice"},
		{name: "unknown flag", args: []string{"node", "v1", "--force"}, wantErr: "flag provided but not defined"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, envFile, output, err := parseUpgradeArgs(tc.args)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(req, tc.want) || output != tc.output || envFile != tc.envFile {
				t.Fatalf("got %+v %q %q, want %+v %q %q", req, output, envFile, tc.want, tc.output, tc.envFile)
			}
		})
	}
	for _, help := range [][]string{{"--help"}, {"-h"}, {"node", "--help"}, {"node", "v1", "-h"}} {
		if _, _, _, err := parseUpgradeArgs(help); !errors.Is(err, flag.ErrHelp) {
			t.Fatalf("%v: %v", help, err)
		}
	}
}

// nodeupgrade.Request.Args is what Launch passes to systemd-run and what an
// operator is told to type; it must parse back to the same request.
func TestUpgradeArgsRoundTrip(t *testing.T) {
	req := nodeupgrade.Request{Version: "v0.6.12", From: "/srv/a b", Rollback: true, AllowUnversioned: true, SkipHostApply: true,
		Op: "op-1", HealthTimeout: 90 * time.Second, SHA256: map[string]string{"sandboxd": "x", "release.json": "y"}}
	args := req.Args()
	if args[0] != upgradeSubcommand {
		t.Fatalf("args = %q", args)
	}
	got, _, _, err := parseUpgradeArgs(args[1:])
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, req) {
		t.Fatalf("round trip = %+v, want %+v", got, req)
	}
}

// install.sh and the upgrader look for these texts in a binary before they
// run the command; the usage must keep carrying them.
func TestUsageCarriesTheCommandMarkers(t *testing.T) {
	if !strings.HasPrefix(upgradeUsage, nodeupgrade.UpgradeCommandMarker) {
		t.Fatalf("upgrade usage does not start with %q", nodeupgrade.UpgradeCommandMarker)
	}
	if !strings.HasPrefix(versionUsage, nodeupgrade.VersionCommandMarker) {
		t.Fatalf("version usage does not start with %q", nodeupgrade.VersionCommandMarker)
	}
	raw, err := os.ReadFile("../../scripts/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "grep -aqF '"+nodeupgrade.UpgradeCommandMarker+"' \"$bin\"") {
		t.Fatal("install.sh no longer probes for the upgrade usage text")
	}
}

func TestRunUpgradeCLI(t *testing.T) {
	t.Run("json", func(t *testing.T) {
		n := newCLINode(t)
		var stdout, stderr bytes.Buffer
		if code := runUpgradeCLI(n.args("v0.6.12", "-o", "json"), &stdout, &stderr); code != 0 {
			t.Fatalf("exit %d\n%s", code, stderr.String())
		}
		var st nodeupgrade.State
		if err := json.Unmarshal(stdout.Bytes(), &st); err != nil {
			t.Fatalf("stdout is not the record: %v\n%s", err, stdout.String())
		}
		if st.Result != nodeupgrade.ResultUpgraded || st.Version != "v0.6.12" {
			t.Fatalf("record = %+v", st)
		}
		if !strings.Contains(stderr.String(), "staged and verified") {
			t.Fatalf("progress did not go to stderr: %s", stderr.String())
		}
		// The install.sh this binary carries is the host setup it assumes.
		if b, _ := os.ReadFile(n.paths.Sandboxd); string(b) != "new sandboxd\n" {
			t.Fatalf("sandboxd = %q", b)
		}
	})
	t.Run("text, then a noop", func(t *testing.T) {
		n := newCLINode(t)
		var stdout, stderr bytes.Buffer
		if code := runUpgradeCLI(n.args("v0.6.12"), &stdout, &stderr); code != 0 {
			t.Fatalf("exit %d\n%s", code, stderr.String())
		}
		if !strings.Contains(stdout.String(), "upgraded to v0.6.12") {
			t.Fatalf("stdout: %s", stdout.String())
		}
		stdout.Reset()
		if code := runUpgradeCLI(n.args("v0.6.12"), &stdout, &stderr); code != 0 {
			t.Fatalf("second run exit %d", code)
		}
		if !strings.Contains(stdout.String(), "v0.6.12 is already installed") {
			t.Fatalf("second run: %s", stdout.String())
		}
	})
	t.Run("failure puts the files back and exits 1", func(t *testing.T) {
		n := newCLINode(t)
		n.host.target = "" // the new sandboxd never answers
		var stdout, stderr bytes.Buffer
		if code := runUpgradeCLI(n.args("v0.6.12", "-o", "json"), &stdout, &stderr); code != 1 {
			t.Fatalf("exit %d\n%s", code, stderr.String())
		}
		if b, _ := os.ReadFile(n.paths.Sandboxd); string(b) != "old sandboxd\n" {
			t.Fatalf("sandboxd = %q after a failed upgrade", b)
		}
		if !strings.Contains(stdout.String(), `"phase": "failed"`) {
			t.Fatalf("no failed record on stdout: %s", stdout.String())
		}
	})
	t.Run("usage errors exit 2", func(t *testing.T) {
		n := newCLINode(t)
		var stdout, stderr bytes.Buffer
		if code := runUpgradeCLI([]string{"node"}, &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "usage: sandboxd upgrade node") {
			t.Fatalf("exit %d: %s", code, stderr.String())
		}
		stderr.Reset()
		if code := runUpgradeCLI([]string{"node", "../x", "--sha256", "sandboxd=" + n.sums["sandboxd"]}, &stdout, &stderr); code != 2 {
			t.Fatalf("a bad version exited %d: %s", code, stderr.String())
		}
	})
	t.Run("help exits 0", func(t *testing.T) {
		var stdout bytes.Buffer
		if code := runUpgradeCLI([]string{"node", "--help"}, &stdout, io.Discard); code != 0 || !strings.HasPrefix(stdout.String(), "usage: sandboxd upgrade node") {
			t.Fatalf("exit %d: %s", code, stdout.String())
		}
	})
	t.Run("paths that cannot be read exit 1", func(t *testing.T) {
		newCLINode(t)
		resolveUpgradePaths = func(string) (nodeupgrade.Paths, error) { return nodeupgrade.Paths{}, errors.New("env file unreadable") }
		var stderr bytes.Buffer
		if code := runUpgradeCLI([]string{"node", "v1.0.0", "--rollback"}, io.Discard, &stderr); code != 1 || !strings.Contains(stderr.String(), "env file unreadable") {
			t.Fatalf("exit %d: %s", code, stderr.String())
		}
	})
}

func TestRunHostCLI(t *testing.T) {
	n := newCLINode(t)
	orig := hostApplyScript
	t.Cleanup(func() { hostApplyScript = orig })
	hostApplyScript = []byte("#!/usr/bin/env bash\n\t\t--domain)\n")
	if err := os.WriteFile(n.paths.NodeJSON, []byte(`{"format": 1, "domain": "sb.example.com"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := runHostCLI([]string{"apply"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if len(n.host.runs) != 1 || !strings.HasPrefix(n.host.runs[0], "bash ") || !strings.HasSuffix(n.host.runs[0], " --config-only --domain sb.example.com") {
		t.Fatalf("runs = %q", n.host.runs)
	}
	other := filepath.Join(t.TempDir(), "other.json")
	if err := os.WriteFile(other, []byte(`{"format": 1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := runHostCLI([]string{"apply", "--node-json", other}, &stdout, &stderr); code != 0 || !strings.HasSuffix(n.host.runs[1], "--config-only") {
		t.Fatalf("exit %d, runs %q", code, n.host.runs)
	}
	for _, tc := range []struct {
		args []string
		code int
		want string
	}{
		{nil, 2, "the only command is"},
		{[]string{"apply", "extra"}, 2, `unexpected argument "extra"`},
		{[]string{"apply", "--bogus"}, 2, "flag provided but not defined"},
	} {
		stderr.Reset()
		if code := runHostCLI(tc.args, io.Discard, &stderr); code != tc.code || !strings.Contains(stderr.String(), tc.want) {
			t.Errorf("%v: exit %d, %s", tc.args, code, stderr.String())
		}
	}
	for _, help := range [][]string{{"--help"}, {"apply", "-h"}} {
		stdout.Reset()
		if code := runHostCLI(help, &stdout, io.Discard); code != 0 || !strings.HasPrefix(stdout.String(), "usage: sandboxd host apply") {
			t.Errorf("%v: exit %d", help, code)
		}
	}
	n.host.runErr = errors.New("exit status 1")
	stderr.Reset()
	if code := runHostCLI([]string{"apply"}, io.Discard, &stderr); code != 1 || !strings.Contains(stderr.String(), "install.sh --config-only") {
		t.Fatalf("a failing install.sh: exit %d, %s", code, stderr.String())
	}
	resolveUpgradePaths = func(string) (nodeupgrade.Paths, error) { return nodeupgrade.Paths{}, errors.New("no env") }
	if code := runHostCLI([]string{"apply"}, io.Discard, &stderr); code != 1 {
		t.Fatalf("unreadable paths: exit %d", code)
	}
}

// `sandboxd upgrade` and `sandboxd host` never boot the daemon, and exit
// with the command's status.
func TestMainDispatchesUpgradeAndHost(t *testing.T) {
	origDaemon := runDaemon
	t.Cleanup(func() { runDaemon = origDaemon })
	runDaemon = func(context.Context, *slog.Logger, daemon.ProviderFactory) error {
		t.Fatal("an upgrade or host command started the daemon")
		return nil
	}
	origExit := osExit
	t.Cleanup(func() { osExit = origExit })
	origArgs := os.Args
	t.Cleanup(func() { os.Args = origArgs })
	for _, tc := range []struct {
		args []string
		code int
	}{
		{[]string{"upgrade", "node", "--help"}, -1},
		{[]string{"upgrade", "bogus"}, 2},
		{[]string{"host", "--help"}, -1},
		{[]string{"host", "bogus"}, 2},
	} {
		exitCode := -1
		osExit = func(code int) { exitCode = code }
		os.Args = append([]string{"sandboxd"}, tc.args...)
		_ = captureStd(t, &os.Stderr, func() { _ = captureStd(t, &os.Stdout, main) })
		if exitCode != tc.code {
			t.Fatalf("%v: exit %d, want %d", tc.args, exitCode, tc.code)
		}
	}
}

// The real seams resolve the node's paths from its env file and build a
// systemd host.
func TestUpgradeSeamsDefault(t *testing.T) {
	env := filepath.Join(t.TempDir(), "sandboxd.env")
	if err := os.WriteFile(env, []byte("SB_DB_PATH=/data/state.db\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := resolveUpgradePaths(env)
	if err != nil || p.StateDir != "/data/upgrade" {
		t.Fatalf("%+v %v", p, err)
	}
	if _, ok := newUpgradeHost().(*nodeupgrade.SystemHost); !ok {
		t.Fatal("the default host is not the systemd one")
	}
	ctx, cancel := upgradeSignalContext()
	cancel()
	<-ctx.Done()
}
