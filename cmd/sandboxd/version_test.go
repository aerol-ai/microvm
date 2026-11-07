package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"reflect"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/internal/version"
	"github.com/aerol-ai/microvm/pkg/daemon"
)

func TestIsVersionArg(t *testing.T) {
	for _, tc := range []struct {
		arg  string
		want bool
	}{
		{"version", true}, {"--version", true}, {"-version", true}, {"-v", true},
		{"", false}, {"key", false}, {"--wasm-worker", false}, {"versions", false}, {"-vv", false},
	} {
		if got := isVersionArg(tc.arg); got != tc.want {
			t.Errorf("isVersionArg(%q) = %v, want %v", tc.arg, got, tc.want)
		}
	}
}

func stubBuildInfo(t *testing.T, info *debug.BuildInfo, ok bool) {
	t.Helper()
	orig := readBuildInfo
	t.Cleanup(func() { readBuildInfo = orig })
	readBuildInfo = func() (*debug.BuildInfo, bool) { return info, ok }
}

func TestBuildCommit(t *testing.T) {
	setting := func(kv ...string) *debug.BuildInfo {
		info := &debug.BuildInfo{}
		for i := 0; i < len(kv); i += 2 {
			info.Settings = append(info.Settings, debug.BuildSetting{Key: kv[i], Value: kv[i+1]})
		}
		return info
	}
	for _, tc := range []struct {
		name string
		info *debug.BuildInfo
		ok   bool
		want string
	}{
		{"no build info", nil, false, ""},
		{"no vcs stamp", setting("-trimpath", "true"), true, ""},
		{"clean checkout", setting("vcs.revision", "abc123", "vcs.modified", "false"), true, "abc123"},
		{"dirty checkout", setting("vcs.revision", "abc123", "vcs.modified", "true"), true, "abc123-dirty"},
		// A modified flag with no revision names nothing to be dirty.
		{"modified without revision", setting("vcs.modified", "true"), true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubBuildInfo(t, tc.info, tc.ok)
			if got := buildCommit(); got != tc.want {
				t.Fatalf("buildCommit() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRunVersionCLIText(t *testing.T) {
	stubBuildInfo(t, &debug.BuildInfo{Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "deadbeef"}}}, true)
	var out bytes.Buffer
	if err := runVersionCLI(nil, &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	// Scripts take the version from the first line alone.
	if lines[0] != "sandboxd "+version.Version {
		t.Fatalf("first line = %q, want %q", lines[0], "sandboxd "+version.Version)
	}
	for _, want := range []string{
		"commit:          deadbeef",
		"fsm ops version: " + strconv.Itoa(cluster.FSMOpsVersion()),
		"go:              " + runtime.Version(),
		"platform:        " + runtime.GOOS + "/" + runtime.GOARCH,
	} {
		if !strings.Contains(out.String(), want+"\n") {
			t.Errorf("output misses %q:\n%s", want, out.String())
		}
	}

	// No commit stamped: the line is left out, not printed empty.
	stubBuildInfo(t, nil, false)
	out.Reset()
	if err := runVersionCLI([]string{"-o", "text"}, &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "commit:") {
		t.Fatalf("an unstamped build printed a commit line:\n%s", out.String())
	}
}

func TestRunVersionCLIJSON(t *testing.T) {
	stubBuildInfo(t, &debug.BuildInfo{Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "deadbeef"}}}, true)
	for _, args := range [][]string{{"-o", "json"}, {"--output", "json"}, {"-o=json"}} {
		var out bytes.Buffer
		if err := runVersionCLI(args, &out); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		var got buildInfo
		if err := json.Unmarshal(out.Bytes(), &got); err != nil {
			t.Fatalf("%v: not JSON: %v\n%s", args, err, out.String())
		}
		want := buildInfo{Version: version.Version, Commit: "deadbeef", FSMOpsVersion: cluster.FSMOpsVersion(),
			EgressGatewayProtocol: egress.ProtocolVersion, Commands: []string{"upgrade-node", "host-apply"},
			GoVersion: runtime.Version(), Platform: runtime.GOOS + "/" + runtime.GOARCH}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%v: got %+v, want %+v", args, got, want)
		}
	}
}

func TestRunVersionCLIRejectsBadArgs(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"-o", "yaml"}, "-o must be text or json"},
		{[]string{"extra"}, `unexpected argument "extra"`},
		{[]string{"--frobnicate"}, "flag provided but not defined"},
	} {
		var out bytes.Buffer
		err := runVersionCLI(tc.args, &out)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("runVersionCLI(%v) = %v, want error %q", tc.args, err, tc.want)
		}
	}
	var out bytes.Buffer
	if err := runVersionCLI([]string{"-h"}, &out); err != nil || !strings.Contains(out.String(), "usage: sandboxd version") {
		t.Fatalf("-h = %v, output %q", err, out.String())
	}
}

// captureStd swaps os.Stdout or os.Stderr for a pipe while fn runs.
func captureStd(t *testing.T, std **os.File, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := *std
	*std = w
	defer func() { *std = orig }()
	fn()
	_ = w.Close()
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String()
}

// The bug this replaces: `sandboxd --version` booted the daemon. Every
// spelling must print the version and return without calling run().
func TestMainVersionNeverStartsTheDaemon(t *testing.T) {
	origDaemon := runDaemon
	t.Cleanup(func() { runDaemon = origDaemon })
	runDaemon = func(context.Context, *slog.Logger, daemon.ProviderFactory) error {
		t.Fatal("a version query started the daemon")
		return nil
	}
	origExit := osExit
	t.Cleanup(func() { osExit = origExit })
	origArgs := os.Args
	t.Cleanup(func() { os.Args = origArgs })

	for _, args := range [][]string{{"version"}, {"--version"}, {"-v"}, {"version", "-o", "json"}} {
		exitCode := -1
		osExit = func(code int) { exitCode = code }
		os.Args = append([]string{"sandboxd"}, args...)
		stdout := captureStd(t, &os.Stdout, main)
		if exitCode != -1 {
			t.Fatalf("%v: exit %d", args, exitCode)
		}
		if !strings.Contains(stdout, version.Version) {
			t.Fatalf("%v: stdout %q does not name version %q", args, stdout, version.Version)
		}
	}

	// A bad argument exits 2 with the usage, still without a daemon.
	exitCode := -1
	osExit = func(code int) { exitCode = code }
	os.Args = []string{"sandboxd", "--version", "-o", "yaml"}
	stderr := captureStd(t, &os.Stderr, main)
	if exitCode != 2 || !strings.Contains(stderr, "-o must be text or json") || !strings.Contains(stderr, "usage: sandboxd version") {
		t.Fatalf("bad -o: exit %d stderr %q", exitCode, stderr)
	}
}
