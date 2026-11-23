package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/nodeupgrade"
	"github.com/aerol-ai/microvm/internal/rootswap"
)

// `sandboxd upgrade recover` and `sandboxd upgrade root-helper` (M1 PR 10):
// the command lines. The work is internal/nodeupgrade's, tested there.

func TestRunUpgradeRecover(t *testing.T) {
	n := newCLINode(t)
	t.Cleanup(func() { recoverUpgrades = nodeupgrade.Recover })
	var dir string
	for _, tc := range []struct {
		name    string
		args    []string
		results []nodeupgrade.RecoverResult
		err     error
		code    int
		out     string
	}{
		{name: "nothing to settle", code: 0},
		{name: "settled", results: []nodeupgrade.RecoverResult{{Op: "op-1", Result: nodeupgrade.ResultRevertedAtBoot}}, out: "op op-1: reverted-at-boot"},
		{name: "settled with a problem", results: []nodeupgrade.RecoverResult{{Op: "op-2", Result: nodeupgrade.ResultCompletedAtBoot, Err: errors.New("caddy down")}}, code: 1, out: "caddy down"},
		{name: "cannot check", err: errors.New("permission denied"), code: 1, out: "permission denied"},
		{name: "help", args: []string{"--help"}, out: "usage: sandboxd upgrade recover"},
		{name: "a stray argument", args: []string{"now"}, code: 2, out: "unexpected argument"},
		{name: "an unknown flag", args: []string{"--op", "x"}, code: 2, out: "flag provided but not defined"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recoverUpgrades = func(_ context.Context, p nodeupgrade.Paths, _ nodeupgrade.Host, _ io.Writer) ([]nodeupgrade.RecoverResult, error) {
				dir = p.StateDir
				return tc.results, tc.err
			}
			var out bytes.Buffer
			if code := runUpgradeCLI(append([]string{"recover"}, tc.args...), &out, &out); code != tc.code {
				t.Fatalf("code %d, want %d: %s", code, tc.code, out.String())
			}
			if !strings.Contains(out.String(), tc.out) {
				t.Fatalf("output %q, want %q", out.String(), tc.out)
			}
		})
	}
	if dir != n.paths.StateDir {
		t.Fatalf("settled %s, want the node's upgrade folder %s", dir, n.paths.StateDir)
	}
	resolveUpgradePaths = func(string) (nodeupgrade.Paths, error) { return nodeupgrade.Paths{}, errors.New("env file unreadable") }
	var out bytes.Buffer
	if code := runUpgradeCLI([]string{"recover"}, &out, &out); code != 1 || !strings.Contains(out.String(), "unreadable") {
		t.Fatalf("code %d: %s", code, out.String())
	}
}

func TestRunUpgradeRootHelper(t *testing.T) {
	n := newCLINode(t)
	t.Cleanup(func() { installRootHelper = nodeupgrade.InstallRootHelper })
	var gotFrom, gotDir string
	var gotOlder bool
	result := nodeupgrade.RootHelperResult{Manifest: rootswap.Manifest{Version: "v0.7.8", API: 3}, Changed: true}
	var fail error
	installRootHelper = func(from, dir string, allowOlder bool) (nodeupgrade.RootHelperResult, error) {
		gotFrom, gotDir, gotOlder = from, dir, allowOlder
		return result, fail
	}
	run := func(args ...string) (int, string) {
		var out bytes.Buffer
		code := runUpgradeCLI(append([]string{"root-helper"}, args...), &out, &out)
		return code, out.String()
	}
	// A node not split yet: the default folder.
	if code, out := run("--from", "/tmp/stage"); code != 0 || !strings.Contains(out, "installed root helper v0.7.8 (API 3)") {
		t.Fatalf("code %d: %s", code, out)
	}
	if gotFrom != "/tmp/stage" || gotDir != nodeupgrade.DefaultRootdDir || gotOlder {
		t.Fatalf("installed from %s into %s (older %v)", gotFrom, gotDir, gotOlder)
	}
	// A split node's own folder; a rollback.
	n.paths.RootdDir = "/opt/rootd"
	result.Changed = false
	if code, out := run("--from", "/tmp/stage", "--allow-older"); code != 0 || !strings.Contains(out, "already installed in /opt/rootd") || !gotOlder {
		t.Fatalf("code %d: %s", code, out)
	}
	// install.sh names the folder.
	if code, _ := run("--from", "/tmp/stage", "--dir", "/srv/rootd"); code != 0 || gotDir != "/srv/rootd" {
		t.Fatalf("code %d, dir %s", code, gotDir)
	}
	fail = errors.New("staged root helper refused (bad_signature)")
	if code, out := run("--from", "/tmp/stage"); code != 1 || !strings.Contains(out, "bad_signature") {
		t.Fatalf("code %d: %s", code, out)
	}
	for _, args := range [][]string{nil, {"--from", "/x", "now"}, {"--bogus"}} {
		if code, _ := run(args...); code != 2 {
			t.Fatalf("%v: code %d", args, code)
		}
	}
	if code, out := run("-h"); code != 0 || !strings.Contains(out, "root-helper --from") {
		t.Fatalf("help: %d %s", code, out)
	}
	resolveUpgradePaths = func(string) (nodeupgrade.Paths, error) { return nodeupgrade.Paths{}, errors.New("env file unreadable") }
	if code, _ := run("--from", "/tmp/stage"); code != 1 {
		t.Fatalf("code %d", code)
	}
}
