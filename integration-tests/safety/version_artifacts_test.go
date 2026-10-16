package safety

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestVersionPinFillsWhatTheReleaseLacks covers run.sh --version <tag>. The
// pin takes the product binaries from the release, but two files may not be
// there: cluster-sign-node.sh (no release before v0.6.7 shipped it, so every
// seed's download 404'd) and the audit-receiver test fixture (never a release
// asset). Both must then come from the working tree's build, or the release
// smoke (plans/open-audit-witness.md T24) cannot provision at all.
//
// prepare_artifacts is lifted out of run.sh and run against a file:// release
// and a fake build.sh, so nothing touches GitHub or AWS.
func TestVersionPinFillsWhatTheReleaseLacks(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not on PATH")
	}
	cases := []struct {
		name            string
		releaseHasSign  bool
		receiverEnabled bool
		published       bool // build.sh urls succeeds without a build
		buildHasRecv    bool
		wantLines       []string // substrings each of which must be a line prefix in artifacts.tfvars
		wantNoBuild     bool
		wantErr         string
	}{
		{
			name:           "release carries the signer and no receiver is needed",
			releaseHasSign: true,
			wantLines:      []string{`cluster_sign_node_script_url = "file://`},
			wantNoBuild:    true,
		},
		{
			name:            "old release lacks the signer, scenario needs the receiver",
			receiverEnabled: true,
			published:       true,
			buildHasRecv:    true,
			wantLines:       []string{`cluster_sign_node_script_url = "https://local/sign`, `audit_receiver_url      = "https://local/recv`},
		},
		{
			name:            "working tree not published yet: build then publish",
			releaseHasSign:  true,
			receiverEnabled: true,
			buildHasRecv:    true,
			wantLines:       []string{`cluster_sign_node_script_url = "file://`, `audit_receiver_url      = "https://local/recv`},
		},
		{
			name:            "build without the receiver fails loudly",
			releaseHasSign:  true,
			receiverEnabled: true,
			published:       true,
			wantErr:         "published no audit_receiver_url",
		},
	}

	runSh, err := os.ReadFile(runScript(t))
	if err != nil {
		t.Fatalf("read run.sh: %v", err)
	}
	fn := extractShellFunc(t, string(runSh), "prepare_artifacts")

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			const tag = "v9.9.9"
			rel := filepath.Join(dir, "releases", "download", tag)
			mustMkdir(t, rel)
			if tc.releaseHasSign {
				mustWrite(t, filepath.Join(rel, "cluster-sign-node.sh"), "#!/bin/sh\n")
			}
			here := filepath.Join(dir, "it")
			mustMkdir(t, filepath.Join(here, "scenarios"))
			scen := "cluster_name = \"x\"\n"
			if tc.receiverEnabled {
				scen += "audit_receiver_enabled = true\n"
			}
			mustWrite(t, filepath.Join(here, "scenarios", "s.tfvars"), scen)

			// Fake build.sh: `urls` fails until `build` has run (unless the case
			// says the tree is already published); `urls`/`publish` print the
			// tfvars lines a real publish would. Every call is logged.
			calls := filepath.Join(dir, "calls")
			lines := `printf 'sandboxd_url = "https://local/sandboxd"\n'
printf 'cluster_sign_node_script_url = "https://local/sign"\n'
`
			if tc.buildHasRecv {
				lines += `printf 'audit_receiver_url      = "https://local/recv"\n'
`
			}
			published := "false"
			if tc.published {
				published = "true"
			}
			fake := `#!/usr/bin/env bash
echo "$1" >>"` + calls + `"
case "$1" in
  urls) if [[ "` + published + `" != true && ! -f "` + dir + `/built" ]]; then echo "not published" >&2; exit 1; fi
` + lines + ` ;;
  build) touch "` + dir + `/built"; echo build-id ;;
  publish) ` + lines + ` ;;
esac
`
			buildSh := filepath.Join(dir, "build.sh")
			mustWrite(t, buildSh, fake)
			if err := os.Chmod(buildSh, 0o755); err != nil {
				t.Fatal(err)
			}

			script := `set -euo pipefail
HERE="` + here + `"
RELEASE_BASE="file://` + filepath.Join(dir, "releases") + `"
BUILD_SH="` + buildSh + `"
BUILD_MODE=version
PIN_VERSION=` + tag + `
artifacts_tfvars_path() { printf '%s\n' "${HERE}/.tf/${1}/artifacts.tfvars"; }
` + fn + `
prepare_artifacts s
`
			cmd := exec.Command("bash", "-c", script)
			out, err := cmd.CombinedOutput()
			t.Logf("prepare_artifacts -> %s", out)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(string(out), tc.wantErr) {
					t.Fatalf("err = %v, output %q; want a failure naming %q", err, out, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("prepare_artifacts: %v", err)
			}
			got, err := os.ReadFile(filepath.Join(here, ".tf", "s", "artifacts.tfvars"))
			if err != nil {
				t.Fatalf("read artifacts.tfvars: %v", err)
			}
			if !strings.Contains(string(got), `sandboxd_url            = "file://`) {
				t.Errorf("sandboxd must stay pinned to the release:\n%s", got)
			}
			for _, w := range tc.wantLines {
				if !hasLinePrefix(string(got), w) {
					t.Errorf("artifacts.tfvars lacks a line starting %q:\n%s", w, got)
				}
			}
			if strings.Contains(string(got), "https://local/sandboxd") {
				t.Errorf("the working-tree sandboxd leaked into a release pin:\n%s", got)
			}
			if n := strings.Count(string(got), "cluster_sign_node_script_url"); n != 1 {
				t.Errorf("cluster_sign_node_script_url appears %d times, want 1:\n%s", n, got)
			}
			_, statErr := os.Stat(calls)
			if tc.wantNoBuild && statErr == nil {
				c, _ := os.ReadFile(calls)
				t.Errorf("build.sh was called (%q) although the release had everything", c)
			}
		})
	}
}

// extractShellFunc returns the text of `name() {` up to its closing `}` at
// column 0, the layout run.sh uses for every top-level function.
func extractShellFunc(t *testing.T, src, name string) string {
	t.Helper()
	start := strings.Index(src, "\n"+name+"() {")
	if start < 0 {
		t.Fatalf("run.sh has no %s()", name)
	}
	rest := src[start+1:]
	end := strings.Index(rest, "\n}\n")
	if end < 0 {
		t.Fatalf("run.sh: %s() has no closing brace at column 0", name)
	}
	return rest[:end+3]
}

func hasLinePrefix(s, prefix string) bool {
	for _, l := range strings.Split(s, "\n") {
		if strings.HasPrefix(l, prefix) {
			return true
		}
	}
	return false
}

func mustMkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, p, s string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}
