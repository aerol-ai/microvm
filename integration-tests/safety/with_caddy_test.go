package safety

// Offline guard for AEROL_WITH_CADDY=1 (run.sh prepare_artifacts ->
// lib/build.sh --with-caddy). Its failure is the silent kind: a build or
// publish call that drops the flag hands the nodes the latest release's
// Caddy, and a run meant to test a Caddy change passes without testing it.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestWithCaddyReachesEveryBuildCall(t *testing.T) {
	src, err := os.ReadFile(runScript(t))
	if err != nil {
		t.Fatal(err)
	}
	fn := extractShellFunc(t, string(src), "prepare_artifacts")

	for _, tc := range []struct {
		name      string
		withCaddy string
		noBuild   string
		// The build.sh subcommands prepare_artifacts must call, in order.
		wantCalls []string
	}{
		{name: "local build", noBuild: "0", wantCalls: []string{"build", "publish"}},
		{name: "local build with Caddy", withCaddy: "1", noBuild: "0", wantCalls: []string{"build", "publish"}},
		// --no-build on a build that is not published yet: urls fails, so
		// the build and publish fallback runs. Every one of the three must
		// ask for Caddy, or the published build is found without it.
		{name: "no-build fallback", noBuild: "1", wantCalls: []string{"build-id", "urls", "build", "publish"}},
		{name: "no-build fallback with Caddy", withCaddy: "1", noBuild: "1", wantCalls: []string{"build-id", "urls", "build", "publish"}},
		// Only "1" turns it on, as for the harness's other switches.
		{name: "any other value is off", withCaddy: "true", noBuild: "0", wantCalls: []string{"build", "publish"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			log := filepath.Join(dir, "build.log")
			buildSh := filepath.Join(dir, "build.sh")
			mustWrite(t, buildSh, `#!/bin/sh
printf '%s\n' "$*" >>`+log+`
case "$1" in
  build|build-id) echo test-id ;;
  urls) exit 1 ;;
  publish) echo 'sandboxd_url = "https://local/sandboxd"' ;;
esac
`)
			if err := os.Chmod(buildSh, 0o755); err != nil {
				t.Fatal(err)
			}
			here := filepath.Join(dir, "it")
			script := `set -euo pipefail
HERE="` + here + `"
REPO_ROOT="` + dir + `"
BUILD_SH="` + buildSh + `"
BUILD_MODE=local
NO_BUILD=` + tc.noBuild + `
artifacts_tfvars_path() { printf '%s\n' "${HERE}/.tf/${1}/artifacts.tfvars"; }
go_tags_for() { :; }
` + fn + `
prepare_artifacts s
`
			cmd := exec.Command("bash", "-c", script)
			cmd.Env = append(os.Environ(), "AEROL_WITH_CADDY="+tc.withCaddy)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("prepare_artifacts: %v\n%s", err, out)
			}
			raw, err := os.ReadFile(log)
			if err != nil {
				t.Fatal(err)
			}
			calls := strings.Split(strings.TrimSpace(string(raw)), "\n")
			if len(calls) != len(tc.wantCalls) {
				t.Fatalf("build.sh calls %q, want subcommands %q", calls, tc.wantCalls)
			}
			on := tc.withCaddy == "1"
			for i, call := range calls {
				args := strings.Fields(call)
				if args[0] != tc.wantCalls[i] {
					t.Fatalf("call %d is %q, want %s", i, call, tc.wantCalls[i])
				}
				// build-id names the source, not the output set; build.sh's
				// cache check is what tells a Caddy build from one without.
				want := on && args[0] != "build-id"
				if got := strings.Contains(call, "--with-caddy"); got != want {
					t.Errorf("AEROL_WITH_CADDY=%q: %q has --with-caddy=%v, want %v", tc.withCaddy, call, got, want)
				}
			}
			if said := strings.Contains(string(out), "Caddy built from this tree"); said != on {
				t.Errorf("AEROL_WITH_CADDY=%q: run.sh says it builds Caddy = %v, want %v:\n%s", tc.withCaddy, said, on, out)
			}
		})
	}
}
