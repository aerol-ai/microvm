// Offline tests for the local artifact pipeline in lib/build.sh
// (plans/integration-test-security.md §4). They shell out to the script's pure
// helpers — no AWS, no compiler — and assert the guards that stand between a
// mistyped flag and three EC2 instances installing the wrong binary.
//
// The guards worth proving here are the ones whose failure is SILENT or
// EXPENSIVE: a presign TTL past the SigV4 ceiling (rejected by AWS minutes
// later), a host binary published as a Linux artifact (fails at exec time on
// the node), and a build id that does not move when the tree does (publishes
// stale bytes under a fresh-looking id).
//
// Runs in the normal `go test ./...` / `make test` flow (no build tag).
package safety

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func buildScript(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve test file path")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "lib", "build.sh")
}

// sourceAndRun sources build.sh (which is why it guards its own main) and runs
// one snippet against its functions, returning combined output and exit code.
func sourceAndRun(t *testing.T, snippet string) (string, int) {
	t.Helper()
	script := "source " + buildScript(t) + "\n" + snippet
	cmd := exec.Command("bash", "-c", script)
	out, err := cmd.CombinedOutput()
	t.Logf("snippet %q -> %s", snippet, out)
	if err == nil {
		return string(out), 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return string(out), ee.ExitCode()
	}
	t.Fatalf("running build.sh: %v", err)
	return "", -1
}

func TestParseTTLAcceptedForms(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"12h", "43200"},
		{"1h", "3600"},
		{"45m", "2700"},
		{"90s", "90"},
		{"900", "900"},
		{"168h", "604800"}, // exactly the 7-day SigV4 ceiling
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			out, code := sourceAndRun(t, "parse_ttl "+tc.in)
			if code != 0 {
				t.Fatalf("parse_ttl %s rejected (exit %d): %s", tc.in, code, out)
			}
			if got := strings.TrimSpace(out); got != tc.want {
				t.Fatalf("parse_ttl %s = %s, want %s", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseTTLRejectsOutOfRange(t *testing.T) {
	// Each of these is a mistake AWS would otherwise report minutes later, at
	// presign time, after a build has already run.
	cases := []struct{ name, in, wantMsg string }{
		{"beyond sigv4 ceiling", "169h", "7-day"},
		{"way beyond ceiling", "30d", "unparseable"}, // d is not a supported unit
		{"zero", "0", "positive"},
		{"not a number", "twelve", "unparseable"},
		{"negative", "-5m", "unparseable"},
		{"empty", "''", "unparseable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, code := sourceAndRun(t, "parse_ttl "+tc.in)
			if code == 0 {
				t.Fatalf("parse_ttl %s accepted, want rejection", tc.in)
			}
			if !strings.Contains(out, tc.wantMsg) {
				t.Fatalf("parse_ttl %s: message %q lacks %q", tc.in, out, tc.wantMsg)
			}
		})
	}
}

func TestAssertLinuxELFRejectsNonELF(t *testing.T) {
	// A shell script stands in for the real failure: a cross-compile that
	// silently did not take effect and produced a host binary. Publishing that
	// succeeds and only fails on the node, 5 minutes into provisioning, with
	// "cannot execute binary file".
	dir := t.TempDir()
	notELF := filepath.Join(dir, "sandboxd_linux_amd64")
	if err := os.WriteFile(notELF, []byte("#!/bin/sh\necho not a binary\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	out, code := sourceAndRun(t, "assert_linux_elf "+notELF+" amd64")
	if code == 0 {
		t.Fatal("assert_linux_elf accepted a non-ELF file")
	}
	if !strings.Contains(out, "not a Linux ELF") {
		t.Fatalf("message %q does not name the problem", out)
	}
}

func TestParseCommonFlagsRejectsBadInput(t *testing.T) {
	cases := []struct{ name, args, wantMsg string }{
		{"unknown flag", "--nope", "unknown flag"},
		{"unsupported arch", "--arch riscv64", "unsupported --arch"},
		{"arch typo in a list", "--arch amd64,x86_64", "unsupported --arch"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, code := sourceAndRun(t, "parse_common_flags "+tc.args)
			if code == 0 {
				t.Fatalf("parse_common_flags %s accepted, want rejection", tc.args)
			}
			if !strings.Contains(out, tc.wantMsg) {
				t.Fatalf("message %q lacks %q", out, tc.wantMsg)
			}
		})
	}
}

func TestParseCommonFlagsDefaultsToAmd64Only(t *testing.T) {
	// D7: arm64 stays out of the default matrix until the x86 matrix is green.
	// A silent change here would double every build's cost and time.
	out, code := sourceAndRun(t, `parse_common_flags; echo "arches=${ARCHES[*]}"`)
	if code != 0 {
		t.Fatalf("parse_common_flags with no args failed: %s", out)
	}
	if !strings.Contains(out, "arches=amd64") {
		t.Fatalf("default arch set is not amd64-only: %s", out)
	}
}

func TestBuildIDTracksUntrackedFiles(t *testing.T) {
	// `git diff HEAD` is blind to untracked files. If the build id ignored them
	// too, adding a new .go file would leave the id unchanged, the content-
	// addressed cache would "hit", and the pipeline would publish the PREVIOUS
	// binary under a fresh-looking id — a wrong-artifact bug that presents as a
	// mysterious test failure. Prove a new file moves the id.
	repoRoot := filepath.Join(filepath.Dir(buildScript(t)), "..", "..")
	probe := filepath.Join(repoRoot, "integration-tests", "zz_build_id_probe.tmp")

	before, code := sourceAndRun(t, "REF=''; resolve_build_id")
	if code != 0 {
		t.Skipf("resolve_build_id unavailable (not a git checkout?): %s", before)
	}

	if err := os.WriteFile(probe, []byte("probe\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	during, code := sourceAndRun(t, "REF=''; resolve_build_id")
	if err := os.Remove(probe); err != nil {
		t.Fatalf("removing probe file: %v", err)
	}
	if code != 0 {
		t.Fatalf("resolve_build_id failed with probe present: %s", during)
	}

	after, code := sourceAndRun(t, "REF=''; resolve_build_id")
	if code != 0 {
		t.Fatalf("resolve_build_id failed after cleanup: %s", after)
	}

	b, d, a := strings.TrimSpace(before), strings.TrimSpace(during), strings.TrimSpace(after)
	if d == b {
		t.Fatalf("build id did not change when an untracked file appeared (%s) — the cache would serve stale bytes", b)
	}
	// Content-addressed, not monotonic: removing the file must restore the id,
	// or an iterate-against---keep loop never gets a cache hit and re-uploads
	// ~100MB every run.
	if a != b {
		t.Fatalf("build id did not return to %s after the file was removed (got %s)", b, a)
	}
	if !strings.Contains(b, "-dirty-") && !strings.Contains(d, "-dirty-") {
		t.Fatalf("expected a -dirty- suffix while an untracked file is present, got %s", d)
	}
}

func runScript(t *testing.T) string {
	t.Helper()
	return filepath.Join(filepath.Dir(buildScript(t)), "..", "run.sh")
}

// TestRunFlagGuardsAbortBeforeAWS covers the argument guards run.sh gained with
// the local-build default (§4.4). Every case here must fail BEFORE the safety
// tripwires and before prepare_artifacts, so none of them touches AWS, spends
// money, or leaves a half-provisioned scenario behind.
func TestRunFlagGuardsAbortBeforeAWS(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		wantMsg string
	}{
		{
			// --no-build means "reuse the last LOCAL build", which is a
			// different artifact source from a release. Honouring both would
			// provision something the operator did not ask for.
			name:    "released plus no-build is contradictory",
			args:    []string{"single-node", "--released", "--no-build"},
			wantMsg: "--no-build only applies to the default local-build mode",
		},
		{
			// --version is the first run.sh flag that takes a value; a bare
			// one would otherwise silently pin nothing.
			name:    "version without a tag",
			args:    []string{"single-node", "--version"},
			wantMsg: "--version needs a release tag",
		},
		{
			name:    "unknown flag",
			args:    []string{"single-node", "--bogus"},
			wantMsg: "unknown flag",
		},
		{
			name:    "no scenario",
			args:    []string{"--keep"},
			wantMsg: "usage: run.sh",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("bash", append([]string{runScript(t)}, tc.args...)...)
			out, err := cmd.CombinedOutput()
			t.Logf("run.sh %v -> %s", tc.args, out)
			if err == nil {
				t.Fatalf("run.sh %v succeeded, want rejection", tc.args)
			}
			ee, ok := err.(*exec.ExitError)
			if !ok {
				t.Fatalf("run.sh %v: %v", tc.args, err)
			}
			if ee.ExitCode() != 2 {
				t.Fatalf("run.sh %v exited %d, want 2 (usage error)", tc.args, ee.ExitCode())
			}
			if !strings.Contains(string(out), tc.wantMsg) {
				t.Fatalf("run.sh %v: output %q lacks %q", tc.args, out, tc.wantMsg)
			}
		})
	}
}

// TestPruneBuildCacheKeepsNewestAndSpecials covers the one function in build.sh
// that DELETES things. Two mistakes here are expensive and silent: reaping the
// build that was just stamped (the next publish then finds nothing), and
// reaping .worktrees (which holds real git worktrees — removing one behind
// git's back leaves a stale registration that breaks the next `worktree add`).
func TestPruneBuildCacheKeepsNewestAndSpecials(t *testing.T) {
	root := t.TempDir()

	// Five completed builds with increasing mtimes, plus one interrupted build
	// (no buildinfo.json) and the .worktrees directory.
	ids := []string{"aaa", "bbb", "ccc", "ddd", "eee"}
	base := time.Now().Add(-time.Hour)
	for i, id := range ids {
		dir := filepath.Join(root, id)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		stamp := filepath.Join(dir, "buildinfo.json")
		if err := os.WriteFile(stamp, []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
		mt := base.Add(time.Duration(i) * time.Minute)
		if err := os.Chtimes(stamp, mt, mt); err != nil {
			t.Fatal(err)
		}
	}
	incomplete := filepath.Join(root, "interrupted")
	if err := os.MkdirAll(incomplete, 0o755); err != nil {
		t.Fatal(err)
	}
	worktrees := filepath.Join(root, ".worktrees", "somecommit")
	if err := os.MkdirAll(worktrees, 0o755); err != nil {
		t.Fatal(err)
	}

	// Keep 2, with "aaa" (the OLDEST) named as the just-built id, so the test
	// also proves the current build survives purely on that protection rather
	// than on being recent.
	out, code := sourceAndRun(t, `BUILD_ROOT=`+root+`; AEROL_BUILD_CACHE_KEEP=2; prune_build_cache aaa`)
	if code != 0 {
		t.Fatalf("prune_build_cache failed: %s", out)
	}

	mustExist := []string{"eee", "ddd", "aaa", ".worktrees/somecommit"}
	for _, p := range mustExist {
		if _, err := os.Stat(filepath.Join(root, p)); err != nil {
			t.Errorf("prune removed %s, which must survive: %v", p, err)
		}
	}
	mustBeGone := []string{"bbb", "ccc", "interrupted"}
	for _, p := range mustBeGone {
		if _, err := os.Stat(filepath.Join(root, p)); err == nil {
			t.Errorf("prune kept %s, which should have been reclaimed", p)
		}
	}
}

// TestPruneBuildCacheIsNoopWhenUnderLimit guards the common case: a fresh
// checkout with a couple of builds must lose nothing.
func TestPruneBuildCacheIsNoopWhenUnderLimit(t *testing.T) {
	root := t.TempDir()
	for _, id := range []string{"one", "two"} {
		dir := filepath.Join(root, id)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "buildinfo.json"), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	out, code := sourceAndRun(t, `BUILD_ROOT=`+root+`; AEROL_BUILD_CACHE_KEEP=5; prune_build_cache two`)
	if code != 0 {
		t.Fatalf("prune_build_cache failed: %s", out)
	}
	for _, id := range []string{"one", "two"} {
		if _, err := os.Stat(filepath.Join(root, id)); err != nil {
			t.Errorf("prune removed %s while under the keep limit: %v", id, err)
		}
	}
}
