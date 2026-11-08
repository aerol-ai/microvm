package safety

// Offline guards for the test-only Go build tags a scenario's local build
// compiles sandboxd with (caps go_tags -> run.sh go_tags_for ->
// lib/build.sh AEROL_GO_TAGS). Their failures are the silent kind: a tagged
// binary served from the cache for an untagged request puts a failpoint into
// a run that believes it tests the release build, and a tag that never
// reaches `go build` turns UC-480 into a skip on every run.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestBuildIDCarriesGoTags(t *testing.T) {
	base, code := sourceAndRun(t, "REF=''; AEROL_GO_TAGS=''; resolve_build_id")
	if code != 0 {
		t.Skipf("resolve_build_id unavailable (not a git checkout?): %s", base)
	}
	base = strings.TrimSpace(base)
	if strings.Contains(base, "-tags-") {
		t.Fatalf("an untagged build id carries a tag suffix: %s", base)
	}
	cases := []struct {
		tags string
		want string
	}{
		{tags: "itest_failpoints", want: base + "-tags-itest_failpoints"},
		// Order and repeats must not mint a second id for the same binary.
		{tags: "b a,b", want: base + "-tags-a-b"},
		{tags: " , ", want: base},
	}
	for _, tc := range cases {
		got, code := sourceAndRun(t, "REF=''; AEROL_GO_TAGS='"+tc.tags+"'; resolve_build_id")
		if code != 0 {
			t.Fatalf("AEROL_GO_TAGS=%q: resolve_build_id failed: %s", tc.tags, got)
		}
		if strings.TrimSpace(got) != tc.want {
			t.Errorf("AEROL_GO_TAGS=%q: id %q, want %q", tc.tags, strings.TrimSpace(got), tc.want)
		}
	}
	// Captured with $(…) the way every caller does, where bash clears
	// errexit: a refused tag must still fail, not hand out an id.
	for _, bad := range []string{"x;y", "*", "a-b", "../x"} {
		out, code := sourceAndRun(t, "set +e; REF=''; AEROL_GO_TAGS='"+bad+"'; id=$(resolve_build_id) || exit 7; printf 'id=[%s]\\n' \"$id\"")
		if code == 0 || strings.Contains(out, "id=[") {
			t.Errorf("AEROL_GO_TAGS=%q was accepted: %s", bad, out)
		}
		if !strings.Contains(out, "not a Go build tag") {
			t.Errorf("AEROL_GO_TAGS=%q: message %q does not name the problem", bad, out)
		}
	}
}

// build_one_arch with a stand-in `go` that records its arguments: the tags
// reach sandboxd's build and nothing else, and no tags means no -tags flag
// at all, the release build's command line.
func TestBuildPassesGoTagsToSandboxdOnly(t *testing.T) {
	run := func(t *testing.T, tags string) []string {
		t.Helper()
		dir := t.TempDir()
		log := filepath.Join(dir, "go.log")
		out, code := sourceAndRun(t, `go() { printf '%s\n' "$*" >>`+log+`; }
assert_linux_elf() { :; }
WITH_RECEIVER=0; WITH_CADDY=0
AEROL_GO_TAGS='`+tags+`'
build_one_arch `+dir+` `+dir+` amd64 test-id`)
		if code != 0 {
			t.Fatalf("build_one_arch failed: %s", out)
		}
		raw, err := os.ReadFile(log)
		if err != nil {
			t.Fatal(err)
		}
		return strings.Split(strings.TrimSpace(string(raw)), "\n")
	}
	lines := run(t, "itest_failpoints")
	if len(lines) != 2 {
		t.Fatalf("want a sandboxd and a toolboxd build, got %q", lines)
	}
	if !strings.Contains(lines[0], "./cmd/sandboxd") || !strings.Contains(lines[0], "-tags itest_failpoints") {
		t.Errorf("sandboxd build lacks the tags: %s", lines[0])
	}
	if !strings.Contains(lines[1], "./cmd/toolboxd") || strings.Contains(lines[1], "-tags") {
		t.Errorf("toolboxd, which runs inside every sandbox, got test tags: %s", lines[1])
	}
	for _, l := range run(t, "") {
		if strings.Contains(l, "-tags") {
			t.Errorf("an untagged build passed -tags: %s", l)
		}
	}
}

func TestGoTagsComeFromCapsAndTheOperatorWins(t *testing.T) {
	run := func(t *testing.T, caps string, env string) string {
		t.Helper()
		capsFile := filepath.Join(t.TempDir(), "s.caps.yml")
		if caps != "" {
			if err := os.WriteFile(capsFile, []byte(caps), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		script := "set -uo pipefail\n" +
			"eval \"$(sed -n '/^go_tags_for()/,/^}/p' " + runScript(t) + ")\"\n" +
			"go_tags_for " + capsFile
		cmd := exec.Command("bash", "-c", script)
		cmd.Env = append(os.Environ(), "AEROL_GO_TAGS="+env)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("go_tags_for: %v\n%s", err, out)
		}
		return strings.TrimSpace(string(out))
	}
	if _, err := exec.LookPath("yq"); err != nil {
		t.Skip("yq not installed")
	}
	cases := []struct {
		name, caps, env, want string
	}{
		{name: "caps declare tags", caps: "name: s\ngo_tags: itest_failpoints\n", want: "itest_failpoints"},
		{name: "caps declare none", caps: "name: s\ncapabilities: [cluster]\n", want: ""},
		{name: "no caps file", want: ""},
		{name: "operator export wins", caps: "name: s\ngo_tags: itest_failpoints\n", env: "itest_other", want: "itest_other"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := run(t, tc.caps, tc.env); got != tc.want {
				t.Fatalf("go_tags_for = %q, want %q", got, tc.want)
			}
		})
	}
}

// go_tags exists for test hooks. A product tag (wasmtime, say) declared here
// would make a scenario test a binary no release ships while its report
// reads like any other run's; such a tag needs its own scenario and review.
// And the scenario whose UC-480 needs a failpoint must keep asking for it,
// or that case skips on every run.
func TestScenarioGoTagsAreTestOnly(t *testing.T) {
	declared := map[string]string{}
	for _, f := range capsFiles(t) {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var caps struct {
			GoTags string `yaml:"go_tags"`
		}
		if err := yaml.Unmarshal(raw, &caps); err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		if caps.GoTags == "" {
			continue
		}
		declared[filepath.Base(f)] = caps.GoTags
		for _, tag := range strings.FieldsFunc(caps.GoTags, func(r rune) bool { return r == ',' || r == ' ' }) {
			if !strings.HasPrefix(tag, "itest_") {
				t.Errorf("%s: go_tags %q is not a test-only (itest_*) tag", filepath.Base(f), tag)
			}
		}
	}
	if !strings.Contains(declared["cluster-chaos.caps.yml"], "itest_failpoints") {
		t.Errorf("cluster-chaos no longer builds with itest_failpoints; UC-480 would skip on every run (declared: %v)", declared)
	}
}
