// Offline tests for the harness's download fallbacks in lib/common.sh:
// tf_init_failover (terraform init survives a provider download failing) and
// download_mirror_tfvar_args (test clusters turn on the node bootstrap's
// mirror fallback).
//
// Why: on 2026-11-09 GitHub's release downloads answered 504 from the laptop,
// and every run stopped at `terraform init` ("Failed to install provider",
// cloudflare). The providers were on disk the whole time.
//
// Runs in the normal `go test ./...` / `make test` flow (no build tag).
package safety

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// fakeTerraform logs its arguments and the plugin-cache variables, and fails
// every call without -plugin-dir while FAKE_TF_FAIL is set.
const fakeTerraform = `#!/usr/bin/env bash
echo "args=$* cache=${TF_PLUGIN_CACHE_DIR:-} break=${TF_PLUGIN_CACHE_MAY_BREAK_DEPENDENCY_LOCK_FILE:-}" >>"$FAKE_TF_LOG"
case "$*" in *-plugin-dir=*) exit 0 ;; esac
[ -z "${FAKE_TF_FAIL:-}" ]
`

func runCommonSnippet(t *testing.T, env []string, snippet string) (string, error) {
	t.Helper()
	cmd := exec.Command("bash", "-c", "source "+filepath.Join(integrationDir(t), "lib", "common.sh")+"\n"+snippet)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestTfInitFailover(t *testing.T) {
	cases := []struct {
		name      string
		fail      bool
		wantCalls int
	}{
		{name: "init works: one call, through the shared cache", fail: false, wantCalls: 1},
		{name: "provider download fails: retried with the cache as -plugin-dir", fail: true, wantCalls: 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			bin, cache, log := filepath.Join(dir, "bin"), filepath.Join(dir, "cache"), filepath.Join(dir, "tf.log")
			writeStageFile(t, filepath.Join(bin, "terraform"), fakeTerraform, 0o755)
			env := []string{
				"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"),
				"FAKE_TF_LOG=" + log, "AEROL_TF_PLUGIN_CACHE=" + cache,
			}
			if tc.fail {
				env = append(env, "FAKE_TF_FAIL=1")
			}
			out, err := runCommonSnippet(t, env, `tf_init_failover -chdir=/x init -reconfigure -input=false -backend-config=key=k`)
			if err != nil {
				t.Fatalf("tf_init_failover: %v\n%s", err, out)
			}
			b, _ := os.ReadFile(log)
			calls := strings.Split(strings.TrimSpace(string(b)), "\n")
			if len(calls) != tc.wantCalls {
				t.Fatalf("terraform called %d times, want %d:\n%s", len(calls), tc.wantCalls, b)
			}
			for _, c := range calls {
				if !strings.Contains(c, "cache="+cache+" break=true") {
					t.Errorf("call without the shared plugin cache: %s", c)
				}
				if !strings.Contains(c, "-chdir=/x init -reconfigure -input=false -backend-config=key=k") {
					t.Errorf("call lost the caller's arguments: %s", c)
				}
			}
			if st, err := os.Stat(cache); err != nil || !st.IsDir() {
				t.Errorf("plugin cache %s not created: %v", cache, err)
			}
			last := calls[len(calls)-1]
			if tc.fail != strings.Contains(last, "-plugin-dir="+cache) {
				t.Errorf("last call %q: -plugin-dir present = %v, want %v", last, !tc.fail, tc.fail)
			}
		})
	}

	t.Run("still failing with the cache: the error stands", func(t *testing.T) {
		dir := t.TempDir()
		bin := filepath.Join(dir, "bin")
		writeStageFile(t, filepath.Join(bin, "terraform"), "#!/usr/bin/env bash\nexit 1\n", 0o755)
		_, err := runCommonSnippet(t, []string{
			"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"),
			"AEROL_TF_PLUGIN_CACHE=" + filepath.Join(dir, "cache"),
		}, `tf_init_failover init`)
		if err == nil {
			t.Fatal("tf_init_failover succeeded although every terraform call failed")
		}
	})
}

func TestDownloadMirrorTfvarArgs(t *testing.T) {
	cases := []struct {
		name string
		env  []string
		want string
	}{
		{name: "unset: the public mirror", want: "-var=download_mirror=https://aerolvm-downloads.s3.us-east-1.amazonaws.com"},
		{name: "own mirror, trailing slash dropped", env: []string{"AEROL_DOWNLOAD_MIRROR=https://m.example.com/x/"}, want: "-var=download_mirror=https://m.example.com/x"},
		{name: "off", env: []string{"AEROL_DOWNLOAD_MIRROR=off"}, want: ""},
		{name: "empty", env: []string{"AEROL_DOWNLOAD_MIRROR="}, want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := tc.env
			if len(env) == 0 {
				env = []string{"AEROL_DOWNLOAD_MIRROR_UNSET=1"}
			}
			snippet := `download_mirror_tfvar_args`
			if len(tc.env) == 0 {
				snippet = `unset AEROL_DOWNLOAD_MIRROR; download_mirror_tfvar_args`
			}
			out, err := runCommonSnippet(t, env, snippet)
			if err != nil {
				t.Fatalf("download_mirror_tfvar_args: %v\n%s", err, out)
			}
			if got := strings.TrimSpace(out); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
