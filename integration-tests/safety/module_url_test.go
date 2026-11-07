package safety

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Terraform/ is a module used by URL (plans/kubectl-style-cluster-ops.md
// §7). Most scenarios run Terraform/root, which calls it by path; a
// module-url scenario runs a root of its own that fetches it by git URL
// (run.sh tf_root, prepare_module_root). These run those functions against a
// throwaway repo under t.TempDir(). Nothing reaches AWS or Terraform.

func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
}

// moduleURLFixture makes a repo with Terraform/root's real files, one
// module-url scenario and one plain one, and returns its path and the
// run.sh functions to source.
func moduleURLFixture(t *testing.T) (repo, funcs string) {
	t.Helper()
	requireYQ(t)
	requireGit(t)
	src, err := os.ReadFile(runScript(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"uses_module_url() {", "tf_root() {", "prepare_module_root() {"} {
		body := hclBlock(string(src), name)
		if body == "" {
			t.Fatalf("run.sh has no %s", name)
		}
		funcs += body + "\n"
	}
	repo = t.TempDir()
	rootSrc := filepath.Join("..", "..", "Terraform", "root")
	entries, err := os.ReadDir(rootSrc)
	if err != nil {
		t.Fatal(err)
	}
	mustMkdir := func(p string) {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mustMkdir(filepath.Join(repo, "Terraform", "root"))
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".tf") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(rootSrc, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		mustWrite(t, filepath.Join(repo, "Terraform", "root", e.Name()), string(b))
	}
	mustMkdir(filepath.Join(repo, "integration-tests", "scenarios"))
	mustWrite(t, filepath.Join(repo, "integration-tests", "scenarios", "by-url.caps.yml"), "capabilities:\n  - cluster\n  - module-url\n")
	mustWrite(t, filepath.Join(repo, "integration-tests", "scenarios", "by-path.caps.yml"), "capabilities:\n  - cluster\n")
	git := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@x", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@x")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	git("init", "-q", "-b", "feat/module")
	git("add", "-A")
	git("-c", "commit.gpgsign=false", "commit", "-q", "-m", "fixture")
	return repo, funcs
}

func runModuleURL(t *testing.T, repo, funcs, body string, env ...string) (string, int) {
	t.Helper()
	script := "set -euo pipefail\nREPO_ROOT=\"$1\"\nHERE=\"$1/integration-tests\"\n" + funcs + body
	stdout, stderr, code := runBashScript(t, script, repo, append(os.Environ(), env...))
	return stdout + stderr, code
}

func TestTfRootPicksTheRootPerScenario(t *testing.T) {
	repo, funcs := moduleURLFixture(t)
	out, code := runModuleURL(t, repo, funcs, `tf_root by-path; tf_root by-url; tf_root no-such-scenario`)
	if code != 0 {
		t.Fatalf("tf_root exited %d: %s", code, out)
	}
	want := []string{
		repo + "/Terraform/root",
		repo + "/integration-tests/.tf/by-url/root",
		repo + "/Terraform/root",
	}
	got := strings.Fields(out)
	if len(got) < 3 || strings.Join(got[:3], " ") != strings.Join(want, " ") {
		t.Fatalf("tf_root = %q, want %q", got, want)
	}
}

func TestPrepareModuleRootFetchesTheModuleByURL(t *testing.T) {
	repo, funcs := moduleURLFixture(t)
	root := filepath.Join(repo, "integration-tests", ".tf", "by-url", "root")

	checkRoot := func(t *testing.T, wantSource string) {
		t.Helper()
		entries, err := os.ReadDir(root)
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		if got := strings.Join(names, " "); got != "backend.tf join.tf main.tf outputs.tf providers.tf variables.tf versions.tf" {
			// No moved.tf: a new root has no old state to move.
			t.Fatalf("root holds %q", got)
		}
		main, _ := os.ReadFile(filepath.Join(root, "main.tf"))
		if !strings.Contains(string(main), `source = "`+wantSource+`"`) || strings.Contains(string(main), `source = "../"`) {
			t.Fatalf("main.tf source is not %q:\n%s", wantSource, main)
		}
		for _, f := range []string{"variables.tf", "outputs.tf", "backend.tf", "providers.tf", "versions.tf"} {
			a, _ := os.ReadFile(filepath.Join(root, f))
			b, _ := os.ReadFile(filepath.Join(repo, "Terraform", "root", f))
			if string(a) != string(b) {
				t.Errorf("%s differs from Terraform/root's", f)
			}
		}
		join, _ := os.ReadFile(filepath.Join(root, "join.tf"))
		if !strings.Contains(string(join), "default = null") {
			t.Fatalf("join.tf does not leave one_line_join to the module's default:\n%s", join)
		}
	}

	t.Run("given URL", func(t *testing.T) {
		src := "git::https://github.com/aerol-ai/microvm//Terraform?ref=v0.6.12"
		out, code := runModuleURL(t, repo, funcs, `prepare_module_root by-url`, "AEROL_TF_MODULE_SOURCE="+src)
		if code != 0 {
			t.Fatalf("prepare_module_root exited %d: %s", code, out)
		}
		checkRoot(t, src)
		if _, err := os.Stat(filepath.Join(repo, "integration-tests", ".tf", "by-url", "module.git")); err == nil {
			t.Fatal("a given URL must not make a local clone")
		}
	})

	t.Run("local clone of HEAD", func(t *testing.T) {
		// A stale module download must not survive: init would reuse it.
		stale := filepath.Join(repo, "integration-tests", ".tf", "by-url", "modules", "aerolvm")
		if err := os.MkdirAll(stale, 0o755); err != nil {
			t.Fatal(err)
		}
		out, code := runModuleURL(t, repo, funcs, `prepare_module_root by-url`, "AEROL_TF_MODULE_SOURCE=")
		if code != 0 {
			t.Fatalf("prepare_module_root exited %d: %s", code, out)
		}
		bare := filepath.Join(repo, "integration-tests", ".tf", "by-url", "module.git")
		checkRoot(t, "git::file://"+bare+"//Terraform?ref=feat/module")
		head, err := exec.Command("git", "-C", repo, "rev-parse", "HEAD").Output()
		if err != nil {
			t.Fatal(err)
		}
		pushed, err := exec.Command("git", "-C", bare, "rev-parse", "refs/heads/feat/module").Output()
		if err != nil {
			t.Fatalf("the bare clone has no feat/module branch: %v", err)
		}
		if strings.TrimSpace(string(head)) != strings.TrimSpace(string(pushed)) {
			t.Fatalf("the bare clone's branch is at %s, HEAD is %s", pushed, head)
		}
		if _, err := os.Stat(stale); err == nil {
			t.Fatal("the stale module download is still there")
		}
	})
}
