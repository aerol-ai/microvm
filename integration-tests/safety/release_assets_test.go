package safety

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Terraform defaults name release assets by URL, and the release workflow
// decides which files exist. Nothing tied the two together, so the seed's
// cluster-sign-node.sh default 404'd on every release from #477 on: a
// Terraform deploy on the defaults sat out curl's 15-minute retry budget and
// then failed the seed's bootstrap. The harness never saw it, because a local
// build presigns its own copy of every script.

var (
	// releaseURLDefault matches a Terraform default that downloads from a
	// release. Only latest/ is checked: a pinned tag names a release that
	// already exists, and changing release.yml cannot fix it.
	releaseURLDefault = regexp.MustCompile(`releases/latest/download/([A-Za-z0-9._-]+)`)
	// docsReleaseURL is the same for docs, which also link other projects'
	// releases; only this repository's are ours to ship.
	docsReleaseURL = regexp.MustCompile(`github\.com/aerol-ai/microvm/releases/latest/download/([A-Za-z0-9._-]+)`)
	// shippedCopy matches release.yml's `cp <src> dist/<name>`.
	shippedCopy = regexp.MustCompile(`\bcp\s+\S+\s+dist/([A-Za-z0-9._-]+)`)
	// shippedBuild matches `-o dist/<name>_${{ matrix.suffix }}` and
	// `--output dist/<name>_${{ matrix.suffix }}`: binaries built per platform.
	shippedBuild = regexp.MustCompile(`(?:-o|--output)\s+"?dist/([A-Za-z0-9._-]+)_\$\{\{\s*matrix\.suffix\s*\}\}`)
)

func repoRoot(t *testing.T) string {
	t.Helper()
	return filepath.Join(filepath.Dir(buildScript(t)), "..", "..")
}

// releaseShipped reports, from release.yml, whether a release carries an
// asset with this name.
func releaseShipped(t *testing.T) func(name string) bool {
	t.Helper()
	release, err := os.ReadFile(filepath.Join(repoRoot(t), ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatalf("read release.yml: %v", err)
	}

	copied := map[string]bool{"checksums.txt": true} // generated in dist/ by sha256sum
	for _, m := range shippedCopy.FindAllStringSubmatch(string(release), -1) {
		copied[m[1]] = true
	}
	var builtPrefixes []string
	for _, m := range shippedBuild.FindAllStringSubmatch(string(release), -1) {
		builtPrefixes = append(builtPrefixes, m[1]+"_")
	}
	// Vacuous-pass guards: if either pattern stops matching release.yml, every
	// lookup below would fail or pass for the wrong reason.
	if !copied["install.sh"] {
		t.Fatalf("release.yml: no `cp ... dist/install.sh` found; shippedCopy no longer matches the workflow")
	}
	if len(builtPrefixes) == 0 {
		t.Fatalf("release.yml: no `-o dist/<name>_${{ matrix.suffix }}` found; shippedBuild no longer matches the workflow")
	}
	return func(name string) bool {
		if copied[name] {
			return true
		}
		for _, p := range builtPrefixes {
			if strings.HasPrefix(name, p) {
				return true
			}
		}
		return false
	}
}

func TestTerraformReleaseURLsNameShippedAssets(t *testing.T) {
	shipped := releaseShipped(t)
	tfFiles, err := filepath.Glob(filepath.Join(repoRoot(t), "Terraform", "*.tf"))
	if err != nil || len(tfFiles) == 0 {
		t.Fatalf("no Terraform/*.tf files found (err=%v)", err)
	}
	checked := 0
	for _, f := range tfFiles {
		body, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for _, m := range releaseURLDefault.FindAllStringSubmatch(string(body), -1) {
			checked++
			if !shipped(m[1]) {
				t.Errorf("%s names releases/latest/download/%s, but .github/workflows/release.yml never ships %s: a deploy on that default fails to download it",
					filepath.Base(f), m[1], m[1])
			}
		}
	}
	if checked == 0 {
		t.Fatal("found no releases/latest/download/ defaults in Terraform/*.tf; the check would pass vacuously")
	}
	t.Logf("checked %d Terraform release-asset defaults", checked)
}

// The single-node and local setup guides told operators to download
// uninstall.sh from releases/latest/ for releases that never uploaded it, so
// the documented uninstall was a 404. Every release URL an operator doc
// gives must name a file the release ships.
func TestDocsReleaseURLsNameShippedAssets(t *testing.T) {
	shipped := releaseShipped(t)
	root := repoRoot(t)
	checked := 0
	for _, dir := range []string{"setup", filepath.Join("docs", "src", "content", "docs"), "Ansible", "README.md"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || (!strings.HasSuffix(path, ".md") && !strings.HasSuffix(path, ".mdx")) {
				return nil
			}
			body, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, m := range docsReleaseURL.FindAllStringSubmatch(string(body), -1) {
				checked++
				if !shipped(m[1]) {
					rel, _ := filepath.Rel(root, path)
					t.Errorf("%s links releases/latest/download/%s, but .github/workflows/release.yml never ships %s: the link is a 404",
						rel, m[1], m[1])
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	if checked == 0 {
		t.Fatal("found no releases/latest/download/ links in the docs; the check would pass vacuously")
	}
	t.Logf("checked %d release-asset links in the docs", checked)
}

// The ops bundle (setup/'s alert rules, Alertmanager config, dashboards and
// runbooks) is a release asset made by cmd/opsbundle from the tagged tree,
// named for the tag, and lands in dist/ before checksums.txt so the
// checksums cover it (plans/kubectl-style-cluster-ops.md §7, CEO D14).
func TestReleaseWorkflowShipsTheOpsBundle(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatalf("read release.yml: %v", err)
	}
	wf := string(raw)
	gen := strings.Index(wf, "go run ./cmd/opsbundle")
	if gen < 0 {
		t.Fatal("release.yml never runs ./cmd/opsbundle, so no release ships aerolvm-ops-<version>.tar.gz")
	}
	line := wf[gen:]
	line = line[:strings.IndexByte(line, '\n')]
	for _, want := range []string{`-o "dist/aerolvm-ops-${VERSION}.tar.gz"`, `-version "$VERSION"`, "-setup setup"} {
		if !strings.Contains(line, want) {
			t.Errorf("release.yml runs %q without %s", line, want)
		}
	}
	sums := strings.Index(wf, "sha256sum * > checksums.txt")
	if sums < 0 {
		t.Fatal("release.yml has no checksums step; this guard needs updating")
	}
	if gen > sums {
		t.Error("the ops bundle is made after checksums.txt, so the checksums do not cover it")
	}
}

// release.json must be generated by the pkg/release generator (never written
// by hand), hash the install.sh the release ships, and land in dist/ before
// the step that makes the tagged copies and before checksums.txt, so the
// published file is covered by both (plans/kubectl-style-cluster-ops.md
// §6.5, eng review T13).
func TestReleaseWorkflowGeneratesReleaseJSON(t *testing.T) {
	repoRoot := filepath.Join(filepath.Dir(buildScript(t)), "..", "..")
	raw, err := os.ReadFile(filepath.Join(repoRoot, ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatalf("read release.yml: %v", err)
	}
	wf := string(raw)
	gen := strings.Index(wf, "go run ./cmd/releasemeta")
	if gen < 0 {
		t.Fatal("release.yml never runs ./cmd/releasemeta, so no release ships release.json")
	}
	line := wf[gen:]
	line = line[:strings.IndexByte(line, '\n')]
	for _, want := range []string{"-o dist/release.json", "-install-script dist/install.sh", `-version "$VERSION"`} {
		if !strings.Contains(line, want) {
			t.Errorf("release.yml runs %q without %s", line, want)
		}
	}
	copyInstall := strings.Index(wf, "cp scripts/install.sh dist/install.sh")
	tagged := strings.Index(wf, `cp "$asset" "${VERSION}_${asset}"`)
	sums := strings.Index(wf, "sha256sum * > checksums.txt")
	if copyInstall < 0 || tagged < 0 || sums < 0 {
		t.Fatalf("release.yml no longer has the install.sh copy (%d), the tagged-copy loop (%d) or the checksums step (%d); this guard needs updating", copyInstall, tagged, sums)
	}
	if gen < copyInstall {
		t.Error("release.json is generated before dist/install.sh exists, so it cannot hash the shipped install.sh")
	}
	if gen > tagged || gen > sums {
		t.Error("release.json is generated after the tagged copies or checksums.txt, so they do not cover it")
	}
}
