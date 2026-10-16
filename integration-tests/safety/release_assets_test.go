package safety

import (
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
	// shippedCopy matches release.yml's `cp <src> dist/<name>`.
	shippedCopy = regexp.MustCompile(`\bcp\s+\S+\s+dist/([A-Za-z0-9._-]+)`)
	// shippedBuild matches `-o dist/<name>_${{ matrix.suffix }}` and
	// `--output dist/<name>_${{ matrix.suffix }}`: binaries built per platform.
	shippedBuild = regexp.MustCompile(`(?:-o|--output)\s+"?dist/([A-Za-z0-9._-]+)_\$\{\{\s*matrix\.suffix\s*\}\}`)
)

func TestTerraformReleaseURLsNameShippedAssets(t *testing.T) {
	repoRoot := filepath.Join(filepath.Dir(buildScript(t)), "..", "..")
	release, err := os.ReadFile(filepath.Join(repoRoot, ".github", "workflows", "release.yml"))
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
	shipped := func(name string) bool {
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

	tfFiles, err := filepath.Glob(filepath.Join(repoRoot, "Terraform", "*.tf"))
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
