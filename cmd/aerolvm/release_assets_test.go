package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// `aerolvm release pull` and `aerolvm upgrade apply` read these release
// assets by name (plans/kubectl-style-cluster-ops.md §7.1). This pins that
// release.yml still publishes each one, and that release.json is made before
// checksums.txt, so checksums.txt covers it.
func TestReleaseWorkflowPublishesWhatUpgradeReads(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot, ".github/workflows/release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	wf := string(raw)
	for _, want := range []string{
		"-o dist/sandboxd_${{ matrix.suffix }} ./cmd/sandboxd",
		"-o dist/toolboxd_${{ matrix.suffix }} ./cmd/toolboxd",
		"--output dist/caddy_${{ matrix.suffix }}",
		"-o dist/release.json",
		"sha256sum * > checksums.txt",
		`cp "$BUNDLE_PATH" "dist/${VERSION}.intoto.jsonl"`,
		"files: dist/*",
	} {
		if !strings.Contains(wf, want) {
			t.Errorf("release.yml no longer has %q", want)
		}
	}
	meta, sums := strings.Index(wf, "-o dist/release.json"), strings.Index(wf, "sha256sum * > checksums.txt")
	if meta < 0 || sums < 0 || meta > sums {
		t.Error("release.json must be generated before checksums.txt")
	}
	// The Linux CPU types a bundle carries all build sandboxd and Caddy.
	for _, suffix := range []string{"linux_amd64", "linux_arm64"} {
		if !strings.Contains(wf, "suffix: "+suffix) {
			t.Errorf("release.yml builds no %s", suffix)
		}
	}
	if !upgradeAssetRe.MatchString("sandboxd_linux_armv7") || upgradeAssetRe.MatchString("v0.6.12_sandboxd_linux_amd64") ||
		upgradeAssetRe.MatchString("toolboxd_freebsd_amd64") {
		t.Error("upgradeAssetRe picks the wrong release files")
	}
}
