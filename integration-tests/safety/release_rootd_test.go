package safety

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The root helper on VMs (plans/security-gaps-m1-m4.md M1 PR 10): every
// release builds aerolvm-rootd for the Linux platforms install.sh
// --privilege-mode split installs on, and signs it in a job of its own
// that alone reads the private key, from the `release` environment. The
// signing step is skipped, not failed, when the secret is absent (a fork,
// or before the owner sets it up), and the signature is checked against
// the public keys in this tree before the release ships it.
func TestReleaseWorkflowSignsTheRootHelper(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	wf := string(raw)
	for _, want := range []string{
		"-o dist/aerolvm-rootd_${{ matrix.suffix }} ./cmd/aerolvm-rootd",
		"  sign-rootd:\n",
		"    environment: release\n",
		"      ROOTD_SIGNING_KEY: ${{ secrets.AEROLVM_ROOTD_SIGNING_KEY }}\n",
		"        if: env.ROOTD_SIGNING_KEY != ''\n",
		`go run ./cmd/aerolvm-rootd-sign -key "$key" -version "$VERSION" dist/aerolvm-rootd_linux_amd64 dist/aerolvm-rootd_linux_arm64`,
		"go run ./cmd/aerolvm-rootd-sign -verify internal/rootswap/release-keys.pub dist/aerolvm-rootd_linux_amd64 dist/aerolvm-rootd_linux_arm64",
		"name: dist-rootd-signatures",
		"needs: [hold-latest, build, cli, sign-rootd]",
	} {
		if !strings.Contains(wf, want) {
			t.Errorf("release.yml lacks %q", want)
		}
	}
	// The key is the signing job's alone: no other job names the secret.
	if n := strings.Count(wf, "secrets.AEROLVM_ROOTD_SIGNING_KEY"); n != 1 {
		t.Errorf("release.yml names the signing key %d times; only sign-rootd may read it", n)
	}
	// The helper is built for the platforms the release signs.
	build := regexp.MustCompile(`(?s)- name: Build aerolvm-rootd \(Linux amd64 and arm64\)\n\s+if: (matrix\.goos == 'linux' && \(matrix\.goarch == 'amd64' \|\| matrix\.goarch == 'arm64'\))`)
	if !build.MatchString(wf) {
		t.Error("release.yml no longer builds aerolvm-rootd for exactly linux amd64 and arm64, the builds sign-rootd signs")
	}
	// The release downloads every dist-* artifact, signatures included.
	if !strings.Contains(wf, "pattern: dist-*") {
		t.Error("the publish job no longer downloads dist-*, so the signatures would not ship")
	}

	// install.sh looks for the helper and its signed manifest beside
	// sandboxd, under the names the release gives them.
	script, err := os.ReadFile(filepath.Join(root, "scripts", "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`ROOTD_URL="${ROOTD_URL:-${SANDBOXD_URL%/*}/aerolvm-rootd_${platform}}"`,
		`rootd_assets+=("${rootd_assets[0]}.manifest" "${rootd_assets[0]}.sig")`,
	} {
		if !strings.Contains(string(script), want) {
			t.Errorf("install.sh lacks %q", want)
		}
	}
}
