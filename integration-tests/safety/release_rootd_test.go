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
		"      HAVE_ROOTD_SIGNING_KEY: ${{ secrets.AEROLVM_ROOTD_SIGNING_KEY != '' }}\n",
		"        if: env.HAVE_ROOTD_SIGNING_KEY == 'true'\n",
		`"$RUNNER_TEMP/aerolvm-rootd-sign" -check-version "$VERSION" dist/aerolvm-rootd_linux_amd64 dist/aerolvm-rootd_linux_arm64`,
		`"$RUNNER_TEMP/aerolvm-rootd-sign" -key "$key" -version "$VERSION" -no-exec dist/aerolvm-rootd_linux_amd64 dist/aerolvm-rootd_linux_arm64`,
		`"$RUNNER_TEMP/aerolvm-rootd-sign" -verify internal/rootswap/release-keys.pub dist/aerolvm-rootd_linux_amd64 dist/aerolvm-rootd_linux_arm64`,
		"name: dist-rootd-signatures",
		"needs: [hold-latest, build, cli, sign-rootd]",
	} {
		if !strings.Contains(wf, want) {
			t.Errorf("release.yml lacks %q", want)
		}
	}
	// The key's value reaches one step's environment alone (the job's
	// environment only says whether it is set), that step runs no built
	// binary, the version is checked before it, and the key file is
	// removed whatever happens.
	value := "ROOTD_SIGNING_KEY: ${{ secrets.AEROLVM_ROOTD_SIGNING_KEY }}"
	if n := strings.Count(wf, value); n != 1 || !strings.Contains(wf, "        env:\n          "+value+"\n") {
		t.Errorf("the signing key's value appears %d times, or not as one step's env", n)
	}
	if n := strings.Count(wf, "secrets.AEROLVM_ROOTD_SIGNING_KEY"); n != 2 {
		t.Errorf("release.yml names the signing key %d times; only sign-rootd may", n)
	}
	sign := regexp.MustCompile(`(?s)- name: Sign aerolvm-rootd\n.*?\n\n`).FindString(wf)
	if sign == "" || !strings.Contains(sign, "-no-exec") || strings.Contains(sign, "go run") || strings.Contains(sign, "go build") {
		t.Errorf("the signing step must run only the signer, with -no-exec:\n%s", sign)
	}
	signAt := strings.Index(wf, "- name: Sign aerolvm-rootd")
	cleanup := strings.Index(wf, "- name: Remove the signing key file\n        if: always()\n")
	if signAt < 0 || cleanup < 0 || cleanup < signAt {
		t.Errorf("want an always() key removal (%d) after the signing step (%d)", cleanup, signAt)
	}
	// The helper runs (its --version) only in check-rootd, a job with no
	// environment and no secret, on a runner of its own. sign-rootd waits
	// for it, runs no helper, and builds the signer with no restored cache.
	checkJob := job(wf, "check-rootd")
	signJob := job(wf, "sign-rootd")
	if !strings.Contains(checkJob, "-check-version") || strings.Contains(checkJob, "environment:") || strings.Contains(checkJob, "secrets.") {
		t.Errorf("check-rootd must run -check-version with no environment and no secret:\n%s", checkJob)
	}
	for _, bad := range []string{"-check-version", "--version", "cache: true"} {
		if strings.Contains(signJob, bad) {
			t.Errorf("sign-rootd has %q: it must run no helper and restore no cache", bad)
		}
	}
	for _, want := range []string{"needs: [build, check-rootd]\n", "cache: false\n"} {
		if !strings.Contains(signJob, want) {
			t.Errorf("sign-rootd lacks %q", want)
		}
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

// job returns one job of a workflow: from its "  <name>:" line to the next
// job's.
func job(wf, name string) string {
	start := strings.Index(wf, "\n  "+name+":\n")
	if start < 0 {
		return ""
	}
	rest := wf[start+1:]
	if next := regexp.MustCompile(`\n  [a-z0-9-]+:\n`).FindStringIndex(rest[1:]); next != nil {
		return rest[:next[0]+1]
	}
	return rest
}
