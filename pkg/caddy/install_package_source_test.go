package caddy

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestInstallerTakesCaddyFromGitHubRelease: install.sh installs the stock
// Caddy package from Caddy's GitHub release (falling back to the download
// mirror's copy), checked against a SHA-256 pinned per architecture, and
// never uses the Cloudsmith apt repository. That repository answers 402
// Payment Required whenever Cloudsmith's bandwidth quota runs out. On
// 2026-10-09 it failed every new install (no Caddy, so no TLS), and on a
// host that still had its source every apt-get update failed, so re-running
// the installer failed too.
func TestInstallerTakesCaddyFromGitHubRelease(t *testing.T) {
	raw, err := os.ReadFile("../../scripts/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	for _, banned := range []string{"dl.cloudsmith.io", "apt-get install -y caddy"} {
		if strings.Contains(src, banned) {
			t.Errorf("install.sh must not install Caddy from the Cloudsmith apt repository (found %q)", banned)
		}
	}
	for _, want := range []string{
		`CADDY_PACKAGE_URL_BASE="https://github.com/caddyserver/caddy/releases/download"`,
		`fetch_pinned "${tmp_dir}/${asset}" caddy "$asset"`,
		// The stale source goes before the first apt-get update.
		"drop_caddy_apt_source\n\t\tapt-get update",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("install.sh is missing %q", want)
		}
	}
	// install_caddy_package's architectures, each with its own pin.
	for _, arch := range []string{"AMD64", "ARM64", "ARMV7", "ARMV6"} {
		m := regexp.MustCompile(`(?m)^CADDY_PACKAGE_SHA256_` + arch + `="([0-9a-f]{64})"$`).FindStringSubmatch(src)
		if m == nil {
			t.Errorf("install.sh has no SHA-256 pin CADDY_PACKAGE_SHA256_%s", arch)
		}
	}
}
