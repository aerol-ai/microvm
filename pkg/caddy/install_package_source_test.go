package caddy

import (
	"os"
	"strings"
	"testing"
)

// TestInstallerTakesCaddyFromGitHubRelease: install.sh installs the stock
// Caddy package from Caddy's GitHub release, checked against its SHA-512
// list, and never uses the Cloudsmith apt repository. That repository
// answers 402 Payment Required whenever Cloudsmith's bandwidth quota runs
// out. On 2026-10-09 it failed every new install (no Caddy, so no TLS), and
// on a host that still had its source every apt-get update failed, so
// re-running the installer failed too.
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
		`sha512sum -c selected-checksum.txt`,
		// The stale source goes before the first apt-get update.
		"drop_caddy_apt_source\n\t\tapt-get update",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("install.sh is missing %q", want)
		}
	}
}
