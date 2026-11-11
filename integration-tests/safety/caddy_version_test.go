package safety

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Caddy used to be built at different versions in different places. The
// release build named no version, so v0.6.12 shipped whatever Caddy was
// newest that day (v2.11.9). The reload e2e test built v2.11.7, the stock
// package was 2.11.7, and the build-service fallback, the integration
// harness and the caddyfx fixture took the newest Caddy and plugins. What
// shipped was never what was tested. scripts/install.sh now pins the Caddy
// release (CADDY_VERSION: the stock package and the build-service fallback),
// the core of every custom build (CADDY_BUILD_VERSION) and the plugin
// versions. These tests keep every other Caddy build in step with them.

type caddyPins struct {
	version, buildVersion, l4, cloudflare, s3 string
}

// readCaddyPins reads the Caddy pins from install.sh's DOWNLOAD PINS block.
func readCaddyPins(t *testing.T) caddyPins {
	t.Helper()
	src := installShSource(t)
	get := func(name string) string {
		m := regexp.MustCompile(`(?m)^` + name + `="([^"]+)"$`).FindStringSubmatch(src)
		if m == nil {
			t.Fatalf("install.sh has no %s=\"...\" line", name)
		}
		return m[1]
	}
	p := caddyPins{
		version:      get("CADDY_VERSION"),
		buildVersion: get("CADDY_BUILD_VERSION"),
		l4:           get("CADDY_L4_MODULE"),
		cloudflare:   get("CADDY_DNS_CLOUDFLARE_MODULE"),
		s3:           get("CADDY_STORAGE_S3_MODULE"),
	}
	if !regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(p.version) {
		t.Fatalf("CADDY_VERSION %q is not x.y.z", p.version)
	}
	// A release tag (vX.Y.Z) or a Go pseudo-version of a commit
	// (vX.Y.Z-0.yyyymmddhhmmss-abcdef123456): xcaddy builds either.
	if !regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(-0\.[0-9]{14}-[0-9a-f]{12})?$`).MatchString(p.buildVersion) {
		t.Fatalf("CADDY_BUILD_VERSION %q is neither vX.Y.Z nor a Go pseudo-version", p.buildVersion)
	}
	for _, m := range []string{p.l4, p.cloudflare, p.s3} {
		if !strings.Contains(m, "@v") {
			t.Fatalf("plugin %q has no @version", m)
		}
	}
	return p
}

// caddyPlugin is AerolVM's own Caddy plugin (the sandbox route's upstream
// lookup), built from the checkout. Not an install.sh pin: Caddy's build
// service cannot add it, so only xcaddy builds carry it.
const caddyPlugin = "github.com/aerol-ai/microvm/caddymod=./caddymod"

// caddyBuilders lists every file that builds Caddy, and what each must say.
// Every one of them builds the custom Caddy, so every one names
// CADDY_BUILD_VERSION, or reads it and the plugin pins from install.sh.
func caddyBuilders(p caddyPins) map[string][]string {
	v := p.buildVersion
	return map[string][]string{
		".github/workflows/release.yml": {
			`xcaddy" build ` + v + ` \`,
			"--with " + caddyPlugin + " \\",
			"list-modules | grep -qx 'http.reverse_proxy.upstreams.aerolvm_route'",
			"--with " + p.l4 + " ",
			"--with " + p.cloudflare + " ",
			"--with " + p.s3 + "\n",
			`version | grep -q '^` + strings.ReplaceAll(v, ".", `\.`) + ` '`,
		},
		"integration-tests/lib/build.sh": {
			"xcaddy build " + v + ` \`,
			"--with " + caddyPlugin + " \\",
			"--with " + p.l4 + " ",
			"--with " + p.cloudflare + " ",
			"--with " + p.s3 + " ",
		},
		// The edge image for kind (C25) reads the pins at build time.
		"scripts/k8s-dev.sh": {
			`pin() { sed -n "s/^$1=\"\(.*\)\"$/\1/p" scripts/install.sh; }`,
			`xcaddy" \` + "\n" + `    build "$(pin CADDY_BUILD_VERSION)"`,
			"--with " + caddyPlugin + " \\",
			`--with "$(pin CADDY_L4_MODULE)"`,
			`--with "$(pin CADDY_DNS_CLOUDFLARE_MODULE)"`,
			`--with "$(pin CADDY_STORAGE_S3_MODULE)"`,
		},
		"Makefile": {
			"CADDY_E2E_VERSION ?= " + v + "\n",
			"--with " + p.l4 + ";",
		},
		"internal/service/testfixtures/caddyfx/xcaddy.go": {
			`const caddyVersion = "` + v + `"`,
			`const certmagicS3Module = "` + p.s3 + `"`,
			`"build", caddyVersion,`,
		},
	}
}

func TestCaddyBuildsUseThePinnedVersion(t *testing.T) {
	p := readCaddyPins(t)
	for file, wants := range caddyBuilders(p) {
		src := readRepoFile(t, strings.Split(file, "/")...)
		for _, want := range wants {
			if !strings.Contains(src, want) {
				t.Errorf("%s does not contain %q: it must build Caddy %s (install.sh's CADDY_BUILD_VERSION) with install.sh's plugin pins", file, want, p.buildVersion)
			}
		}
	}
}

// The plugin compiles against the Caddy core a release builds: a Caddy bump
// that breaks it fails the plugin's own tests, not the release build. Its
// go.mod also takes part in the release build's version choice, so a
// dependency it pins lower would not hold back the shipped Caddy, and one it
// pins higher would raise it.
func TestCaddyPluginUsesThePinnedVersion(t *testing.T) {
	p := readCaddyPins(t)
	src := readRepoFile(t, "caddymod", "go.mod")
	if want := "\tgithub.com/caddyserver/caddy/v2 " + p.buildVersion + "\n"; !strings.Contains(src, want) {
		t.Fatalf("caddymod/go.mod must require Caddy %s, install.sh's CADDY_BUILD_VERSION", p.buildVersion)
	}
}

// A new place that builds Caddy with xcaddy must join caddyBuilders, so it
// cannot quietly build another version.
func TestEveryXcaddyBuildIsChecked(t *testing.T) {
	builds := regexp.MustCompile(`xcaddy/cmd/xcaddy@|\bxcaddy"?\s+build\b`)
	known := caddyBuilders(readCaddyPins(t))
	root := filepath.Join("..", "..")
	skipDirs := map[string]bool{".git": true, "node_modules": true, "docs": true, "bin": true, "vendor": true, ".claude": true, "safety": true}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] || strings.HasPrefix(d.Name(), ".tf") {
				return filepath.SkipDir
			}
			return nil
		}
		switch filepath.Ext(path) {
		case ".sh", ".yml", ".yaml", ".go", ".py":
		default:
			if d.Name() != "Makefile" {
				return nil
			}
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if builds.Match(raw) {
			if _, ok := known[rel]; !ok {
				t.Errorf("%s builds Caddy with xcaddy but is not in caddyBuilders; pin it to install.sh's CADDY_BUILD_VERSION and plugins, and add it there", rel)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// The build-service fallback asks for the pinned plugins, and checks the
// core after the download: the service ignores a requested Caddy version.
func TestBuildServiceFallbackUsesThePins(t *testing.T) {
	body := installShFunction(t, installShSource(t), "install_custom_caddy")
	for _, want := range []string{
		"&p=${CADDY_L4_MODULE}",
		"&p=${CADDY_DNS_CLOUDFLARE_MODULE}",
		"&p=${CADDY_STORAGE_S3_MODULE}",
		`check_caddy_core_version "$tmp_binary" "Caddy build server"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("install_custom_caddy does not contain %q", want)
		}
	}
}

func TestCheckCaddyCoreVersion(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	p := readCaddyPins(t)
	fn := installShFunction(t, installShSource(t), "check_caddy_core_version")
	cases := []struct {
		name    string
		prints  string
		ok      bool
		message string
	}{
		{name: "the pinned version", prints: "v" + p.version + " h1:bhZtcRKQ=", ok: true},
		{name: "a newer Caddy from the build service", prints: "v9.99.0 h1:abc=", message: "built Caddy v9.99.0, but this installer pins v" + p.version},
		{name: "a version that only starts the same", prints: "v" + p.version + "0 h1:abc=", message: "pins v" + p.version},
		{name: "no version at all", prints: "", message: "built Caddy of an unknown version"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			bin := filepath.Join(dir, "caddy")
			script := "#!/bin/sh\n[ \"$1\" = version ] || exit 2\nprintf '%s\\n' '" + tc.prints + "'\n"
			if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("bash", "-c", `CADDY_VERSION="$1"; `+fn+`
check_caddy_core_version "$2" "Caddy build server"`, "_", p.version, bin)
			out, err := cmd.CombinedOutput()
			if tc.ok {
				if err != nil {
					t.Fatalf("refused the pinned version: %v\n%s", err, out)
				}
				return
			}
			if err == nil {
				t.Fatalf("accepted %q, want a refusal", tc.prints)
			}
			if !strings.Contains(string(out), tc.message) {
				t.Fatalf("refusal %q does not say %q", out, tc.message)
			}
		})
	}
}
