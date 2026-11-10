package safety

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// On 2026-11-08 GitHub's release downloads answered 504 for hours while its
// status page stayed green. install.sh fetched everything from GitHub, so
// every customer install, every Terraform-booted node and every integration
// run failed. Each GitHub download now goes through fetch_with_fallback:
// GitHub, then the public mirror, then the vendor's own site, with every
// file still checked against the release's checksums.txt or a pinned
// SHA-256 whichever source served it.
//
// These tests run install.sh's real functions with curl_download, systemctl
// and uname replaced by bash functions, so nothing reaches the network or
// changes the machine running them.

const testMirror = "https://mirror.test"

// installShPinsDefaults is install.sh's DOWNLOAD PINS block with every
// NAME="value" turned into NAME="${NAME-value}", so a hash the test set for
// its fixture wins over the real pin.
func installShPinsDefaults(t *testing.T, src string) string {
	t.Helper()
	start := strings.Index(src, "\n# --- BEGIN DOWNLOAD PINS")
	end := strings.Index(src, "\n# --- END DOWNLOAD PINS")
	if start < 0 || end < start {
		t.Fatal("install.sh has no DOWNLOAD PINS block")
	}
	return regexp.MustCompile(`(?m)^([A-Z0-9_]+)="([^"]*)"$`).
		ReplaceAllString(src[start:end+1], `$1="$${$1-$2}"`)
}

// fetchFuncs are the download helpers, cut out of install.sh.
func fetchFuncs(t *testing.T, src string) string {
	t.Helper()
	var b strings.Builder
	for _, name := range []string{"fetch_with_fallback", "fetch_source", "download_mirror_on",
		"mirror_url_for", "release_mirror_path", "fetch_pinned", "sha256_of"} {
		b.WriteString(extractShellFunc(t, src, name))
	}
	return b.String()
}

// serveKey is the file name the curl_download stub serves a URL from.
func serveKey(url string) string {
	return regexp.MustCompile(`[^A-Za-z0-9._-]`).ReplaceAllString(url, "_")
}

// fetchStubs: curl_download logs each request with the retry count it would
// use, then serves $SERVE/<url as a file name> or fails like a 504.
// DOWNLOAD_RETRY=60 stands in for install.sh's patient default.
const fetchStubs = `
DOWNLOAD_RETRY=60
MIRROR_LATEST_TAG=""
curl_download() {
	local url="$1" dest="$3" f
	echo "GET ${url} retry=${DOWNLOAD_RETRY}" >>"$LOG"
	f="$SERVE/$(printf '%s' "$url" | tr -c 'A-Za-z0-9._-' '_')"
	[[ -f "$f" ]] || return 22
	if [[ "$dest" == - ]]; then cat "$f"; else cat "$f" >"$dest"; fi
}
`

type fetchRig struct {
	t                 *testing.T
	serve, log        string
	stdout, stderr    string
	code              int
	requests, outFile string
}

func newFetchRig(t *testing.T, served map[string]string) *fetchRig {
	t.Helper()
	dir := t.TempDir()
	r := &fetchRig{t: t, serve: filepath.Join(dir, "serve"), log: filepath.Join(dir, "requests.log"),
		outFile: filepath.Join(dir, "out", "file.bin")}
	mustMkdir(t, r.serve)
	mustMkdir(t, filepath.Dir(r.outFile))
	for url, body := range served {
		mustWrite(t, filepath.Join(r.serve, serveKey(url)), body)
	}
	return r
}

// run runs snippet after the stubs, the pins block (defaults only) and the
// helpers, with env as shell variables.
func (r *fetchRig) run(snippet string, env map[string]string) {
	r.t.Helper()
	src := installShSource(r.t)
	vars := "set -euo pipefail\nLOG='" + r.log + "'\nSERVE='" + r.serve + "'\nOUT='" + r.outFile + "'\n"
	for k, v := range env {
		vars += k + "='" + v + "'\n"
	}
	script := vars + fetchStubs + installShPinsDefaults(r.t, src) + fetchFuncs(r.t, src) + snippet
	cmd := exec.Command("bash", "-c", script)
	var out, errOut strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	r.stdout, r.stderr = out.String(), errOut.String()
	r.code = 0
	if ee, ok := err.(*exec.ExitError); ok {
		r.code = ee.ExitCode()
	} else if err != nil {
		r.t.Fatalf("bash: %v", err)
	}
	raw, _ := os.ReadFile(r.log)
	r.requests = strings.TrimSpace(string(raw))
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// TestFetchWithFallbackOrder: GitHub first, then the mirror, then the vendor;
// a source that fails moves on in seconds (two quick retries) and only the
// last source keeps the patient retries; every source's file must match the
// pin; "off" and "" skip the mirror.
func TestFetchWithFallbackOrder(t *testing.T) {
	const (
		gh     = "https://github.com/acme/tool/releases/download/v1.0.0/tool.tgz"
		path   = "deps/tool/v1.0.0/tool.tgz"
		mirror = testMirror + "/" + path
		vendor = "https://downloads.acme.example/tool-v1.0.0.tgz"
		good   = "the real tool\n"
		bad    = "something else\n"
	)
	goodSHA := sha256Hex([]byte(good))
	cases := []struct {
		name       string
		served     map[string]string
		mirrorBase string // DOWNLOAD_MIRROR
		sha        bool   // pass --sha256 of good
		wantCode   int
		wantFile   string // "" = no file left behind
		want       []string
		never      []string
		wantErr    string
	}{
		{name: "GitHub answers: one request, the mirror is never asked",
			served: map[string]string{gh: good}, mirrorBase: testMirror, sha: true, wantFile: good,
			want: []string{"GET " + gh + " retry=2"}, never: []string{mirror, vendor}},
		{name: "GitHub 504 goes to the mirror, quickly",
			served: map[string]string{mirror: good}, mirrorBase: testMirror, sha: true, wantFile: good,
			want: []string{"GET " + gh + " retry=2", "GET " + mirror + " retry=2"}, never: []string{vendor}},
		{name: "a mirror miss goes to the vendor, which is last and patient",
			served: map[string]string{vendor: good}, mirrorBase: testMirror, sha: true, wantFile: good,
			want: []string{"GET " + gh + " retry=2", "GET " + mirror + " retry=2", "GET " + vendor + " retry=60"}},
		{name: "every source fails: a clear error naming each",
			mirrorBase: testMirror, sha: true, wantCode: 1,
			want:    []string{"GET " + gh, "GET " + mirror, "GET " + vendor},
			wantErr: "Failed to download file.bin from every source:\n  " + gh + "\n  " + mirror + "\n  " + vendor},
		{name: "a checksum mismatch from GitHub is refused, not retried elsewhere",
			served: map[string]string{gh: bad, mirror: good}, mirrorBase: testMirror, sha: true, wantCode: 1,
			want: []string{"GET " + gh}, never: []string{mirror, vendor},
			wantErr: "checksum verification failed for file.bin: got " + sha256Hex([]byte(bad)) + ", pinned " + goodSHA + " (served by " + gh + ")"},
		{name: "a checksum mismatch from the mirror is refused",
			served: map[string]string{mirror: bad, vendor: good}, mirrorBase: testMirror, sha: true, wantCode: 1,
			want: []string{"GET " + gh, "GET " + mirror}, never: []string{vendor},
			wantErr: "(served by " + mirror + "); refusing it"},
		{name: "a checksum mismatch from the vendor is refused",
			served: map[string]string{vendor: bad}, mirrorBase: testMirror, sha: true, wantCode: 1,
			want:    []string{"GET " + vendor},
			wantErr: "(served by " + vendor + "); refusing it"},
		{name: "off turns the mirror off",
			served: map[string]string{mirror: good, vendor: good}, mirrorBase: "off", sha: true, wantFile: good,
			want: []string{"GET " + gh + " retry=2", "GET " + vendor + " retry=60"}, never: []string{"mirror.test"}},
		{name: "empty turns the mirror off",
			served: map[string]string{mirror: good, vendor: good}, mirrorBase: "", sha: true, wantFile: good,
			want: []string{"GET " + vendor}, never: []string{"mirror.test"}},
		{name: "without --sha256 the file is taken as served",
			served: map[string]string{mirror: bad}, mirrorBase: testMirror, wantFile: bad,
			want: []string{"GET " + gh, "GET " + mirror}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newFetchRig(t, tc.served)
			shaFlag := ""
			if tc.sha {
				shaFlag = "--sha256 " + goodSHA + " "
			}
			r.run(`rc=0; fetch_with_fallback `+shaFlag+`"$OUT" `+path+` `+gh+` `+vendor+` || rc=$?; exit "$rc"`,
				map[string]string{"DOWNLOAD_MIRROR": tc.mirrorBase})
			t.Logf("requests:\n%s\nstderr:\n%s", r.requests, r.stderr)
			if r.code != tc.wantCode {
				t.Fatalf("exit %d, want %d", r.code, tc.wantCode)
			}
			checkCalls(t, strings.Split(r.requests, "\n"), tc.want, tc.never)
			if tc.wantErr != "" && !strings.Contains(r.stderr, tc.wantErr) {
				t.Errorf("stderr lacks %q", tc.wantErr)
			}
			got, err := os.ReadFile(r.outFile)
			switch {
			case tc.wantFile == "" && err == nil:
				t.Errorf("a refused download left %q behind", got)
			case tc.wantFile != "" && string(got) != tc.wantFile:
				t.Errorf("file = %q (%v), want %q", got, err, tc.wantFile)
			}
		})
	}
}

// TestFetchWithFallbackFindsTheLatestReleaseOnTheMirror: a releases/latest URL
// has no tag, so the mirror's copy is found through aerolvm/latest.txt, read
// once for the whole run. Without one the mirror is skipped.
func TestFetchWithFallbackFindsTheLatestReleaseOnTheMirror(t *testing.T) {
	const (
		ghSandboxd = "https://github.com/aerol-ai/microvm/releases/latest/download/sandboxd_linux_amd64"
		ghToolboxd = "https://github.com/aerol-ai/microvm/releases/latest/download/toolboxd_linux_amd64"
		latest     = testMirror + "/aerolvm/latest.txt"
	)
	snippet := `rc=0
fetch_with_fallback "$OUT" "$(release_mirror_path ` + ghSandboxd + `)" ` + ghSandboxd + ` || rc=$?
fetch_with_fallback "$OUT.2" "$(release_mirror_path ` + ghToolboxd + `)" ` + ghToolboxd + ` || rc=$?
exit "$rc"`
	t.Run("latest.txt names the release", func(t *testing.T) {
		r := newFetchRig(t, map[string]string{
			latest: "v0.6.11\n",
			testMirror + "/aerolvm/v0.6.11/sandboxd_linux_amd64": "sandboxd",
			testMirror + "/aerolvm/v0.6.11/toolboxd_linux_amd64": "toolboxd",
		})
		r.run(snippet, map[string]string{"DOWNLOAD_MIRROR": testMirror})
		if r.code != 0 {
			t.Fatalf("exit %d\n%s\n%s", r.code, r.requests, r.stderr)
		}
		checkCalls(t, strings.Split(r.requests, "\n"),
			[]string{ghSandboxd, latest, "/aerolvm/v0.6.11/sandboxd_linux_amd64", ghToolboxd, "/aerolvm/v0.6.11/toolboxd_linux_amd64"}, nil)
		if n := strings.Count(r.requests, latest); n != 1 {
			t.Errorf("latest.txt read %d times, want once:\n%s", n, r.requests)
		}
	})
	t.Run("no latest.txt: the mirror is skipped, once", func(t *testing.T) {
		r := newFetchRig(t, nil)
		r.run(snippet, map[string]string{"DOWNLOAD_MIRROR": testMirror})
		if r.code == 0 {
			t.Fatal("succeeded with nothing served")
		}
		if n := strings.Count(r.requests, latest); n != 1 {
			t.Errorf("latest.txt read %d times, want once:\n%s", n, r.requests)
		}
		if strings.Contains(r.requests, "/aerolvm/latest/") {
			t.Errorf("asked the mirror for a literal latest/ path:\n%s", r.requests)
		}
		if !strings.Contains(r.stderr, "no latest release named there") {
			t.Errorf("stderr does not say why the mirror was skipped:\n%s", r.stderr)
		}
	})
	t.Run("latest.txt that is not a version is ignored", func(t *testing.T) {
		r := newFetchRig(t, map[string]string{latest: "../../etc\n"})
		r.run(snippet, map[string]string{"DOWNLOAD_MIRROR": testMirror})
		if r.code == 0 || strings.Contains(r.requests, "etc/") {
			t.Fatalf("followed a bad latest.txt:\n%s", r.requests)
		}
	})
}

// TestReleaseMirrorPath: only aerol-ai/microvm release URLs have a mirror
// copy, at aerolvm/<tag>/<file>.
func TestReleaseMirrorPath(t *testing.T) {
	src := installShSource(t)
	fn := extractShellFunc(t, src, "release_mirror_path")
	for url, want := range map[string]string{
		"https://github.com/aerol-ai/microvm/releases/download/v0.6.11/sandboxd_linux_amd64":  "aerolvm/v0.6.11/sandboxd_linux_amd64",
		"https://github.com/aerol-ai/microvm/releases/download/v0.7.0-rc.1/checksums.txt":     "aerolvm/v0.7.0-rc.1/checksums.txt",
		"https://github.com/aerol-ai/microvm/releases/latest/download/caddy_linux_arm64":      "aerolvm/latest/caddy_linux_arm64",
		"https://github.com/some-fork/microvm/releases/download/v0.6.11/sandboxd_linux_amd64": "",
		"https://github.com/aerol-ai/microvm/releases/download/..%2f/x":                       "",
		"https://github.com/aerol-ai/microvm/releases/download/main/sandboxd":                 "",
		"https://bucket.s3.amazonaws.com/builds/abc/sandboxd_linux_amd64?X-Amz-Signature=x":   "",
		"file:///tmp/sandboxd": "",
	} {
		out, err := exec.Command("bash", "-c", "set -euo pipefail\n"+fn+`release_mirror_path "$1"`, "bash", url).Output()
		if err != nil {
			t.Fatalf("release_mirror_path %s: %v", url, err)
		}
		if got := strings.TrimSpace(string(out)); got != want {
			t.Errorf("release_mirror_path %s = %q, want %q", url, got, want)
		}
	}
}

// pinRow is one line of install.sh's download_pins.
type pinRow struct{ project, version, file, sha, origin string }

func downloadPins(t *testing.T) []pinRow {
	t.Helper()
	src := installShSource(t)
	out, err := exec.Command("bash", "-c", "set -euo pipefail\n"+installShPinsDefaults(t, src)+"download_pins").Output()
	if err != nil {
		t.Fatalf("download_pins: %v", err)
	}
	var rows []pinRow
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Fields(line)
		if len(f) != 5 {
			t.Fatalf("download_pins line %q has %d fields, want 5", line, len(f))
		}
		rows = append(rows, pinRow{f[0], f[1], f[2], f[3], f[4]})
	}
	return rows
}

// TestDownloadPinsAreWellFormed: every row has a SHA-256, a safe path on the
// mirror and an https origin (or a member of an earlier row's file), and
// every row install.sh downloads is fetched from its origin and then
// deps/<project>/<version>/<file> on the mirror.
func TestDownloadPinsAreWellFormed(t *testing.T) {
	rows := downloadPins(t)
	if len(rows) < 12 {
		t.Fatalf("download_pins lists %d files; want caddy, workerd, firecracker, cni-plugins and buildkit", len(rows))
	}
	hexSHA := regexp.MustCompile(`^[0-9a-f]{64}$`)
	safe := regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)
	seen := map[string]bool{}
	for _, r := range rows {
		key := r.project + "/" + r.version + "/" + r.file
		if seen[key] {
			t.Errorf("%s listed twice", key)
		}
		seen[key] = true
		if !hexSHA.MatchString(r.sha) {
			t.Errorf("%s: %q is not a SHA-256", key, r.sha)
		}
		for _, part := range []string{r.project, r.version, r.file} {
			if !safe.MatchString(part) {
				t.Errorf("%s: %q is not a safe path segment", key, part)
			}
		}
		if !strings.HasPrefix(r.version, "v") {
			t.Errorf("%s: version %q, want the v-prefixed release tag", key, r.version)
		}
		switch {
		case strings.HasPrefix(r.origin, "tar:"):
			parts := strings.SplitN(strings.TrimPrefix(r.origin, "tar:"), ":", 2)
			if len(parts) != 2 || !seen[r.project+"/"+r.version+"/"+parts[0]] {
				t.Errorf("%s: %q must name a file listed before it for %s %s", key, r.origin, r.project, r.version)
			}
		case strings.HasPrefix(r.origin, "https://"):
			if !strings.HasSuffix(r.origin, "/"+r.file) {
				t.Errorf("%s: origin %q does not end in the file name", key, r.origin)
			}
		default:
			t.Errorf("%s: origin %q is neither https:// nor tar:", key, r.origin)
		}
	}

	// fetch_pinned, row by row, with GitHub down and a mirror that serves
	// the wrong bytes: it must ask the origin, then the mirror at the
	// documented layout, and refuse what the mirror sent.
	for _, row := range rows {
		if !strings.HasPrefix(row.origin, "https://") {
			continue
		}
		mirror := testMirror + "/deps/" + row.project + "/" + row.version + "/" + row.file
		r := newFetchRig(t, map[string]string{mirror: "not the pinned file"})
		r.run(`rc=0; fetch_pinned "$OUT" `+row.project+` `+row.file+` || rc=$?; exit "$rc"`,
			map[string]string{"DOWNLOAD_MIRROR": testMirror})
		if r.code == 0 {
			t.Errorf("%s: fetch_pinned accepted a file that does not match its pin", row.file)
		}
		checkCalls(t, strings.Split(r.requests, "\n"), []string{"GET " + row.origin + " retry=2", "GET " + mirror}, nil)
		if !strings.Contains(r.stderr, "pinned "+row.sha) {
			t.Errorf("%s: stderr does not name the pin:\n%s", row.file, r.stderr)
		}
	}
}

// TestInstallShSendsEveryGitHubDownloadThroughTheFallback: a GitHub URL in
// install.sh is a pin's origin (download_pins), the release URL base that
// release_mirror_path maps to the mirror, or that function's own pattern.
// A new curl_download of a GitHub URL would have no fallback.
func TestInstallShSendsEveryGitHubDownloadThroughTheFallback(t *testing.T) {
	src := installShSource(t)
	start := strings.Index(src, "\n# --- BEGIN DOWNLOAD PINS")
	end := strings.Index(src, "\n# --- END DOWNLOAD PINS")
	pinsBlock := src[start:end]
	outside := src[:start] + src[end:]
	allowed := []string{
		`release_base="https://github.com/${GITHUB_REPO}/releases"`,
		`local re='^https://github\.com/aerol-ai/microvm/releases/`,
	}
	for i, line := range strings.Split(outside, "\n") {
		if !strings.Contains(line, "https://github.com/") || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		ok := false
		for _, a := range allowed {
			ok = ok || strings.Contains(line, a)
		}
		if !ok {
			t.Errorf("install.sh line %d (outside the pins block) names a GitHub URL with no mirror fallback:\n%s", i+1, line)
		}
	}
	if strings.Contains(pinsBlock, "curl") {
		t.Error("the pins block downloads something; mirror-sync.sh runs it and must only read values")
	}
	for _, fn := range []string{"install_caddy_package", "install_workerd_binary", "install_firecracker_release",
		"install_cni_plugins", "install_buildkit"} {
		if !strings.Contains(extractShellFunc(t, src, fn), "fetch_pinned ") {
			t.Errorf("%s does not download through fetch_pinned", fn)
		}
	}
	for _, fn := range []string{"download_asset", "install_custom_caddy"} {
		if !strings.Contains(extractShellFunc(t, src, fn), "fetch_with_fallback ") {
			t.Errorf("%s does not download through fetch_with_fallback", fn)
		}
	}
}

// bootstrapContainerdDefaults reads Terraform's default containerd socket,
// namespace and CNI directory (Terraform/locals.tf containerd_cfg).
func bootstrapContainerdDefaults(t *testing.T) (socket, namespace, cniDir string) {
	t.Helper()
	locals := readRepoFile(t, "Terraform", "locals.tf")
	get := func(key string) string {
		m := regexp.MustCompile(key + `\s*=\s*try\(local\.cluster_ops\.containerd\.` + key + `, "([^"]+)"\)`).FindStringSubmatch(locals)
		if m == nil {
			t.Fatalf("Terraform/locals.tf has no containerd_cfg.%s default", key)
		}
		return m[1]
	}
	return get("socket"), get("namespace"), get("cni_plugin_dir")
}

// bootstrapBuildkitUnit is the bootstrap's buildkit.service rendered with
// Terraform's defaults, which is what a node with no containerd settings in
// cluster.yml gets.
func bootstrapBuildkitUnit(t *testing.T) string {
	t.Helper()
	tpl := readRepoFile(t, "Terraform", "templates", "bootstrap.sh.tftpl")
	start := strings.Index(tpl, "/etc/systemd/system/buildkit.service >/dev/null <<UNIT\n")
	if start < 0 {
		t.Fatal("the bootstrap no longer writes buildkit.service from a <<UNIT heredoc")
	}
	body := tpl[strings.Index(tpl[start:], "\n")+start+1:]
	end := strings.Index(body, "\nUNIT\n")
	if end < 0 {
		t.Fatal("the bootstrap's buildkit.service heredoc has no end")
	}
	socket, namespace, _ := bootstrapContainerdDefaults(t)
	unit := strings.NewReplacer("${containerd_cfg.socket}", socket, "${containerd_cfg.namespace}", namespace).Replace(body[:end+1])
	if strings.ContainsAny(unit, "$%") {
		t.Fatalf("the bootstrap's unit has template syntax this test does not render:\n%s", unit)
	}
	return unit
}

// TestInstallBuildkitMatchesTheBootstrap: a Terraform node runs install.sh
// before the bootstrap's BuildKit and CNI steps, which skip themselves when
// buildkitd, buildkit.service and <cni_dir>/bridge exist. So whatever
// install.sh puts there must be exactly what the bootstrap would have: the
// same versions, binaries, paths and unit. The versions are the one-line
// join path's, the first bk_ver= and cni_ver= in the template; the old path
// keeps v0.6.13's (see TestBootstrapDownloadMirrorPinsMatchInstallSh).
func TestInstallBuildkitMatchesTheBootstrap(t *testing.T) {
	src := installShSource(t)
	tpl := readRepoFile(t, "Terraform", "templates", "bootstrap.sh.tftpl")
	want := bootstrapBuildkitUnit(t)

	t.Run("same unit", func(t *testing.T) {
		out, err := exec.Command("bash", "-c", "set -euo pipefail\n"+extractShellFunc(t, src, "buildkit_unit")+"buildkit_unit").Output()
		if err != nil {
			t.Fatal(err)
		}
		if string(out) != want {
			t.Errorf("install.sh's buildkit.service differs from the bootstrap's.\ninstall.sh:\n%s\nbootstrap:\n%s", out, want)
		}
	})
	t.Run("same versions, binaries, paths and guards", func(t *testing.T) {
		checks := []struct{ what, re, want string }{
			{"BuildKit version", `bk_ver=(v[0-9.]+)`, installShVarSafety(t, src, "BUILDKIT_VERSION")},
			{"CNI plugins version", `cni_ver=(v[0-9.]+)`, installShVarSafety(t, src, "CNI_PLUGINS_VERSION")},
			{"unit path", `if \[ ! -f (/etc/systemd/system/buildkit\.service) \]`, installShVarSafety(t, src, "BUILDKIT_UNIT_FILE")},
			{"binary guard", `if ! command -v (buildkitd) >/dev/null 2>&1; then`, "buildkitd"},
		}
		for _, c := range checks {
			m := regexp.MustCompile(c.re).FindStringSubmatch(tpl)
			if m == nil || m[1] != c.want {
				t.Errorf("%s: bootstrap has %q, install.sh %q", c.what, m, c.want)
			}
		}
		bins := regexp.MustCompile(`install -m 0755 "\$\$\{bk_tmp\}/bin/([a-z]+)" (/usr/local/bin)/([a-z]+)`).FindAllStringSubmatch(tpl, -1)
		if len(bins) != 2 || bins[0][1] != "buildkitd" || bins[1][1] != "buildctl" {
			t.Fatalf("the bootstrap installs %q; this test expects buildkitd and buildctl", bins)
		}
		if dir := installShVarSafety(t, src, "BUILDKIT_BIN_DIR"); dir != bins[0][2] {
			t.Errorf("install.sh puts BuildKit in %s, the bootstrap in %s", dir, bins[0][2])
		}
		_, _, cniDir := bootstrapContainerdDefaults(t)
		if cni := extractShellFunc(t, src, "install_cni_plugins"); !strings.Contains(cni, `-C `+cniDir+"\n") {
			t.Errorf("install_cni_plugins does not extract into Terraform's default cni_plugin_dir %s", cniDir)
		}
		if !strings.Contains(tpl, `if [ ! -x "$${cni_dir}/bridge" ]; then`) {
			t.Error("the bootstrap's CNI step no longer skips itself when bridge exists")
		}
	})

	// The install itself, against a fake release tarball that also carries
	// a binary the bootstrap does not install.
	tarball := buildkitTarball(t, map[string]string{"bin/buildkitd": "buildkitd", "bin/buildctl": "buildctl", "bin/buildkit-runc": "runc"})
	version := installShVarSafety(t, src, "BUILDKIT_VERSION")
	arch := "amd64"
	file := "buildkit-" + version + ".linux-" + arch + ".tar.gz"
	origin := "https://github.com/moby/buildkit/releases/download/" + version + "/" + file
	mirror := testMirror + "/deps/buildkit/" + version + "/" + file
	for _, tc := range []struct {
		name       string
		served     map[string][]byte
		preinstall bool // buildkitd on PATH and a unit already there
		// ours, when set, is the release a buildkitd already in
		// BUILDKIT_BIN_DIR reports (the path install.sh and the bootstrap
		// use), with the bootstrap's unit beside it.
		ours        string
		want, never []string
		wantErr     string
	}{
		{name: "fresh node: GitHub", served: map[string][]byte{origin: tarball},
			want: []string{"GET " + origin, "systemctl daemon-reload", "systemctl enable --now buildkit.service"}, never: []string{mirror}},
		{name: "fresh node: GitHub down, the mirror", served: map[string][]byte{mirror: tarball},
			want: []string{"GET " + origin, "GET " + mirror, "systemctl daemon-reload", "systemctl enable --now buildkit.service"}},
		{name: "already installed: nothing downloaded or rewritten, still enabled", preinstall: true,
			want: []string{"systemctl enable --now buildkit.service"}, never: []string{"GET ", "daemon-reload"}},
		{name: "a tarball that is not the pinned one is refused", served: map[string][]byte{origin: []byte("junk")},
			never: []string{"systemctl"}, wantErr: "checksum verification failed"},
		// A node from before v0.7.0 has BuildKit v0.17.2 (92 known
		// vulnerabilities): a re-run replaces it and restarts the service.
		{name: "ours at an older release: stopped, replaced, started", ours: "v0.17.2", served: map[string][]byte{origin: tarball},
			want: []string{"GET " + origin, "systemctl stop buildkit.service", "systemctl enable --now buildkit.service"}, never: []string{"daemon-reload"}},
		{name: "ours at the pinned release: nothing downloaded or stopped", ours: version,
			want: []string{"systemctl enable --now buildkit.service"}, never: []string{"GET ", "systemctl stop", "daemon-reload"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			serve, bin, tools := filepath.Join(dir, "serve"), filepath.Join(dir, "bin"), filepath.Join(dir, "tools")
			unit := filepath.Join(dir, "buildkit.service")
			for _, d := range []string{serve, bin, tools} {
				mustMkdir(t, d)
			}
			for url, body := range tc.served {
				if err := os.WriteFile(filepath.Join(serve, serveKey(url)), body, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			// PATH holds only the real tools install_buildkit and the
			// helpers run, so buildkitd is "installed" only when this case
			// puts it there, and nothing else on the machine is reached.
			for _, name := range []string{"mktemp", "rm", "tar", "gzip", "install", "cat", "tr", "shasum", "sha256sum", "awk"} {
				if p, err := exec.LookPath(name); err == nil {
					if err := os.Symlink(p, filepath.Join(tools, name)); err != nil {
						t.Fatal(err)
					}
				}
			}
			if tc.preinstall {
				mustWrite(t, filepath.Join(tools, "buildkitd"), "#!/bin/sh\n")
				if err := os.Chmod(filepath.Join(tools, "buildkitd"), 0o755); err != nil {
					t.Fatal(err)
				}
				mustWrite(t, unit, "operator's unit\n")
			}
			if tc.ours != "" {
				mustWrite(t, filepath.Join(bin, "buildkitd"), "#!/bin/sh\necho 'buildkitd github.com/moby/buildkit "+tc.ours+" 0123abcd'\n")
				if err := os.Chmod(filepath.Join(bin, "buildkitd"), 0o755); err != nil {
					t.Fatal(err)
				}
				mustWrite(t, filepath.Join(bin, "buildctl"), "old buildctl\n")
				mustWrite(t, unit, want)
			}
			log := filepath.Join(dir, "calls.log")
			script := "set -euo pipefail\nPATH='" + tools + "'\nLOG='" + log + "'\nSERVE='" + serve + "'\nTMPDIR='" + dir + "'\n" +
				"DOWNLOAD_MIRROR='" + testMirror + "'\nBUILDKIT_BIN_DIR='" + bin + "'\nBUILDKIT_UNIT_FILE='" + unit + "'\n" +
				"BUILDKIT_SHA256_AMD64='" + sha256Hex(tarball) + "'\n" +
				"uname() { echo x86_64; }\nsystemctl() { echo \"systemctl $*\" >>\"$LOG\"; }\n" +
				fetchStubs + installShPinsDefaults(t, src) + fetchFuncs(t, src) +
				extractShellFunc(t, src, "install_buildkit") + extractShellFunc(t, src, "buildkit_unit") +
				extractShellFunc(t, src, "buildkit_version_at") +
				"install_buildkit\necho DONE\n"
			cmd := exec.Command("bash", "-c", script)
			var out, errOut strings.Builder
			cmd.Stdout, cmd.Stderr = &out, &errOut
			err := cmd.Run()
			raw, _ := os.ReadFile(log)
			calls := strings.Split(strings.TrimSpace(string(raw)), "\n")
			t.Logf("calls:\n%s\nstderr:\n%s", raw, errOut.String())
			if tc.wantErr != "" {
				if err == nil || strings.Contains(out.String(), "DONE") || !strings.Contains(errOut.String(), tc.wantErr) {
					t.Fatalf("install_buildkit = %v, want a refusal naming %q", err, tc.wantErr)
				}
			} else if err != nil || !strings.Contains(out.String(), "DONE") {
				t.Fatalf("install_buildkit: %v\n%s", err, errOut.String())
			}
			checkCalls(t, calls, tc.want, tc.never)

			entries, _ := os.ReadDir(bin)
			var names []string
			for _, e := range entries {
				names = append(names, e.Name())
			}
			gotUnit, _ := os.ReadFile(unit)
			switch {
			case tc.wantErr != "":
				if len(names) != 0 || len(gotUnit) != 0 {
					t.Errorf("a refused install left binaries %v and unit %q", names, gotUnit)
				}
			case tc.preinstall:
				if len(names) != 0 || string(gotUnit) != "operator's unit\n" {
					t.Errorf("a node that had BuildKit got binaries %v and unit %q", names, gotUnit)
				}
			case tc.ours == version:
				if got, _ := os.ReadFile(filepath.Join(bin, "buildctl")); string(got) != "old buildctl\n" {
					t.Errorf("BuildKit at the pinned release was replaced: buildctl is now %q", got)
				}
			case tc.ours != "":
				for name, body := range map[string]string{"buildkitd": "buildkitd", "buildctl": "buildctl"} {
					if got, _ := os.ReadFile(filepath.Join(bin, name)); string(got) != body {
						t.Errorf("%s after the upgrade = %q, want the pinned release's", name, got)
					}
				}
				if string(gotUnit) != want {
					t.Errorf("the upgrade rewrote the unit:\n%s", gotUnit)
				}
			default:
				if strings.Join(names, " ") != "buildctl buildkitd" {
					t.Errorf("installed %v, want exactly buildctl and buildkitd, as the bootstrap does", names)
				}
				if string(gotUnit) != want {
					t.Errorf("unit written:\n%s\nbootstrap's:\n%s", gotUnit, want)
				}
			}
		})
	}
}

// installShVarSafety is install.sh's top-level NAME="value".
func installShVarSafety(t *testing.T, src, name string) string {
	t.Helper()
	m := regexp.MustCompile(`(?m)^` + name + `="([^"]*)"$`).FindStringSubmatch(src)
	if m == nil {
		t.Fatalf("install.sh has no top-level %s=\"...\"", name)
	}
	return m[1]
}

func buildkitTarball(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, name := range []string{"bin/buildkitd", "bin/buildctl", "bin/buildkit-runc"} {
		body := files[name]
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestInstallShDownloadMirrorSetting runs install.sh itself, --cli-only, in
// an environment where it cannot install anything (noInstallEnv) and a curl
// that logs each URL and fails like a 504. The URLs it tried show where the
// mirror setting points: the public bucket by default, AEROL_DOWNLOAD_MIRROR
// or --download-mirror when set (the flag wins), nowhere when "off" or "".
func TestInstallShDownloadMirrorSetting(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	script, err := filepath.Abs(filepath.Join("..", "..", "scripts", "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	osName := runtime.GOOS
	arch := map[string]string{"amd64": "amd64", "arm64": "arm64"}[runtime.GOARCH]
	if (osName != "linux" && osName != "darwin") || arch == "" {
		t.Skip("--cli-only needs linux or darwin on amd64 or arm64")
	}
	asset := "aerolvm_" + osName + "_" + arch
	gh := "https://github.com/aerol-ai/microvm/releases/download/v9.9.9/" + asset
	const public = "https://aerolvm-downloads.s3.us-east-1.amazonaws.com"
	unset := "\x00unset"
	cases := []struct {
		name, env string
		args      []string
		wantURLs  []string
		wantErr   string
	}{
		{name: "default: the public mirror", env: unset, wantURLs: []string{gh, public + "/aerolvm/v9.9.9/" + asset}},
		{name: "AEROL_DOWNLOAD_MIRROR", env: "https://mirror.example/", wantURLs: []string{gh, "https://mirror.example/aerolvm/v9.9.9/" + asset}},
		{name: "the flag wins over the variable", env: "https://env.example", args: []string{"--download-mirror", "https://flag.example"},
			wantURLs: []string{gh, "https://flag.example/aerolvm/v9.9.9/" + asset}},
		{name: "--download-mirror off", env: unset, args: []string{"--download-mirror", "off"}, wantURLs: []string{gh}},
		{name: "AEROL_DOWNLOAD_MIRROR empty", env: "", wantURLs: []string{gh}},
		{name: "plain http is refused", env: unset, args: []string{"--download-mirror", "http://mirror.example"},
			wantErr: "must be an https:// URL"},
		{name: "a bad variable is refused", env: "ftp://mirror.example", wantErr: "must be an https:// URL"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := noInstallEnv(t)
			curlDir := t.TempDir()
			urls := filepath.Join(curlDir, "urls.log")
			// Logs the URL (the argument that starts with https://) and
			// fails as GitHub did.
			mustWrite(t, filepath.Join(curlDir, "curl"), "#!/bin/sh\nfor a in \"$@\"; do case \"$a\" in https://*) echo \"$a\" >>'"+urls+"';; esac; done\nexit 22\n")
			if err := os.Chmod(filepath.Join(curlDir, "curl"), 0o755); err != nil {
				t.Fatal(err)
			}
			var full []string
			for _, kv := range env {
				switch {
				case strings.HasPrefix(kv, "PATH="):
					full = append(full, "PATH="+curlDir+string(os.PathListSeparator)+strings.TrimPrefix(kv, "PATH="))
				case strings.HasPrefix(kv, "AEROL_DOWNLOAD_MIRROR="), strings.HasPrefix(kv, "AEROL_DOWNLOAD_RETRY"):
				default:
					full = append(full, kv)
				}
			}
			if tc.env != unset {
				full = append(full, "AEROL_DOWNLOAD_MIRROR="+tc.env)
			}
			prefix := filepath.Join(t.TempDir(), "bin")
			args := append([]string{script, "--cli-only", "--version", "v9.9.9", "--install-prefix", prefix}, tc.args...)
			cmd := exec.Command("bash", args...)
			cmd.Dir = t.TempDir()
			cmd.Env = full
			out, err := cmd.CombinedOutput()
			t.Logf("install.sh %v:\n%s", tc.args, out)
			if err == nil {
				t.Fatal("install.sh succeeded with every download failing")
			}
			if _, statErr := os.Stat(filepath.Join(prefix, "aerolvm")); statErr == nil {
				t.Fatal("install.sh installed aerolvm although every download failed")
			}
			raw, _ := os.ReadFile(urls)
			got := strings.Fields(string(raw))
			if tc.wantErr != "" {
				if !strings.Contains(string(out), tc.wantErr) || len(got) != 0 {
					t.Fatalf("want a refusal %q before any download; downloads: %v", tc.wantErr, got)
				}
				return
			}
			if strings.Join(got, " ") != strings.Join(tc.wantURLs, " ") {
				t.Errorf("downloads tried:\n  %s\nwant:\n  %s", strings.Join(got, "\n  "), strings.Join(tc.wantURLs, "\n  "))
			}
		})
	}
}

// TestInstallShHelpDocumentsTheMirror: --help names the flag and the
// variable, as installer-options.mdx does.
func TestInstallShHelpDocumentsTheMirror(t *testing.T) {
	script, err := filepath.Abs(filepath.Join("..", "..", "scripts", "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", script, "--help")
	cmd.Dir = t.TempDir()
	cmd.Env = noInstallEnv(t)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("--help: %v\n%s", err, out)
	}
	docs := readRepoFile(t, "docs", "src", "content", "docs", "getting-started", "installer-options.mdx")
	for _, want := range []string{"--download-mirror", "AEROL_DOWNLOAD_MIRROR", "https://aerolvm-downloads.s3.us-east-1.amazonaws.com"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("install.sh --help does not mention %s", want)
		}
		if !strings.Contains(docs, want) {
			t.Errorf("installer-options.mdx does not mention %s", want)
		}
	}
}
