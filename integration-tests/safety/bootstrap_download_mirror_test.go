// Offline tests for the node bootstrap's download mirror fallback
// (Terraform variable download_mirror, Terraform/templates/bootstrap.sh.tftpl).
//
// Why it matters: on 2026-11-09 GitHub's release downloads answered 504 from
// us-east-1, and the bootstrap's one GitHub-only download of the CNI plugins
// stopped the script on two servers and the ingress of a live cluster. With
// download_mirror set, every download that has a copy on the mirror falls back
// to it. Unset, nothing changes: an existing cluster's user_data must stay
// byte for byte the same, or the next apply replaces every node.
//
// Runs in the normal `go test ./...` / `make test` flow (no build tag).
package safety

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const bootstrapTestMirror = "https://mirror.example.com/base"

// Unset (the fixture's base), the template renders none of the fallback and
// keeps the old one-line downloads. TestBootstrapTemplateRenders' outputs
// were also compared byte for byte against main's template when this landed.
func TestBootstrapWithoutDownloadMirrorRendersNoFallback(t *testing.T) {
	out := renderBootstrap(t, "joiner")
	for _, gone := range []string{"mirror_path_for", "curl_retry", "download mirror", "cni_sha=", "bk_sha="} {
		if strings.Contains(out, gone) {
			t.Errorf("bootstrap without download_mirror contains %q", gone)
		}
	}
	for _, kept := range []string{
		`curl -fsSL "${cni_url}" | sudo tar -xz -C "${cni_dir}"`,
		`curl -fsSL "${bk_url}" | sudo tar -xz -C "${bk_tmp}"`,
	} {
		if !strings.Contains(out, kept) {
			t.Errorf("bootstrap without download_mirror lost %q", kept)
		}
	}
}

// With a mirror, the CNI plugins and BuildKit are checked against the same
// SHA-256 pins install.sh uses (and mirror-sync.sh fills the mirror from), so
// the two cannot drift apart. That holds on the one-line join path; the old
// path keeps v0.6.13's versions and hashes byte for byte, because changing
// them would replace every node (TestBootstrapOldJoinPathRendersLikeV0613),
// and install.sh upgrades those nodes in place.
func TestBootstrapDownloadMirrorPinsMatchInstallSh(t *testing.T) {
	out := renderBootstrap(t, "joiner_join_download_mirror")
	install, err := os.ReadFile(filepath.Join(integrationDir(t), "..", "scripts", "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	pin := func(name string) string {
		m := regexp.MustCompile(`(?m)^` + name + `="([0-9a-f]{64})"$`).FindStringSubmatch(string(install))
		if m == nil {
			t.Fatalf("install.sh has no %s", name)
		}
		return m[1]
	}
	version := func(name string) string {
		m := regexp.MustCompile(`(?m)^` + name + `="(v[0-9.]+)"$`).FindStringSubmatch(string(install))
		if m == nil {
			t.Fatalf("install.sh has no %s", name)
		}
		return m[1]
	}
	for _, want := range []string{
		"amd64) cni_sha=" + pin("CNI_PLUGINS_SHA256_AMD64") + " ;;",
		"arm64) cni_sha=" + pin("CNI_PLUGINS_SHA256_ARM64") + " ;;",
		"amd64) bk_sha=" + pin("BUILDKIT_SHA256_AMD64") + " ;;",
		"arm64) bk_sha=" + pin("BUILDKIT_SHA256_ARM64") + " ;;",
		"cni_ver=" + version("CNI_PLUGINS_VERSION"),
		"bk_ver=" + version("BUILDKIT_VERSION"),
		`curl_download "${cni_url}" -o "${cni_tmp}/cni-plugins.tgz"`,
		`curl_download "${bk_url}" -o "${bk_tmp}/buildkit.tar.gz"`,
		"'" + bootstrapTestMirror + "/aerolvm/latest.txt'",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("bootstrap with download_mirror lacks %q", want)
		}
	}
}

// fakeMirrorCurl stands in for curl: it logs each URL, fails any URL whose prefix
// is in FAKE_CURL_FAIL (space-separated), answers the mirror's latest.txt
// with FAKE_CURL_LATEST, and otherwise writes "from <url>" to -o or stdout.
const fakeMirrorCurl = `#!/usr/bin/env bash
url="" out=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    --retry|--retry-delay|--retry-max-time|--connect-timeout|--max-time|--speed-limit|--speed-time) shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
echo "$url" >>"$FAKE_CURL_LOG"
for p in $FAKE_CURL_FAIL; do
  case "$url" in "$p"*) exit 22 ;; esac
done
case "$url" in
  */aerolvm/latest.txt) body="$FAKE_CURL_LATEST" ;;
  *) body="from $url" ;;
esac
if [ -n "$out" ]; then printf '%s\n' "$body" >"$out"; else printf '%s\n' "$body"; fi
`

// TestBootstrapDownloadMirrorFallsBack runs the rendered helpers against a
// fake curl: the original source first, the mirror copy only when it fails,
// and nothing new for a URL the mirror keeps no copy of.
func TestBootstrapDownloadMirrorFallsBack(t *testing.T) {
	out := renderBootstrap(t, "joiner_download_mirror")
	start := strings.Index(out, "curl_retry() {")
	end := strings.Index(out, "\n%")
	if i := strings.Index(out[start:], "curl_retry 60 '"+bootstrapTestMirror+"'"); i > 0 {
		end = start + i + strings.Index(out[start+i:], "\n}") + 2
	}
	if start < 0 || end <= start {
		t.Fatalf("rendered bootstrap has no fallback helpers")
	}
	helpers := out[start:end]

	dir := t.TempDir()
	writeStageFile(t, filepath.Join(dir, "bin", "curl"), fakeMirrorCurl, 0o755)
	const (
		gh     = "https://github.com/"
		latest = "v0.6.12"
	)
	cases := []struct {
		name      string
		url       string
		fail      string
		latest    string
		wantOK    bool
		wantCalls []string
	}{
		{
			name: "install.sh from the domain, GitHub fails", url: "https://aerolvm.aerol.ai",
			fail: "https://aerolvm.aerol.ai", latest: latest, wantOK: true,
			wantCalls: []string{"https://aerolvm.aerol.ai", bootstrapTestMirror + "/aerolvm/latest.txt", bootstrapTestMirror + "/aerolvm/v0.6.12/install.sh"},
		},
		{
			name: "latest release script, GitHub fails", url: gh + "aerol-ai/microvm/releases/latest/download/cluster-join.sh",
			fail: gh, latest: latest, wantOK: true,
			wantCalls: []string{gh + "aerol-ai/microvm/releases/latest/download/cluster-join.sh", bootstrapTestMirror + "/aerolvm/latest.txt", bootstrapTestMirror + "/aerolvm/v0.6.12/cluster-join.sh"},
		},
		{
			name: "pinned release script, GitHub answers", url: gh + "aerol-ai/microvm/releases/download/v0.6.12/cluster-init.sh",
			wantOK: true, wantCalls: []string{gh + "aerol-ai/microvm/releases/download/v0.6.12/cluster-init.sh"},
		},
		{
			name: "pinned release script, GitHub fails", url: gh + "aerol-ai/microvm/releases/download/v0.6.12/cluster-init.sh",
			fail: gh, wantOK: true,
			wantCalls: []string{gh + "aerol-ai/microvm/releases/download/v0.6.12/cluster-init.sh", bootstrapTestMirror + "/aerolvm/v0.6.12/cluster-init.sh"},
		},
		{
			name: "CNI plugins", url: gh + "containernetworking/plugins/releases/download/v1.5.1/cni-plugins-linux-amd64-v1.5.1.tgz",
			fail: gh, wantOK: true,
			wantCalls: []string{gh + "containernetworking/plugins/releases/download/v1.5.1/cni-plugins-linux-amd64-v1.5.1.tgz", bootstrapTestMirror + "/deps/cni-plugins/v1.5.1/cni-plugins-linux-amd64-v1.5.1.tgz"},
		},
		{
			name: "BuildKit", url: gh + "moby/buildkit/releases/download/v0.17.2/buildkit-v0.17.2.linux-arm64.tar.gz",
			fail: gh, wantOK: true,
			wantCalls: []string{gh + "moby/buildkit/releases/download/v0.17.2/buildkit-v0.17.2.linux-arm64.tar.gz", bootstrapTestMirror + "/deps/buildkit/v0.17.2/buildkit-v0.17.2.linux-arm64.tar.gz"},
		},
		{
			name: "Firecracker checksum file", url: gh + "firecracker-microvm/firecracker/releases/download/v1.15.1/firecracker-v1.15.1-x86_64.tgz.sha256.txt",
			fail: gh, wantOK: true,
			wantCalls: []string{gh + "firecracker-microvm/firecracker/releases/download/v1.15.1/firecracker-v1.15.1-x86_64.tgz.sha256.txt", bootstrapTestMirror + "/deps/firecracker/v1.15.1/firecracker-v1.15.1-x86_64.tgz.sha256.txt"},
		},
		{
			name: "presigned bucket URL has no mirror copy", url: "https://bucket.s3.amazonaws.com/builds/x/install.sh?X-Amz-Signature=abc",
			fail: "https://bucket.", wantOK: false,
			wantCalls: []string{"https://bucket.s3.amazonaws.com/builds/x/install.sh?X-Amz-Signature=abc"},
		},
		{
			name: "mirror names no latest release", url: gh + "aerol-ai/microvm/releases/latest/download/install.sh",
			fail: gh, latest: "not-a-tag", wantOK: false,
			wantCalls: []string{gh + "aerol-ai/microvm/releases/latest/download/install.sh", bootstrapTestMirror + "/aerolvm/latest.txt"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			log := filepath.Join(t.TempDir(), "calls")
			dest := filepath.Join(t.TempDir(), "file")
			script := helpers + "\ncurl_download '" + tc.url + "' -o '" + dest + "'\n"
			cmd := exec.Command("bash", "-c", script)
			cmd.Env = append(os.Environ(),
				"PATH="+filepath.Join(dir, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"),
				"FAKE_CURL_LOG="+log, "FAKE_CURL_FAIL="+tc.fail, "FAKE_CURL_LATEST="+tc.latest)
			outb, err := cmd.CombinedOutput()
			if (err == nil) != tc.wantOK {
				t.Fatalf("curl_download %s: err=%v, want ok=%v\n%s", tc.url, err, tc.wantOK, outb)
			}
			calls, _ := os.ReadFile(log)
			if got := strings.Fields(string(calls)); strings.Join(got, "\n") != strings.Join(tc.wantCalls, "\n") {
				t.Fatalf("calls:\n  %s\nwant:\n  %s", strings.Join(got, "\n  "), strings.Join(tc.wantCalls, "\n  "))
			}
			if tc.wantOK {
				body, err := os.ReadFile(dest)
				last := tc.wantCalls[len(tc.wantCalls)-1]
				if err != nil || strings.TrimSpace(string(body)) != "from "+last {
					t.Fatalf("downloaded %q (%v), want the body served by %s", body, err, last)
				}
			}
		})
	}
}
