package safety

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// When GitHub's release downloads fail (504s for hours on 2026-11-08), the
// harness takes a pinned release's files, and the released custom Caddy,
// from the download mirror instead. These tests point "GitHub" and "the
// mirror" at file:// trees, so the real curl probes run with no network.

// fileTree writes files (path -> body) under a fresh directory and returns
// its file:// URL.
func fileTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for p, body := range files {
		mustMkdir(t, filepath.Dir(filepath.Join(dir, p)))
		mustWrite(t, filepath.Join(dir, p), body)
	}
	return "file://" + dir
}

func requireCurl(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not on PATH")
	}
}

// TestRunShReleaseBaseAndMirrorAreOverridable: AEROL_RELEASE_BASE replaces
// the GitHub releases URL; AEROL_DOWNLOAD_MIRROR the mirror, where "" means
// off rather than the default.
func TestRunShReleaseBaseAndMirrorAreOverridable(t *testing.T) {
	src, err := os.ReadFile(runScript(t))
	if err != nil {
		t.Fatal(err)
	}
	var assigns []string
	for _, line := range strings.Split(string(src), "\n") {
		if strings.HasPrefix(line, "RELEASE_BASE=") || strings.HasPrefix(line, "DOWNLOAD_MIRROR=") {
			assigns = append(assigns, line)
		}
	}
	if len(assigns) != 2 {
		t.Fatalf("run.sh has %d top-level RELEASE_BASE= / DOWNLOAD_MIRROR= lines, want 2: %q", len(assigns), assigns)
	}
	for _, tc := range []struct {
		name, env, want string
	}{
		{"defaults", "", "https://github.com/aerol-ai/microvm/releases|https://aerolvm-downloads.s3.us-east-1.amazonaws.com"},
		{"both set", "AEROL_RELEASE_BASE=https://github.com/fork/microvm/releases AEROL_DOWNLOAD_MIRROR=https://m.example",
			"https://github.com/fork/microvm/releases|https://m.example"},
		{"empty mirror stays empty", "AEROL_DOWNLOAD_MIRROR=", "https://github.com/aerol-ai/microvm/releases|"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			script := "set -euo pipefail\nunset AEROL_RELEASE_BASE AEROL_DOWNLOAD_MIRROR\n"
			if tc.env != "" {
				script += "export " + tc.env + "\n"
			}
			script += strings.Join(assigns, "\n") + "\nprintf '%s|%s' \"$RELEASE_BASE\" \"$DOWNLOAD_MIRROR\"\n"
			out, err := exec.Command("bash", "-c", script).Output()
			if err != nil {
				t.Fatal(err)
			}
			if string(out) != tc.want {
				t.Errorf("got %q, want %q", out, tc.want)
			}
		})
	}
}

// TestReleaseDownloadBaseFallsBackToTheMirror: a --version pin probes the
// release's checksums.txt on GitHub, then on the mirror at aerolvm/<tag>.
func TestReleaseDownloadBaseFallsBackToTheMirror(t *testing.T) {
	requireCurl(t)
	src, err := os.ReadFile(runScript(t))
	if err != nil {
		t.Fatal(err)
	}
	fn := extractShellFunc(t, string(src), "release_download_base") + extractShellFunc(t, string(src), "prepare_artifacts")
	const tag = "v9.9.9"
	release := map[string]string{"checksums.txt": "x  sandboxd_linux_amd64\n", "cluster-sign-node.sh": "#!/bin/sh\n"}
	for _, tc := range []struct {
		name               string
		github, mirror     bool
		mirrorOff          bool
		wantMirror, wantGH bool
		wantErr            string
	}{
		{name: "GitHub answers", github: true, mirror: true, wantGH: true},
		{name: "GitHub down: the mirror", mirror: true, wantMirror: true, wantErr: "taking v9.9.9 from the mirror"},
		{name: "neither: GitHub, named", wantGH: true, wantErr: "neither"},
		{name: "mirror off: GitHub", mirror: true, mirrorOff: true, wantGH: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gh := map[string]string{}
			mir := map[string]string{}
			for name, body := range release {
				if tc.github {
					gh["download/"+tag+"/"+name] = body
				}
				if tc.mirror {
					mir["aerolvm/"+tag+"/"+name] = body
				}
			}
			ghURL, mirURL := fileTree(t, gh), fileTree(t, mir)
			mirrorVar := mirURL
			if tc.mirrorOff {
				mirrorVar = "off"
			}
			here := filepath.Join(t.TempDir(), "it")
			mustMkdir(t, filepath.Join(here, "scenarios"))
			mustWrite(t, filepath.Join(here, "scenarios", "s.tfvars"), "cluster_name = \"x\"\n")
			// When no release answers, the signer comes from the working
			// tree's build, as for a release that predates it.
			buildSh := filepath.Join(t.TempDir(), "build.sh")
			mustWrite(t, buildSh, "#!/bin/sh\necho 'cluster_sign_node_script_url = \"https://local/sign\"'\n")
			if err := os.Chmod(buildSh, 0o755); err != nil {
				t.Fatal(err)
			}
			script := `set -euo pipefail
HERE="` + here + `"
RELEASE_BASE="` + ghURL + `"
DOWNLOAD_MIRROR="` + mirrorVar + `"
BUILD_SH="` + buildSh + `"
BUILD_MODE=version
PIN_VERSION=` + tag + `
artifacts_tfvars_path() { printf '%s\n' "${HERE}/.tf/${1}/artifacts.tfvars"; }
` + fn + `
prepare_artifacts s
`
			out, err := exec.Command("bash", "-c", script).CombinedOutput()
			t.Logf("prepare_artifacts -> %s", out)
			if err != nil {
				t.Fatalf("prepare_artifacts: %v", err)
			}
			got, err := os.ReadFile(filepath.Join(here, ".tf", "s", "artifacts.tfvars"))
			if err != nil {
				t.Fatal(err)
			}
			wantBase := ghURL + "/download/" + tag
			if tc.wantMirror {
				wantBase = mirURL + "/aerolvm/" + tag
			}
			for _, key := range []string{"sandboxd_url", "toolboxd_url", "checksums_url", "install_script_url", "cluster_init_script_url", "cluster_join_script_url"} {
				found := false
				for _, line := range strings.Split(string(got), "\n") {
					if strings.HasPrefix(line, key+" ") {
						found = strings.Contains(line, `"`+wantBase+"/")
					}
				}
				if !found {
					t.Errorf("%s does not come from %s:\n%s", key, wantBase, got)
				}
			}
			if tc.wantErr != "" && !strings.Contains(string(out), tc.wantErr) {
				t.Errorf("output lacks %q", tc.wantErr)
			}
		})
	}
}

// TestReleaseCaddyURLFallsBackToTheMirror: build.sh names the newest
// release's custom Caddy; when GitHub does not serve it, or GitHub's API does
// not answer, the mirror's copy.
func TestReleaseCaddyURLFallsBackToTheMirror(t *testing.T) {
	requireCurl(t)
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq not on PATH")
	}
	const api = `[{"tag_name":"v1.2.3","draft":false,"prerelease":false,"assets":[{"name":"caddy_linux_amd64"}]}]`
	for _, tc := range []struct {
		name                      string
		apiUp, github, mirrorFile bool
		latestTxt                 string
		mirrorOff                 bool
		want                      string // with GH= and MIRROR= placeholders
	}{
		{name: "GitHub serves it", apiUp: true, github: true, mirrorFile: true, want: "GH/download/v1.2.3/caddy_linux_amd64"},
		{name: "GitHub down: the mirror's copy", apiUp: true, mirrorFile: true, want: "MIRROR/aerolvm/v1.2.3/caddy_linux_amd64"},
		{name: "neither serves it: GitHub's URL", apiUp: true, want: "GH/download/v1.2.3/caddy_linux_amd64"},
		{name: "mirror off: GitHub's URL", apiUp: true, mirrorFile: true, mirrorOff: true, want: "GH/download/v1.2.3/caddy_linux_amd64"},
		{name: "API down: the mirror's latest", mirrorFile: true, latestTxt: "v1.2.3\n", want: "MIRROR/aerolvm/v1.2.3/caddy_linux_amd64"},
		{name: "API down, mirror has no latest: releases/latest", mirrorFile: true, want: "GH/latest/download/caddy_linux_amd64"},
		{name: "API down, bad latest.txt: releases/latest", mirrorFile: true, latestTxt: "../x\n", want: "GH/latest/download/caddy_linux_amd64"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gh := map[string]string{}
			if tc.github {
				gh["download/v1.2.3/caddy_linux_amd64"] = "caddy"
			}
			mir := map[string]string{}
			if tc.mirrorFile {
				mir["aerolvm/v1.2.3/caddy_linux_amd64"] = "caddy"
			}
			if tc.latestTxt != "" {
				mir["aerolvm/latest.txt"] = tc.latestTxt
			}
			apiFiles := map[string]string{}
			if tc.apiUp {
				apiFiles["releases.json"] = api
			}
			ghURL, mirURL, apiURL := fileTree(t, gh), fileTree(t, mir), fileTree(t, apiFiles)
			mirrorVar := mirURL
			if tc.mirrorOff {
				mirrorVar = "off"
			}
			out, code := sourceAndRun(t, `AEROL_RELEASE_BASE='`+ghURL+`' AEROL_DOWNLOAD_MIRROR='`+mirrorVar+
				`' AEROL_RELEASE_API='`+apiURL+`/releases.json' release_caddy_url amd64 2>/dev/null`)
			if code != 0 {
				t.Fatalf("release_caddy_url exited %d: %s", code, out)
			}
			want := strings.NewReplacer("GH", ghURL, "MIRROR", mirURL).Replace(tc.want)
			if out != want {
				t.Errorf("release_caddy_url = %q, want %q", out, want)
			}
		})
	}
}

// fakeS3CLI is an aws CLI over a directory: s3api head-object, s3 cp (either
// way) and s3 presign. Every call is logged.
const fakeS3CLI = `#!/usr/bin/env bash
echo "aws $*" >>"$AWS_LOG"
args=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --region|--profile|--expires-in) shift 2 ;;
    --only-show-errors|--no-progress) shift ;;
    *) args+=("$1"); shift ;;
  esac
done
local_of() { local p="${1#s3://}"; echo "$FAKE_BUCKET/${p#*/}"; }
case "${args[0]} ${args[1]}" in
  "s3api head-object")
    key=""; for ((i=2;i<${#args[@]};i++)); do [[ "${args[$i]}" == --key ]] && key="${args[$((i+1))]}"; done
    [[ -f "$FAKE_BUCKET/$key" ]] ;;
  "s3 presign") p="${args[2]#s3://}"; echo "https://presigned.test/${p#*/}" ;;
  "s3 cp")
    src="${args[2]}"; dst="${args[3]}"
    [[ "$src" == s3://* ]] && src="$(local_of "$src")"
    [[ "$dst" == s3://* ]] && { dst="$(local_of "$dst")"; mkdir -p "$(dirname "$dst")"; }
    cp "$src" "$dst" ;;
  *) echo "fake aws: unhandled $*" >&2; exit 2 ;;
esac
`

// TestEmitURLsPassesTheDownloadMirrorToNodes: with AEROL_DOWNLOAD_MIRROR set,
// nodes get a copy of the build's install.sh whose default mirror is that
// value (the bootstrap's `sudo /tmp/install.sh` carries no variables, and the
// bootstrap template must not change). Unset, nodes get the build's own
// install.sh and nothing is uploaded.
func TestEmitURLsPassesTheDownloadMirrorToNodes(t *testing.T) {
	installSh := installShSource(t)
	const prefix = "builds/b1"
	for _, tc := range []struct {
		name      string
		env       string // "" = unset
		value     string
		oldScript bool
		wantCopy  bool
		wantErr   string
	}{
		{name: "unset: the build's install.sh, nothing uploaded"},
		{name: "a mirror URL", env: "set", value: "https://m.example/base", wantCopy: true},
		{name: "empty: the nodes' mirror off", env: "set", value: "", wantCopy: true},
		{name: "off", env: "set", value: "off", wantCopy: true},
		{name: "a value that could break out of the quotes is refused", env: "set", value: `https://x/"$(id)"`, wantErr: "must be an https:// URL"},
		{name: "an install.sh from before the mirror: unchanged", env: "set", value: "https://m.example", oldScript: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			bucket := filepath.Join(dir, "bucket")
			script := installSh
			if tc.oldScript {
				script = "#!/bin/sh\necho old\n"
			}
			for _, f := range []string{"sandboxd_linux_amd64", "toolboxd_linux_amd64", "checksums.txt", "cluster-init.sh", "cluster-join.sh", "caddy_linux_amd64"} {
				mustMkdir(t, filepath.Join(bucket, prefix))
				mustWrite(t, filepath.Join(bucket, prefix, f), f)
			}
			mustWrite(t, filepath.Join(bucket, prefix, "install.sh"), script)
			aws := filepath.Join(dir, "aws")
			mustWrite(t, aws, fakeS3CLI)
			if err := os.Chmod(aws, 0o755); err != nil {
				t.Fatal(err)
			}
			awsLog := filepath.Join(dir, "aws.log")
			env := "unset AEROL_DOWNLOAD_MIRROR\n"
			if tc.env != "" {
				env = "export AEROL_DOWNLOAD_MIRROR='" + tc.value + "'\n"
			}
			out, code := sourceAndRun(t, env+`export AWS_LOG='`+awsLog+`' FAKE_BUCKET='`+bucket+`'
AWSCLI=('`+aws+`'); ARCHES=(amd64); WITH_CADDY=1
emit_urls b1 bucket us-east-1 2>"`+filepath.Join(dir, "stderr")+`"`)
			stderr, _ := os.ReadFile(filepath.Join(dir, "stderr"))
			calls, _ := os.ReadFile(awsLog)
			if tc.wantErr != "" {
				if code == 0 || !strings.Contains(string(stderr), tc.wantErr) {
					t.Fatalf("emit_urls exited %d, stderr %q; want a refusal %q", code, stderr, tc.wantErr)
				}
				return
			}
			if code != 0 {
				t.Fatalf("emit_urls exited %d: %s\n%s", code, out, stderr)
			}
			var installURL string
			for _, line := range strings.Split(out, "\n") {
				if strings.HasPrefix(line, "install_script_url ") {
					installURL = line
				}
			}
			copies, _ := filepath.Glob(filepath.Join(bucket, prefix, "install.mirror-*.sh"))
			if !tc.wantCopy {
				if !strings.Contains(installURL, `"https://presigned.test/`+prefix+`/install.sh"`) || len(copies) != 0 {
					t.Fatalf("install_script_url = %q, copies %v; want the build's install.sh and no upload\naws calls:\n%s", installURL, copies, calls)
				}
				if tc.env == "" && strings.Contains(string(calls), " s3 cp ") {
					t.Errorf("unset AEROL_DOWNLOAD_MIRROR still copied something:\n%s", calls)
				}
				return
			}
			if len(copies) != 1 {
				t.Fatalf("want one install.mirror-*.sh copy, got %v", copies)
			}
			if !strings.Contains(installURL, `"https://presigned.test/`+prefix+"/"+filepath.Base(copies[0])+`"`) {
				t.Errorf("install_script_url = %q, want the copy %s", installURL, filepath.Base(copies[0]))
			}
			got, _ := os.ReadFile(copies[0])
			want := strings.Replace(installSh,
				`DOWNLOAD_MIRROR_DEFAULT="https://aerolvm-downloads.s3.us-east-1.amazonaws.com"`,
				`DOWNLOAD_MIRROR_DEFAULT="`+tc.value+`"`, 1)
			if want == installSh {
				t.Fatal("install.sh no longer has the DOWNLOAD_MIRROR_DEFAULT line this test rewrites")
			}
			if string(got) != want {
				t.Error("the copy differs from install.sh in more than the DOWNLOAD_MIRROR_DEFAULT line")
			}
		})
	}
}
