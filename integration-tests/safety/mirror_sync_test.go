package safety

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// scripts/mirror-sync.sh fills the download mirror install.sh falls back to.
// What it must never do is upload a file that did not check out: a release
// file that does not match checksums.txt, or a third-party file that does
// not match its pin. These tests run it with gh, aws and curl replaced by
// scripts over directories, so nothing reaches GitHub or AWS.

// fakeGH serves releases from $FAKE_GH/<owner>/<repo>/<tag>/ and the latest
// tag from $FAKE_GH/<owner>/<repo>/LATEST.
const fakeGH = `#!/usr/bin/env bash
echo "gh $*" >>"$TOOL_LOG"
[[ "$1 $2" == "release view" || "$1 $2" == "release download" ]] || { echo "fake gh: $*" >&2; exit 2; }
sub="$2"; shift 2
tag="" repo="" dir="" pattern="" json=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo) repo="$2"; shift 2 ;;
    --dir) dir="$2"; shift 2 ;;
    --pattern) pattern="$2"; shift 2 ;;
    --json) json="$2"; shift 2 ;;
    --jq) shift 2 ;;
    *) tag="$1"; shift ;;
  esac
done
root="$FAKE_GH/$repo"
if [[ "$sub" == view ]]; then
  if [[ -z "$tag" ]]; then cat "$root/LATEST"; exit; fi
  [[ -d "$root/$tag" ]] || exit 1
  ls "$root/$tag"; exit
fi
[[ -d "$root/$tag" ]] || exit 1
mkdir -p "$dir"
if [[ -n "$pattern" ]]; then
  [[ -f "$root/$tag/$pattern" ]] || exit 1
  cp "$root/$tag/$pattern" "$dir/"
else
  cp "$root/$tag/"* "$dir/"
fi
`

// fakeS3 copies what would be uploaded into $FAKE_S3/<bucket>/<key>.
const fakeS3 = `#!/usr/bin/env bash
echo "aws $*" >>"$TOOL_LOG"
args=()
size_only=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --region|--content-type|--cache-control) shift 2 ;;
    --only-show-errors|--no-progress) shift ;;
    --size-only) size_only=1; shift ;;
    *) args+=("$1"); shift ;;
  esac
done
dst="$FAKE_S3/${args[3]#s3://}"
if [[ "${args[0]} ${args[1]}" == "s3 cp" && "${args[2]}" == s3://* ]]; then
  # A download from the bucket: missing is an error, as with aws.
  from="$FAKE_S3/${args[2]#s3://}"
  [[ -f "$from" ]] || exit 1
  cp "$from" "${args[3]}"
  exit 0
fi
case "${args[0]} ${args[1]}" in
  "s3 sync")
    # Like aws s3 sync: with --size-only a file already there at the same
    # size is left alone.
    src="${args[2]}"
    (cd "$src" && find . -type f) | while read -r rel; do
      to="$dst/${rel#./}"
      if [[ -n "$size_only" && -f "$to" && $(wc -c <"$src/$rel") -eq $(wc -c <"$to") ]]; then
        echo "skip ${rel#./}" >>"$TOOL_LOG"
        continue
      fi
      mkdir -p "$(dirname "$to")"; cp "$src/$rel" "$to"
    done ;;
  "s3 cp") mkdir -p "$(dirname "$dst")"; cp "${args[2]}" "$dst" ;;
  *) echo "fake aws: $*" >&2; exit 2 ;;
esac
`

type syncRig struct {
	t                    *testing.T
	gh, s3, log, binDir  string
	stdout, stderr, logs string
	code                 int
}

func newSyncRig(t *testing.T) *syncRig {
	t.Helper()
	dir := t.TempDir()
	r := &syncRig{t: t, gh: filepath.Join(dir, "gh"), s3: filepath.Join(dir, "s3"), log: filepath.Join(dir, "tools.log"), binDir: filepath.Join(dir, "bin")}
	for _, d := range []string{r.gh, r.s3, r.binDir} {
		mustMkdir(t, d)
	}
	for name, body := range map[string]string{
		"gh":   fakeGH,
		"aws":  fakeS3,
		"curl": "#!/usr/bin/env bash\necho \"curl $*\" >>\"$TOOL_LOG\"\nfor a in \"$@\"; do case \"$a\" in https://*) url=\"$a\";; esac; done\nf=\"$FAKE_WEB/${url#https://}\"\n[[ -f \"$f\" ]] || exit 22\nwhile [[ $# -gt 0 ]]; do [[ \"$1\" == -o ]] && { cp \"$f\" \"$2\"; exit; }; shift; done\n",
	} {
		mustWrite(t, filepath.Join(r.binDir, name), body)
		if err := os.Chmod(filepath.Join(r.binDir, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return r
}

// release puts files into a fake GitHub release.
func (r *syncRig) release(repo, tag string, files map[string]string) {
	for name, body := range files {
		mustMkdir(r.t, filepath.Join(r.gh, repo, tag))
		mustWrite(r.t, filepath.Join(r.gh, repo, tag, name), body)
	}
}

func (r *syncRig) run(args ...string) {
	r.t.Helper()
	script, err := filepath.Abs(filepath.Join("..", "..", "scripts", "mirror-sync.sh"))
	if err != nil {
		r.t.Fatal(err)
	}
	cmd := exec.Command("bash", append([]string{script}, args...)...)
	cmd.Dir = r.t.TempDir()
	cmd.Env = []string{"PATH=" + r.binDir + string(os.PathListSeparator) + os.Getenv("PATH"), "HOME=" + r.t.TempDir(),
		"TOOL_LOG=" + r.log, "FAKE_GH=" + r.gh, "FAKE_S3=" + r.s3, "FAKE_WEB=" + filepath.Join(r.gh, "web")}
	var out, errOut strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err = cmd.Run()
	r.stdout, r.stderr = out.String(), errOut.String()
	r.code = 0
	if ee, ok := err.(*exec.ExitError); ok {
		r.code = ee.ExitCode()
	} else if err != nil {
		r.t.Fatal(err)
	}
	raw, _ := os.ReadFile(r.log)
	r.logs = string(raw)
	r.t.Logf("mirror-sync %v -> %d\nstdout:\n%s\nstderr:\n%s\ntools:\n%s", args, r.code, r.stdout, r.stderr, r.logs)
}

// uploaded lists the keys under the fake bucket, with their content.
func (r *syncRig) uploaded() map[string]string {
	got := map[string]string{}
	_ = filepath.Walk(r.s3, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			rel, _ := filepath.Rel(r.s3, p)
			b, _ := os.ReadFile(p)
			got[filepath.ToSlash(rel)] = string(b)
		}
		return nil
	})
	return got
}

func checksumsFor(files map[string]string) string {
	var names []string
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		b.WriteString(sha256Hex([]byte(files[n])) + "  " + n + "\n")
	}
	return b.String()
}

func TestMirrorSyncReleaseUploadsOnlyAVerifiedRelease(t *testing.T) {
	const repo, tag = "aerol-ai/microvm", "v1.2.3"
	assets := map[string]string{"sandboxd_linux_amd64": "sandboxd", "install.sh": "#!/bin/sh\n", "v1.2.3_install.sh": "#!/bin/sh\n"}
	for _, tc := range []struct {
		name       string
		latest     string // GitHub's latest release
		args       []string
		mutate     func(files map[string]string) // after checksums.txt is written
		wantCode   int
		wantLatest bool
		bucket     string
		wantErr    string
	}{
		{name: "verified, and GitHub's latest: synced, then latest.txt", latest: tag, wantLatest: true},
		{name: "verified, an older release: latest.txt left alone", latest: "v1.2.4"},
		{name: "--no-latest", latest: tag, args: []string{"--no-latest"}},
		{name: "--latest", latest: "v1.2.4", args: []string{"--latest"}, wantLatest: true},
		{name: "--bucket", latest: tag, args: []string{"--bucket", "other-bucket"}, bucket: "other-bucket", wantLatest: true},
		{name: "the provenance bundle needs no checksum line", latest: tag, wantLatest: true,
			mutate: func(f map[string]string) { f[tag+".intoto.jsonl"] = "{}" }},
		{name: "a file that does not match checksums.txt: nothing uploaded", latest: tag, wantCode: 1,
			mutate:  func(f map[string]string) { f["sandboxd_linux_amd64"] = "tampered" },
			wantErr: "sandboxd_linux_amd64 does not match checksums.txt"},
		{name: "a file missing from checksums.txt: nothing uploaded", latest: tag, wantCode: 1,
			mutate:  func(f map[string]string) { f["extra"] = "x" },
			wantErr: "extra is in the release but not in checksums.txt"},
		{name: "a listed file missing from the release: nothing uploaded", latest: tag, wantCode: 1,
			mutate:  func(f map[string]string) { delete(f, "install.sh") },
			wantErr: "install.sh is in checksums.txt but not in the release"},
		{name: "no checksums.txt: nothing uploaded", latest: tag, wantCode: 1,
			mutate:  func(f map[string]string) { delete(f, "checksums.txt") },
			wantErr: "has no checksums.txt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newSyncRig(t)
			files := map[string]string{}
			for k, v := range assets {
				files[k] = v
			}
			files["checksums.txt"] = checksumsFor(assets)
			if tc.mutate != nil {
				tc.mutate(files)
			}
			r.release(repo, tag, files)
			mustWrite(t, filepath.Join(r.gh, repo, "LATEST"), tc.latest+"\n")
			r.run(append([]string{"--release", tag}, tc.args...)...)
			if r.code != tc.wantCode {
				t.Fatalf("exit %d, want %d", r.code, tc.wantCode)
			}
			got := r.uploaded()
			if tc.wantCode != 0 {
				if len(got) != 0 || strings.Contains(r.logs, "aws ") {
					t.Errorf("uploaded %v after a failed check", got)
				}
				if !strings.Contains(r.stderr, tc.wantErr) || !strings.Contains(r.stderr, "nothing uploaded") {
					t.Errorf("stderr lacks %q and \"nothing uploaded\"", tc.wantErr)
				}
				return
			}
			bucket := tc.bucket
			if bucket == "" {
				bucket = "aerolvm-downloads"
			}
			for name, body := range files {
				if got[bucket+"/aerolvm/"+tag+"/"+name] != body {
					t.Errorf("%s/aerolvm/%s/%s not uploaded as released", bucket, tag, name)
				}
			}
			latest, has := got[bucket+"/aerolvm/latest.txt"]
			if has != tc.wantLatest || (has && latest != tag+"\n") {
				t.Errorf("latest.txt = %q (present %v), want present %v naming %s", latest, has, tc.wantLatest, tag)
			}
			if tc.wantLatest && strings.Index(r.logs, "latest.txt s3://") < strings.Index(r.logs, "aws s3 sync") {
				t.Error("latest.txt moved before the release's files were up")
			}
			if strings.Contains(r.logs, "curl ") {
				t.Error("release files must come through gh, not github.com download links")
			}
		})
	}

	t.Run("dry run plans from the release listing and touches nothing", func(t *testing.T) {
		r := newSyncRig(t)
		r.release(repo, tag, map[string]string{"sandboxd_linux_amd64": "x", "checksums.txt": "y"})
		mustWrite(t, filepath.Join(r.gh, repo, "LATEST"), tag+"\n")
		r.run("--release", tag, "--dry-run")
		if r.code != 0 || strings.Contains(r.logs, "release download") || strings.Contains(r.logs, "aws ") {
			t.Fatalf("dry run exited %d, or downloaded or uploaded:\n%s", r.code, r.logs)
		}
		for _, want := range []string{"sandboxd_linux_amd64 -> s3://aerolvm-downloads/aerolvm/v1.2.3/sandboxd_linux_amd64",
			"Then point s3://aerolvm-downloads/aerolvm/latest.txt at v1.2.3"} {
			if !strings.Contains(r.stdout, want) {
				t.Errorf("plan lacks %q", want)
			}
		}
	})
	for _, args := range [][]string{{"--release", "main"}, {"--release", "v1.2.3;rm"}, {"--release"}, {"--deps", "--latest"}, {}} {
		t.Run("refused: "+strings.Join(args, " "), func(t *testing.T) {
			r := newSyncRig(t)
			r.run(args...)
			if r.code == 0 || strings.Contains(r.logs, "gh ") || strings.Contains(r.logs, "aws ") {
				t.Fatalf("exit %d; tools called:\n%s", r.code, r.logs)
			}
		})
	}
}

// pinsScript is an install.sh stand-in holding only a DOWNLOAD PINS block.
func pinsScript(rows ...string) string {
	return "#!/usr/bin/env bash\nSOMETHING_ELSE=\"not in the block\"\n# --- BEGIN DOWNLOAD PINS ---\nV=\"v1.0.0\"\ndownload_pins() {\n" +
		"\tcat <<EOF\n" + strings.Join(rows, "\n") + "\nEOF\n}\n# --- END DOWNLOAD PINS ---\necho must-not-run\n"
}

func tgz(t *testing.T, files map[string]string) string {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
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
	return buf.String()
}

func TestMirrorSyncDepsUploadsOnlyVerifiedPins(t *testing.T) {
	tarball := tgz(t, map[string]string{"release-v1.0.0/tool": "the tool binary"})
	const ghFile, webFile = "tool-v1.0.0.tgz", "extra.deb"
	ghRow := func(sha string) string {
		return "tool ${V} " + ghFile + " " + sha + " https://github.com/acme/tool/releases/download/${V}/" + ghFile
	}
	webRow := func(sha string) string {
		return "extra ${V} " + webFile + " " + sha + " https://downloads.acme.example/" + webFile
	}
	tarRow := func(sha string) string {
		return "tool ${V} tool " + sha + " tar:" + ghFile + ":release-v1.0.0/tool"
	}
	good := []string{ghRow(sha256Hex([]byte(tarball))), webRow(sha256Hex([]byte("extra"))), tarRow(sha256Hex([]byte("the tool binary")))}
	for _, tc := range []struct {
		name    string
		rows    []string
		wantErr string
	}{
		{name: "every pin matches: all uploaded at deps/<project>/<version>/<file>", rows: good},
		{name: "a GitHub file that does not match its pin", rows: []string{ghRow(strings.Repeat("0", 64)), good[1]},
			wantErr: ghFile + " does not match its pin"},
		{name: "a vendor file that does not match its pin", rows: []string{good[0], webRow(strings.Repeat("1", 64))},
			wantErr: webFile + " does not match its pin"},
		{name: "a file taken from a tarball that does not match its pin", rows: []string{good[0], tarRow(strings.Repeat("2", 64))},
			wantErr: "tool does not match its pin"},
		{name: "a tar: row before its source", rows: []string{good[2], good[0]}, wantErr: "names a file not downloaded before it"},
		{name: "an unsafe path", rows: []string{"../x ${V} f " + strings.Repeat("a", 64) + " https://x.example/f"}, wantErr: "unsafe path segment"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newSyncRig(t)
			r.release("acme/tool", "v1.0.0", map[string]string{ghFile: tarball})
			mustMkdir(t, filepath.Join(r.gh, "web", "downloads.acme.example"))
			mustWrite(t, filepath.Join(r.gh, "web", "downloads.acme.example", webFile), "extra")
			installSh := filepath.Join(t.TempDir(), "install.sh")
			mustWrite(t, installSh, pinsScript(tc.rows...))
			r.run("--deps", "--install-sh", installSh)
			got := r.uploaded()
			if tc.wantErr != "" {
				if r.code == 0 || len(got) != 0 || strings.Contains(r.logs, "aws ") {
					t.Fatalf("exit %d, uploaded %v; want a refusal with nothing uploaded", r.code, got)
				}
				if !strings.Contains(r.stderr, tc.wantErr) {
					t.Errorf("stderr lacks %q", tc.wantErr)
				}
				return
			}
			if r.code != 0 {
				t.Fatalf("exit %d", r.code)
			}
			want := map[string]string{
				"aerolvm-downloads/deps/tool/v1.0.0/" + ghFile:   tarball,
				"aerolvm-downloads/deps/extra/v1.0.0/" + webFile: "extra",
				"aerolvm-downloads/deps/tool/v1.0.0/tool":        "the tool binary",
			}
			if len(got) != len(want) {
				t.Errorf("uploaded %d keys, want %d: %v", len(got), len(want), keysOf(got))
			}
			for k, v := range want {
				if got[k] != v {
					t.Errorf("%s not uploaded with the pinned content", k)
				}
			}
			if !strings.Contains(r.logs, "gh release download v1.0.0 --repo acme/tool --pattern "+ghFile) {
				t.Error("the GitHub file did not come through gh")
			}
			if strings.Contains(r.stdout+r.stderr, "must-not-run") {
				t.Error("mirror-sync ran install.sh outside its pins block")
			}
		})
	}
}

func keysOf(m map[string]string) []string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// TestMirrorSyncDepsPlanCoversTheMirrorLayout: the dry run over the real
// install.sh plans every key the mirror is documented to hold (the ones the
// owner uploaded by hand on 2026-11-08 among them), and calls no tool.
func TestMirrorSyncDepsPlanCoversTheMirrorLayout(t *testing.T) {
	r := newSyncRig(t)
	r.run("--deps", "--dry-run")
	if r.code != 0 || r.logs != "" {
		t.Fatalf("dry run exited %d or called tools:\n%s", r.code, r.logs)
	}
	for _, key := range []string{
		"deps/cni-plugins/v1.5.1/cni-plugins-linux-amd64-v1.5.1.tgz",
		"deps/cni-plugins/v1.5.1/cni-plugins-linux-amd64-v1.5.1.tgz.sha256",
		"deps/cni-plugins/v1.5.1/cni-plugins-linux-amd64-v1.5.1.tgz.sha512",
		"deps/cni-plugins/v1.5.1/cni-plugins-linux-arm64-v1.5.1.tgz",
		"deps/cni-plugins/v1.5.1/cni-plugins-linux-arm64-v1.5.1.tgz.sha256",
		"deps/cni-plugins/v1.5.1/cni-plugins-linux-arm64-v1.5.1.tgz.sha512",
		"deps/caddy/v2.11.7/caddy_2.11.7_linux_amd64.deb",
		"deps/caddy/v2.11.7/caddy_2.11.7_linux_arm64.deb",
		"deps/caddy/v2.11.7/caddy_2.11.7_checksums.txt",
		"deps/buildkit/v0.17.2/buildkit-v0.17.2.linux-amd64.tar.gz (sha256 24d73e4456ebbe6dbb53779e362b2164a000e9636cd9ca8bd90f742fb024b731)",
		"deps/buildkit/v0.17.2/buildkit-v0.17.2.linux-arm64.tar.gz (sha256 77384e2726c93d7c2bd7b745c079e1953f92683570203c7bfca361965db2f0c2)",
		"deps/workerd/v1.20260717.1/workerd-linux-64.gz",
		"deps/firecracker/v1.15.1/firecracker-v1.15.1-x86_64.tgz",
		"deps/firecracker/v1.15.1/firecracker-v1.15.1-x86_64 ",
		"deps/firecracker/v1.15.1/jailer-v1.15.1-aarch64 ",
	} {
		if !strings.Contains(r.stdout, "s3://aerolvm-downloads/"+key) {
			t.Errorf("the plan has no %s", key)
		}
	}
}

// A re-run sends only what the mirror lacks: a file already there at the
// same size is left alone (on 2026-11-08 a plain sync re-sent all of v0.6.11
// because every freshly downloaded file looked newer). --force sends every
// file again, for a release re-cut under the same tag.
func TestMirrorSyncSkipsFilesAlreadyOnTheMirror(t *testing.T) {
	const repo, tag = "aerol-ai/microvm", "v1.2.3"
	r := newSyncRig(t)
	files := map[string]string{"sandboxd_linux_amd64": "sandboxd", "install.sh": "#!/bin/sh\n"}
	files["checksums.txt"] = checksumsFor(files)
	r.release(repo, tag, files)
	mustWrite(t, filepath.Join(r.gh, repo, "LATEST"), tag+"\n")

	r.run("--release", tag)
	if r.code != 0 {
		t.Fatalf("first sync exit %d", r.code)
	}
	key := filepath.Join(r.s3, "aerolvm-downloads", "aerolvm", tag, "sandboxd_linux_amd64")
	// Same size, different bytes: a skipped file keeps them.
	mustWrite(t, key, "SANDBOXD")

	r.run("--release", tag)
	if r.code != 0 {
		t.Fatalf("second sync exit %d", r.code)
	}
	if got := r.uploaded()["aerolvm-downloads/aerolvm/"+tag+"/sandboxd_linux_amd64"]; got != "SANDBOXD" {
		t.Fatalf("a file already on the mirror at the same size was uploaded again (now %q)", got)
	}
	if !strings.Contains(r.logs, "skip sandboxd_linux_amd64") {
		t.Fatal("the sync did not ask to skip files already there (--size-only)")
	}

	r.run("--release", tag, "--force")
	if r.code != 0 {
		t.Fatalf("forced sync exit %d", r.code)
	}
	if got := r.uploaded()["aerolvm-downloads/aerolvm/"+tag+"/sandboxd_linux_amd64"]; got != "sandboxd" {
		t.Fatalf("--force left %q, want the released bytes", got)
	}

	// A re-cut under the same tag: a same-size change and a new
	// checksums.txt (same size too). The mirror's checksums.txt differs, so
	// every file goes again without --force.
	recut := map[string]string{"sandboxd_linux_amd64": "SANDBOXD", "install.sh": "#!/bin/sh\n"}
	recut["checksums.txt"] = checksumsFor(recut)
	if len(recut["checksums.txt"]) != len(files["checksums.txt"]) {
		t.Fatal("test setup: the re-cut checksums.txt should keep its size")
	}
	r.release(repo, tag, recut)
	r.run("--release", tag)
	if r.code != 0 {
		t.Fatalf("re-cut sync exit %d", r.code)
	}
	got := r.uploaded()
	if got["aerolvm-downloads/aerolvm/"+tag+"/sandboxd_linux_amd64"] != "SANDBOXD" || got["aerolvm-downloads/aerolvm/"+tag+"/checksums.txt"] != recut["checksums.txt"] {
		t.Fatal("a re-cut release left stale files on the mirror")
	}
	if !strings.Contains(r.stdout, "differs from the release's") {
		t.Fatal("the re-cut was not detected")
	}
}

// onPublicMirror makes the fake curl serve a deps file at the public mirror
// URL (https://aerolvm-downloads.s3.us-east-1.amazonaws.com/<key>).
func (r *syncRig) onPublicMirror(key, body string) {
	p := filepath.Join(r.gh, "web", "aerolvm-downloads.s3.us-east-1.amazonaws.com", key)
	mustMkdir(r.t, filepath.Dir(p))
	mustWrite(r.t, p, body)
}

// --deps --check only reads the public mirror: no credentials, no downloads,
// no uploads. It is what a pull request that changes install.sh runs, so a
// pin bumped without its mirror copy shows before the release.
func TestMirrorSyncDepsCheck(t *testing.T) {
	rows := []string{
		"tool ${V} tool-v1.0.0.tgz " + strings.Repeat("a", 64) + " https://github.com/acme/tool/releases/download/${V}/tool-v1.0.0.tgz",
		"extra ${V} extra.deb " + strings.Repeat("b", 64) + " https://downloads.acme.example/extra.deb",
	}
	for _, tc := range []struct {
		name     string
		present  []string
		wantCode int
		wantOut  string
	}{
		{name: "every pinned file on the mirror", present: []string{"deps/tool/v1.0.0/tool-v1.0.0.tgz", "deps/extra/v1.0.0/extra.deb"},
			wantCode: 0, wantOut: "All 2 pinned files are on the mirror"},
		{name: "one missing", present: []string{"deps/tool/v1.0.0/tool-v1.0.0.tgz"},
			wantCode: 1, wantOut: "deps/extra/v1.0.0/extra.deb"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newSyncRig(t)
			for _, k := range tc.present {
				r.onPublicMirror(k, "x")
			}
			installSh := filepath.Join(t.TempDir(), "install.sh")
			mustWrite(t, installSh, pinsScript(rows...))
			r.run("--deps", "--check", "--install-sh", installSh)
			if r.code != tc.wantCode {
				t.Fatalf("exit %d, want %d", r.code, tc.wantCode)
			}
			if !strings.Contains(r.stdout+r.stderr, tc.wantOut) {
				t.Errorf("output lacks %q", tc.wantOut)
			}
			if strings.Contains(r.logs, "aws ") || strings.Contains(r.logs, "gh ") || len(r.uploaded()) != 0 {
				t.Errorf("--check called aws or gh or uploaded something:\n%s", r.logs)
			}
		})
	}

	t.Run("--check goes with --deps only", func(t *testing.T) {
		r := newSyncRig(t)
		r.run("--release", "v1.0.0", "--check")
		if r.code == 0 || !strings.Contains(r.stderr, "--check goes with --deps") {
			t.Fatalf("exit %d, stderr %q; want a refusal", r.code, r.stderr)
		}
	})
}

// The release workflow runs --deps on every release. When the mirror already
// serves every pinned file (pins rarely change), nothing is downloaded from
// GitHub or a vendor and nothing is uploaded, so a GitHub outage cannot fail
// the step for nothing.
func TestMirrorSyncDepsDoesNothingWhenTheMirrorHasEveryPin(t *testing.T) {
	r := newSyncRig(t)
	rows := []string{
		"tool ${V} tool-v1.0.0.tgz " + strings.Repeat("a", 64) + " https://github.com/acme/tool/releases/download/${V}/tool-v1.0.0.tgz",
		"tool ${V} tool " + strings.Repeat("c", 64) + " tar:tool-v1.0.0.tgz:release-v1.0.0/tool",
	}
	r.onPublicMirror("deps/tool/v1.0.0/tool-v1.0.0.tgz", "x")
	r.onPublicMirror("deps/tool/v1.0.0/tool", "x")
	installSh := filepath.Join(t.TempDir(), "install.sh")
	mustWrite(t, installSh, pinsScript(rows...))
	r.run("--deps", "--install-sh", installSh)
	if r.code != 0 || !strings.Contains(r.stdout, "nothing to do") {
		t.Fatalf("exit %d, stdout %q; want success with nothing to do", r.code, r.stdout)
	}
	if strings.Contains(r.logs, "aws ") || strings.Contains(r.logs, "gh ") || len(r.uploaded()) != 0 {
		t.Errorf("downloaded or uploaded although the mirror had every pin:\n%s", r.logs)
	}
}
