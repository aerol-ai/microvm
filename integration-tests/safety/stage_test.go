// Offline tests for moving files to test nodes through S3 (lib/stage.sh,
// lib/build.sh's cmd_stage), and the tripwire that keeps scp uploads out of
// the harness.
//
// Why it matters: one scp is one TCP stream over the operator's uplink. The
// adopt gate's 129 MB build took 20+ minutes per node that way (2026-11-09)
// and slowed every other session's uploads. Through S3 the laptop uploads a
// file once with many connections, or not at all when its build is already
// published, and each node downloads inside AWS in seconds.
//
// Runs in the normal `go test ./...` / `make test` flow (no build tag).
package safety

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

var scpCall = regexp.MustCompile(`(^|[\s;&|({])scp(\s|$)`)

// TestNoScpUploadsToNodes keeps every harness script on stage_to_node: an
// scp whose source is a local file is an upload over this machine's uplink.
// A download (the source is user@host:path) uses the downlink and stays
// allowed.
func TestNoScpUploadsToNodes(t *testing.T) {
	root := integrationDir(t)
	var bad []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".tf", ".build", "reports", "testdata", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".sh") {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1024*1024), 1024*1024)
		for n := 1; sc.Scan(); n++ {
			line := sc.Text()
			code := strings.TrimSpace(line)
			if strings.HasPrefix(code, "#") || !scpCall.MatchString(code) {
				continue
			}
			if !scpIsDownload(code) {
				rel, _ := filepath.Rel(root, path)
				bad = append(bad, rel+":"+strconv.Itoa(n)+": "+code)
			}
		}
		return sc.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(bad) > 0 {
		t.Fatalf("scp uploads to a node (use stage_to_node from lib/stage.sh, which goes through S3):\n  %s", strings.Join(bad, "\n  "))
	}
}

// scpIsDownload reports whether the first non-option argument of the scp in
// line is remote (user@host:path).
func scpIsDownload(line string) bool {
	loc := scpCall.FindStringIndex(line)
	fields := strings.Fields(line[loc[1]:])
	for i := 0; i < len(fields); i++ {
		f := fields[i]
		switch {
		case strings.HasSuffix(f, `[@]}"`) || strings.HasSuffix(f, `[@]}`):
			continue // "${SSH_OPTS[@]}"
		case f == "-i" || f == "-o" || f == "-P" || f == "-F":
			i++
			continue
		case strings.HasPrefix(f, "-"):
			continue
		}
		f = strings.Trim(f, `"'`)
		at := strings.Index(f, "@")
		return at >= 0 && strings.Contains(f[at:], ":")
	}
	return false
}

func TestScpIsDownload(t *testing.T) {
	cases := map[string]bool{
		`scp "${SSH_OPTS[@]}" "ubuntu@${obs_ip}:${remote}" "${out_dir}/${uid}.png" || true`: true,
		`scp -q "${SSH_OPTS[@]}" "$f" "${TARGET}:/tmp/"`:                                    false,
		`scp "${SSH_ID[@]}" "$BIN" "ubuntu@$ip:/tmp/sandboxd.new" >/dev/null 2>&1`:          false,
		`if ! scp -i key -o X=y "$file" "${tgt}:/tmp/a.wasm"; then`:                         false,
	}
	for line, want := range cases {
		if got := scpIsDownload(line); got != want {
			t.Errorf("scpIsDownload(%q) = %v, want %v", line, got, want)
		}
	}
}

// stageRig is build.sh's cmd_stage run against a fake aws CLI that keeps
// its bucket in a folder and logs every call.
type stageRig struct {
	t      *testing.T
	root   string // fake REPO_ROOT
	bucket string // folder standing in for the bucket
	log    string
}

const fakeStageAWS = `#!/usr/bin/env bash
# Fake aws for stage tests: the bucket is $FAKE_BUCKET/<key>.
echo "$*" >>"$FAKE_AWS_LOG"
args=("$@")
key=""; src=""; dst=""
for ((i = 0; i < ${#args[@]}; i++)); do
  [[ "${args[i]}" == "--key" ]] && key="${args[i+1]}"
done
case "$*" in
  *"sts get-caller-identity"*) echo 123456789012 ;;
  *"s3api head-object"*)
    [[ -f "$FAKE_BUCKET/$key" ]] || exit 254
    if [[ "$*" == *"--query ContentLength"* ]]; then wc -c <"$FAKE_BUCKET/$key" | tr -d ' '; fi ;;
  *"s3 cp"*)
    for a in "${args[@]}"; do
      case "$a" in s3://*) dst="${a#s3://*/}" ;; -*|cp|s3|--region|us-east-1) ;; *) [[ -f "$a" ]] && src="$a" ;; esac
    done
    mkdir -p "$(dirname "$FAKE_BUCKET/$dst")"; cp "$src" "$FAKE_BUCKET/$dst" ;;
  *"s3 presign"*)
    for a in "${args[@]}"; do case "$a" in s3://*) echo "file://$FAKE_BUCKET/${a#s3://*/}" ;; esac; done ;;
  *) echo "fake aws: unexpected $*" >&2; exit 1 ;;
esac
`

func newStageRig(t *testing.T) *stageRig {
	t.Helper()
	dir := t.TempDir()
	r := &stageRig{t: t, root: filepath.Join(dir, "repo"), bucket: filepath.Join(dir, "bucket"), log: filepath.Join(dir, "aws.log")}
	for _, d := range []string{filepath.Join(r.root, "config"), filepath.Join(r.root, "integration-tests", ".build"), r.bucket, filepath.Join(dir, "bin")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeStageFile(t, filepath.Join(r.root, "config", "terraform.tfvars"), "aws_region = \"us-east-1\"\n", 0o644)
	writeStageFile(t, filepath.Join(dir, "bin", "aws"), fakeStageAWS, 0o755)
	return r
}

func writeStageFile(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// stage runs cmd_stage on files and returns its stdout lines.
func (r *stageRig) stage(files ...string) []string {
	r.t.Helper()
	snippet := "REPO_ROOT='" + r.root + "'; BUILD_ROOT='" + filepath.Join(r.root, "integration-tests", ".build") + "'; cmd_stage"
	for _, f := range files {
		snippet += " '" + f + "'"
	}
	cmd := exec.Command("bash", "-c", "source "+buildScript(r.t)+"\n"+snippet)
	cmd.Env = append(os.Environ(),
		"PATH="+filepath.Join(filepath.Dir(r.bucket), "bin")+string(os.PathListSeparator)+os.Getenv("PATH"),
		"FAKE_BUCKET="+r.bucket, "FAKE_AWS_LOG="+r.log)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		r.t.Fatalf("cmd_stage %v: %v\n%s", files, err, stderr.String())
	}
	return strings.Split(strings.TrimSpace(string(out)), "\n")
}

func (r *stageRig) uploads() int {
	r.t.Helper()
	b, _ := os.ReadFile(r.log)
	return strings.Count(string(b), "s3 cp")
}

// stageLib is lib/stage.sh, for tests that copy common.sh into a scratch
// tree: common.sh sources it.
func stageLib(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(integrationDir(t), "lib", "stage.sh"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func stageSHA(body string) string {
	s := sha256.Sum256([]byte(body))
	return hex.EncodeToString(s[:])
}

// A file of a published build is fetched from that build's copy: no upload.
// Anything else goes up once, under its SHA-256, and a second stage of the
// same bytes uploads nothing.
func TestStageReusesThePublishedBuildAndUploadsTheRestOnce(t *testing.T) {
	r := newStageRig(t)
	built := filepath.Join(r.root, "integration-tests", ".build", "abc123", "sandboxd_linux_amd64")
	writeStageFile(t, built, "daemon bytes", 0o755)
	// publish put the same bytes under builds/<id>/.
	writeStageFile(t, filepath.Join(r.bucket, "builds", "abc123", "sandboxd_linux_amd64"), "daemon bytes", 0o644)
	suite := filepath.Join(r.root, "work", "suite.test")
	writeStageFile(t, suite, "suite bytes", 0o644)

	lines := r.stage(built, suite)
	if len(lines) != 2 {
		t.Fatalf("stage printed %d lines, want 2: %q", len(lines), lines)
	}
	wantBuilt := stageSHA("daemon bytes") + " 0755 sandboxd_linux_amd64 file://" + filepath.Join(r.bucket, "builds", "abc123", "sandboxd_linux_amd64")
	if lines[0] != wantBuilt {
		t.Fatalf("published build file:\n got %q\nwant %q", lines[0], wantBuilt)
	}
	wantSuite := stageSHA("suite bytes") + " 0644 suite.test file://" + filepath.Join(r.bucket, "builds", "stage", stageSHA("suite bytes"), "suite.test")
	if lines[1] != wantSuite {
		t.Fatalf("other file:\n got %q\nwant %q", lines[1], wantSuite)
	}
	if got := r.uploads(); got != 1 {
		t.Fatalf("uploads = %d, want 1 (only the file no build holds)", got)
	}

	r.stage(built, suite)
	if got := r.uploads(); got != 1 {
		t.Fatalf("uploads after staging the same files again = %d, want still 1", got)
	}
}

// A build folder whose published copy differs in size (a rebuild after the
// publish) is not trusted: the local bytes go up under their own SHA-256.
func TestStageUploadsABuildFileThePublishedCopyDoesNotMatch(t *testing.T) {
	r := newStageRig(t)
	built := filepath.Join(r.root, "integration-tests", ".build", "abc123", "sandboxd_linux_amd64")
	writeStageFile(t, built, "rebuilt daemon bytes", 0o755)
	writeStageFile(t, filepath.Join(r.bucket, "builds", "abc123", "sandboxd_linux_amd64"), "old", 0o644)
	lines := r.stage(built)
	want := "file://" + filepath.Join(r.bucket, "builds", "stage", stageSHA("rebuilt daemon bytes"), "sandboxd_linux_amd64")
	if !strings.HasSuffix(lines[0], want) || r.uploads() != 1 {
		t.Fatalf("stage = %q with %d uploads, want the content key %s and 1 upload", lines[0], r.uploads(), want)
	}
}

func TestStageRefusesWhatItCannotStage(t *testing.T) {
	for name, snippet := range map[string]string{
		"no files":     "cmd_stage",
		"missing file": "cmd_stage /nonexistent/file",
		"unknown flag": "cmd_stage --bogus x",
	} {
		t.Run(name, func(t *testing.T) {
			out, code := sourceAndRun(t, snippet)
			if code == 0 || !strings.Contains(out, "stage:") {
				t.Fatalf("%s = %d %q, want a stage: refusal", snippet, code, out)
			}
		})
	}
}

// The node keeps a file only once its SHA-256 matches this machine's copy,
// with the mode it had here; a wrong download leaves nothing behind.
func TestStageRemoteScriptChecksEveryFile(t *testing.T) {
	needTools(t, "curl", "sha256sum")
	src := t.TempDir()
	writeStageFile(t, filepath.Join(src, "tool"), "tool bytes", 0o644)
	writeStageFile(t, filepath.Join(src, "notes"), "notes bytes", 0o644)
	dest := filepath.Join(t.TempDir(), "stage")

	run := func(lines string) (string, error) {
		gen := exec.Command("bash", "-c", "source "+filepath.Join(integrationDir(t), "lib", "stage.sh")+"\nstage_remote_script '"+dest+"'")
		gen.Stdin = strings.NewReader(lines)
		script, err := gen.Output()
		if err != nil {
			t.Fatalf("stage_remote_script: %v", err)
		}
		out, err := exec.Command("bash", "-c", string(script)).CombinedOutput()
		return string(out), err
	}

	good := stageSHA("tool bytes") + " 0755 tool file://" + filepath.Join(src, "tool") + "\n" +
		stageSHA("notes bytes") + " 0644 notes file://" + filepath.Join(src, "notes") + "\n"
	if out, err := run(good); err != nil {
		t.Fatalf("good files: %v\n%s", err, out)
	}
	for name, mode := range map[string]os.FileMode{"tool": 0o755, "notes": 0o644} {
		st, err := os.Stat(filepath.Join(dest, name))
		if err != nil || st.Mode().Perm() != mode {
			t.Fatalf("%s: %v mode %v, want %v", name, err, st, mode)
		}
	}

	bad := stageSHA("something else") + " 0644 notes2 file://" + filepath.Join(src, "notes") + "\n"
	out, err := run(bad)
	if err == nil || !strings.Contains(out, "notes2 does not match its SHA-256") {
		t.Fatalf("mismatched file = %v %q, want a refusal", err, out)
	}
	if left, _ := filepath.Glob(filepath.Join(dest, "*notes2*")); len(left) > 0 {
		t.Fatalf("a mismatched download left %v", left)
	}
	if left, _ := filepath.Glob(filepath.Join(dest, ".notes2*")); len(left) > 0 {
		t.Fatalf("a mismatched download left %v", left)
	}
}

// stage_to_node end to end, with the fake aws and an ssh that runs the
// node's script here.
func TestStageToNodeDeliversTheFiles(t *testing.T) {
	needTools(t, "curl", "sha256sum")
	r := newStageRig(t)
	bin := filepath.Join(filepath.Dir(r.bucket), "bin")
	writeStageFile(t, filepath.Join(bin, "ssh"), "#!/usr/bin/env bash\n# fake ssh: the last argument is the command; run it here.\nexec bash -c \"${@: -1}\"\n", 0o755)
	file := filepath.Join(r.root, "work", "suite.test")
	writeStageFile(t, file, "suite bytes", 0o755)
	dest := filepath.Join(t.TempDir(), "node-dir")

	// stage.sh calls build.sh as a script; point it at a copy whose REPO_ROOT
	// is the rig's, the way the real tree's config/ would be found.
	lib := filepath.Join(r.root, "integration-tests", "lib")
	for _, f := range []string{"build.sh", "stage.sh"} {
		b, err := os.ReadFile(filepath.Join(integrationDir(t), "lib", f))
		if err != nil {
			t.Fatal(err)
		}
		writeStageFile(t, filepath.Join(lib, f), string(b), 0o755)
	}
	cmd := exec.Command("bash", "-c", "SSH_OPTS=(); source '"+filepath.Join(lib, "stage.sh")+"'; stage_to_node ubuntu@node '"+dest+"' '"+file+"'")
	cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"FAKE_BUCKET="+r.bucket, "FAKE_AWS_LOG="+r.log)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("stage_to_node: %v\n%s", err, out)
	}
	got, err := os.ReadFile(filepath.Join(dest, "suite.test"))
	if err != nil || string(got) != "suite bytes" {
		t.Fatalf("node got %q (%v), want the file", got, err)
	}
}
