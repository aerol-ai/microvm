package safety

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// run.sh's teardown empties the audit-witness bucket before `terraform
// destroy` (lib/common.sh empty_versioned_bucket), and the only other proof
// that it works is a live run against a real Object Lock bucket — after which
// a mistake is a bucket nobody can delete. The properties that fail silently
// or expensively are checked here against a fake `aws` on PATH: every version
// AND every delete marker goes, past S3's 1000-entry page, in batches of at
// most 1000, each with the governance-bypass flag; an empty or missing bucket
// is quiet; and an entry S3 keeps fails loudly instead of looping forever.

// fakeAWS is just enough of `aws s3api list-object-versions` (one page of at
// most 1000 entries, versions first, as S3 counts them together) and
// `aws s3api delete-objects` (at most 1000 keys, or every key refused when
// FAKE_AWS_REFUSE is set) over a JSON state file. A missing state file is a
// missing bucket.
const fakeAWS = `#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$FAKE_AWS_LOG"
op="" file="" prev=""
for a in "$@"; do
  case "$a" in list-object-versions|delete-objects) op="$a" ;; esac
  if [[ "$prev" == "--delete" ]]; then file="${a#file://}"; fi
  prev="$a"
done
state="$FAKE_AWS_STATE"
case "$op" in
  list-object-versions)
    if [[ ! -f "$state" ]]; then
      echo "An error occurred (NoSuchBucket) when calling the ListObjectVersions operation: The specified bucket does not exist" >&2
      exit 254
    fi
    jq '(.Versions[:1000]) as $v | {Name: "b", IsTruncated: false, Versions: $v, DeleteMarkers: .DeleteMarkers[:(1000 - ($v | length))]}' "$state"
    ;;
  delete-objects)
    if (( $(jq '.Objects | length' "$file") > 1000 )); then
      echo "An error occurred (MalformedXML) when calling the DeleteObjects operation" >&2
      exit 254
    fi
    if [[ -n "${FAKE_AWS_REFUSE:-}" ]]; then
      jq '{Errors: [.Objects[] | {Key, VersionId, Code: "AccessDenied", Message: "Access Denied because object protected by object lock."}]}' "$file"
      exit 0
    fi
    jq --slurpfile del "$file" '(reduce $del[0].Objects[] as $o ({}; .[$o.Key + " " + $o.VersionId] = true)) as $gone
      | .Versions |= map(select($gone[.Key + " " + .VersionId] | not))
      | .DeleteMarkers |= map(select($gone[.Key + " " + .VersionId] | not))' "$state" >"$state.tmp"
    mv "$state.tmp" "$state"
    ;;
  *)
    echo "fake aws: unsupported: $*" >&2
    exit 2
    ;;
esac
`

type fakeBucket struct {
	Versions      []map[string]string `json:"Versions"`
	DeleteMarkers []map[string]string `json:"DeleteMarkers"`
}

type emptyBucketRig struct {
	t                     *testing.T
	dir, state, log, tmp  string
	commonSh, fakeAWSPath string
}

func newEmptyBucketRig(t *testing.T) *emptyBucketRig {
	t.Helper()
	for _, bin := range []string{"bash", "jq"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not on PATH", bin)
		}
	}
	dir := t.TempDir()
	r := &emptyBucketRig{
		t:        t,
		dir:      dir,
		state:    filepath.Join(dir, "bucket.json"),
		log:      filepath.Join(dir, "aws.log"),
		tmp:      filepath.Join(dir, "tmp"),
		commonSh: filepath.Join(filepath.Dir(buildScript(t)), "common.sh"),
	}
	if err := os.MkdirAll(filepath.Join(dir, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(r.tmp, 0o755); err != nil {
		t.Fatal(err)
	}
	r.fakeAWSPath = filepath.Join(dir, "bin", "aws")
	if err := os.WriteFile(r.fakeAWSPath, []byte(fakeAWS), 0o755); err != nil {
		t.Fatal(err)
	}
	return r
}

func (r *emptyBucketRig) fill(versions, markers int) {
	r.t.Helper()
	var b fakeBucket
	for i := 0; i < versions; i++ {
		b.Versions = append(b.Versions, map[string]string{
			"Key":       fmt.Sprintf("witness/node=aerolvm-itest-x-node%d/day=2026-10-16/head.json", i%8),
			"VersionId": fmt.Sprintf("v%06d", i),
		})
	}
	for i := 0; i < markers; i++ {
		b.DeleteMarkers = append(b.DeleteMarkers, map[string]string{
			"Key":       fmt.Sprintf("witness/canary/node=aerolvm-itest-x-node%d", i%8),
			"VersionId": fmt.Sprintf("m%06d", i),
		})
	}
	raw, err := json.Marshal(b)
	if err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(r.state, raw, 0o644); err != nil {
		r.t.Fatal(err)
	}
}

func (r *emptyBucketRig) remaining() int {
	r.t.Helper()
	raw, err := os.ReadFile(r.state)
	if err != nil {
		r.t.Fatal(err)
	}
	var b fakeBucket
	if err := json.Unmarshal(raw, &b); err != nil {
		r.t.Fatal(err)
	}
	return len(b.Versions) + len(b.DeleteMarkers)
}

// run sources common.sh under run.sh's own shell options and empties bucket
// "b" through the fake. Returns stdout, stderr and the exit code.
func (r *emptyBucketRig) run(extraEnv ...string) (string, string, int) {
	r.t.Helper()
	cmd := exec.Command("bash", "-c",
		`set -euo pipefail; source "$1"; empty_versioned_bucket b aws --region us-east-1 --profile itest`,
		"bash", r.commonSh)
	cmd.Env = append(os.Environ(),
		"PATH="+filepath.Join(r.dir, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"),
		"FAKE_AWS_STATE="+r.state,
		"FAKE_AWS_LOG="+r.log,
		"TMPDIR="+r.tmp,
	)
	cmd.Env = append(cmd.Env, extraEnv...)
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		r.t.Fatalf("run bash: %v", err)
	}
	return stdout.String(), stderr.String(), code
}

func (r *emptyBucketRig) calls() []string {
	r.t.Helper()
	raw, err := os.ReadFile(r.log)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		r.t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(raw)), "\n")
}

// The working directory the helper creates must not outlive it: run.sh can
// call it twice per teardown, and teardown runs on every scenario.
func (r *emptyBucketRig) assertNoTempLeft() {
	r.t.Helper()
	left, err := filepath.Glob(filepath.Join(r.tmp, "aerol-empty-bucket.*"))
	if err != nil {
		r.t.Fatal(err)
	}
	if len(left) > 0 {
		r.t.Fatalf("empty_versioned_bucket left its working directory behind: %v", left)
	}
}

func TestEmptyVersionedBucketDeletesEveryVersionAndMarker(t *testing.T) {
	r := newEmptyBucketRig(t)
	// More than two pages, with delete markers straddling a page boundary.
	r.fill(2500, 300)

	stdout, stderr, code := r.run()
	if code != 0 {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
	if n := r.remaining(); n != 0 {
		t.Fatalf("%d entries left in the bucket; terraform destroy would refuse to delete it", n)
	}
	if !strings.Contains(stdout, "deleted 2800 ") {
		t.Fatalf("the summary does not count 2800 entries: %q", stdout)
	}
	deletes := 0
	for _, call := range r.calls() {
		if !strings.Contains(call, "--region us-east-1 --profile itest") {
			t.Errorf("call does not use the scenario's region and profile: %s", call)
		}
		if !strings.Contains(call, "delete-objects") {
			continue
		}
		deletes++
		// Without the header a governance lock refuses even a principal that
		// holds the bypass permission, and every version stays.
		if !strings.Contains(call, "--bypass-governance-retention") {
			t.Errorf("delete-objects without --bypass-governance-retention: %s", call)
		}
		if !strings.Contains(call, "--delete file://") {
			t.Errorf("the batch must go through a file, not argv: %s", call)
		}
	}
	if deletes != 3 {
		t.Fatalf("%d delete-objects calls for 2800 entries, want 3 batches of at most 1000", deletes)
	}
	r.assertNoTempLeft()

	// Idempotent and quiet: a second teardown, or --destroy-only after a
	// clean one, lists once and deletes nothing.
	before := len(r.calls())
	stdout, stderr, code = r.run()
	if code != 0 || stdout != "" || stderr != "" {
		t.Fatalf("an empty bucket must be a quiet success: exit %d stdout %q stderr %q", code, stdout, stderr)
	}
	if got := r.calls()[before:]; len(got) != 1 || !strings.Contains(got[0], "list-object-versions") {
		t.Fatalf("an empty bucket made calls %v, want one listing", got)
	}
	r.assertNoTempLeft()
}

// A bucket that is already gone (destroyed out of band, or a re-run after a
// destroy that deleted it) is nothing to do, not a failure.
func TestEmptyVersionedBucketIsQuietOnAMissingBucket(t *testing.T) {
	r := newEmptyBucketRig(t)
	stdout, stderr, code := r.run()
	if code != 0 || stdout != "" || stderr != "" {
		t.Fatalf("a missing bucket must be a quiet success: exit %d stdout %q stderr %q", code, stdout, stderr)
	}
	r.assertNoTempLeft()
}

// An entry S3 keeps (a COMPLIANCE lock, credentials without the bypass
// permission) is answered 200 with an Errors list. Treating that as progress
// would relist the same entries forever; it must fail and say which and why.
func TestEmptyVersionedBucketFailsLoudlyOnARefusedDelete(t *testing.T) {
	r := newEmptyBucketRig(t)
	r.fill(5, 1)
	stdout, stderr, code := r.run("FAKE_AWS_REFUSE=1")
	if code == 0 {
		t.Fatalf("a refused delete reported success: stdout %q stderr %q", stdout, stderr)
	}
	if !strings.Contains(stderr, "AccessDenied") || !strings.Contains(stderr, "witness/node=") {
		t.Fatalf("the failure does not name the kept entry and the reason: %q", stderr)
	}
	if n := r.remaining(); n != 6 {
		t.Fatalf("%d entries left, want all 6 (the fake refused every delete)", n)
	}
	r.assertNoTempLeft()
}
