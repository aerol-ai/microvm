package docker

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestSplitDestRefCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantRepo string
		wantTag  string
	}{
		{name: "repo with tag", input: "ghcr.io/org/img:v1.2.3", wantRepo: "ghcr.io/org/img", wantTag: "v1.2.3"},
		{name: "repo no tag defaults latest", input: "ghcr.io/org/img", wantRepo: "ghcr.io/org/img", wantTag: "latest"},
		{name: "host port not mistaken for tag", input: "localhost:5000/img", wantRepo: "localhost:5000/img", wantTag: "latest"},
		{name: "host port with tag", input: "localhost:5000/img:dev", wantRepo: "localhost:5000/img", wantTag: "dev"},
		{name: "bare name no slash", input: "alpine", wantRepo: "alpine", wantTag: "latest"},
		{name: "bare name with tag", input: "alpine:3.20", wantRepo: "alpine", wantTag: "3.20"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotRepo, gotTag := splitDestRef(tc.input)
			if gotRepo != tc.wantRepo || gotTag != tc.wantTag {
				t.Fatalf("splitDestRef(%q) = (%q, %q), want (%q, %q)",
					tc.input, gotRepo, gotTag, tc.wantRepo, tc.wantTag)
			}
		})
	}
}

func TestBuildTagForIsDeterministicAndSensitiveToInputs(t *testing.T) {
	a := BuildTagFor("FROM alpine\nRUN echo hi", nil)
	b := BuildTagFor("FROM alpine\nRUN echo hi", nil)
	if a != b {
		t.Fatalf("same input must produce same tag, got %q vs %q", a, b)
	}
	if !strings.HasPrefix(a, BuiltImageNamespace+"/") || !strings.HasSuffix(a, ":latest") {
		t.Fatalf("tag %q missing namespace/latest scaffolding", a)
	}

	if BuildTagFor("FROM alpine\nRUN echo hi", nil) ==
		BuildTagFor("FROM alpine\nRUN echo bye", nil) {
		t.Fatal("different dockerfile must produce different tag")
	}
	if BuildTagFor("FROM alpine", nil) == BuildTagFor("FROM alpine", []string{"deadbeef"}) {
		t.Fatal("adding a context hash must change the tag")
	}

	// Whitespace at the boundaries must not affect the tag — the resolver
	// trims before hashing so a SDK that pretty-prints a Dockerfile doesn't
	// blow the cache.
	if BuildTagFor("FROM alpine\nRUN echo hi", nil) !=
		BuildTagFor("  FROM alpine\nRUN echo hi  \n", nil) {
		t.Fatal("BuildTagFor must be insensitive to surrounding whitespace")
	}
}

func TestBuildGroupKeyDistinguishesContent(t *testing.T) {
	base := buildGroupKey("aerolvm-build/x:latest", "FROM alpine", []byte("ctx-a"))
	if base == buildGroupKey("aerolvm-build/y:latest", "FROM alpine", []byte("ctx-a")) {
		t.Fatal("different tag must yield different singleflight key")
	}
	if base == buildGroupKey("aerolvm-build/x:latest", "FROM ubuntu", []byte("ctx-a")) {
		t.Fatal("different dockerfile must yield different singleflight key")
	}
	if base == buildGroupKey("aerolvm-build/x:latest", "FROM alpine", []byte("ctx-b")) {
		t.Fatal("different context bytes must yield different singleflight key")
	}
	if base != buildGroupKey("aerolvm-build/x:latest", "FROM alpine", []byte("ctx-a")) {
		t.Fatal("same inputs must yield same singleflight key")
	}
}

// assembleBuildContext must always emit a Dockerfile entry (even on nil
// extra), and must override any caller-supplied Dockerfile entry — Docker's
// tar reader uses last-write-wins, so the explicit DockerfileContent always
// reaches the daemon's parser.
func TestAssembleBuildContextEmitsDockerfile(t *testing.T) {
	out, err := assembleBuildContext("FROM alpine\n", nil)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	files := readTarEntries(t, out)
	if got := files["Dockerfile"]; got != "FROM alpine\n" {
		t.Fatalf("Dockerfile body = %q", got)
	}
}

func TestAssembleBuildContextMergesExtraTar(t *testing.T) {
	extra := makeTar(t, map[string]string{"app/main.py": "print('hi')\n"})
	out, err := assembleBuildContext("FROM alpine\n", extra)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	files := readTarEntries(t, out)
	if files["Dockerfile"] != "FROM alpine\n" {
		t.Fatalf("Dockerfile body = %q", files["Dockerfile"])
	}
	if files["app/main.py"] != "print('hi')\n" {
		t.Fatalf("extra entry missing or wrong: %q", files["app/main.py"])
	}
}

func TestAssembleBuildContextOverridesExtraDockerfile(t *testing.T) {
	// Caller's tar carries a Dockerfile that should be overridden by the
	// explicit DockerfileContent ("last-write-wins" per archive/tar reader).
	extra := makeTar(t, map[string]string{
		"Dockerfile":  "FROM ubuntu\n",
		"app/main.py": "print('hi')\n",
	})
	out, err := assembleBuildContext("FROM alpine\n", extra)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	files := readTarEntries(t, out)
	if files["Dockerfile"] != "FROM alpine\n" {
		t.Fatalf("explicit Dockerfile should win, got %q", files["Dockerfile"])
	}
	if files["app/main.py"] != "print('hi')\n" {
		t.Fatalf("extra entry survived merge: got %q", files["app/main.py"])
	}
}

func TestDecodeBuildStreamForwardsLogsAndReturnsNil(t *testing.T) {
	body := strings.NewReader(
		`{"stream":"Step 1/2 : FROM alpine\n"}` + "\n" +
			`{"stream":"Step 2/2 : RUN echo hi\n"}` + "\n",
	)
	var lines []string
	if err := decodeBuildStream(body, func(line string) { lines = append(lines, line) }); err != nil {
		t.Fatalf("decode: %v", err)
	}
	want := []string{"Step 1/2 : FROM alpine", "Step 2/2 : RUN echo hi"}
	if len(lines) != len(want) {
		t.Fatalf("lines = %v, want %v", lines, want)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Fatalf("lines[%d] = %q, want %q", i, lines[i], want[i])
		}
	}
}

func TestDecodeBuildStreamPromotesError(t *testing.T) {
	body := strings.NewReader(
		`{"stream":"Step 1/1 : RUN false\n"}` + "\n" +
			`{"errorDetail":{"message":"command failed"},"error":"command failed"}` + "\n",
	)
	err := decodeBuildStream(body, nil)
	if err == nil || !strings.Contains(err.Error(), "command failed") {
		t.Fatalf("expected build error to surface, got %v", err)
	}
}

// A truncated stream (network drop mid-message) must surface as a decode
// error rather than a silent success — otherwise a half-built image looks
// indistinguishable from a complete one.
func TestDecodeBuildStreamReportsTruncated(t *testing.T) {
	body := strings.NewReader(`{"stream":"Step 1`) // unterminated JSON
	err := decodeBuildStream(body, nil)
	if err == nil {
		t.Fatal("expected error on truncated stream")
	}
	if errors.Is(err, io.EOF) {
		t.Fatalf("EOF must be wrapped, not returned bare: %v", err)
	}
}

func TestDecodePushStreamForwardsStatuses(t *testing.T) {
	body := strings.NewReader(
		`{"status":"The push refers to repository [ghcr.io/x/y]"}` + "\n" +
			`{"status":"v1: digest: sha256:abc size: 123"}` + "\n",
	)
	var lines []string
	if err := decodePushStream(body, func(line string) { lines = append(lines, line) }, nil); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(lines) != 2 {
		t.Fatalf("statuses = %v", lines)
	}
}

func TestDecodePushStreamCapturesAuxDigest(t *testing.T) {
	body := strings.NewReader(
		`{"status":"Pushing"}` + "\n" +
			`{"progressDetail":{},"aux":{"Tag":"latest","Digest":"sha256:abc123","Size":42}}` + "\n",
	)
	var digest string
	if err := decodePushStream(body, nil, func(d string) { digest = d }); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if digest != "sha256:abc123" {
		t.Fatalf("digest = %q, want sha256:abc123", digest)
	}
}

func TestDecodePushStreamPromotesError(t *testing.T) {
	body := strings.NewReader(
		`{"status":"Pushing"}` + "\n" +
			`{"errorDetail":{"message":"unauthorized: authentication required"}}` + "\n",
	)
	err := decodePushStream(body, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "unauthorized") {
		t.Fatalf("expected push error, got %v", err)
	}
}

// helpers -----------------------------------------------------------------

func makeTar(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatalf("write header %q: %v", name, err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatalf("write body %q: %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	return buf.Bytes()
}

func readTarEntries(t *testing.T, raw []byte) map[string]string {
	t.Helper()
	out := map[string]string{}
	tr := tar.NewReader(bytes.NewReader(raw))
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("tar.Next: %v", err)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("read body of %q: %v", h.Name, err)
		}
		// Last-write-wins: a duplicate entry overwrites the earlier one,
		// which is exactly what Docker's build reader does.
		out[h.Name] = string(body)
	}
	return out
}
