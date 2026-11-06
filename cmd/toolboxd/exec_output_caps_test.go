package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// execRequestWith sends one buffered exec request and returns the status, the
// decoded result (on 200) and the raw body.
func execRequestWith(t *testing.T, s *server, req models.ExecRequest) (int, models.ExecResult, string) {
	t.Helper()
	body, _ := json.Marshal(req)
	rr := httptest.NewRecorder()
	s.handleExec(rr, httptest.NewRequest(http.MethodPost, "/process/execute", strings.NewReader(string(body))))
	var res models.ExecResult
	if rr.Code == http.StatusOK {
		if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
			t.Fatalf("decode %s: %v", rr.Body.String(), err)
		}
	}
	return rr.Code, res, rr.Body.String()
}

func setExecCeiling(t *testing.T, n int64) {
	t.Helper()
	old := execOutputCeiling
	execOutputCeiling = n
	t.Cleanup(func() { execOutputCeiling = old })
}

// E1: each stream keeps its first N bytes and says when it was cut; the
// other stream and the exit status are untouched.
func TestExecOutputCaps(t *testing.T) {
	setExecGrace(t, 200*time.Millisecond)
	s := newExecTestServer()
	// 100 KiB on each stream: more than one pipe buffer, so a reader that
	// stopped reading at the cap would block the command.
	const both = "head -c 102400 /dev/zero | tr '\\0' o; head -c 102400 /dev/zero | tr '\\0' e 1>&2; exit 3"
	for _, tc := range []struct {
		name                     string
		maxOut, maxErr           int64
		wantOut, wantErr         int
		wantOutTrunc, wantErrTrn bool
	}{
		{name: "no caps", wantOut: 102400, wantErr: 102400},
		{name: "stdout capped", maxOut: 10, wantOut: 10, wantErr: 102400, wantOutTrunc: true},
		{name: "stderr capped", maxErr: 7, wantOut: 102400, wantErr: 7, wantErrTrn: true},
		{name: "both capped", maxOut: 1, maxErr: 4096, wantOut: 1, wantErr: 4096, wantOutTrunc: true, wantErrTrn: true},
		{name: "cap above output", maxOut: 102401, maxErr: 1 << 20, wantOut: 102400, wantErr: 102400},
		{name: "cap equals output", maxOut: 102400, wantOut: 102400, wantErr: 102400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, res, body := execRequestWith(t, s, models.ExecRequest{Command: both, TimeoutSeconds: 20, MaxStdoutBytes: tc.maxOut, MaxStderrBytes: tc.maxErr})
			if code != http.StatusOK {
				t.Fatalf("exec = %d %s", code, body)
			}
			if len(res.Stdout) != tc.wantOut || len(res.Stderr) != tc.wantErr {
				t.Fatalf("lengths = %d/%d, want %d/%d", len(res.Stdout), len(res.Stderr), tc.wantOut, tc.wantErr)
			}
			if strings.Trim(res.Stdout, "o") != "" || strings.Trim(res.Stderr, "e") != "" {
				t.Fatal("streams mixed or out of order")
			}
			if res.StdoutTruncated != tc.wantOutTrunc || res.StderrTruncated != tc.wantErrTrn {
				t.Fatalf("truncated = %v/%v, want %v/%v", res.StdoutTruncated, res.StderrTruncated, tc.wantOutTrunc, tc.wantErrTrn)
			}
			if res.ExitCode != 3 || res.TimedOut {
				t.Fatalf("result = exit %d timed_out %v, want exit 3", res.ExitCode, res.TimedOut)
			}
		})
	}
}

// E1: a command that prints far past its cap still runs to the end at full
// speed: toolboxd keeps reading and dropping, so the pipe never fills.
func TestExecOutputCapDrainsTheRest(t *testing.T) {
	setExecGrace(t, 200*time.Millisecond)
	start := time.Now()
	code, res, body := execRequestWith(t, newExecTestServer(), models.ExecRequest{
		Command:        "head -c 33554432 /dev/zero; echo done 1>&2",
		TimeoutSeconds: 30,
		MaxStdoutBytes: 16,
	})
	if code != http.StatusOK {
		t.Fatalf("exec = %d %s", code, body)
	}
	if len(res.Stdout) != 16 || !res.StdoutTruncated || strings.TrimSpace(res.Stderr) != "done" || res.ExitCode != 0 {
		t.Fatalf("result = stdout %d bytes truncated %v stderr %q exit %d", len(res.Stdout), res.StdoutTruncated, res.Stderr, res.ExitCode)
	}
	if res.TimedOut || time.Since(start) > 20*time.Second {
		t.Fatalf("exec took %v (timed_out %v); the capped stream blocked the command", time.Since(start), res.TimedOut)
	}
}

// E1: toolboxd's own ceiling applies with no cap and above a requested one.
func TestExecOutputCeiling(t *testing.T) {
	setExecGrace(t, 200*time.Millisecond)
	setExecCeiling(t, 1000)
	s := newExecTestServer()
	for _, tc := range []struct {
		name    string
		max     int64
		want    int
		trunced bool
	}{
		{name: "no cap", want: 1000, trunced: true},
		{name: "cap above the ceiling", max: 5000, want: 1000, trunced: true},
		{name: "cap below the ceiling", max: 10, want: 10, trunced: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, res, body := execRequestWith(t, s, models.ExecRequest{Command: "head -c 5000 /dev/zero | tr '\\0' x", MaxStdoutBytes: tc.max})
			if code != http.StatusOK || len(res.Stdout) != tc.want || res.StdoutTruncated != tc.trunced {
				t.Fatalf("exec = %d, %d bytes, truncated %v (%s)", code, len(res.Stdout), res.StdoutTruncated, body)
			}
		})
	}
	// Output under the ceiling is whole and not marked (ER2: full output).
	if _, res, _ := execRequestWith(t, s, models.ExecRequest{Command: "printf 12345"}); res.Stdout != "12345" || res.StdoutTruncated {
		t.Fatalf("small output = %q truncated %v", res.Stdout, res.StdoutTruncated)
	}
}

// E1 with B2: output a background job prints after the reply is dropped as
// before and does not count as truncation; output inside the grace counts
// against the cap like any other.
func TestExecOutputCapsWithBackgroundJobs(t *testing.T) {
	setExecGrace(t, 600*time.Millisecond)
	s := newExecTestServer()
	_, res, _ := execRequestWith(t, s, models.ExecRequest{Command: "(sleep 0.1; echo inside-grace) & echo first", TimeoutSeconds: 10, MaxStdoutBytes: 8})
	if res.Stdout != "first\nin" || !res.StdoutTruncated {
		t.Fatalf("stdout %q truncated %v, want the cap applied across the grace", res.Stdout, res.StdoutTruncated)
	}

	setExecGrace(t, 100*time.Millisecond)
	_, res, _ = execRequestWith(t, s, models.ExecRequest{Command: "(sleep 1; echo after-the-reply) & echo first", TimeoutSeconds: 10, MaxStdoutBytes: 100})
	if res.Stdout != "first\n" || res.StdoutTruncated {
		t.Fatalf("stdout %q truncated %v, want late output dropped without truncation", res.Stdout, res.StdoutTruncated)
	}
}

// E1: a cut never leaves half a UTF-8 character behind, which JSON would
// turn into a replacement character and so grow past the cap.
func TestExecOutputCapKeepsWholeCharacters(t *testing.T) {
	setExecGrace(t, 200*time.Millisecond)
	// "é" is two bytes; a 3-byte cap would split the second one.
	_, res, _ := execRequestWith(t, newExecTestServer(), models.ExecRequest{Command: "printf 'éééé'", MaxStdoutBytes: 3})
	if res.Stdout != "é" || !res.StdoutTruncated {
		t.Fatalf("stdout %q truncated %v, want one whole é", res.Stdout, res.StdoutTruncated)
	}
}

func TestExecOutputCapsRejectNegative(t *testing.T) {
	for _, req := range []models.ExecRequest{
		{Command: "true", MaxStdoutBytes: -1},
		{Command: "true", MaxStderrBytes: -5},
	} {
		code, _, body := execRequestWith(t, newExecTestServer(), req)
		if code != http.StatusBadRequest || !strings.Contains(body, "max_stdout_bytes and max_stderr_bytes") {
			t.Fatalf("negative cap = %d %s, want 400", code, body)
		}
	}
}

func TestCapturedStreamAdd(t *testing.T) {
	for _, tc := range []struct {
		name      string
		limit     int64
		writes    []string
		want      string
		truncated bool
	}{
		{name: "fits", limit: 10, writes: []string{"abc", "def"}, want: "abcdef"},
		{name: "exact", limit: 6, writes: []string{"abc", "def"}, want: "abcdef"},
		{name: "cut inside a write", limit: 4, writes: []string{"abc", "def"}, want: "abcd", truncated: true},
		{name: "cut on a write boundary", limit: 3, writes: []string{"abc", "def"}, want: "abc", truncated: true},
		{name: "nothing after the cut", limit: 2, writes: []string{"abc", "def", "ghi"}, want: "ab", truncated: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := capturedStream{limit: tc.limit}
			for _, w := range tc.writes {
				s.add([]byte(w))
			}
			if string(s.data) != tc.want || s.truncated != tc.truncated {
				t.Fatalf("data %q truncated %v, want %q %v", s.data, s.truncated, tc.want, tc.truncated)
			}
		})
	}
}

func TestTrimPartialRune(t *testing.T) {
	euro := "€"  // three bytes: e2 82 ac
	emoji := "😀" // four bytes: f0 9f 98 80
	for _, tc := range []struct {
		name, in, want string
	}{
		{name: "empty", in: "", want: ""},
		{name: "ascii", in: "abc", want: "abc"},
		{name: "whole two-byte", in: "aé", want: "aé"},
		{name: "half a two-byte", in: "a" + "é"[:1], want: "a"},
		{name: "whole three-byte", in: "a" + euro, want: "a" + euro},
		{name: "two of three bytes", in: "a" + euro[:2], want: "a"},
		{name: "one of three bytes", in: "a" + euro[:1], want: "a"},
		{name: "three of four bytes", in: "a" + emoji[:3], want: "a"},
		{name: "whole four-byte", in: emoji, want: emoji},
		// Not UTF-8 at all: binary output is left as it is.
		{name: "stray continuation bytes", in: "a\x80\x80", want: "a\x80\x80"},
		{name: "only continuation bytes", in: "\x80\x80\x80\x80\x80", want: "\x80\x80\x80\x80\x80"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := string(trimPartialRune([]byte(tc.in))); got != tc.want {
				t.Fatalf("trimPartialRune(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
	// Untruncated output is never trimmed, even if it ends mid-character.
	s := capturedStream{limit: 10, data: []byte("a" + euro[:1])}
	if s.text() != "a"+euro[:1] {
		t.Fatalf("untruncated text trimmed: %q", s.text())
	}
}

func TestVersionListsExecMaxOutputBytes(t *testing.T) {
	h := authedRoutes(newDaytonaTestServer(t))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/version", nil))
	if !strings.Contains(rr.Body.String(), `"exec.max_output_bytes"`) {
		t.Fatalf("/version = %s, want exec.max_output_bytes", rr.Body.String())
	}
}
