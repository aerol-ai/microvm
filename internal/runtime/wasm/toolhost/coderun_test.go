package toolhost

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func codeRun(t *testing.T, procs Processes, body string) *httptest.ResponseRecorder {
	t.Helper()
	h := New(Config{SandboxID: "sb", WorkDir: t.TempDir(), AuthToken: "tok", Procs: procs})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/process/code-run", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer tok")
	h.Handler().ServeHTTP(rec, req)
	return rec
}

// codeRunAsync runs a code-run in the background while the test feeds its
// run; done receives the response.
func codeRunAsync(t *testing.T, procs *fakeProcs, body string) (run *fakeRun, done chan *httptest.ResponseRecorder) {
	t.Helper()
	done = make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- codeRun(t, procs, body) }()
	return procs.run(t, 0), done
}

func decodeCodeRun(t *testing.T, rec *httptest.ResponseRecorder) codeRunResponse {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body %s", rec.Code, rec.Body.String())
	}
	var resp codeRunResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestCodeRunWithoutProcessesIs501(t *testing.T) {
	if rec := codeRun(t, nil, `{"language":"python","code":"print(1)"}`); rec.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestCodeRunRequestErrors(t *testing.T) {
	old := codeRunMaxBody
	codeRunMaxBody = 64
	t.Cleanup(func() { codeRunMaxBody = old })
	cases := []struct {
		body   string
		err    error
		status int
		want   string
	}{
		{body: `{`, status: http.StatusBadRequest, want: "invalid JSON"},
		{body: `{"language":"python"}`, status: http.StatusBadRequest, want: "code is required"},
		{body: `{"language":"python","code":"` + strings.Repeat("x", 100) + `"}`, status: http.StatusRequestEntityTooLarge, want: "larger than"},
		{body: `{"language":"cobol","code":"x"}`, err: &CodeRunLanguageError{Message: `code-run language "cobol" is not supported; supported: python`}, status: http.StatusBadRequest, want: "supported: python"},
		{body: `{"language":"python","code":"x"}`, err: ErrTooManyProcesses, status: http.StatusTooManyRequests, want: "maximum number"},
		{body: `{"language":"python","code":"x"}`, err: ErrStreamingUnsupported, status: http.StatusNotImplemented, want: "not supported"},
		{body: `{"language":"python","code":"x"}`, err: errors.New("resolve failed"), status: http.StatusInternalServerError, want: "resolve failed"},
	}
	for _, tc := range cases {
		rec := codeRun(t, &fakeProcs{startErr: tc.err}, tc.body)
		if rec.Code != tc.status || !strings.Contains(rec.Body.String(), tc.want) {
			t.Fatalf("%s: %d %s, want %d containing %q", tc.body, rec.Code, rec.Body.String(), tc.status, tc.want)
		}
	}
}

func TestCodeRunCollectsOutput(t *testing.T) {
	procs := &fakeProcs{}
	run, done := codeRunAsync(t, procs, `{"language":"python","code":"print(1 + 2)","argv":["a b"],"envs":{"K":"v"},"timeout":7}`)
	run.events <- ProcessEvent{Stdout: []byte("3")}
	run.events <- ProcessEvent{Stdout: []byte("\n"), Stderr: []byte("warn")}
	run.events <- ProcessEvent{Exit: &ProcessExit{ExitCode: 0}}
	resp := decodeCodeRun(t, <-done)
	if resp.ExitCode != 0 || resp.Result != "3\n" {
		t.Fatalf("response = %+v", resp)
	}
	spec := procs.codeRuns[0]
	if spec.Language != "python" || spec.Code != "print(1 + 2)" || spec.Argv[0] != "a b" || spec.Env["K"] != "v" ||
		spec.Timeout != 7*time.Second || spec.MaxOutputBytes != codeRunMaxOutput {
		t.Fatalf("spec = %+v", spec)
	}
	run.waitClosed(t)
}

func TestCodeRunReportsFailures(t *testing.T) {
	cases := []struct {
		name   string
		body   string
		stderr string
		exit   ProcessExit
		code   int
		result string
	}{
		{"stderr when no stdout", `{"language":"py","code":"x"}`, "Traceback\n", ProcessExit{ExitCode: 1}, 1, "Traceback\n"},
		{"timed out", `{"language":"py","code":"x","timeout":2}`, "partial", ProcessExit{ExitCode: -1, TimedOut: true}, -1, "partial\ncode-run timed out after 2s"},
		{"timed out on the default", `{"language":"py","code":"x"}`, "", ProcessExit{ExitCode: -1, TimedOut: true}, -1, "code-run timed out after the wasm wall timeout"},
		{"killed", `{"language":"py","code":"x"}`, "", ProcessExit{ExitCode: -1, Killed: true}, -1, "code-run was killed"},
		{"trap", `{"language":"py","code":"x"}`, "", ProcessExit{ExitCode: 1, Error: "wasm error: out of memory"}, 1, "wasm error: out of memory"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			procs := &fakeProcs{}
			run, done := codeRunAsync(t, procs, tc.body)
			if tc.stderr != "" {
				run.events <- ProcessEvent{Stderr: []byte(tc.stderr)}
			}
			exit := tc.exit
			run.events <- ProcessEvent{Exit: &exit}
			resp := decodeCodeRun(t, <-done)
			if resp.ExitCode != tc.code || resp.Result != tc.result {
				t.Fatalf("response = %+v, want %d %q", resp, tc.code, tc.result)
			}
		})
	}
}

func TestCodeRunStreamErrorAndClientGone(t *testing.T) {
	procs := &fakeProcs{}
	run, done := codeRunAsync(t, procs, `{"language":"py","code":"x"}`)
	run.errs <- errors.New("worker gone")
	if rec := <-done; rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "worker gone") {
		t.Fatalf("recv error = %d %s", rec.Code, rec.Body.String())
	}

	// A caller that goes away kills its run.
	procs = &fakeProcs{}
	ctx, cancel := context.WithCancel(context.Background())
	h := New(Config{SandboxID: "sb", WorkDir: t.TempDir(), Procs: procs})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/process/code-run", strings.NewReader(`{"language":"py","code":"x"}`)).WithContext(ctx)
	finished := make(chan struct{})
	go func() {
		h.Handler().ServeHTTP(rec, req)
		close(finished)
	}()
	run = procs.run(t, 0)
	cancel()
	<-finished
	run.waitClosed(t)
	if _, _, kills := run.snapshot(); kills != 1 {
		t.Fatalf("kills = %d", kills)
	}
}

func TestJoinLines(t *testing.T) {
	if joinLines("", "b") != "b" || joinLines("a", "b") != "a\nb" || joinLines("a\n", "b") != "a\nb" {
		t.Fatal("joinLines")
	}
}
