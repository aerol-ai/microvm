package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// fakeAPI is an in-memory AerolVM: creates sleep createDelay, then make a
// sandbox; hooks shape failures.
type fakeAPI struct {
	mu          sync.Mutex
	live        map[string]sdktypes.CreateSandboxOptions
	seq         int
	createDelay time.Duration
	creates     int
	deletes     int
	maxLive     int
	// createErr, when set, decides each create's outcome: (made, err).
	// made=true makes the sandbox even when err is set: an answer lost.
	createErr func(n int) (bool, error)
	// blockCreates holds every create until its ctx ends; the sandbox is
	// made on the server all the same.
	blockCreates bool
	destroyErr   func(id string, n int) error
	destroyHold  chan struct{} // set: every destroy waits on it
	listErr      error
	opts         []sdktypes.CreateSandboxOptions
}

func newFakeAPI() *fakeAPI { return &fakeAPI{live: map[string]sdktypes.CreateSandboxOptions{}} }

func (f *fakeAPI) Create(ctx context.Context, opts sdktypes.CreateSandboxOptions) (created, error) {
	f.mu.Lock()
	f.creates++
	n := f.creates
	f.opts = append(f.opts, opts)
	f.mu.Unlock()
	mk := func() string {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.seq++
		id := fmt.Sprintf("sb-%d", f.seq)
		f.live[id] = opts
		if len(f.live) > f.maxLive {
			f.maxLive = len(f.live)
		}
		return id
	}
	if f.blockCreates {
		mk()
		<-ctx.Done()
		return created{}, ctx.Err()
	}
	select {
	case <-time.After(f.createDelay):
	case <-ctx.Done():
		return created{}, ctx.Err()
	}
	if f.createErr != nil {
		if made, err := f.createErr(n); err != nil {
			if made {
				mk()
			}
			return created{}, err
		}
	}
	return created{ID: mk(), Status: string(models.SandboxStatusStarted)}, nil
}

func (f *fakeAPI) Destroy(ctx context.Context, id string) error {
	if f.destroyHold != nil {
		select {
		case <-f.destroyHold:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deletes++
	if f.destroyErr != nil {
		if err := f.destroyErr(id, f.deletes); err != nil {
			return err
		}
	}
	delete(f.live, id)
	return nil
}

func (f *fakeAPI) ListRun(_ context.Context, runID string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	var ids []string
	for id, o := range f.live {
		if o.Tags[runTagKey] == runID {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

func (f *fakeAPI) liveCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.live)
}

func testConfig(mut func(*config)) config {
	cfg := config{token: "t", concurrency: 3, duration: 150 * time.Millisecond, image: "alpine:3.20",
		maxAge: time.Hour, createTimeout: time.Minute, runID: "testrun"}
	if mut != nil {
		mut(&cfg)
	}
	return cfg
}

func runFake(t *testing.T, api *fakeAPI, cfg config) *report {
	t.Helper()
	stop, cancel := context.WithTimeout(context.Background(), cfg.duration)
	defer cancel()
	return newBench(api, cfg, io.Discard).run(stop, context.Background())
}

func TestBenchCreatesThenDeletesEverySandbox(t *testing.T) {
	api := newFakeAPI()
	api.createDelay = 5 * time.Millisecond
	rep := runFake(t, api, testConfig(nil))
	if rep.Creates.Succeeded == 0 || rep.Creates.Failed != 0 {
		t.Fatalf("creates = %+v", rep.Creates)
	}
	l := rep.CreateLatencyMs
	if l.Samples != rep.Creates.Succeeded || l.P50 < 5 || l.P50 > l.P90 || l.P90 > l.P99 || l.P99 > l.Max {
		t.Fatalf("create latency = %+v", l)
	}
	if rep.CreatesPerSecond <= 0 || rep.ElapsedSeconds <= 0 {
		t.Fatalf("rate %v over %v s", rep.CreatesPerSecond, rep.ElapsedSeconds)
	}
	if rep.LeftBehind != 0 || api.liveCount() != 0 || rep.DeleteLatencyMs.Samples != rep.Creates.Succeeded || rep.exitCode() != exitOK {
		t.Fatalf("left %d (fake holds %d), %d deletes for %d creates", rep.LeftBehind, api.liveCount(), rep.DeleteLatencyMs.Samples, rep.Creates.Succeeded)
	}
	// Deleted as they were made: never many more alive than workers plus
	// the delete queue.
	if api.maxLive > 3+4*3+3 {
		t.Fatalf("up to %d sandboxes alive at once with deletes running", api.maxLive)
	}
	for i, o := range api.opts {
		if !strings.HasPrefix(o.Name, "bench-testrun-") || o.Tags[runTagKey] != "testrun" || o.Image != "alpine:3.20" ||
			o.Lifecycle == nil || o.Lifecycle.DestroyAtAge != time.Hour {
			t.Fatalf("create %d options = %+v", i, o)
		}
	}
}

func TestBenchHoldDeletesAtTheEnd(t *testing.T) {
	api := newFakeAPI()
	api.createDelay = 2 * time.Millisecond
	rep := runFake(t, api, testConfig(func(c *config) { c.hold = true; c.maxAge = 0; c.runtime = "gvisor" }))
	if api.maxLive != rep.Creates.Succeeded || rep.LeftBehind != 0 || api.liveCount() != 0 {
		t.Fatalf("held %d of %d, left %d", api.maxLive, rep.Creates.Succeeded, rep.LeftBehind)
	}
	if o := api.opts[0]; o.Lifecycle != nil || o.Runtime != "gvisor" {
		t.Fatalf("options = %+v, want no lifecycle with -max-age 0 and the runtime set", o)
	}
}

func TestBenchCountsFailuresAndCleansUpLostAnswers(t *testing.T) {
	api := newFakeAPI()
	api.createDelay = time.Millisecond
	api.createErr = func(n int) (bool, error) {
		switch n % 4 {
		case 1:
			return false, &microvm.APIError{StatusCode: http.StatusServiceUnavailable, Code: "capacity_exhausted", Message: "no room"}
		case 2:
			// The server made it; the answer never came.
			return true, fmt.Errorf("post: %w", context.DeadlineExceeded)
		}
		return false, nil
	}
	rep := runFake(t, api, testConfig(nil))
	byKind := map[string]int{}
	for _, e := range rep.Errors {
		byKind[e.Kind] = e.Count
		if e.Example == "" {
			t.Fatalf("error %q has no example", e.Kind)
		}
	}
	if byKind["HTTP 503 capacity_exhausted"] == 0 || byKind["timeout"] == 0 || rep.Creates.Failed != byKind["HTTP 503 capacity_exhausted"]+byKind["timeout"] {
		t.Fatalf("errors = %+v, failed %d", rep.Errors, rep.Creates.Failed)
	}
	if rep.Unsure != byKind["timeout"] {
		t.Fatalf("unsure = %d, want the %d unanswered creates", rep.Unsure, byKind["timeout"])
	}
	// The sweep by tag found the sandboxes whose answer was lost.
	if rep.LeftBehind != 0 || api.liveCount() != 0 {
		t.Fatalf("left %d, fake holds %d", rep.LeftBehind, api.liveCount())
	}
}

func TestBenchRetriesAFailedDeleteInCleanup(t *testing.T) {
	api := newFakeAPI()
	api.createDelay = time.Millisecond
	api.destroyErr = func(_ string, n int) error {
		if n == 1 {
			return errors.New("connection reset")
		}
		return nil
	}
	rep := runFake(t, api, testConfig(nil))
	if rep.DeleteFailures != 1 || rep.LeftBehind != 0 || api.liveCount() != 0 {
		t.Fatalf("delete failures %d, left %d, fake holds %d", rep.DeleteFailures, rep.LeftBehind, api.liveCount())
	}
}

func TestBenchReportsAFailedCheck(t *testing.T) {
	api := newFakeAPI()
	api.listErr = errors.New("503")
	var log bytes.Buffer
	stop, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	rep := newBench(api, testConfig(nil), &log).run(stop, context.Background())
	if rep.LeftBehind != -1 || rep.exitCode() != exitFailed || !strings.Contains(log.String(), "-cleanup testrun") {
		t.Fatalf("left %d, exit %d, log %q", rep.LeftBehind, rep.exitCode(), log.String())
	}
}

// A server that refuses everything at once is not flooded: each worker
// pauses after a failed create.
func TestBenchEveryCreateFailing(t *testing.T) {
	old := failurePause
	failurePause = 50 * time.Millisecond
	t.Cleanup(func() { failurePause = old })
	api := newFakeAPI()
	api.createErr = func(int) (bool, error) { return false, errors.New("dial tcp: connection refused") }
	rep := runFake(t, api, testConfig(func(c *config) { c.duration = 200 * time.Millisecond; c.concurrency = 2 }))
	if rep.Creates.Succeeded != 0 || rep.exitCode() != exitFailed || rep.Errors[0].Kind != "network" || rep.CreatesPerSecond != 0 {
		t.Fatalf("report = %+v", rep)
	}
	// 2 workers, 200 ms, a 50 ms pause after each failure: about 8.
	if rep.Creates.Failed < 2 || rep.Creates.Failed > 14 {
		t.Fatalf("%d failed creates in 200 ms from 2 workers, want about 8", rep.Creates.Failed)
	}
}

func TestSummarize(t *testing.T) {
	msList := func(from, to, step int) []time.Duration {
		var out []time.Duration
		for i := from; i != to+step; i += step {
			out = append(out, time.Duration(i)*time.Millisecond)
		}
		return out
	}
	cases := []struct {
		name string
		in   []time.Duration
		want latency
	}{
		{name: "none", want: latency{}},
		{name: "one", in: []time.Duration{1500 * time.Microsecond}, want: latency{Samples: 1, P50: 1.5, P90: 1.5, P99: 1.5, Max: 1.5, Mean: 1.5}},
		// Unsorted input; nearest rank picks real samples.
		{name: "100 down to 1 ms", in: msList(100, 1, -1), want: latency{Samples: 100, P50: 50, P90: 90, P99: 99, Max: 100, Mean: 50.5}},
		// With 10 samples p99 is the slowest one.
		{name: "10 to 100 ms", in: msList(10, 100, 10), want: latency{Samples: 10, P50: 50, P90: 90, P99: 100, Max: 100, Mean: 55}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := summarize(tc.in); got != tc.want {
				t.Fatalf("summarize = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestErrorKind(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{&microvm.APIError{StatusCode: 503, Code: "capacity_exhausted"}, "HTTP 503 capacity_exhausted"},
		{fmt.Errorf("wrapped: %w", &microvm.APIError{StatusCode: 429}), "HTTP 429"},
		{fmt.Errorf("post: %w", context.DeadlineExceeded), "timeout"},
		{errors.New("connection reset by peer"), "network"},
	}
	for _, tc := range cases {
		if got := errorKind(tc.err); got != tc.want {
			t.Errorf("errorKind(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}

func TestParseFlags(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		env     map[string]string
		wantErr string
		check   func(t *testing.T, c config)
	}{
		{name: "defaults", args: []string{"-token", "tok"}, check: func(t *testing.T, c config) {
			if c.concurrency != 4 || c.duration != 30*time.Second || c.image != "alpine:3.20" || c.runtime != "" || c.hold || c.json {
				t.Fatalf("defaults = %+v", c)
			}
			if c.maxAge != 30*time.Second+5*time.Minute+maxAgeSlack {
				t.Fatalf("max age = %v, want the run plus the create timeout plus slack", c.maxAge)
			}
			if !runIDPattern.MatchString(c.runID) {
				t.Fatalf("run id %q", c.runID)
			}
		}},
		{name: "token and URL from the environment", env: map[string]string{"SB_API_TOKEN": "fromenv", "SB_API_URL": "https://api.test"}, check: func(t *testing.T, c config) {
			if c.token != "fromenv" || c.apiURL != "https://api.test" {
				t.Fatalf("token %q url %q", c.token, c.apiURL)
			}
		}},
		{name: "every flag", args: []string{"-token", "t", "-api", "https://x", "-concurrency", "16", "-duration", "2m", "-image", "python:3.12", "-runtime", "firecracker", "-template", "py312",
			"-hold", "-max-age", "0s", "-create-timeout", "30s", "-json", "-run-id", "night-1"}, check: func(t *testing.T, c config) {
			want := config{apiURL: "https://x", token: "t", concurrency: 16, duration: 2 * time.Minute, image: "python:3.12", runtime: "firecracker", template: "py312",
				hold: true, maxAge: 0, createTimeout: 30 * time.Second, json: true, runID: "night-1"}
			if c != want {
				t.Fatalf("config = %+v, want %+v", c, want)
			}
		}},
		{name: "cleanup", args: []string{"-token", "t", "-cleanup", "abc123"}, check: func(t *testing.T, c config) {
			if c.cleanupRun != "abc123" {
				t.Fatalf("cleanup = %q", c.cleanupRun)
			}
		}},
		{name: "no token", wantErr: "token is required"},
		{name: "concurrency 0", args: []string{"-token", "t", "-concurrency", "0"}, wantErr: "-concurrency"},
		{name: "concurrency too high", args: []string{"-token", "t", "-concurrency", "1001"}, wantErr: "-concurrency"},
		{name: "no duration", args: []string{"-token", "t", "-duration", "0s"}, wantErr: "-duration"},
		{name: "no create timeout", args: []string{"-token", "t", "-create-timeout", "0s"}, wantErr: "-create-timeout"},
		{name: "negative max age", args: []string{"-token", "t", "-max-age", "-1s"}, wantErr: "-max-age"},
		{name: "no image", args: []string{"-token", "t", "-image", " "}, wantErr: "-image"},
		{name: "bad run id", args: []string{"-token", "t", "-run-id", "Bad Id"}, wantErr: "-run-id"},
		{name: "bad cleanup id", args: []string{"-token", "t", "-cleanup", "../x"}, wantErr: "-cleanup"},
		{name: "extra argument", args: []string{"-token", "t", "now"}, wantErr: "unexpected arguments"},
		{name: "unknown flag", args: []string{"-nope"}, wantErr: "not defined"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, k := range []string{"SB_API_URL", "SB_PAT_TOKEN", "SB_API_TOKEN"} {
				t.Setenv(k, tc.env[k])
			}
			cfg, err := parseFlags(tc.args, io.Discard)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			tc.check(t, cfg)
		})
	}
	if _, err := parseFlags([]string{"-h"}, io.Discard); !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("-h = %v", err)
	}
}

// runWith runs the command against api and returns its exit code, stdout
// and stderr.
func runWith(t *testing.T, api sandboxAPI, signals chan os.Signal, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(append([]string{"-token", "t"}, args...), &stdout, &stderr, signals,
		func(string, string) (sandboxAPI, error) { return api, nil })
	return code, stdout.String(), stderr.String()
}

func TestRunPrintsTheReport(t *testing.T) {
	api := newFakeAPI()
	api.createDelay = time.Millisecond
	code, out, _ := runWith(t, api, make(chan os.Signal), "-duration", "100ms", "-json", "-run-id", "r1")
	var rep report
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("stdout is not the JSON report: %v\n%s", err, out)
	}
	if code != exitOK || rep.RunID != "r1" || rep.Creates.Succeeded == 0 || rep.LeftBehind != 0 || rep.Interrupted {
		t.Fatalf("exit %d, report %+v", code, rep)
	}

	code, out, _ = runWith(t, newFakeAPI(), make(chan os.Signal), "-duration", "50ms", "-hold", "-run-id", "r2")
	for _, want := range []string{"run r2:", "the server's default", "held to the end", "creates:", "create latency: p50", "errors: none", "left behind: 0 sandboxes"} {
		if !strings.Contains(out, want) {
			t.Fatalf("text report lacks %q:\n%s", want, out)
		}
	}
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
}

func TestReportTextNamesProblems(t *testing.T) {
	r := &report{RunID: "x", Image: "i", Runtime: "docker", Duration: "1s", Interrupted: true,
		Creates:        counts{Succeeded: 1, Failed: 2, NotStarted: 1, Abandoned: 3},
		Errors:         []kind{{Kind: "HTTP 503", Count: 2, Example: "busy"}},
		DeleteFailures: 1, LeftBehind: -1, Unsure: 3}
	var b bytes.Buffer
	if err := r.write(&b, false); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"runtime docker", "deleted as they were made", "(interrupted)", "no samples", "not started when answered: 1",
		"abandoned in flight: 3", "error HTTP 503 x2, e.g. busy", "delete failures (retried in cleanup): 1", "left behind: unknown", "3 creates never answered"} {
		if !strings.Contains(b.String(), want) {
			t.Fatalf("report lacks %q:\n%s", want, b.String())
		}
	}
	if truncate(strings.Repeat("a", 300), 200) != strings.Repeat("a", 200)+"..." {
		t.Fatal("truncate")
	}
}

// The first interrupt stops new creates, lets the ones in flight answer,
// and deletes every sandbox the run made.
func TestRunFirstInterruptCleansUp(t *testing.T) {
	api := newFakeAPI()
	api.createDelay = 20 * time.Millisecond
	signals := make(chan os.Signal, 1)
	go func() {
		for {
			api.mu.Lock()
			n := api.creates
			api.mu.Unlock()
			if n >= 6 {
				signals <- os.Interrupt
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()
	start := time.Now()
	code, out, errOut := runWith(t, api, signals, "-duration", "1h", "-json", "-run-id", "int1")
	var rep report
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if time.Since(start) > 30*time.Second || !rep.Interrupted || code != exitOK || rep.LeftBehind != 0 || api.liveCount() != 0 || rep.Creates.Abandoned != 0 {
		t.Fatalf("exit %d after %v, report %+v, fake holds %d", code, time.Since(start), rep, api.liveCount())
	}
	if !strings.Contains(errOut, "interrupt again to stop waiting") {
		t.Fatalf("stderr = %q", errOut)
	}
}

// The second interrupt stops waiting for creates in flight; cleanup still
// finds and deletes the sandboxes the server made for them.
func TestRunSecondInterruptAbandonsCreatesButCleansUp(t *testing.T) {
	api := newFakeAPI()
	api.blockCreates = true
	signals := make(chan os.Signal, 2)
	go func() {
		for api.liveCount() < 3 {
			time.Sleep(time.Millisecond)
		}
		signals <- os.Interrupt
		signals <- os.Interrupt
	}()
	code, out, errOut := runWith(t, api, signals, "-duration", "1h", "-concurrency", "3", "-json", "-run-id", "int2")
	var rep report
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if rep.Creates.Abandoned != 3 || rep.Unsure != 3 || rep.Creates.Failed != 0 || rep.LeftBehind != 0 || api.liveCount() != 0 {
		t.Fatalf("report %+v, fake holds %d", rep, api.liveCount())
	}
	// Nothing succeeded, so the run is a failure, but nothing was left.
	if code != exitFailed || !strings.Contains(errOut, "no longer waiting") {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
}

// The third interrupt leaves at once and says how to finish the cleanup.
func TestRunThirdInterruptLeaves(t *testing.T) {
	api := newFakeAPI()
	api.createDelay = time.Millisecond
	api.destroyHold = make(chan struct{})
	defer close(api.destroyHold)
	signals := make(chan os.Signal, 3)
	go func() {
		for api.liveCount() < 2 {
			time.Sleep(time.Millisecond)
		}
		signals <- os.Interrupt
		signals <- os.Interrupt
		signals <- os.Interrupt
	}()
	code, _, errOut := runWith(t, api, signals, "-duration", "1h", "-run-id", "int3")
	if code != exitAbandoned || !strings.Contains(errOut, "aerolvm-bench -cleanup int3") {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
}

func TestRunCleanupMode(t *testing.T) {
	api := newFakeAPI()
	for _, run := range []string{"old1", "old1", "other"} {
		api.live["id-"+fmt.Sprint(len(api.live))] = sdktypes.CreateSandboxOptions{Tags: map[string]string{runTagKey: run}}
	}
	code, out, _ := runWith(t, api, nil, "-cleanup", "old1")
	if code != exitOK || !strings.Contains(out, "deleted 2 sandboxes of run old1; 0 left") || api.liveCount() != 1 {
		t.Fatalf("exit %d, %q, fake holds %d", code, out, api.liveCount())
	}

	api.destroyErr = func(string, int) error { return errors.New("no") }
	if code, _, _ := runWith(t, api, nil, "-cleanup", "other"); code != exitFailed {
		t.Fatalf("a cleanup that left one exited %d", code)
	}
	api.listErr = errors.New("down")
	if code, _, errOut := runWith(t, api, nil, "-cleanup", "other"); code != exitFailed || !strings.Contains(errOut, "down") {
		t.Fatalf("a cleanup that could not list exited %d: %q", code, errOut)
	}
}

func TestRunUsageErrors(t *testing.T) {
	var stderr bytes.Buffer
	if code := run([]string{"-token", "t", "-concurrency", "0"}, io.Discard, &stderr, nil, nil); code != exitUsage {
		t.Fatalf("bad flag exited %d", code)
	}
	if code := run([]string{"-h"}, io.Discard, &stderr, nil, nil); code != exitOK {
		t.Fatalf("-h exited %d", code)
	}
	failing := func(string, string) (sandboxAPI, error) { return nil, errors.New("bad url") }
	if code := run([]string{"-token", "t"}, io.Discard, &stderr, nil, failing); code != exitUsage || !strings.Contains(stderr.String(), "bad url") {
		t.Fatalf("client error exited %d: %q", code, stderr.String())
	}
}

// sdkAPI against a fake AerolVM HTTP API: what the tool sends, and that a
// list feeding deletes trusts only rows that carry the run's tag and name.
func TestSDKAPI(t *testing.T) {
	var creates atomic.Int64
	var gotCreate models.CreateSandboxRequest
	var gotIdemKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/sandboxes":
			if creates.Add(1) == 2 {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = io.WriteString(w, `{"error":"busy","code":"capacity_exhausted"}`)
				return
			}
			_ = json.NewDecoder(r.Body).Decode(&gotCreate)
			gotIdemKey = r.Header.Get("Idempotency-Key")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(models.Sandbox{ID: "sb-1", Name: gotCreate.Name, Status: models.SandboxStatusStarted})
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/sandboxes/sb-gone":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"error":"not found"}`)
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/sandboxes/sb-broken":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":"refused"}`)
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/sandboxes":
			if r.URL.Query().Get("tag."+runTagKey) != "run9" {
				t.Errorf("list query = %q, want the run's tag", r.URL.RawQuery)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]models.Sandbox{
				{ID: "mine", Name: "bench-run9-1", Tags: map[string]string{runTagKey: "run9"}},
				{ID: "foreign-untagged", Name: "bench-run9-2"},
				{ID: "foreign-named", Name: "prod-db", Tags: map[string]string{runTagKey: "run9"}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	api, err := newSDKAPI(srv.URL, "tok")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	opts := sdktypes.CreateSandboxOptions{Name: "bench-run9-1", Image: "alpine:3.20", Tags: map[string]string{runTagKey: "run9"},
		Lifecycle: &models.Lifecycle{DestroyAtAge: time.Hour}}
	c, err := api.Create(ctx, opts)
	if err != nil || c.ID != "sb-1" || c.Status != "started" {
		t.Fatalf("create = %+v, %v", c, err)
	}
	if gotCreate.Name != "bench-run9-1" || gotCreate.Tags[runTagKey] != "run9" || gotCreate.Lifecycle == nil || gotCreate.Lifecycle.DestroyAtAge != time.Hour || gotIdemKey == "" {
		t.Fatalf("server got %+v (idempotency key %q)", gotCreate, gotIdemKey)
	}
	// A refused create is sent once and reported, not retried.
	if _, err := api.Create(ctx, opts); errorKind(err) != "HTTP 503 capacity_exhausted" || creates.Load() != 2 {
		t.Fatalf("refused create = %v after %d sends", err, creates.Load())
	}
	if err := api.Destroy(ctx, "sb-1"); err != nil {
		t.Fatal(err)
	}
	if err := api.Destroy(ctx, "sb-gone"); err != nil {
		t.Fatalf("deleting a sandbox already gone = %v", err)
	}
	if err := api.Destroy(ctx, "sb-broken"); err == nil {
		t.Fatal("a refused delete reported success")
	}
	ids, err := api.ListRun(ctx, "run9")
	if err != nil || len(ids) != 1 || ids[0] != "mine" {
		t.Fatalf("ListRun = %v, %v; want only the tagged, named sandbox", ids, err)
	}

	bad, _ := newSDKAPI(srv.URL, "wrong")
	if _, err := bad.ListRun(ctx, "run9"); err == nil {
		t.Fatal("a list refused 401 reported no error")
	}
	t.Setenv("SB_PAT_TOKEN", "")
	t.Setenv("SB_API_TOKEN", "")
	if _, err := newSDKAPI(srv.URL, ""); err == nil {
		t.Fatal("a client with no token was made")
	}
}

// -template reaches every create, so a Firecracker run can measure the
// template path; the image and runtime ride along unchanged.
func TestBenchPassesTheTemplateToEveryCreate(t *testing.T) {
	api := newFakeAPI()
	runFake(t, api, testConfig(func(c *config) {
		c.runtime, c.image, c.template = "firecracker", "python:3.12", "py312"
	}))
	api.mu.Lock()
	defer api.mu.Unlock()
	if len(api.opts) == 0 {
		t.Fatal("no creates")
	}
	for _, o := range api.opts {
		if o.TemplateID != "py312" || o.Runtime != "firecracker" || o.Image != "python:3.12" {
			t.Fatalf("create options = %+v, want template py312 on firecracker from python:3.12", o)
		}
	}
}
