package e2b

import (
	"errors"
	"math"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/codeinterp"
)

func TestStripQuotes(t *testing.T) {
	cases := []struct{ in, want string }{
		{"'abc'", "abc"},
		{`"abc"`, "abc"},
		{"''", ""},
		{"'", ""},
		{`"`, ""},
		{"", ""},
		{"abc", "abc"},
		{"'abc", "'abc"},
		{`'abc"`, `'abc"`},
		{"''a''", "'a'"}, // one pair only
		{"2", "2"},
	}
	for _, tc := range cases {
		if got := stripQuotes(tc.in); got != tc.want {
			t.Errorf("stripQuotes(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestResultLineMapping(t *testing.T) {
	cases := []struct {
		name   string
		bundle map[string]any
		main   bool
		want   string
	}{
		{
			name: "every E2B field",
			bundle: map[string]any{
				"text/plain": "'t'", "text/html": "<p>&</p>", "text/markdown": "# m", "image/svg+xml": "<svg/>",
				"image/png": "UE5H", "image/jpeg": "SlBH", "application/pdf": "UERG", "text/latex": "$x$",
				"application/json": map[string]any{"a": 1.0}, "application/javascript": "f()",
				"e2b/data": map[string]any{"col": []any{1.0, 2.0}},
			},
			main: true,
			want: `{"type":"result","text":"t","html":"<p>&</p>","markdown":"# m","svg":"<svg/>","png":"UE5H","jpeg":"SlBH","pdf":"UERG","latex":"$x$","json":{"a":1},"javascript":"f()","data":{"col":[1,2]},"extra":{},"is_main_result":true}`,
		},
		{
			name:   "unknown MIME types go to extra",
			bundle: map[string]any{"application/vnd.custom+json": map[string]any{"k": "v"}, "e2b/chart": map[string]any{"type": "line"}},
			want:   `{"type":"result","extra":{"application/vnd.custom+json":{"k":"v"},"e2b/chart":{"type":"line"}},"is_main_result":false}`,
		},
		{
			name:   "a non-string value for a string field goes to extra",
			bundle: map[string]any{"text/html": 5.0},
			want:   `{"type":"result","extra":{"text/html":5},"is_main_result":false}`,
		},
		{
			name:   "an empty text is kept, a null json is left out",
			bundle: map[string]any{"text/plain": "", "application/json": nil},
			main:   true,
			want:   `{"type":"result","text":"","extra":{},"is_main_result":true}`,
		},
		{
			name:   "an empty bundle",
			bundle: nil,
			want:   `{"type":"result","extra":{},"is_main_result":false}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := string(eventLine(codeinterp.Event{Kind: codeinterp.EventResult, Bundle: tc.bundle, Main: tc.main}, testNow))
			if got != tc.want+"\n" {
				t.Fatalf("got  %s\nwant %s", got, tc.want)
			}
		})
	}
}

func TestEventLineKinds(t *testing.T) {
	cases := []struct {
		ev   codeinterp.Event
		want string
	}{
		{codeinterp.Event{Kind: codeinterp.EventCount, Count: 7}, `{"type":"number_of_executions","execution_count":7}`},
		{codeinterp.Event{Kind: codeinterp.EventStdout, Text: "line\n"}, `{"type":"stdout","text":"line\n","timestamp":"` + testStamp + `"}`},
		{codeinterp.Event{Kind: codeinterp.EventStderr, Text: "<warn>"}, `{"type":"stderr","text":"<warn>","timestamp":"` + testStamp + `"}`},
		{codeinterp.Event{Kind: codeinterp.EventError, ErrName: "NameError"}, `{"type":"error","name":"NameError","value":"","traceback":""}`},
	}
	for _, tc := range cases {
		if got := string(eventLine(tc.ev, testNow.In(time.FixedZone("x", 3600)))); got != tc.want+"\n" {
			t.Errorf("got  %s\nwant %s", got, tc.want)
		}
	}
	if got := eventLine(codeinterp.Event{Kind: codeinterp.EventKind(99)}, testNow); got != nil {
		t.Fatalf("unknown kind rendered %q", got)
	}
}

func TestEncodeFailureStillWritesALine(t *testing.T) {
	got := string(eventLine(codeinterp.Event{Kind: codeinterp.EventResult, Bundle: map[string]any{"application/json": math.NaN()}}, testNow))
	if !strings.HasPrefix(got, `{"type":"error","name":"EncodingError","value":"json: unsupported value: NaN"`) || !strings.HasSuffix(got, "}\n") {
		t.Fatalf("got %q", got)
	}
}

// brokenWriter fails every write after the first n, like a client that
// hung up mid-stream.
type brokenWriter struct {
	mu     sync.Mutex
	header http.Header
	writes int
	okFor  int
	body   strings.Builder
}

func (w *brokenWriter) Header() http.Header {
	if w.header == nil {
		w.header = http.Header{}
	}
	return w.header
}
func (w *brokenWriter) WriteHeader(int) {}
func (w *brokenWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writes++
	if w.writes > w.okFor {
		return 0, errors.New("broken pipe")
	}
	return w.body.WriteString(string(p))
}

func (w *brokenWriter) snapshot() (int, string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.writes, w.body.String()
}

// After a write fails the stream stops writing but keeps draining, so a
// kernel blocked in its sink is never stuck behind a dead client. The
// writer here cannot flush, which must not count as a failure.
func TestStreamDrainsAfterAWriteFails(t *testing.T) {
	w := &brokenWriter{okFor: 1}
	s := newStream(w, time.Hour)
	for i := 0; i < 100; i++ {
		s.send([]byte("line\n"))
	}
	s.send(nil) // nothing to send
	s.close()
	writes, body := w.snapshot()
	if writes != 2 || body != "line\n" {
		t.Fatalf("writes = %d body = %q, want one good write, one failed, then silence", writes, body)
	}
}

func TestStreamKeepaliveResetsOnOutput(t *testing.T) {
	w := &brokenWriter{okFor: 1 << 30}
	s := newStream(w, 300*time.Millisecond)
	// Output more often than the interval holds keepalives back.
	for i := 0; i < 5; i++ {
		s.send([]byte("x\n"))
		time.Sleep(5 * time.Millisecond)
	}
	waitFor(t, "a keepalive", func() bool {
		_, body := w.snapshot()
		return strings.Contains(body, "keepalive")
	})
	s.close()
	_, body := w.snapshot()
	if !strings.HasPrefix(body, strings.Repeat("x\n", 5)) {
		t.Fatalf("body = %q, want the output before any keepalive", body)
	}
}
