package e2b

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/aerol-ai/microvm/internal/codeinterp"
)

// KeepaliveInterval is how long /execute may go without writing before it
// sends a keepalive line, as E2B's server does. A write is the only way to
// notice a client that vanished without closing its connection, and the
// run is interrupted when the client goes.
const KeepaliveInterval = 5 * time.Second

// Synthesized errors. The names and texts are E2B's, so code that matches
// on them keeps working.
const (
	errNameRestarting = "ContextRestarting"
	errTextRestarting = "Context was restarted"
	errNameUnexpected = "UnexpectedEndOfExecution"
	errTextUnexpected = "Connection to the execution was closed before the execution was finished"
)

type countLine struct {
	Type           string `json:"type"`
	ExecutionCount int    `json:"execution_count"`
}

type outputLine struct {
	Type      string `json:"type"`
	Text      string `json:"text"`
	Timestamp string `json:"timestamp"`
}

type errorLine struct {
	Type      string `json:"type"`
	Name      string `json:"name"`
	Value     string `json:"value"`
	Traceback string `json:"traceback"`
}

// resultLine is E2B's result model with its nulls left out. Field order is
// E2B's; extra is always present because E2B's server always sends it.
type resultLine struct {
	Type         string         `json:"type"`
	Text         *string        `json:"text,omitempty"`
	HTML         *string        `json:"html,omitempty"`
	Markdown     *string        `json:"markdown,omitempty"`
	SVG          *string        `json:"svg,omitempty"`
	PNG          *string        `json:"png,omitempty"`
	JPEG         *string        `json:"jpeg,omitempty"`
	PDF          *string        `json:"pdf,omitempty"`
	LaTeX        *string        `json:"latex,omitempty"`
	JSON         any            `json:"json,omitempty"`
	JavaScript   *string        `json:"javascript,omitempty"`
	Data         any            `json:"data,omitempty"`
	Extra        map[string]any `json:"extra"`
	IsMainResult bool           `json:"is_main_result"`
}

var (
	keepaliveLine = []byte(`{"type":"keepalive"}` + "\n")
	endLine       = []byte(`{"type":"end_of_execution"}` + "\n")
)

// stringField returns the result field a string MIME type fills, or nil.
func (r *resultLine) stringField(mime string) **string {
	switch mime {
	case "text/plain":
		return &r.Text
	case "text/html":
		return &r.HTML
	case "text/markdown":
		return &r.Markdown
	case "image/svg+xml":
		return &r.SVG
	case "image/png":
		return &r.PNG
	case "image/jpeg":
		return &r.JPEG
	case "application/pdf":
		return &r.PDF
	case "text/latex":
		return &r.LaTeX
	case "application/javascript":
		return &r.JavaScript
	}
	return nil
}

func newResultLine(bundle map[string]any, main bool) resultLine {
	out := resultLine{Type: "result", Extra: map[string]any{}, IsMainResult: main}
	for mime, v := range bundle {
		switch mime {
		case "application/json":
			out.JSON = v
			continue
		case "e2b/data":
			out.Data = v
			continue
		}
		field := out.stringField(mime)
		s, ok := v.(string)
		if field == nil || !ok {
			// E2B keeps every MIME type it has no field for under extra.
			out.Extra[mime] = v
			continue
		}
		if mime == "text/plain" {
			s = stripQuotes(s)
		}
		*field = &s
	}
	return out
}

// stripQuotes drops one pair of matching surrounding quotes. E2B does it so
// a Python string's repr ('abc') reads as the string itself; a lone quote
// character becomes empty there too.
func stripQuotes(s string) string {
	if s == "" {
		return s
	}
	for _, q := range []byte{'\'', '"'} {
		if s[0] == q && s[len(s)-1] == q {
			if len(s) == 1 {
				return ""
			}
			return s[1 : len(s)-1]
		}
	}
	return s
}

// eventLine renders one kernel event as an NDJSON line.
func eventLine(ev codeinterp.Event, now time.Time) []byte {
	switch ev.Kind {
	case codeinterp.EventCount:
		return encodeLine(countLine{Type: "number_of_executions", ExecutionCount: ev.Count})
	case codeinterp.EventStdout, codeinterp.EventStderr:
		typ := "stdout"
		if ev.Kind == codeinterp.EventStderr {
			typ = "stderr"
		}
		return encodeLine(outputLine{Type: typ, Text: ev.Text, Timestamp: now.UTC().Format(time.RFC3339Nano)})
	case codeinterp.EventResult:
		return encodeLine(newResultLine(ev.Bundle, ev.Main))
	case codeinterp.EventError:
		return newErrorLine(ev.ErrName, ev.ErrValue, ev.ErrTraceback)
	}
	return nil
}

func newErrorLine(name, value, traceback string) []byte {
	return encodeLine(errorLine{Type: "error", Name: name, Value: value, Traceback: traceback})
}

// encodeLine marshals v followed by one newline. HTML stays unescaped so
// html and svg results are not inflated. Kernel values come from decoded
// JSON, so a failure means a launcher bug; the run still gets a line that
// says what went wrong instead of a silent gap.
func encodeLine(v any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		buf.Reset()
		_ = enc.Encode(errorLine{Type: "error", Name: "EncodingError", Value: err.Error()})
	}
	return buf.Bytes()
}

// stream is the single writer of an /execute response. The kernel's sink
// and the handler hand it lines; it writes and flushes each one, and sends
// a keepalive when nothing was written for a while.
type stream struct {
	w     io.Writer
	rc    *http.ResponseController
	every time.Duration
	lines chan []byte
	done  chan struct{}
}

func newStream(w http.ResponseWriter, every time.Duration) *stream {
	s := &stream{
		w:     w,
		rc:    http.NewResponseController(w),
		every: every,
		// A little slack so a burst of output does not wait on each write;
		// beyond it a slow client slows the kernel instead of growing memory.
		lines: make(chan []byte, 16),
		done:  make(chan struct{}),
	}
	go s.run()
	return s
}

// send queues one line. It blocks while the client is slow to read.
func (s *stream) send(line []byte) {
	if len(line) > 0 {
		s.lines <- line
	}
}

// close sends nothing more and waits until every queued line is written.
func (s *stream) close() {
	close(s.lines)
	<-s.done
}

func (s *stream) run() {
	defer close(s.done)
	t := time.NewTimer(s.every)
	defer t.Stop()
	broken := false
	write := func(line []byte) {
		if broken {
			return
		}
		if _, err := s.w.Write(line); err != nil {
			broken = true
			return
		}
		if err := s.rc.Flush(); err != nil && !errors.Is(err, http.ErrNotSupported) {
			broken = true
		}
	}
	for {
		select {
		case line, ok := <-s.lines:
			if !ok {
				return
			}
			// After the client went away the lines are still drained, so a
			// kernel blocked in its sink is never stuck; the cancelled
			// request has already interrupted it.
			write(line)
			t.Reset(s.every)
		case <-t.C:
			write(keepaliveLine)
			t.Reset(s.every)
		}
	}
}
