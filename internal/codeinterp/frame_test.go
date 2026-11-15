package codeinterp

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	frames := []struct {
		kind    string
		payload string
	}{
		{"READY", "1"},
		{"EXEC", "print('a')\nprint('b')\n"},
		{"QUIT", ""},
		{"ERROR", "ValueError\x1fbad\x1ftrace\nline"},
		{"OUT", "héllo ✓"},
	}
	for _, f := range frames {
		if err := WriteFrame(&buf, f.kind, []byte(f.payload)); err != nil {
			t.Fatal(err)
		}
	}
	r := NewFrameReader(&buf)
	for _, want := range frames {
		kind, payload, err := r.Read()
		if err != nil {
			t.Fatal(err)
		}
		if kind != want.kind || string(payload) != want.payload {
			t.Fatalf("got %q %q, want %q %q", kind, payload, want.kind, want.payload)
		}
	}
	if _, _, err := r.Read(); err != io.EOF {
		t.Fatalf("after last frame: %v, want EOF", err)
	}
}

func TestFrameReaderRejects(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want error
	}{
		{"no space", "READY\n", ErrBadFrame},
		{"lower case kind", "ready 1\n1", ErrBadFrame},
		{"empty kind", " 1\n1", ErrBadFrame},
		{"long kind", strings.Repeat("A", 17) + " 0\n", ErrBadFrame},
		{"bad length", "OUT x\n", ErrBadFrame},
		{"negative length", "OUT -1\n", ErrBadFrame},
		{"too large", "OUT 999999999999\n", ErrBadFrame},
		{"cut header", "OUT 3", io.ErrUnexpectedEOF},
		{"cut payload", "OUT 3\nab", io.ErrUnexpectedEOF},
		{"endless header", strings.Repeat("A", 200<<10), ErrBadFrame},
		{"no payload", "OUT 3\n", io.ErrUnexpectedEOF},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := NewFrameReader(strings.NewReader(tc.in)).Read()
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

type failWriter struct{ after int }

func (w *failWriter) Write(p []byte) (int, error) {
	if w.after <= 0 {
		return 0, errors.New("closed")
	}
	w.after--
	return len(p), nil
}

func TestWriteFrameErrors(t *testing.T) {
	if err := WriteFrame(&failWriter{after: 0}, "OUT", []byte("x")); err == nil {
		t.Fatal("header write error lost")
	}
	if err := WriteFrame(&failWriter{after: 1}, "OUT", []byte("x")); err == nil {
		t.Fatal("payload write error lost")
	}
}

func TestParseErrorPayload(t *testing.T) {
	cases := []struct {
		in                    string
		name, value, traceTxt string
	}{
		{"A\x1fB\x1fC", "A", "B", "C"},
		{"A\x1fB", "A", "B", ""},
		{"A", "A", "", ""},
		{"A\x1fB\x1fC\x1fD", "A", "B", "C\x1fD"},
	}
	for _, tc := range cases {
		n, v, tb := ParseErrorPayload([]byte(tc.in))
		if n != tc.name || v != tc.value || tb != tc.traceTxt {
			t.Fatalf("%q -> %q %q %q", tc.in, n, v, tb)
		}
	}
}

func TestNormalizeLanguage(t *testing.T) {
	cases := map[string]string{
		"": LangPython, " Python ": LangPython, "py": LangPython, "python3": LangPython,
		"js": LangJavaScript, "JavaScript": LangJavaScript, "node": LangJavaScript,
		"ts": LangTypeScript, "TYPESCRIPT": LangTypeScript,
		"r": LangR, "R": LangR, "java": LangJava, "bash": LangBash, "sh": LangBash,
	}
	for in, want := range cases {
		got, err := NormalizeLanguage(in)
		if err != nil || got != want {
			t.Fatalf("%q -> %q %v, want %q", in, got, err, want)
		}
	}
	if _, err := NormalizeLanguage("cobol"); !errors.Is(err, ErrUnsupportedLanguage) {
		t.Fatalf("cobol: %v", err)
	}
}

func TestMissingInterpreterError(t *testing.T) {
	e := &MissingInterpreterError{Language: "r", Programs: []string{"Rscript"}}
	if !strings.Contains(e.Error(), "Rscript") {
		t.Fatal(e.Error())
	}
	e.Detail = "install r-base"
	if !strings.Contains(e.Error(), "install r-base") {
		t.Fatal(e.Error())
	}
	if (Outcome{Status: "interrupted"}).Interrupted() != true {
		t.Fatal("Interrupted")
	}
}

func TestEventFromFrame(t *testing.T) {
	cases := []struct {
		kind, payload string
		want          Event
		ok            bool
	}{
		{kind: "COUNT", payload: "7", want: Event{Kind: EventCount, Count: 7}, ok: true},
		{kind: "COUNT", payload: "x"},
		{kind: "OUT", payload: "hi\n", want: Event{Kind: EventStdout, Text: "hi\n"}, ok: true},
		{kind: "ERR", payload: "oops", want: Event{Kind: EventStderr, Text: "oops"}, ok: true},
		{kind: "RESULT", payload: `{"data":{"text/plain":"5","application/json":{"n":12345678901234567890}},"main":true}`,
			want: Event{Kind: EventResult, Main: true, Bundle: map[string]any{
				"text/plain": "5", "application/json": map[string]any{"n": json.Number("12345678901234567890")},
			}}, ok: true},
		{kind: "RESULT", payload: `{"data":{}}`},
		{kind: "RESULT", payload: `not json`},
		{kind: "TEXT", payload: "'a'", want: Event{Kind: EventResult, Main: true, Bundle: map[string]any{"text/plain": "'a'"}}, ok: true},
		{kind: "ERROR", payload: "NameError\x1fname 'x' is not defined\x1fTraceback", want: Event{Kind: EventError,
			ErrName: "NameError", ErrValue: "name 'x' is not defined", ErrTraceback: "Traceback"}, ok: true},
		{kind: "READY", payload: "1"},
		{kind: "DONE", payload: "ok"},
		{kind: "SYNC", payload: "3"},
		{kind: "FUTURE", payload: "x"},
	}
	for _, tc := range cases {
		got, ok := EventFromFrame(tc.kind, []byte(tc.payload))
		if ok != tc.ok || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s %q = %+v %v, want %+v %v", tc.kind, tc.payload, got, ok, tc.want, tc.ok)
		}
	}
}
