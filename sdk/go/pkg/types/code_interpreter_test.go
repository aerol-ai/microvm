package types

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestCodeResultFormats(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		result CodeResult
		want   []string
	}{
		{"nothing", CodeResult{}, nil},
		{"every named format in order", CodeResult{
			Data: map[string]any{}, JavaScript: "j", JSON: map[string]any{}, LaTeX: "l", PDF: "p", JPEG: "j",
			PNG: "p", SVG: "s", Markdown: "m", HTML: "h", Text: "t",
		}, []string{"text", "html", "markdown", "svg", "png", "jpeg", "pdf", "latex", "json", "javascript", "data"}},
		{"extra keys sorted after", CodeResult{Text: "t", Extra: map[string]any{"b/x": 1, "a/y": 2}}, []string{"text", "a/y", "b/x"}},
	}
	for _, tc := range cases {
		if got := tc.result.Formats(); !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("%s: Formats() = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestExecutionText(t *testing.T) {
	t.Parallel()
	var none *Execution
	if none.Text() != "" {
		t.Fatal("nil execution has text")
	}
	exec := &Execution{Results: []CodeResult{{Text: "shown"}, {Text: "42", IsMainResult: true}}}
	if exec.Text() != "42" {
		t.Fatalf("Text() = %q, want the main result's", exec.Text())
	}
	if (&Execution{Results: []CodeResult{{Text: "shown"}}}).Text() != "" {
		t.Fatal("Text() without a main result")
	}
}

func TestCodeContextWireNames(t *testing.T) {
	t.Parallel()
	var got CodeContext
	if err := json.Unmarshal([]byte(`{"id":"c1","language":"python","cwd":"/w","createdAt":"2026-11-15T10:00:00Z","active":true}`), &got); err != nil {
		t.Fatal(err)
	}
	if got != (CodeContext{ID: "c1", Language: "python", Cwd: "/w", CreatedAt: "2026-11-15T10:00:00Z", Active: true}) {
		t.Fatalf("decoded %+v", got)
	}
	body, _ := json.Marshal(CodeContextOptions{Cwd: "/w"})
	if string(body) != `{"cwd":"/w"}` {
		t.Fatalf("options encode as %s", body)
	}
}
