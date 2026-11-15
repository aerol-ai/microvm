package types

import "sort"

// CodeContext is one code interpreter context: a long-lived interpreter
// process in the sandbox that keeps its variables between runs. The JSON
// names are the agent's (camelCase, Daytona's wire shape).
type CodeContext struct {
	ID       string `json:"id"`
	Language string `json:"language"`
	Cwd      string `json:"cwd"`
	// CreatedAt is the agent's timestamp, kept as the string it sent.
	CreatedAt string `json:"createdAt"`
	// Active is false after the context's process died or a run timed out;
	// the next run starts a fresh process (its variables are gone).
	Active bool `json:"active"`
}

// CodeContextOptions are the options of CreateCodeContext. Both are
// optional: the language defaults to python and cwd to the sandbox's
// working folder.
type CodeContextOptions struct {
	Language string `json:"language,omitempty"`
	Cwd      string `json:"cwd,omitempty"`
}

// RunCodeOptions are the options of RunCode.
type RunCodeOptions struct {
	// ContextID runs the code in this context. Empty runs it in the default
	// context of Language (python when Language is empty too). Set
	// ContextID or Language, not both.
	ContextID string
	// Language picks the default context of a language ("python",
	// "javascript", "typescript", "bash", "r", "java").
	Language string
	// Envs are set for this run only.
	Envs map[string]string
	// TimeoutSeconds stops the run after this many seconds. nil keeps the
	// agent's default (600 s); a pointer to 0 means no timeout. A run that
	// times out returns a *CodeRunError matching ErrCodeRunTimeout, and its
	// context loses its variables.
	TimeoutSeconds *int
	// OnStdout and OnStderr get output as it arrives, OnResult each rich
	// result and OnError the code's exception. They run on the goroutine
	// reading the stream, in order; a slow callback slows the stream.
	OnStdout func(text string)
	OnStderr func(text string)
	OnResult func(result CodeResult)
	OnError  func(err ExecutionError)
}

// CodeResult is one rich result of a run: the value of the last expression,
// or something the code displayed (a chart, a table). Each field holds one
// format of the same value; an empty field means that format is absent.
type CodeResult struct {
	Text     string `json:"text,omitempty"`
	HTML     string `json:"html,omitempty"`
	Markdown string `json:"markdown,omitempty"`
	SVG      string `json:"svg,omitempty"`
	// PNG, JPEG and PDF are base64, as the agent sent them.
	PNG        string         `json:"png,omitempty"`
	JPEG       string         `json:"jpeg,omitempty"`
	PDF        string         `json:"pdf,omitempty"`
	LaTeX      string         `json:"latex,omitempty"`
	JSON       map[string]any `json:"json,omitempty"`
	JavaScript string         `json:"javascript,omitempty"`
	// Data is a table's data (a pandas DataFrame) as an object.
	Data map[string]any `json:"data,omitempty"`
	// Extra holds formats the fields above do not name, by MIME type.
	Extra map[string]any `json:"extra,omitempty"`
	// IsMainResult is true for the value of the run's last expression.
	IsMainResult bool `json:"is_main_result"`
}

// Formats lists the formats this result carries: text, html, markdown,
// svg, png, jpeg, pdf, latex, json, javascript, data (in that order), then
// the keys of Extra, sorted.
func (r CodeResult) Formats() []string {
	var out []string
	for _, f := range []struct {
		name    string
		present bool
	}{
		{"text", r.Text != ""},
		{"html", r.HTML != ""},
		{"markdown", r.Markdown != ""},
		{"svg", r.SVG != ""},
		{"png", r.PNG != ""},
		{"jpeg", r.JPEG != ""},
		{"pdf", r.PDF != ""},
		{"latex", r.LaTeX != ""},
		{"json", r.JSON != nil},
		{"javascript", r.JavaScript != ""},
		{"data", r.Data != nil},
	} {
		if f.present {
			out = append(out, f.name)
		}
	}
	extra := make([]string, 0, len(r.Extra))
	for key := range r.Extra {
		extra = append(extra, key)
	}
	sort.Strings(extra)
	return append(out, extra...)
}

// ExecutionError is the exception the code raised. It is part of a
// successful run, not an SDK error: RunCode still returns a nil error.
type ExecutionError struct {
	Name      string `json:"name"`
	Value     string `json:"value"`
	Traceback string `json:"traceback"`
}

// ExecutionLogs is a run's output, chunk by chunk as it arrived.
type ExecutionLogs struct {
	Stdout []string `json:"stdout"`
	Stderr []string `json:"stderr"`
}

// Execution is what one run produced.
type Execution struct {
	Results []CodeResult    `json:"results"`
	Logs    ExecutionLogs   `json:"logs"`
	Error   *ExecutionError `json:"error,omitempty"`
	// ExecutionCount is the context's run counter; nil when the agent sent
	// none.
	ExecutionCount *int `json:"executionCount,omitempty"`
	// Interrupted is true when the run was stopped by an interrupt
	// (a cancelled ctx) rather than finishing.
	Interrupted bool `json:"interrupted"`
}

// Text is the text of the main result (the value of the last expression),
// or "" when there is none.
func (e *Execution) Text() string {
	if e == nil {
		return ""
	}
	for _, r := range e.Results {
		if r.IsMainResult {
			return r.Text
		}
	}
	return ""
}
