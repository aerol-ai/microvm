package agenttools

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/aerol-ai/microvm/internal/agenttools/agenttoolstest"
	"github.com/aerol-ai/microvm/pkg/models"
)

func numberedLines(n int) string {
	var b strings.Builder
	for i := 1; i <= n; i++ {
		fmt.Fprintf(&b, "line %d\n", i)
	}
	return b.String()
}

func TestReadFileWindows(t *testing.T) {
	ctx := context.Background()
	tools, fake, _ := newTestTools(t, SourceCLI)
	box := fake.AddSandbox(models.Sandbox{Name: "box"})
	sb := resolveTarget(t, tools, "box")
	fake.PutFile(box.ID, "/work/big.txt", []byte(numberedLines(10000)))

	first, err := tools.ReadFile(ctx, sb, "/work/big.txt", 0, 0)
	if err != nil || first.StartLine != 1 || first.EndLine != DefaultReadLines || first.NextOffset != DefaultReadLines+1 {
		t.Fatalf("first window = %+v, %v", first, err)
	}
	if !strings.HasPrefix(first.Content, "line 1\n") || !strings.HasSuffix(first.Content, "line 2000\n") {
		t.Fatalf("first window content edges wrong")
	}
	// Continuation offsets walk the rest of the file with nothing lost.
	var total strings.Builder
	total.WriteString(first.Content)
	next := first.NextOffset
	for next != 0 {
		w, err := tools.ReadFile(ctx, sb, "/work/big.txt", next, 0)
		if err != nil {
			t.Fatal(err)
		}
		total.WriteString(w.Content)
		next = w.NextOffset
	}
	if total.String() != numberedLines(10000) {
		t.Fatal("continuation reads did not reassemble the file")
	}
	// A limit and an offset past the end.
	w, err := tools.ReadFile(ctx, sb, "/work/big.txt", 9999, 5)
	if err != nil || w.Content != "line 9999\nline 10000\n" || w.NextOffset != 0 || w.EndLine != 10000 {
		t.Fatalf("tail window = %+v, %v", w, err)
	}
	if w, err := tools.ReadFile(ctx, sb, "/work/big.txt", 20000, 0); err != nil || w.Content != "" || w.NextOffset != 0 {
		t.Fatalf("past EOF = %+v, %v", w, err)
	}
	if _, err := tools.ReadFile(ctx, sb, "/missing", 0, 0); !IsCode(err, CodeNotFound) || !strings.Contains(err.Error(), "/missing") {
		t.Fatalf("missing = %v", err)
	}
	if _, err := tools.ReadFile(ctx, sb, " ", 0, 0); !IsCode(err, CodeInvalidArgument) {
		t.Fatalf("blank path = %v", err)
	}
}

func TestReadFileByteWindowAndLongLines(t *testing.T) {
	ctx := context.Background()
	tools, fake, _ := newTestTools(t, SourceCLI)
	box := fake.AddSandbox(models.Sandbox{Name: "box"})
	sb := resolveTarget(t, tools, "box")

	// 100 lines of 4 KiB: the 256 KiB byte window stops before the line cap.
	wide := strings.Repeat(strings.Repeat("w", 4095)+"\n", 100)
	fake.PutFile(box.ID, "/wide.txt", []byte(wide))
	w, err := tools.ReadFile(ctx, sb, "/wide.txt", 0, 0)
	if err != nil || len(w.Content) > MaxReadBytes || w.EndLine != MaxReadBytes/4096 || w.NextOffset != w.EndLine+1 {
		t.Fatalf("byte window = end %d next %d len %d, %v", w.EndLine, w.NextOffset, len(w.Content), err)
	}
	// One line larger than the whole window is cut and skipped.
	huge := strings.Repeat("h", MaxReadBytes+100) + "\nafter\n"
	fake.PutFile(box.ID, "/huge.txt", []byte(huge))
	w, err = tools.ReadFile(ctx, sb, "/huge.txt", 0, 0)
	if err != nil || !w.LineTruncated || len(w.Content) != MaxReadBytes || w.NextOffset != 2 {
		t.Fatalf("huge line = truncated %v len %d next %d, %v", w.LineTruncated, len(w.Content), w.NextOffset, err)
	}
	if w, err := tools.ReadFile(ctx, sb, "/huge.txt", 2, 0); err != nil || w.Content != "after\n" {
		t.Fatalf("after huge line = %+v, %v", w, err)
	}
	// A line so long its newline is past the overflowing read: the rest of
	// the line is skipped, not the next line.
	longer := strings.Repeat("h", MaxReadBytes+200000) + "\nafter\n"
	fake.PutFile(box.ID, "/longer.txt", []byte(longer))
	if w, err := tools.ReadFile(ctx, sb, "/longer.txt", 0, 0); err != nil || !w.LineTruncated || w.NextOffset != 2 {
		t.Fatalf("longer line = truncated %v next %d, %v", w.LineTruncated, w.NextOffset, err)
	}
	if w, err := tools.ReadFile(ctx, sb, "/longer.txt", 2, 0); err != nil || w.Content != "after\n" {
		t.Fatalf("after longer line = %+v, %v", w, err)
	}
	// No trailing newline.
	fake.PutFile(box.ID, "/nonl.txt", []byte("a\nb"))
	if w, err := tools.ReadFile(ctx, sb, "/nonl.txt", 0, 0); err != nil || w.Content != "a\nb" || w.EndLine != 2 || w.NextOffset != 0 {
		t.Fatalf("no trailing newline = %+v, %v", w, err)
	}
}

func TestReadFileRefusesBinary(t *testing.T) {
	ctx := context.Background()
	tools, fake, _ := newTestTools(t, SourceCLI)
	box := fake.AddSandbox(models.Sandbox{Name: "box"})
	sb := resolveTarget(t, tools, "box")
	png := append([]byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"), make([]byte, 3000)...)
	fake.PutFile(box.ID, "/img.png", png)
	_, err := tools.ReadFile(ctx, sb, "/img.png", 0, 0)
	e := Classify(err)
	if e.Code != CodeBinaryFile || !strings.Contains(e.Message, "image/png") || !strings.Contains(e.Message, "KiB") || !strings.Contains(e.Hint, "xxd") {
		t.Fatalf("binary = %+v", e)
	}
	fake.PutFile(box.ID, "/latin1.txt", []byte("caf\xe9 au lait\n"))
	if _, err := tools.ReadFile(ctx, sb, "/latin1.txt", 0, 0); !IsCode(err, CodeBinaryFile) {
		t.Fatalf("invalid UTF-8 = %v", err)
	}
	// WASM has no /files/info: the refusal still names the type.
	wasm := fake.AddSandbox(models.Sandbox{Name: "wasm", Runtime: models.RuntimeWasm})
	fake.PutFile(wasm.ID, "/img.png", png)
	if _, err := tools.ReadFile(ctx, resolveTarget(t, tools, "wasm"), "/img.png", 0, 0); !IsCode(err, CodeBinaryFile) {
		t.Fatalf("wasm binary = %v", err)
	}
}

// countingTransport counts response body bytes the client actually reads.
type countingTransport struct {
	base http.RoundTripper
	read atomic.Int64
}

type countingBody struct {
	io.ReadCloser
	n *atomic.Int64
}

func (b countingBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.n.Add(int64(n))
	return n, err
}

func (c *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := c.base.RoundTrip(r)
	if err == nil && strings.HasSuffix(r.URL.Path, "/files/download") {
		resp.Body = countingBody{resp.Body, &c.read}
	}
	return resp, err
}

// TestReadFileReadsOneWindow is the D14 required proof: read_file on a
// large file reads one window plus at most a read buffer, not the file.
func TestReadFileReadsOneWindow(t *testing.T) {
	fake := agenttoolstest.New(t)
	counter := &countingTransport{base: http.DefaultTransport}
	tools, err := New(Config{APIURL: fake.URL, Token: agenttoolstest.Token, HTTPClient: &http.Client{Transport: counter}})
	if err != nil {
		t.Fatal(err)
	}
	box := fake.AddSandbox(models.Sandbox{Name: "box"})
	fake.PutFile(box.ID, "/big.log", []byte(strings.Repeat("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde\n", 1<<20))) // 64 MiB
	sb := resolveTarget(t, tools, "box")
	w, err := tools.ReadFile(context.Background(), sb, "/big.log", 0, 0)
	if err != nil || w.EndLine != DefaultReadLines {
		t.Fatalf("ReadFile = %+v, %v", w, err)
	}
	if read := counter.read.Load(); read > int64(MaxReadBytes)+256*1024 {
		t.Fatalf("read %d bytes of a 64 MiB file; want about one window", read)
	}
}

func TestWriteEditListSearchGrep(t *testing.T) {
	ctx := context.Background()
	tools, fake, _ := newTestTools(t, SourceCLI)
	box := fake.AddSandbox(models.Sandbox{Name: "box"})
	sb := resolveTarget(t, tools, "box")

	if err := tools.WriteFile(ctx, sb, "/work/main.go", "package main\nfunc a() {}\nfunc b() {}\n"); err != nil {
		t.Fatal(err)
	}
	if got, _ := fake.File(box.ID, "/work/main.go"); !strings.Contains(string(got), "func a") {
		t.Fatalf("written = %q", got)
	}
	if err := tools.WriteFile(ctx, sb, " ", "x"); !IsCode(err, CodeInvalidArgument) {
		t.Fatalf("blank path = %v", err)
	}

	if err := tools.EditFile(ctx, sb, "/work/main.go", "func a() {}", "func a() { return }"); err != nil {
		t.Fatalf("unique edit: %v", err)
	}
	if got, _ := fake.File(box.ID, "/work/main.go"); !strings.Contains(string(got), "func a() { return }") {
		t.Fatalf("edited = %q", got)
	}
	edits := map[string][3]string{
		"no match":  {"/work/main.go", "func z()", "x"},
		"ambiguous": {"/work/main.go", "func ", "fn "},
	}
	for name, e := range edits {
		if err := tools.EditFile(ctx, sb, e[0], e[1], e[2]); !IsCode(err, CodeEditConflict) || Classify(err).Hint == "" {
			t.Fatalf("%s = %v", name, err)
		}
	}
	for name, args := range map[string][3]string{
		"blank path": {" ", "a", "b"},
		"blank old":  {"/work/main.go", "", "b"},
		"same text":  {"/work/main.go", "a", "a"},
	} {
		if err := tools.EditFile(ctx, sb, args[0], args[1], args[2]); !IsCode(err, CodeInvalidArgument) {
			t.Fatalf("%s = %v", name, err)
		}
	}
	fake.PutFile(box.ID, "/big.txt", make([]byte, MaxEditBytes+1))
	if err := tools.EditFile(ctx, sb, "/big.txt", "a", "b"); !IsCode(err, CodeTooLarge) {
		t.Fatalf("too large = %v", err)
	}
	fake.PutFile(box.ID, "/bin", []byte("a\x00b"))
	if err := tools.EditFile(ctx, sb, "/bin", "a", "b"); !IsCode(err, CodeBinaryFile) {
		t.Fatalf("binary edit = %v", err)
	}
	if err := tools.EditFile(ctx, sb, "/missing", "a", "b"); !IsCode(err, CodeNotFound) {
		t.Fatalf("missing edit = %v", err)
	}

	list, err := tools.ListFiles(ctx, sb, "/work")
	if err != nil || len(list.Entries) != 1 || list.Entries[0].Name != "main.go" || list.Entries[0].Mode == "" {
		t.Fatalf("list = %+v, %v", list, err)
	}
	search, err := tools.SearchFiles(ctx, sb, "/work", "*.go")
	if err != nil || len(search.Files) != 1 {
		t.Fatalf("search = %+v, %v", search, err)
	}
	if _, err := tools.SearchFiles(ctx, sb, "", " "); !IsCode(err, CodeInvalidArgument) {
		t.Fatalf("blank pattern = %v", err)
	}
	grep, err := tools.GrepFiles(ctx, sb, "", "func b")
	if err != nil || len(grep.Matches) != 1 || grep.Matches[0].Line != 3 {
		t.Fatalf("grep = %+v, %v", grep, err)
	}
	if _, err := tools.GrepFiles(ctx, sb, "/work", ""); !IsCode(err, CodeInvalidArgument) {
		t.Fatalf("blank grep = %v", err)
	}
}

func TestListAndGrepBounds(t *testing.T) {
	ctx := context.Background()
	tools, fake, _ := newTestTools(t, SourceCLI)
	box := fake.AddSandbox(models.Sandbox{Name: "box"})
	sb := resolveTarget(t, tools, "box")
	for i := 0; i < MaxListEntries+5; i++ {
		fake.PutFile(box.ID, fmt.Sprintf("/many/f%04d.txt", i), []byte("needle "+strings.Repeat("x", 600)+"\n"))
	}
	list, err := tools.ListFiles(ctx, sb, "/many")
	if err != nil || !list.Truncated || len(list.Entries) != MaxListEntries {
		t.Fatalf("list bound = %d truncated %v, %v", len(list.Entries), list.Truncated, err)
	}
	search, err := tools.SearchFiles(ctx, sb, "/many", "*.txt")
	if err != nil || !search.Truncated || len(search.Files) != MaxSearchResults {
		t.Fatalf("search bound = %d, %v", len(search.Files), err)
	}
	grep, err := tools.GrepFiles(ctx, sb, "/many", "needle")
	if err != nil || !grep.Truncated || len(grep.Matches) != MaxGrepMatches || len(grep.Matches[0].Content) > maxGrepLineChars+4 {
		t.Fatalf("grep bound = %d, %v", len(grep.Matches), err)
	}
}

func TestWasmFileFallbacks(t *testing.T) {
	ctx := context.Background()
	tools, fake, _ := newTestTools(t, SourceCLI)
	wasm := fake.AddSandbox(models.Sandbox{Name: "wasm", Runtime: models.RuntimeWasm})
	fake.PutFile(wasm.ID, "/app/main.py", []byte("print(1)\n"))
	sb := resolveTarget(t, tools, "wasm")
	list, err := tools.ListFiles(ctx, sb, "/app")
	if err != nil || len(list.Entries) != 1 || list.Entries[0].Name != "main.py" {
		t.Fatalf("wasm list (bare names) = %+v, %v", list, err)
	}
	if _, err := tools.SearchFiles(ctx, sb, "/app", "*.py"); !IsCode(err, CodeUnsupportedRuntime) {
		t.Fatalf("wasm search = %v", err)
	}
	if _, err := tools.GrepFiles(ctx, sb, "/app", "print"); !IsCode(err, CodeUnsupportedRuntime) || !strings.Contains(Classify(err).Hint, "grep") {
		t.Fatalf("wasm grep = %v", err)
	}
}

func TestProcesses(t *testing.T) {
	ctx := context.Background()
	tools, fake, _ := newTestTools(t, SourceMCP)
	box := fake.AddSandbox(models.Sandbox{Name: "box"})
	sb := resolveTarget(t, tools, "box")

	p1, err := tools.StartProcess(ctx, sb, "npm run dev", "/app", nil)
	if err != nil || p1.SessionID == "" || p1.Status != "running" {
		t.Fatalf("start = %+v, %v", p1, err)
	}
	p2, err := tools.StartProcess(ctx, sb, "npm run worker", "", nil)
	if err != nil || p2.SessionID == p1.SessionID {
		t.Fatalf("second start reused the first session: %+v", p2)
	}
	fake.AppendSessionLog(box.ID, p1.SessionID, []byte(strings.Repeat("log line\n", 10000)))
	logs, err := tools.ProcessLogs(ctx, sb, p1.SessionID, 0)
	if err != nil || !logs.Truncated || len(logs.Output) > DefaultMaxOutputBytes+64 || logs.SessionID != p1.SessionID {
		t.Fatalf("logs = truncated %v len %d, %v", logs.Truncated, len(logs.Output), err)
	}
	if _, err := tools.ProcessLogs(ctx, sb, "nope", 0); !IsCode(err, CodeNotFound) || !strings.Contains(err.Error(), "nope") {
		t.Fatalf("missing logs = %v", err)
	}
	if err := tools.StopProcess(ctx, sb, p1.SessionID); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if err := tools.StopProcess(ctx, sb, p1.SessionID); err != nil {
		t.Fatalf("stopping twice must succeed: %v", err)
	}
	for name, fn := range map[string]func() error{
		"start blank": func() error { _, err := tools.StartProcess(ctx, sb, " ", "", nil); return err },
		"logs blank":  func() error { _, err := tools.ProcessLogs(ctx, sb, " ", 0); return err },
		"stop blank":  func() error { return tools.StopProcess(ctx, sb, " ") },
	} {
		if err := fn(); !IsCode(err, CodeInvalidArgument) {
			t.Fatalf("%s = %v", name, err)
		}
	}
	iso := fake.AddSandbox(models.Sandbox{Name: "iso", Runtime: models.RuntimeIsolate})
	isoSB := *sb
	isoSB.ID, isoSB.Runtime = iso.ID, models.RuntimeIsolate
	if _, err := tools.StartProcess(ctx, &isoSB, "x", "", nil); !IsCode(err, CodeUnsupportedRuntime) {
		t.Fatalf("isolate process = %v", err)
	}
}
