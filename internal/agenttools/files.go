package agenttools

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
)

// Read and listing bounds (§5.3). They protect the model's context window
// and this process's memory: a read returns one window and a continuation
// offset, never a whole large file.
const (
	DefaultReadLines   = 2000
	MaxReadBytes       = 256 * 1024
	MaxEditBytes       = 1 << 20
	MaxListEntries     = 1000
	MaxSearchResults   = 500
	MaxGrepMatches     = 200
	maxGrepLineChars   = 500
	maxToolboxJSONBody = 4 << 20
	binarySniffBytes   = 8 * 1024
)

// ReadFileResult is one window of a text file. Lines are 1-based. NextOffset
// is the line to pass as Offset to read on; zero means the window reached
// the end of the file.
type ReadFileResult struct {
	Path       string `json:"path"`
	Content    string `json:"content"`
	StartLine  int    `json:"start_line"`
	EndLine    int    `json:"end_line"`
	NextOffset int    `json:"next_offset,omitempty"`
	// LineTruncated is set when one line alone exceeded the byte window and
	// was cut; NextOffset then skips the rest of that line.
	LineTruncated bool `json:"line_truncated,omitempty"`
}

// ReadFile returns up to limit lines (default and maximum 2,000) and at most
// 256 KiB of path, starting at line offset (1-based; 0 means 1). It streams
// the file and stops reading one byte after the window (eng review D14): a
// multi-GB file costs one window, plus whatever precedes offset. Binary
// files are refused with their size and type.
func (t *Tools) ReadFile(ctx context.Context, sb *microvm.Sandbox, path string, offset, limit int) (ReadFileResult, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return ReadFileResult{}, newError(CodeInvalidArgument, "path is required")
	}
	if offset <= 0 {
		offset = 1
	}
	if limit <= 0 || limit > DefaultReadLines {
		limit = DefaultReadLines
	}
	body, err := sb.DownloadFileStream(ctx, path)
	if err != nil {
		return ReadFileResult{}, fileError(err, path)
	}
	defer body.Close()
	r := bufio.NewReaderSize(body, 64*1024)

	if offset == 1 {
		head, _ := r.Peek(binarySniffBytes)
		if looksBinary(head) {
			return ReadFileResult{}, t.binaryFileError(ctx, sb, path, head)
		}
	}
	for line := 1; line < offset; line++ {
		if err := skipLine(r); err != nil {
			if errors.Is(err, io.EOF) {
				return ReadFileResult{Path: path, StartLine: offset, EndLine: offset - 1}, nil
			}
			return ReadFileResult{}, Classify(err)
		}
	}

	res := ReadFileResult{Path: path, StartLine: offset, EndLine: offset - 1}
	var content strings.Builder
	for read := 0; read < limit; read++ {
		line, complete, lineEnded, err := readLine(r, MaxReadBytes-content.Len())
		if len(line) == 0 && errors.Is(err, io.EOF) {
			break
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return ReadFileResult{}, Classify(err)
		}
		if !complete && content.Len() > 0 {
			// The next line doesn't fit in what's left of the window; it
			// starts the next read instead of being cut.
			res.NextOffset = res.EndLine + 1
			break
		}
		content.Write(line)
		res.EndLine++
		if !complete {
			// A single line larger than the whole window: keep its start and
			// skip the rest so the next line is where reading resumes.
			res.LineTruncated = true
			if !lineEnded {
				if err := skipLine(r); err != nil && !errors.Is(err, io.EOF) {
					return ReadFileResult{}, Classify(err)
				}
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
	}
	if res.NextOffset == 0 {
		// Window + 1 byte: one more byte tells whether the file continues.
		if _, err := r.Peek(1); err == nil {
			res.NextOffset = res.EndLine + 1
		}
	}
	res.Content = content.String()
	return res, nil
}

// readLine reads one line (including its newline) up to budget bytes.
// complete is false when the line was longer than budget: the bytes returned
// are then its first budget bytes, and lineEnded reports whether the read
// already consumed the line's newline (if not, the caller skips the rest).
func readLine(r *bufio.Reader, budget int) (line []byte, complete, lineEnded bool, err error) {
	var out []byte
	for {
		chunk, err := r.ReadSlice('\n')
		if len(out)+len(chunk) > budget {
			take := max(budget-len(out), 0)
			out = append(out, chunk[:take]...)
			return out, false, !errors.Is(err, bufio.ErrBufferFull), nil
		}
		out = append(out, chunk...)
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return out, true, true, err
	}
}

func skipLine(r *bufio.Reader) error {
	for {
		_, err := r.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return err
	}
}

func looksBinary(head []byte) bool {
	if bytes.IndexByte(head, 0) >= 0 {
		return true
	}
	return !utf8.Valid(trimIncompleteRuneEnd(head))
}

func (t *Tools) binaryFileError(ctx context.Context, sb *microvm.Sandbox, path string, head []byte) *Error {
	detail := http.DetectContentType(head)
	if size, ok := t.fileSize(ctx, sb, path); ok {
		detail = formatBytes(size) + ", " + detail
	}
	return &Error{
		Code:    CodeBinaryFile,
		Message: path + " is a binary file (" + detail + "); read_file returns text only",
		Hint:    "inspect it with exec instead, e.g. `file " + path + "` or `xxd " + path + " | head`",
	}
}

// fileSize asks the toolbox for a file's size. WASM sandboxes have no
// /files/info, so the size is optional.
func (t *Tools) fileSize(ctx context.Context, sb *microvm.Sandbox, path string) (int64, bool) {
	resp, err := sb.ToolboxRequest(ctx, http.MethodGet, "/files/info", url.Values{"path": {path}}, nil, "")
	if err != nil {
		return 0, false
	}
	defer resp.Body.Close()
	var info struct {
		Size json.Number `json:"size"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&info); err != nil {
		return 0, false
	}
	size, err := info.Size.Int64()
	return size, err == nil && size >= 0
}

// WriteFile writes content to path, creating parent directories. It is
// idempotent: writing the same bytes twice leaves the same file.
func (t *Tools) WriteFile(ctx context.Context, sb *microvm.Sandbox, path, content string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return newError(CodeInvalidArgument, "path is required")
	}
	if err := sb.UploadFileStream(ctx, path, strings.NewReader(content)); err != nil {
		return fileError(err, path)
	}
	return nil
}

// EditFile replaces the one occurrence of oldString in path with newString.
// It refuses when oldString is missing or appears more than once, so an edit
// never lands somewhere the caller didn't mean. Read and write are separate
// requests: a concurrent writer's change between them is lost (agent
// sessions are effectively single-writer).
func (t *Tools) EditFile(ctx context.Context, sb *microvm.Sandbox, path, oldString, newString string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return newError(CodeInvalidArgument, "path is required")
	}
	if oldString == "" {
		return newError(CodeInvalidArgument, "old_string is required; use write_file to create or replace a whole file")
	}
	if oldString == newString {
		return newError(CodeInvalidArgument, "old_string and new_string are identical")
	}
	body, err := sb.DownloadFileStream(ctx, path)
	if err != nil {
		return fileError(err, path)
	}
	data, err := io.ReadAll(io.LimitReader(body, MaxEditBytes+1))
	_ = body.Close()
	if err != nil {
		return Classify(err)
	}
	if len(data) > MaxEditBytes {
		return &Error{
			Code:    CodeTooLarge,
			Message: path + " is larger than 1 MiB, too large to edit in place",
			Hint:    "edit it with exec instead, e.g. sed",
		}
	}
	if looksBinary(data[:min(len(data), binarySniffBytes)]) {
		return &Error{Code: CodeBinaryFile, Message: path + " is a binary file; edit_file edits text only"}
	}
	text := string(data)
	switch n := strings.Count(text, oldString); n {
	case 0:
		return &Error{Code: CodeEditConflict, Message: "old_string was not found in " + path, Hint: "read_file the file and copy the exact text, including whitespace"}
	case 1:
	default:
		return &Error{Code: CodeEditConflict, Message: "old_string appears " + strconv.Itoa(n) + " times in " + path, Hint: "include more surrounding lines in old_string so it matches exactly once"}
	}
	return t.WriteFile(ctx, sb, path, strings.Replace(text, oldString, newString, 1))
}

// FileEntry is one directory entry.
type FileEntry struct {
	Name    string `json:"name"`
	IsDir   bool   `json:"is_dir"`
	Size    int64  `json:"size,omitempty"`
	Mode    string `json:"mode,omitempty"`
	ModTime string `json:"mod_time,omitempty"`
}

// ListFilesResult is a directory listing, cut at MaxListEntries.
type ListFilesResult struct {
	Path      string      `json:"path"`
	Entries   []FileEntry `json:"entries"`
	Truncated bool        `json:"truncated,omitempty"`
}

// ListFiles lists one directory. toolboxd returns rich entries; the WASM
// toolhost returns bare names. Both decode here.
func (t *Tools) ListFiles(ctx context.Context, sb *microvm.Sandbox, path string) (ListFilesResult, error) {
	path = strings.TrimSpace(path)
	var raw []json.RawMessage
	if err := t.toolboxJSON(ctx, sb, "/files", url.Values{"path": {path}}, &raw); err != nil {
		return ListFilesResult{}, fileError(err, path)
	}
	res := ListFilesResult{Path: path, Entries: make([]FileEntry, 0, min(len(raw), MaxListEntries))}
	for _, item := range raw {
		if len(res.Entries) == MaxListEntries {
			res.Truncated = true
			break
		}
		var name string
		if json.Unmarshal(item, &name) == nil {
			res.Entries = append(res.Entries, FileEntry{Name: name})
			continue
		}
		var info struct {
			Name    string      `json:"name"`
			IsDir   bool        `json:"isDir"`
			Size    json.Number `json:"size"`
			Mode    string      `json:"mode"`
			ModTime string      `json:"modTime"`
		}
		if err := json.Unmarshal(item, &info); err != nil {
			continue
		}
		size, _ := info.Size.Int64()
		res.Entries = append(res.Entries, FileEntry{Name: info.Name, IsDir: info.IsDir, Size: size, Mode: info.Mode, ModTime: info.ModTime})
	}
	return res, nil
}

// SearchResult lists paths whose names match a glob, cut at MaxSearchResults.
type SearchResult struct {
	Files     []string `json:"files"`
	Truncated bool     `json:"truncated,omitempty"`
}

// SearchFiles finds files under path whose name matches pattern (a glob
// such as "*.go").
func (t *Tools) SearchFiles(ctx context.Context, sb *microvm.Sandbox, path, pattern string) (SearchResult, error) {
	if err := requireToolboxFS(sb, "search_files", "find "+path+" -name '"+pattern+"'"); err != nil {
		return SearchResult{}, err
	}
	if strings.TrimSpace(pattern) == "" {
		return SearchResult{}, newError(CodeInvalidArgument, "pattern is required")
	}
	var out struct {
		Files []string `json:"files"`
	}
	if err := t.toolboxJSON(ctx, sb, "/files/search", url.Values{"path": {defaultPath(path)}, "pattern": {pattern}}, &out); err != nil {
		return SearchResult{}, fileError(err, path)
	}
	res := SearchResult{Files: out.Files}
	if res.Files == nil {
		res.Files = []string{}
	}
	if len(res.Files) > MaxSearchResults {
		res.Files, res.Truncated = res.Files[:MaxSearchResults], true
	}
	return res, nil
}

// GrepMatch is one matching line.
type GrepMatch struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Content string `json:"content"`
}

// GrepResult is a content search, cut at MaxGrepMatches.
type GrepResult struct {
	Matches   []GrepMatch `json:"matches"`
	Truncated bool        `json:"truncated,omitempty"`
}

// GrepFiles finds lines under path that contain text (a plain substring).
func (t *Tools) GrepFiles(ctx context.Context, sb *microvm.Sandbox, path, text string) (GrepResult, error) {
	if err := requireToolboxFS(sb, "grep_files", "grep -rn '"+text+"' "+path); err != nil {
		return GrepResult{}, err
	}
	if text == "" {
		return GrepResult{}, newError(CodeInvalidArgument, "pattern is required")
	}
	var out []GrepMatch
	if err := t.toolboxJSON(ctx, sb, "/files/find", url.Values{"path": {defaultPath(path)}, "pattern": {text}}, &out); err != nil {
		return GrepResult{}, fileError(err, path)
	}
	res := GrepResult{Matches: out}
	if res.Matches == nil {
		res.Matches = []GrepMatch{}
	}
	if len(res.Matches) > MaxGrepMatches {
		res.Matches, res.Truncated = res.Matches[:MaxGrepMatches], true
	}
	for i := range res.Matches {
		if c := res.Matches[i].Content; len(c) > maxGrepLineChars {
			res.Matches[i].Content = string(trimIncompleteRuneEnd([]byte(c[:maxGrepLineChars]))) + "…"
		}
	}
	return res, nil
}

func defaultPath(path string) string {
	if strings.TrimSpace(path) == "" {
		return "."
	}
	return path
}

// requireToolboxFS refuses the search endpoints on WASM sandboxes, whose
// toolhost serves only upload, download and list.
func requireToolboxFS(sb *microvm.Sandbox, tool, alternative string) error {
	if IsWasm(sb) {
		return &Error{
			Code:    CodeUnsupportedRuntime,
			Message: tool + " is not available on WASM sandboxes",
			Hint:    "use exec instead, e.g. `" + alternative + "`",
		}
	}
	return nil
}

// toolboxJSON GETs a toolbox endpoint and decodes at most
// maxToolboxJSONBody bytes of its JSON reply into out.
func (t *Tools) toolboxJSON(ctx context.Context, sb *microvm.Sandbox, path string, query url.Values, out any) error {
	resp, err := sb.ToolboxRequest(ctx, http.MethodGet, path, query, nil, "")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxToolboxJSONBody+1))
	if err != nil {
		return err
	}
	if len(raw) > maxToolboxJSONBody {
		return &Error{Code: CodeTooLarge, Message: "the result is larger than 4 MiB", Hint: "narrow the path or the pattern"}
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return &Error{Code: CodeInternal, Message: "decode toolbox response: " + err.Error(), cause: err}
	}
	return nil
}

// fileError adds the path to a not-found error.
func fileError(err error, path string) *Error {
	e := Classify(err)
	if e.Code == CodeNotFound && path != "" {
		cp := *e
		cp.Message = "no such file or directory: " + path
		return &cp
	}
	return e
}
