package agentmcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/aerol-ai/microvm/internal/agenttools"
	"github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// Tool descriptions are written for the model: what the tool does, when to
// use it, and what comes back. The agent eval (-tags=agenteval) exercises
// them; run it before changing any name, description or notice text.

const (
	listPageSize       = 20
	defaultExecTimeout = 5 * time.Minute
	maxExecTimeout     = time.Hour
)

func (s *Server) register() {
	addTool(s, toolSpec{
		toolset: ToolsetCore, fleet: true,
		tool: &mcp.Tool{
			Name:        "sandbox_create",
			Description: "Create a sandbox (an isolated Linux machine), or return the existing one with the same name. Safe to retry. Without a name, one is generated. Returns its id and name; pass either as `sandbox` to the other tools. New sandboxes stop after 30 minutes idle and are destroyed after 24 hours idle.",
			Annotations: &mcp.ToolAnnotations{Title: "Create sandbox", IdempotentHint: true, DestructiveHint: boolPtr(false), OpenWorldHint: boolPtr(false)},
		},
	}, s.sandboxCreate)
	addTool(s, toolSpec{
		toolset: ToolsetCore, fleet: true, readOnly: true,
		tool: &mcp.Tool{
			Name:        "sandbox_list",
			Description: "List your sandboxes, 20 per page, as {id, name, status, runtime, created_at, tags}. Pass next_page_token back as page_token for the next page. Filter with tags.",
			Annotations: &mcp.ToolAnnotations{Title: "List sandboxes", ReadOnlyHint: true, OpenWorldHint: boolPtr(false)},
		},
	}, s.sandboxList)
	addTool(s, toolSpec{
		toolset: ToolsetCore, fleet: true,
		tool: &mcp.Tool{
			Name:        "sandbox_destroy",
			Description: "Destroy a sandbox and everything in it. Cannot be undone. Destroying one that is already gone succeeds.",
			Annotations: &mcp.ToolAnnotations{Title: "Destroy sandbox", DestructiveHint: boolPtr(true), IdempotentHint: true, OpenWorldHint: boolPtr(false)},
		},
	}, s.sandboxDestroy)
	addTool(s, toolSpec{
		toolset: ToolsetCore,
		tool: &mcp.Tool{
			Name:        "exec",
			Description: "Run a shell command line in the sandbox (/bin/sh -c) and wait for it to exit. Returns exit_code, stdout and stderr; a non-zero exit_code is a normal result. Long output keeps its first 4 KiB and last 12 KiB per stream. Times out after timeout_seconds (default 300) with exit_code 124. Not for servers or watchers that never exit; use start_process for those.",
			Annotations: &mcp.ToolAnnotations{Title: "Run command", DestructiveHint: boolPtr(false), OpenWorldHint: boolPtr(true)},
		},
	}, s.exec)
	addTool(s, toolSpec{
		toolset: ToolsetCore, readOnly: true,
		tool: &mcp.Tool{
			Name:        "read_file",
			Description: "Read a text file from the sandbox: up to 2,000 lines or 256 KiB per call, starting at offset_line (1-based). If next_offset is set, call again with offset_line=next_offset for the rest. Binary files are refused; inspect them with exec.",
			Annotations: &mcp.ToolAnnotations{Title: "Read file", ReadOnlyHint: true, OpenWorldHint: boolPtr(false)},
		},
	}, s.readFile)
	addTool(s, toolSpec{
		toolset: ToolsetCore,
		tool: &mcp.Tool{
			Name:        "write_file",
			Description: "Write a file in the sandbox, replacing it if it exists and creating parent directories. Use it to create files; to change part of a file use edit_file if it is available.",
			Annotations: &mcp.ToolAnnotations{Title: "Write file", IdempotentHint: true, DestructiveHint: boolPtr(false), OpenWorldHint: boolPtr(false)},
		},
	}, s.writeFile)
	addTool(s, toolSpec{
		toolset: ToolsetCore, readOnly: true,
		tool: &mcp.Tool{
			Name:        "list_files",
			Description: "List one directory in the sandbox (default: the working directory). Directories have is_dir true.",
			Annotations: &mcp.ToolAnnotations{Title: "List files", ReadOnlyHint: true, OpenWorldHint: boolPtr(false)},
		},
	}, s.listFiles)
	addTool(s, toolSpec{
		toolset: ToolsetCore,
		tool: &mcp.Tool{
			Name:        "expose_port",
			Description: "Publish a port the sandbox listens on and return its public URL, e.g. to preview a dev server. Calling it again returns the same URL. Start the server first (start_process, or exec with nohup ... &).",
			Annotations: &mcp.ToolAnnotations{Title: "Expose port", IdempotentHint: true, DestructiveHint: boolPtr(false), OpenWorldHint: boolPtr(true)},
		},
	}, s.exposePort)

	addTool(s, toolSpec{
		toolset: ToolsetFiles,
		tool: &mcp.Tool{
			Name:        "edit_file",
			Description: "Replace one exact occurrence of old_string with new_string in a sandbox file. Fails if old_string is missing or appears more than once; include enough surrounding lines to make it unique. Read the file first to copy the text exactly, whitespace included.",
			Annotations: &mcp.ToolAnnotations{Title: "Edit file", DestructiveHint: boolPtr(false), OpenWorldHint: boolPtr(false)},
		},
	}, s.editFile)
	addTool(s, toolSpec{
		toolset: ToolsetFiles, readOnly: true,
		tool: &mcp.Tool{
			Name:        "search_files",
			Description: "Find files under path whose names match a glob pattern such as *.go. Returns up to 500 paths.",
			Annotations: &mcp.ToolAnnotations{Title: "Search file names", ReadOnlyHint: true, OpenWorldHint: boolPtr(false)},
		},
	}, s.searchFiles)
	addTool(s, toolSpec{
		toolset: ToolsetFiles, readOnly: true,
		tool: &mcp.Tool{
			Name:        "grep_files",
			Description: "Find lines containing pattern (plain text, not a regex) in files under path. Returns up to 200 matches as {file, line, content}.",
			Annotations: &mcp.ToolAnnotations{Title: "Search file contents", ReadOnlyHint: true, OpenWorldHint: boolPtr(false)},
		},
	}, s.grepFiles)

	addTool(s, toolSpec{
		toolset: ToolsetProcess,
		tool: &mcp.Tool{
			Name:        "start_process",
			Description: "Start a long-running command (dev server, watcher, worker) in the background and return its session_id at once. Read its output with process_logs and stop it with stop_process.",
			Annotations: &mcp.ToolAnnotations{Title: "Start background process", DestructiveHint: boolPtr(false), OpenWorldHint: boolPtr(true)},
		},
	}, s.startProcess)
	addTool(s, toolSpec{
		toolset: ToolsetProcess, readOnly: true,
		tool: &mcp.Tool{
			Name:        "process_logs",
			Description: "Show a background process's status and output (first 4 KiB and last 12 KiB).",
			Annotations: &mcp.ToolAnnotations{Title: "Background process output", ReadOnlyHint: true, OpenWorldHint: boolPtr(false)},
		},
	}, s.processLogs)
	addTool(s, toolSpec{
		toolset: ToolsetProcess,
		tool: &mcp.Tool{
			Name:        "stop_process",
			Description: "Stop a background process started with start_process. Stopping one that is already gone succeeds.",
			Annotations: &mcp.ToolAnnotations{Title: "Stop background process", IdempotentHint: true, DestructiveHint: boolPtr(false), OpenWorldHint: boolPtr(false)},
		},
	}, s.stopProcess)
}

// SandboxRow is the compact sandbox view returned to the model (eng review
// D15): enough to choose a sandbox, nothing that costs context for no use.
type SandboxRow struct {
	ID        string            `json:"id"`
	Name      string            `json:"name,omitempty"`
	Status    string            `json:"status"`
	Runtime   string            `json:"runtime,omitempty"`
	CreatedAt string            `json:"created_at"`
	Tags      map[string]string `json:"tags,omitempty"`
}

func rowOf(sb *microvm.Sandbox) SandboxRow {
	return SandboxRow{
		ID:        sb.ID,
		Name:      sb.Name,
		Status:    string(sb.Status),
		Runtime:   sb.Runtime,
		CreatedAt: sb.CreatedAt.UTC().Format(time.RFC3339),
		Tags:      sb.Tags,
	}
}

func asJSON(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}

type createIn struct {
	Name                 string            `json:"name,omitempty" jsonschema:"sandbox name, unique among your sandboxes; omit to generate one"`
	Image                string            `json:"image,omitempty" jsonschema:"container image such as python:3.12 or node:22; for runtime wasm, the module"`
	Runtime              string            `json:"runtime,omitempty" jsonschema:"isolation runtime; omit for the server default"`
	CPU                  float64           `json:"cpu,omitempty" jsonschema:"CPU cores"`
	MemoryMB             int               `json:"memory_mb,omitempty" jsonschema:"memory in MiB"`
	Env                  map[string]string `json:"env,omitempty" jsonschema:"environment variables"`
	DestroyIfIdleMinutes int               `json:"destroy_if_idle_minutes,omitempty" jsonschema:"destroy after this many idle minutes (default 1440)"`
}

type createOut struct {
	SandboxRow
	Created bool `json:"created"`
}

func (s *Server) sandboxCreate(ctx context.Context, in createIn) (createOut, string, error) {
	s.createMu.Lock()
	defer s.createMu.Unlock()
	if in.DestroyIfIdleMinutes < 0 {
		return createOut{}, "", &agenttools.Error{Code: agenttools.CodeInvalidArgument, Message: "destroy_if_idle_minutes must be positive"}
	}
	// The cap (CEO review C4) counts creates that happened. A name that
	// already exists isn't a create, so it is answered even at the cap.
	if s.opts.MaxCreates > 0 && s.created >= s.opts.MaxCreates {
		if name := strings.TrimSpace(in.Name); name != "" {
			if existing, err := s.tools.Client().GetByName(ctx, name); err == nil {
				return createOut{SandboxRow: rowOf(existing)}, asJSON(createOut{SandboxRow: rowOf(existing)}), nil
			}
		}
		return createOut{}, "", &agenttools.Error{
			Code:    agenttools.CodeCreateLimit,
			Message: fmt.Sprintf("create limit reached for this session (%d sandboxes)", s.opts.MaxCreates),
			Hint:    "reuse a sandbox from sandbox_list, destroy one with sandbox_destroy, or ask the user to raise --max-creates",
		}
	}
	res, err := s.tools.GetOrCreate(ctx, agenttools.CreateSpec{
		Name:      in.Name,
		Image:     in.Image,
		Runtime:   in.Runtime,
		CPU:       in.CPU,
		MemoryMB:  in.MemoryMB,
		Env:       in.Env,
		Lifecycle: s.opts.lifecycle(minutes(in.DestroyIfIdleMinutes)),
	})
	if err != nil {
		return createOut{}, "", err
	}
	if res.Created {
		s.created++
	}
	out := createOut{SandboxRow: rowOf(res.Sandbox), Created: res.Created}
	return out, asJSON(out), nil
}

type listIn struct {
	Tags      map[string]string `json:"tags,omitempty" jsonschema:"only sandboxes with all these labels"`
	PageToken string            `json:"page_token,omitempty" jsonschema:"next_page_token from the previous page"`
}

type listOut struct {
	Sandboxes     []SandboxRow `json:"sandboxes"`
	NextPageToken string       `json:"next_page_token,omitempty"`
}

func (s *Server) sandboxList(ctx context.Context, in listIn) (listOut, string, error) {
	items, next, err := s.tools.Client().ListPage(ctx, in.PageToken, microvm.WithTags(in.Tags), microvm.WithLimit(listPageSize))
	if err != nil {
		return listOut{}, "", err
	}
	// Servers without single-node paging return every row: keep 20.
	if len(items) > listPageSize {
		items = items[:listPageSize]
	}
	out := listOut{Sandboxes: make([]SandboxRow, 0, len(items)), NextPageToken: next}
	for _, sb := range items {
		out.Sandboxes = append(out.Sandboxes, rowOf(sb))
	}
	return out, asJSON(out), nil
}

type destroyIn struct {
	Sandbox string `json:"sandbox" jsonschema:"the sandbox's ID or name"`
}

type destroyOut struct {
	ID          string `json:"id,omitempty"`
	Destroyed   bool   `json:"destroyed"`
	AlreadyGone bool   `json:"already_gone,omitempty"`
}

func (s *Server) sandboxDestroy(ctx context.Context, in destroyIn) (destroyOut, string, error) {
	sb, err := s.tools.Resolve(ctx, in.Sandbox)
	if agenttools.IsCode(err, agenttools.CodeNotFound) {
		out := destroyOut{Destroyed: true, AlreadyGone: true}
		return out, asJSON(out), nil
	}
	if err != nil {
		return destroyOut{}, "", err
	}
	if err := s.tools.Client().Destroy(ctx, sb.ID); err != nil && !agenttools.IsCode(err, agenttools.CodeNotFound) {
		return destroyOut{}, "", err
	}
	out := destroyOut{ID: sb.ID, Destroyed: true}
	return out, asJSON(out), nil
}

type execIn struct {
	Sandbox        string            `json:"sandbox" jsonschema:"the sandbox's ID or name"`
	Command        string            `json:"command" jsonschema:"shell command line, run with /bin/sh -c"`
	Cwd            string            `json:"cwd,omitempty" jsonschema:"working directory"`
	Env            map[string]string `json:"env,omitempty" jsonschema:"extra environment variables"`
	TimeoutSeconds int               `json:"timeout_seconds,omitempty" jsonschema:"kill the command after this many seconds (default 300, max 3600)"`
}

type execOut struct {
	agenttools.ExecResult
	Notice
}

func (s *Server) exec(ctx context.Context, in execIn) (execOut, string, error) {
	timeout := defaultExecTimeout
	if in.TimeoutSeconds < 0 {
		return execOut{}, "", &agenttools.Error{Code: agenttools.CodeInvalidArgument, Message: "timeout_seconds must be positive"}
	}
	if in.TimeoutSeconds > 0 {
		timeout = min(time.Duration(in.TimeoutSeconds)*time.Second, maxExecTimeout)
	}
	sb, notice, err := s.target(ctx, in.Sandbox, true)
	if err != nil {
		return execOut{}, "", err
	}
	res, err := s.tools.Exec(ctx, sb, agenttools.ExecRequest{
		Command:        in.Command,
		Cwd:            in.Cwd,
		Env:            in.Env,
		Timeout:        timeout,
		MaxOutputBytes: s.opts.MaxOutputBytes,
		Buffered:       s.opts.Remote,
	})
	if err != nil {
		return execOut{}, "", err
	}
	out := execOut{ExecResult: res, Notice: notice}
	return out, withNotice(notice, renderExec(res)), nil
}

func renderExec(r agenttools.ExecResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "exit_code: %d", r.ExitCode)
	if r.Signal != "" {
		fmt.Fprintf(&b, " (signal %s)", r.Signal)
	}
	if r.TimedOut {
		b.WriteString(" (timed out)")
	}
	fmt.Fprintf(&b, "\nduration_ms: %d\n", r.DurationMS)
	if r.Stdout != "" {
		b.WriteString("--- stdout ---\n" + r.Stdout)
		if !strings.HasSuffix(r.Stdout, "\n") {
			b.WriteString("\n")
		}
	}
	if r.Stderr != "" {
		b.WriteString("--- stderr ---\n" + r.Stderr)
		if !strings.HasSuffix(r.Stderr, "\n") {
			b.WriteString("\n")
		}
	}
	if r.Stdout == "" && r.Stderr == "" {
		b.WriteString("(no output)\n")
	}
	return b.String()
}

type readIn struct {
	Sandbox    string `json:"sandbox" jsonschema:"the sandbox's ID or name"`
	Path       string `json:"path" jsonschema:"file path in the sandbox"`
	OffsetLine int    `json:"offset_line,omitempty" jsonschema:"first line to return, 1-based (default 1)"`
	LimitLines int    `json:"limit_lines,omitempty" jsonschema:"maximum lines to return (default and maximum 2000)"`
}

type readOut struct {
	agenttools.ReadFileResult
	Notice
}

func (s *Server) readFile(ctx context.Context, in readIn) (readOut, string, error) {
	sb, notice, err := s.target(ctx, in.Sandbox, true)
	if err != nil {
		return readOut{}, "", err
	}
	res, err := s.tools.ReadFile(ctx, sb, in.Path, in.OffsetLine, in.LimitLines)
	if err != nil {
		return readOut{}, "", err
	}
	header := fmt.Sprintf("%s (lines %d-%d", res.Path, res.StartLine, res.EndLine)
	if res.NextOffset != 0 {
		header += fmt.Sprintf("; more from offset_line=%d", res.NextOffset)
	}
	header += ")\n"
	return readOut{ReadFileResult: res, Notice: notice}, withNotice(notice, header+res.Content), nil
}

type writeIn struct {
	Sandbox string `json:"sandbox" jsonschema:"the sandbox's ID or name"`
	Path    string `json:"path" jsonschema:"file path in the sandbox"`
	Content string `json:"content" jsonschema:"the whole new file content"`
}

type writeOut struct {
	Path  string `json:"path"`
	Bytes int    `json:"bytes"`
	Notice
}

func (s *Server) writeFile(ctx context.Context, in writeIn) (writeOut, string, error) {
	sb, notice, err := s.target(ctx, in.Sandbox, true)
	if err != nil {
		return writeOut{}, "", err
	}
	if err := s.tools.WriteFile(ctx, sb, in.Path, in.Content); err != nil {
		return writeOut{}, "", err
	}
	out := writeOut{Path: in.Path, Bytes: len(in.Content), Notice: notice}
	return out, withNotice(notice, fmt.Sprintf("wrote %d bytes to %s", out.Bytes, out.Path)), nil
}

type listFilesIn struct {
	Sandbox string `json:"sandbox" jsonschema:"the sandbox's ID or name"`
	Path    string `json:"path,omitempty" jsonschema:"directory (default: the working directory)"`
}

type listFilesOut struct {
	agenttools.ListFilesResult
	Notice
}

func (s *Server) listFiles(ctx context.Context, in listFilesIn) (listFilesOut, string, error) {
	sb, notice, err := s.target(ctx, in.Sandbox, true)
	if err != nil {
		return listFilesOut{}, "", err
	}
	res, err := s.tools.ListFiles(ctx, sb, in.Path)
	if err != nil {
		return listFilesOut{}, "", err
	}
	out := listFilesOut{ListFilesResult: res, Notice: notice}
	return out, withNotice(notice, asJSON(res)), nil
}

type exposeIn struct {
	Sandbox string `json:"sandbox" jsonschema:"the sandbox's ID or name"`
	Port    int    `json:"port" jsonschema:"port the sandbox listens on (1-65535)"`
}

type exposeOut struct {
	Port int    `json:"port"`
	URL  string `json:"url"`
	Notice
}

func (s *Server) exposePort(ctx context.Context, in exposeIn) (exposeOut, string, error) {
	if in.Port <= 0 || in.Port > 65535 {
		return exposeOut{}, "", &agenttools.Error{Code: agenttools.CodeInvalidArgument, Message: "port must be 1-65535"}
	}
	sb, notice, err := s.target(ctx, in.Sandbox, false)
	if err != nil {
		return exposeOut{}, "", err
	}
	res, err := sb.ExposePort(ctx, in.Port, microvm.WithProtocol(sdktypes.ExposeProtocolHTTP))
	if err != nil {
		return exposeOut{}, "", err
	}
	out := exposeOut{Port: in.Port, URL: res.PublicURL, Notice: notice}
	return out, withNotice(notice, out.URL), nil
}

type editIn struct {
	Sandbox   string `json:"sandbox" jsonschema:"the sandbox's ID or name"`
	Path      string `json:"path" jsonschema:"file path in the sandbox"`
	OldString string `json:"old_string" jsonschema:"exact text to replace; must occur exactly once"`
	NewString string `json:"new_string" jsonschema:"replacement text"`
}

type editOut struct {
	Path     string `json:"path"`
	Replaced int    `json:"replaced"`
	Notice
}

func (s *Server) editFile(ctx context.Context, in editIn) (editOut, string, error) {
	sb, notice, err := s.target(ctx, in.Sandbox, true)
	if err != nil {
		return editOut{}, "", err
	}
	if err := s.tools.EditFile(ctx, sb, in.Path, in.OldString, in.NewString); err != nil {
		return editOut{}, "", err
	}
	out := editOut{Path: in.Path, Replaced: 1, Notice: notice}
	return out, withNotice(notice, "edited "+in.Path), nil
}

type searchIn struct {
	Sandbox string `json:"sandbox" jsonschema:"the sandbox's ID or name"`
	Path    string `json:"path,omitempty" jsonschema:"directory to search (default: the working directory)"`
	Pattern string `json:"pattern" jsonschema:"file name glob, e.g. *.py"`
}

type searchOut struct {
	agenttools.SearchResult
	Notice
}

func (s *Server) searchFiles(ctx context.Context, in searchIn) (searchOut, string, error) {
	sb, notice, err := s.target(ctx, in.Sandbox, true)
	if err != nil {
		return searchOut{}, "", err
	}
	res, err := s.tools.SearchFiles(ctx, sb, in.Path, in.Pattern)
	if err != nil {
		return searchOut{}, "", err
	}
	return searchOut{SearchResult: res, Notice: notice}, withNotice(notice, asJSON(res)), nil
}

type grepIn struct {
	Sandbox string `json:"sandbox" jsonschema:"the sandbox's ID or name"`
	Path    string `json:"path,omitempty" jsonschema:"directory to search (default: the working directory)"`
	Pattern string `json:"pattern" jsonschema:"text to find (plain text, not a regex)"`
}

type grepOut struct {
	agenttools.GrepResult
	Notice
}

func (s *Server) grepFiles(ctx context.Context, in grepIn) (grepOut, string, error) {
	sb, notice, err := s.target(ctx, in.Sandbox, true)
	if err != nil {
		return grepOut{}, "", err
	}
	res, err := s.tools.GrepFiles(ctx, sb, in.Path, in.Pattern)
	if err != nil {
		return grepOut{}, "", err
	}
	return grepOut{GrepResult: res, Notice: notice}, withNotice(notice, asJSON(res)), nil
}

type startProcessIn struct {
	Sandbox string            `json:"sandbox" jsonschema:"the sandbox's ID or name"`
	Command string            `json:"command" jsonschema:"shell command line to run in the background"`
	Cwd     string            `json:"cwd,omitempty" jsonschema:"working directory"`
	Env     map[string]string `json:"env,omitempty" jsonschema:"extra environment variables"`
}

type processOut struct {
	agenttools.Process
	Notice
}

func (s *Server) startProcess(ctx context.Context, in startProcessIn) (processOut, string, error) {
	sb, notice, err := s.target(ctx, in.Sandbox, true)
	if err != nil {
		return processOut{}, "", err
	}
	proc, err := s.tools.StartProcess(ctx, sb, in.Command, in.Cwd, in.Env)
	if err != nil {
		return processOut{}, "", err
	}
	out := processOut{Process: proc, Notice: notice}
	return out, withNotice(notice, asJSON(proc)), nil
}

type sessionIn struct {
	Sandbox   string `json:"sandbox" jsonschema:"the sandbox's ID or name"`
	SessionID string `json:"session_id" jsonschema:"session_id from start_process"`
}

type logsOut struct {
	agenttools.ProcessLogs
	Notice
}

func (s *Server) processLogs(ctx context.Context, in sessionIn) (logsOut, string, error) {
	sb, notice, err := s.target(ctx, in.Sandbox, true)
	if err != nil {
		return logsOut{}, "", err
	}
	logs, err := s.tools.ProcessLogs(ctx, sb, in.SessionID, s.opts.MaxOutputBytes)
	if err != nil {
		return logsOut{}, "", err
	}
	text := fmt.Sprintf("status: %s", logs.Status)
	if logs.Status != "running" {
		text += fmt.Sprintf(" (exit_code %d)", logs.ExitCode)
	}
	text += "\n--- output ---\n" + logs.Output
	return logsOut{ProcessLogs: logs, Notice: notice}, withNotice(notice, text), nil
}

type stopOut struct {
	SessionID string `json:"session_id"`
	Stopped   bool   `json:"stopped"`
	Notice
}

func (s *Server) stopProcess(ctx context.Context, in sessionIn) (stopOut, string, error) {
	sb, notice, err := s.target(ctx, in.Sandbox, true)
	if err != nil {
		return stopOut{}, "", err
	}
	if err := s.tools.StopProcess(ctx, sb, in.SessionID); err != nil {
		return stopOut{}, "", err
	}
	out := stopOut{SessionID: in.SessionID, Stopped: true, Notice: notice}
	return out, withNotice(notice, "stopped "+in.SessionID), nil
}
