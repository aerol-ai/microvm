package agentmcp

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/aerol-ai/microvm/internal/agenttools"
	"github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
)

// Server is one MCP server over one agenttools.Tools.
type Server struct {
	opts   Options
	tools  *agenttools.Tools
	server *mcp.Server

	// pinMu serialises pinned-sandbox resolution, so concurrent first
	// calls create the sandbox once (single-flight). A failed create is not
	// latched: the next call tries again.
	pinMu sync.Mutex
	pinID string

	// createMu serialises unpinned creates so the cap can't be raced.
	createMu sync.Mutex
	created  int

	shutdownOnce sync.Once

	instrument Instrument
}

// Instrument wraps every tool call. It runs before the call with the tool
// name and returns the context to run the call in and a func called after it
// with the sandbox the call acted on (if known) and its error. The remote
// endpoint uses it for metrics, a log line and a span per call; stdio has
// none.
type Instrument func(ctx context.Context, tool string) (context.Context, func(sandboxID string, err error))

// ServerOption configures New.
type ServerOption func(*Server)

// WithInstrument sets the per-call instrumentation.
func WithInstrument(fn Instrument) ServerOption {
	return func(s *Server) { s.instrument = fn }
}

// New builds a server with the tools opts enable. It validates opts.
func New(tools *agenttools.Tools, opts Options, version string, options ...ServerOption) (*Server, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	s := &Server{opts: opts, tools: tools}
	for _, o := range options {
		o(s)
	}
	s.server = mcp.NewServer(&mcp.Implementation{Name: "aerolvm", Title: "AerolVM sandboxes", Version: version}, &mcp.ServerOptions{
		Instructions: s.instructions(),
	})
	s.register()
	return s, nil
}

// MCP is the underlying server, for transports and tests.
func (s *Server) MCP() *mcp.Server { return s.server }

// Run serves the transport until the client disconnects or ctx ends.
func (s *Server) Run(ctx context.Context, t mcp.Transport) error {
	return s.server.Run(ctx, t)
}

// Shutdown runs the clean-exit work: with Ephemeral, destroy the pinned
// sandbox once. Best effort; the idle lifecycle is the real guarantee,
// because MCP hosts often SIGKILL their servers.
func (s *Server) Shutdown(ctx context.Context) error {
	var err error
	s.shutdownOnce.Do(func() {
		if !s.opts.Ephemeral {
			return
		}
		s.pinMu.Lock()
		id := s.pinID
		s.pinID = ""
		s.pinMu.Unlock()
		if id == "" {
			return // never created or used: nothing to clean up
		}
		if derr := s.tools.Client().Destroy(ctx, id); derr != nil && !agenttools.IsCode(derr, agenttools.CodeNotFound) {
			err = derr
		}
	})
	return err
}

func (s *Server) instructions() string {
	var b strings.Builder
	b.WriteString("Tools for AerolVM sandboxes: isolated Linux machines for running code. ")
	if s.opts.pinned() {
		fmt.Fprintf(&b, "Every tool acts on one sandbox, %q; you can't reach any other. ", s.opts.Sandbox)
		if s.opts.CreateIfMissing {
			b.WriteString("It is created on the first call that needs it. ")
		}
	} else {
		b.WriteString("Create a sandbox with sandbox_create (or reuse one from sandbox_list), then pass its ID or name as `sandbox`. ")
	}
	b.WriteString("Sandboxes stop after 30 minutes idle (files are kept) and are destroyed after 24 hours idle. ")
	b.WriteString("exec runs a command and returns when it exits; for servers and watchers use start_process if it is available.")
	return b.String()
}

// Notice tells the model when the sandbox behind a pinned server is new:
// recreated after it disappeared (stdio, eng review D6) or created by a
// remote call (eng re-review RR2). Files from earlier calls are gone.
//
// The text field isn't named Notice: an embedded Notice would shadow it and
// drop "notice" from the inferred output schema.
type Notice struct {
	SandboxRecreated bool   `json:"sandbox_recreated,omitempty"`
	SandboxCreated   bool   `json:"sandbox_created,omitempty"`
	Text             string `json:"notice,omitempty"`
}

const (
	recreatedNotice = "the pinned sandbox no longer existed (probably destroyed after idling), so a new one was created; files and processes from earlier calls are gone"
	createdNotice   = "this is a newly created sandbox; files from any earlier session are not present"
)

// target resolves the sandbox a tool acts on: the pinned one, or ref.
func (s *Server) target(ctx context.Context, ref string, needShell bool) (*microvm.Sandbox, Notice, error) {
	if s.opts.pinned() {
		return s.pinnedTarget(ctx, needShell)
	}
	if strings.TrimSpace(ref) == "" {
		return nil, Notice{}, &agenttools.Error{Code: agenttools.CodeInvalidArgument, Message: "sandbox is required", Hint: "pass a sandbox ID or name from sandbox_list or sandbox_create"}
	}
	var (
		sb  *microvm.Sandbox
		err error
	)
	if needShell {
		sb, err = s.tools.Target(ctx, ref)
	} else {
		sb, err = s.tools.Resolve(ctx, ref)
	}
	if err != nil {
		return nil, Notice{}, agenttools.WithHint(err, notFoundHint(err))
	}
	return sb, Notice{}, nil
}

func notFoundHint(err error) string {
	if agenttools.IsCode(err, agenttools.CodeNotFound) {
		return "it may have been destroyed by its idle lifecycle; call sandbox_list or sandbox_create"
	}
	return ""
}

// pinnedTarget resolves the pinned sandbox, creating it lazily with
// CreateIfMissing (never at startup: hosts spawn every configured server at
// session start, and an eager create would bill a sandbox for every chat
// that never runs code). The cached ID is checked on each call; if the
// sandbox is gone it is recreated by name and the result says so.
//
//	[unresolved] ─first call─► resolve(name)
//	   ├─ found ─────────────────────────────► [ready]
//	   ├─ 404 + create_if_missing ─► create ──► [ready]  (remote: sandbox_created)
//	   └─ 404 otherwise ─► error
//	[ready] ─cached ID 404s─► drop cache, recreate ─► sandbox_recreated (D6)
func (s *Server) pinnedTarget(ctx context.Context, needShell bool) (*microvm.Sandbox, Notice, error) {
	s.pinMu.Lock()
	defer s.pinMu.Unlock()

	hadSandbox := false
	if s.pinID != "" {
		sb, err := s.tools.Client().Get(ctx, s.pinID)
		switch {
		case err == nil:
			return s.ready(ctx, sb, Notice{}, needShell)
		case !agenttools.IsCode(err, agenttools.CodeNotFound):
			return nil, Notice{}, agenttools.Classify(err)
		}
		s.pinID = ""
		hadSandbox = true
	}

	sb, err := s.tools.Resolve(ctx, s.opts.Sandbox)
	if err == nil {
		s.pinID = sb.ID
		notice := Notice{}
		if hadSandbox {
			notice = Notice{SandboxRecreated: true, Text: recreatedNotice}
		}
		return s.ready(ctx, sb, notice, needShell)
	}
	if !agenttools.IsCode(err, agenttools.CodeNotFound) {
		return nil, Notice{}, err
	}
	if !s.opts.CreateIfMissing {
		return nil, Notice{}, &agenttools.Error{
			Code:    agenttools.CodeNotFound,
			Message: fmt.Sprintf("the pinned sandbox %q does not exist", s.opts.Sandbox),
			Hint:    "create it (aerolvm create --name " + s.opts.Sandbox + ") or restart this server with --create-if-missing",
		}
	}
	res, err := s.tools.GetOrCreate(ctx, agenttools.CreateSpec{
		Name:      s.opts.Sandbox,
		Image:     s.opts.Image,
		Runtime:   s.opts.Runtime,
		Lifecycle: s.opts.lifecycle(0),
	})
	if err != nil {
		return nil, Notice{}, err
	}
	s.pinID = res.Sandbox.ID
	notice := Notice{}
	switch {
	case hadSandbox:
		notice = Notice{SandboxRecreated: true, Text: recreatedNotice}
	case s.opts.Remote && res.Created:
		// The remote endpoint is stateless and can't tell a first call from
		// a recreate, so it announces every sandbox it creates.
		notice = Notice{SandboxCreated: true, Text: createdNotice}
	}
	return s.ready(ctx, res.Sandbox, notice, needShell)
}

// ready applies the shell guard and starts a stopped sandbox (D7).
func (s *Server) ready(ctx context.Context, sb *microvm.Sandbox, notice Notice, needShell bool) (*microvm.Sandbox, Notice, error) {
	if !needShell {
		return sb, notice, nil
	}
	if err := agenttools.RequireShell(sb); err != nil {
		return nil, notice, err
	}
	started, err := s.tools.EnsureStarted(ctx, sb)
	if err != nil {
		return nil, notice, err
	}
	return started, notice, nil
}

// modelError renders an error as tool-error text the model can act on:
// what failed, the code, whether a retry can help, and the next step.
func modelError(err error) error {
	e := agenttools.Classify(err)
	var b strings.Builder
	b.WriteString(e.Message)
	fmt.Fprintf(&b, " [code: %s", e.Code)
	if e.Retryable {
		b.WriteString(", retryable")
	}
	b.WriteString("]")
	if e.Hint != "" {
		b.WriteString(" Next: " + e.Hint)
	}
	return errors.New(b.String())
}

// toolSpec describes one tool for registration.
type toolSpec struct {
	tool *mcp.Tool
	// readOnly tools are the only ones --read-only registers.
	readOnly bool
	// fleet tools exist only unpinned (sandbox_create/list/destroy).
	fleet bool
	// toolset gates registration.
	toolset string
}

// addTool registers a typed tool. The input schema is inferred from In and
// then adjusted: the sandbox argument is removed in pinned mode, and the
// runtime enum is filled in where present. Each result carries
// structuredContent plus a text rendering for clients that only read text.
func addTool[In, Out any](s *Server, spec toolSpec, h func(context.Context, In) (Out, string, error)) {
	if spec.fleet && s.opts.pinned() {
		return
	}
	if s.opts.ReadOnly && !spec.readOnly {
		return
	}
	if !s.opts.hasToolset(spec.toolset) {
		return
	}
	schema := inputSchema[In](spec.tool.Name)
	if s.opts.pinned() {
		delete(schema.Properties, "sandbox")
		schema.Required = without(schema.Required, "sandbox")
	}
	if p, ok := schema.Properties["runtime"]; ok {
		enum := make([]any, len(MCPRuntimes))
		for i, r := range MCPRuntimes {
			enum[i] = r
		}
		p.Enum = enum
	}
	tool := *spec.tool
	tool.InputSchema = schema
	mcp.AddTool(s.server, &tool, func(ctx context.Context, _ *mcp.CallToolRequest, in In) (*mcp.CallToolResult, Out, error) {
		var done func(string, error)
		if s.instrument != nil {
			ctx, done = s.instrument(ctx, tool.Name)
		}
		out, text, err := h(ctx, in)
		if done != nil {
			done(s.pinnedID(), err)
		}
		if err != nil {
			var zero Out
			return nil, zero, modelError(err)
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, out, nil
	})
}

// schemaCache holds the inferred input schema per input type. Inference is
// reflection work, and the remote endpoint builds a server per request.
var schemaCache sync.Map // reflect.Type -> *jsonschema.Schema

// inputSchema returns a private copy of In's inferred schema that addTool
// may edit: the property map, required list and runtime property are
// copied; untouched property schemas are shared read-only.
func inputSchema[In any](tool string) *jsonschema.Schema {
	key := reflect.TypeFor[In]()
	cached, ok := schemaCache.Load(key)
	if !ok {
		inferred, err := jsonschema.For[In](nil)
		if err != nil {
			panic(fmt.Sprintf("agentmcp: schema for %s: %v", tool, err))
		}
		cached, _ = schemaCache.LoadOrStore(key, inferred)
	}
	base := cached.(*jsonschema.Schema)
	cp := *base
	cp.Properties = make(map[string]*jsonschema.Schema, len(base.Properties))
	for k, v := range base.Properties {
		cp.Properties[k] = v
	}
	if rt, ok := cp.Properties["runtime"]; ok {
		rtCopy := *rt
		cp.Properties["runtime"] = &rtCopy
	}
	cp.Required = append([]string(nil), base.Required...)
	return &cp
}

// pinnedID is the pinned sandbox's ID, if resolved, for instrumentation.
func (s *Server) pinnedID() string {
	if !s.opts.pinned() {
		return ""
	}
	s.pinMu.Lock()
	defer s.pinMu.Unlock()
	return s.pinID
}

func without(list []string, drop string) []string {
	out := list[:0:0]
	for _, v := range list {
		if v != drop {
			out = append(out, v)
		}
	}
	return out
}

func boolPtr(b bool) *bool { return &b }

// withNotice prefixes text with a pinned-sandbox notice when there is one.
func withNotice(n Notice, text string) string {
	if n.Text == "" {
		return text
	}
	return "NOTICE: " + n.Text + "\n\n" + text
}

func minutes(n int) time.Duration { return time.Duration(n) * time.Minute }
