// Package agentmcp is the AerolVM MCP tool registry (plans/mcp-server-and-
// agent-cli.md §5.3). `aerolvm mcp` serves it over stdio, and sandboxd's
// remote /mcp endpoint serves the same registry over Streamable HTTP, so a
// tool behaves the same wherever the model reaches it. Every tool runs
// through internal/agenttools, which the CLI shares.
package agentmcp

import (
	"flag"
	"fmt"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// Toolsets. Every extra tool costs the model selection accuracy and
// context, so only core is on by default.
const (
	ToolsetCore    = "core"
	ToolsetFiles   = "files"
	ToolsetProcess = "process"
)

var knownToolsets = []string{ToolsetCore, ToolsetFiles, ToolsetProcess}

// MCPRuntimes is the runtime enum sandbox_create offers. Isolate is left
// out: it has no shell or filesystem, so none of the other tools would work
// on it (eng review D11). Kata is reserved and rejected at create.
var MCPRuntimes = []string{
	models.RuntimeDocker,
	models.RuntimeGvisor,
	models.RuntimeFirecracker,
	models.RuntimeWasm,
}

// Defaults for sandboxes the MCP server creates (eng review D7).
const (
	DefaultStopIfIdle    = 30 * time.Minute
	DefaultDestroyIfIdle = 24 * time.Hour
	DefaultMaxCreates    = 5
)

// Options configure one MCP server. The stdio flags (`aerolvm mcp --...`)
// and the remote endpoint's URL query parameters both fill an Options and
// call Validate, so the two front ends can't drift apart on names or rules
// (eng re-review, required by CEO review CF1). Option names below are the
// query-parameter spelling; the flags use dashes for underscores.
type Options struct {
	// Sandbox pins the server to one sandbox (name or ID): the sandbox
	// argument disappears from every tool and the fleet tools
	// (sandbox_create/list/destroy) are not registered.
	Sandbox string
	// CreateIfMissing creates the pinned sandbox, by name, on the first tool
	// call that needs it (never at startup), and recreates it if it later
	// disappears.
	CreateIfMissing bool
	Image           string
	Runtime         string
	// Toolsets lists the enabled toolsets; empty means core.
	Toolsets []string
	// ReadOnly registers only tools that change nothing.
	ReadOnly bool
	// Ephemeral destroys the pinned sandbox on clean shutdown (stdio only;
	// best effort, the lifecycle timers are the guarantee).
	Ephemeral bool
	// Keep turns off the idle stop/destroy defaults on created sandboxes.
	Keep bool
	// StopIfIdle and DestroyIfIdle override the defaults. Zero means the
	// default; Keep turns both off.
	StopIfIdle    time.Duration
	DestroyIfIdle time.Duration
	// MaxCreates caps successful creates per process in unpinned mode (CEO
	// review C4). Zero means unlimited; parsers default it to
	// DefaultMaxCreates.
	MaxCreates int
	// MaxOutputBytes bounds exec output per stream; zero means 16 KiB.
	MaxOutputBytes int
	// Remote marks the sandboxd /mcp endpoint: pinned only, buffered exec,
	// and a notice on every lazy create (CEO review CF2, eng re-review RR2).
	Remote bool
}

// OptionError names the option a validation failure is about, so the
// remote endpoint can answer 400 naming the parameter and the CLI can name
// the flag.
type OptionError struct {
	Param   string
	Message string
}

func (e *OptionError) Error() string { return e.Param + ": " + e.Message }

// Flag is the stdio flag spelling of the parameter.
func (e *OptionError) Flag() string { return "--" + strings.ReplaceAll(e.Param, "_", "-") }

func optErr(param, format string, args ...any) *OptionError {
	return &OptionError{Param: param, Message: fmt.Sprintf(format, args...)}
}

// Validate checks the options and normalises them in place.
func (o *Options) Validate() error {
	o.Sandbox = strings.TrimSpace(o.Sandbox)
	o.Image = strings.TrimSpace(o.Image)
	o.Runtime = strings.TrimSpace(o.Runtime)
	toolsets, err := normaliseToolsets(o.Toolsets)
	if err != nil {
		return err
	}
	o.Toolsets = toolsets
	if o.Remote && o.Sandbox == "" {
		return optErr("sandbox", "remote MCP requires ?sandbox=<name>")
	}
	if o.CreateIfMissing {
		if o.Sandbox == "" {
			return optErr("create_if_missing", "needs a sandbox name to create")
		}
		if err := models.ValidateSandboxName(o.Sandbox); err != nil {
			return optErr("sandbox", "%v", err)
		}
	}
	if (o.Image != "" || o.Runtime != "") && !o.CreateIfMissing && o.Sandbox != "" {
		param := "image"
		if o.Image == "" {
			param = "runtime"
		}
		return optErr(param, "only applies with create_if_missing")
	}
	if o.Runtime != "" && !contains(MCPRuntimes, o.Runtime) {
		return optErr("runtime", "must be one of %s", strings.Join(MCPRuntimes, ", "))
	}
	if o.Ephemeral && o.Sandbox == "" {
		return optErr("ephemeral", "needs a pinned sandbox")
	}
	if o.Ephemeral && o.Remote {
		return optErr("ephemeral", "is not available on the remote endpoint")
	}
	if o.MaxCreates < 0 {
		return optErr("max_creates", "must be 0 (unlimited) or more")
	}
	if o.MaxOutputBytes < 0 {
		return optErr("max_output_bytes", "must be positive")
	}
	if o.StopIfIdle < 0 || o.DestroyIfIdle < 0 {
		return optErr("stop_if_idle", "durations must be positive")
	}
	if o.StopIfIdle > models.MaxLifecycleDuration || o.DestroyIfIdle > models.MaxLifecycleDuration {
		return optErr("destroy_if_idle", "at most %s", models.MaxLifecycleDuration)
	}
	return nil
}

// RemoteParams are the options the remote endpoint takes as URL query
// parameters (CEO review CF1). The token stays in the Authorization header;
// stdio-only options (ephemeral, max_creates, ...) are not accepted there.
var RemoteParams = []string{"sandbox", "create_if_missing", "image", "runtime", "toolsets", "read_only"}

// BindFlags registers the stdio flags on fs (query names with dashes) and
// returns a parser that validates them. It and ParseQuery are the only two
// ways to build Options, and both end in Validate.
func BindFlags(fs *flag.FlagSet) func() (Options, error) {
	var (
		opts     Options
		toolsets string
	)
	fs.StringVar(&opts.Sandbox, "sandbox", "", "")
	fs.BoolVar(&opts.CreateIfMissing, "create-if-missing", false, "")
	fs.StringVar(&opts.Image, "image", "", "")
	fs.StringVar(&opts.Runtime, "runtime", "", "")
	fs.StringVar(&toolsets, "toolsets", ToolsetCore, "")
	fs.BoolVar(&opts.ReadOnly, "read-only", false, "")
	fs.BoolVar(&opts.Ephemeral, "ephemeral", false, "")
	fs.BoolVar(&opts.Keep, "keep", false, "")
	fs.DurationVar(&opts.StopIfIdle, "stop-if-idle", DefaultStopIfIdle, "")
	fs.DurationVar(&opts.DestroyIfIdle, "destroy-if-idle", DefaultDestroyIfIdle, "")
	fs.IntVar(&opts.MaxCreates, "max-creates", DefaultMaxCreates, "")
	fs.IntVar(&opts.MaxOutputBytes, "max-output-bytes", 0, "")
	return func() (Options, error) {
		o := opts
		o.Toolsets = ParseToolsets(toolsets)
		return o, o.Validate()
	}
}

// ParseQuery builds Options for the remote endpoint from URL query
// parameters, parsed on every request (the endpoint is stateless). An
// unknown or stdio-only parameter is refused by name, so a typo such as
// create-if-missing fails loudly instead of being ignored.
func ParseQuery(q url.Values) (Options, error) {
	opts := Options{Remote: true}
	for key, values := range q {
		if !slices.Contains(RemoteParams, key) {
			return Options{}, optErr(key, "unknown parameter (remote MCP takes %s)", strings.Join(RemoteParams, ", "))
		}
		if len(values) != 1 {
			return Options{}, optErr(key, "give it once")
		}
		value := values[0]
		switch key {
		case "sandbox":
			opts.Sandbox = value
		case "image":
			opts.Image = value
		case "runtime":
			opts.Runtime = value
		case "toolsets":
			opts.Toolsets = ParseToolsets(value)
		case "create_if_missing", "read_only":
			b, err := strconv.ParseBool(value)
			if err != nil {
				return Options{}, optErr(key, "must be true or false, got %q", value)
			}
			if key == "create_if_missing" {
				opts.CreateIfMissing = b
			} else {
				opts.ReadOnly = b
			}
		}
	}
	return opts, opts.Validate()
}

// ParseToolsets splits a comma-separated toolset list ("core,files", "all").
func ParseToolsets(s string) []string {
	var out []string
	for part := range strings.SplitSeq(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func normaliseToolsets(in []string) ([]string, error) {
	if len(in) == 0 {
		return []string{ToolsetCore}, nil
	}
	set := map[string]bool{}
	for _, t := range in {
		t = strings.ToLower(strings.TrimSpace(t))
		switch {
		case t == "":
		case t == "all":
			for _, k := range knownToolsets {
				set[k] = true
			}
		case contains(knownToolsets, t):
			set[t] = true
		default:
			return nil, optErr("toolsets", "unknown toolset %q (want %s or all)", t, strings.Join(knownToolsets, ", "))
		}
	}
	if len(set) == 0 {
		return []string{ToolsetCore}, nil
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
}

func (o *Options) hasToolset(name string) bool { return contains(o.Toolsets, name) }

func (o *Options) pinned() bool { return o.Sandbox != "" }

// lifecycle is the idle policy for sandboxes this server creates.
func (o *Options) lifecycle(destroyOverride time.Duration) *models.Lifecycle {
	if o.Keep && destroyOverride <= 0 {
		return nil
	}
	lc := &models.Lifecycle{StopIfIdleFor: DefaultStopIfIdle, DestroyIfIdleFor: DefaultDestroyIfIdle}
	if o.Keep {
		lc.StopIfIdleFor = 0
	}
	if o.StopIfIdle > 0 {
		lc.StopIfIdleFor = o.StopIfIdle
	}
	if o.DestroyIfIdle > 0 {
		lc.DestroyIfIdleFor = o.DestroyIfIdle
	}
	if destroyOverride > 0 {
		lc.DestroyIfIdleFor = destroyOverride
	}
	return lc
}

func contains(list []string, s string) bool { return slices.Contains(list, s) }
