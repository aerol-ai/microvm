// Package agenttools is the operation layer the aerolvm CLI and the aerolvm
// MCP server share (plans/mcp-server-and-agent-cli.md §5.1). It holds the
// behaviour that has to be identical in both front ends: how a "<id-or-name>"
// reference resolves, idempotent create, output bounds, and error codes.
//
// It talks to sandboxd only through the Go SDK (sdk/go/pkg/microvm) and
// imports nothing from the server tree, so the CLI stays a small static
// binary. Each front end keeps its own surface on top: the CLI has
// positional args, stdin and live output; MCP has JSON schemas and bounded
// results.
package agenttools

import (
	"net/http"
	"strings"

	"github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// Source records which front end created a sandbox.
type Source string

const (
	SourceCLI Source = "cli"
	SourceMCP Source = "mcp"
)

// CreatedByTag is added to every sandbox the CLI or MCP server creates
// (CEO review C6) so agent usage and cleanup are visible with the existing
// tag filters. A value the caller sets explicitly wins.
const CreatedByTag = "aerolvm.created_by"

// Config builds a Tools.
type Config struct {
	// APIURL and Token default to SB_API_URL and SB_PAT_TOKEN, the same
	// variables every SDK reads.
	APIURL string
	Token  string
	Source Source
	// HTTPClient overrides the transport: the --debug logger, the remote
	// MCP endpoint's in-process transport, and tests.
	HTTPClient *http.Client
	// Warn receives non-fatal notices, such as an existing sandbox whose
	// image differs from a create request. Nil discards them.
	Warn func(string)
}

// Tools runs agent operations against one sandboxd.
type Tools struct {
	client  *microvm.Client
	apiURL  string
	source  Source
	warn    func(string)
	newName func() (string, error)
}

// New connects to sandboxd. Nothing is sent until the first operation.
func New(cfg Config) (*Tools, error) {
	client, err := microvm.NewClientWithConfig(&sdktypes.MicroVMConfig{
		APIUrl:     cfg.APIURL,
		PATToken:   cfg.Token,
		HTTPClient: cfg.HTTPClient,
	})
	if err != nil {
		return nil, &Error{Code: CodeUnauthorized, Message: "no API token: set SB_PAT_TOKEN", cause: err}
	}
	source := cfg.Source
	if source == "" {
		source = SourceCLI
	}
	warn := cfg.Warn
	if warn == nil {
		warn = func(string) {}
	}
	return &Tools{client: client, apiURL: strings.TrimSpace(cfg.APIURL), source: source, warn: warn, newName: autoName}, nil
}

// Client is the underlying SDK client, for operations agenttools doesn't
// wrap (start/stop, snapshots, health).
func (t *Tools) Client() *microvm.Client { return t.client }

// Source reports which front end this Tools creates sandboxes for.
func (t *Tools) Source() Source { return t.source }
