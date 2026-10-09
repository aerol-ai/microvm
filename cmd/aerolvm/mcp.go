package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/aerol-ai/microvm/internal/agentmcp"
	"github.com/aerol-ai/microvm/internal/agenttools"
)

const mcpHelp = `Run the AerolVM MCP server over stdio, for Claude Code, Claude Desktop,
Cursor, VS Code and other MCP clients.

Usage: aerolvm mcp [flags]
       aerolvm mcp config <claude-code|claude-desktop|cursor|vscode> [flags]

"config" prints the setup snippet for a client (it never prints your token
and never edits the client's files).

Pinned mode gives the model one sandbox and nothing else: the sandbox
argument disappears from every tool and the create/list/destroy tools are
not offered. With --create-if-missing the sandbox is created on the first
tool call that needs it, not at startup, and recreated (the model is told)
if it disappears.

Flags:
  --sandbox NAME        pin the server to this sandbox
  --create-if-missing   create the pinned sandbox if it doesn't exist
  --image I             image for the created sandbox
  --runtime R           runtime for the created sandbox
  --allow-host H        limit the created sandbox's outbound network to these
                        destinations (repeatable or comma list): a host,
                        *.domain, host:port or CIDR
  --toolsets LIST       core (default), files, process, or all (comma list)
  --read-only           offer only tools that change nothing
  --ephemeral           destroy the pinned sandbox when the server exits
  --keep                don't stop/destroy created sandboxes when idle
  --stop-if-idle D      idle stop for created sandboxes (default 30m)
  --destroy-if-idle D   idle destroy for created sandboxes (default 24h)
  --max-creates N       creates allowed per session when not pinned
                        (default 5, 0 = unlimited)
  --max-output-bytes N  exec output kept per stream (default 16384)
  --debug               log API requests to stderr (the token is redacted)

Examples:
  aerolvm mcp --sandbox my-agent --create-if-missing --image python:3.12
  aerolvm mcp --toolsets all
  aerolvm mcp config claude-code --sandbox my-agent --create-if-missing
`

func runMCP(ctx context.Context, a *app, args []string) int {
	if len(args) > 0 && args[0] == "config" {
		return runMCPConfig(a, args[1:])
	}
	fs, c := a.newFlagSet("mcp")
	parse := agentmcp.BindFlags(fs)
	pos, _, err := parseArgs(fs, args)
	if err != nil {
		return a.flagError(c, "mcp", err)
	}
	if len(pos) > 0 {
		return a.usageError(c, "mcp", "unexpected argument %q", pos[0])
	}
	opts, err := parse()
	if err != nil {
		return a.optionError(c, err)
	}
	conn, err := a.connection()
	if err != nil {
		return a.fail(c, err, exitError)
	}
	cfg := agenttools.Config{
		APIURL: conn.apiURL,
		Token:  conn.token,
		Source: agenttools.SourceMCP,
		// stdout is the JSON-RPC channel: every notice goes to stderr.
		Warn: func(s string) { a.note("aerolvm mcp: %s", s) },
	}
	if c.debug {
		cfg.HTTPClient = debugHTTPClient(a.stderr)
	}
	tools, err := a.newTools(cfg)
	if err != nil {
		return a.fail(c, err, exitError)
	}
	server, err := agentmcp.New(tools, opts, versionString())
	if err != nil {
		return a.optionError(c, err)
	}

	// Stdin EOF (the host closed the pipe) and SIGTERM both end the run;
	// either way the clean-shutdown work runs once.
	runCtx, received, stop := a.notifySignals(ctx)
	defer stop()
	transport := &mcp.IOTransport{Reader: io.NopCloser(a.stdin), Writer: nopWriteCloser{a.stdout}}
	runErr := server.Run(runCtx, transport)
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		a.note("aerolvm mcp: --ephemeral cleanup failed (the idle lifecycle will remove the sandbox): %v", err)
	}
	if received() != nil || runErr == nil || errors.Is(runErr, context.Canceled) || errors.Is(runErr, io.EOF) {
		return exitOK
	}
	a.note("aerolvm mcp: %v", runErr)
	return exitError
}

// optionError reports an invalid option by its flag name.
func (a *app) optionError(c *commonFlags, err error) int {
	var oe *agentmcp.OptionError
	if errors.As(err, &oe) {
		return a.usageError(c, "mcp", "%s: %s", oe.Flag(), oe.Message)
	}
	return a.usageError(c, "mcp", "%v", err)
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

var mcpClients = []string{"claude-code", "claude-desktop", "cursor", "vscode"}

// runMCPConfig prints a client's setup for `aerolvm mcp`. The token is
// referenced, never copied: an env reference where the client expands one,
// a prompt or a placeholder where it doesn't. It writes nothing to disk;
// client config formats change, and the file is the user's to edit.
func runMCPConfig(a *app, args []string) int {
	fs, c := a.newFlagSet("mcp config")
	parse := agentmcp.BindFlags(fs)
	pos, _, err := parseArgs(fs, args)
	if err != nil {
		return a.flagError(c, "mcp", err)
	}
	if len(pos) != 1 || !slices.Contains(mcpClients, pos[0]) {
		return a.usageError(c, "mcp", "usage: aerolvm mcp config <%s>", strings.Join(mcpClients, "|"))
	}
	if _, err := parse(); err != nil {
		return a.optionError(c, err)
	}
	serverArgs := append([]string{"mcp"}, explicitFlags(fs)...)
	// After `aerolvm login` the server reads the saved login itself, so the
	// client config needs no URL or token at all.
	if conn, err := a.connection(); err == nil && conn.saved {
		a.printMCPConfigForLogin(pos[0], serverArgs, conn)
		return exitOK
	}
	apiURL := strings.TrimSpace(a.getenv("SB_API_URL"))
	if apiURL == "" {
		apiURL = defaultAPIURL
	}
	switch pos[0] {
	case "claude-code":
		fmt.Fprintf(a.stdout, "claude mcp add aerolvm -e SB_API_URL=%s -e SB_PAT_TOKEN=\"$SB_PAT_TOKEN\" -- aerolvm %s\n", shellQuote(apiURL), shellArgs(serverArgs))
		a.note("run it in a shell where SB_PAT_TOKEN is set; the shell fills in the token")
	case "claude-desktop":
		a.printJSON(map[string]any{"mcpServers": map[string]any{"aerolvm": map[string]any{
			"command": "aerolvm", "args": serverArgs,
			"env": map[string]string{"SB_API_URL": apiURL, "SB_PAT_TOKEN": "<paste your AerolVM token>"},
		}}})
		a.note("add this to claude_desktop_config.json and replace the token placeholder")
	case "cursor":
		a.printJSON(map[string]any{"mcpServers": map[string]any{"aerolvm": map[string]any{
			"command": "aerolvm", "args": serverArgs,
			"env": map[string]string{"SB_API_URL": apiURL, "SB_PAT_TOKEN": "${env:SB_PAT_TOKEN}"},
		}}})
		a.note("add this to .cursor/mcp.json; Cursor reads SB_PAT_TOKEN from your environment")
	case "vscode":
		a.printJSON(map[string]any{
			"inputs": []map[string]any{{"type": "promptString", "id": "aerolvm-token", "description": "AerolVM API token", "password": true}},
			"servers": map[string]any{"aerolvm": map[string]any{
				"type": "stdio", "command": "aerolvm", "args": serverArgs,
				"env": map[string]string{"SB_API_URL": apiURL, "SB_PAT_TOKEN": "${input:aerolvm-token}"},
			}},
		})
		a.note("add this to .vscode/mcp.json; VS Code asks for the token once and stores it securely")
	}
	return exitOK
}

// printMCPConfigForLogin prints a client's setup with no credentials in it:
// the server finds the saved login on its own.
func (a *app) printMCPConfigForLogin(client string, serverArgs []string, conn connection) {
	server := map[string]any{"command": "aerolvm", "args": serverArgs}
	switch client {
	case "claude-code":
		fmt.Fprintf(a.stdout, "claude mcp add aerolvm -- aerolvm %s\n", shellArgs(serverArgs))
	case "claude-desktop", "cursor":
		a.printJSON(map[string]any{"mcpServers": map[string]any{"aerolvm": server}})
	case "vscode":
		server["type"] = "stdio"
		a.printJSON(map[string]any{"servers": map[string]any{"aerolvm": server}})
	}
	a.note("the server uses your aerolvm login (%s, saved in %s); nothing secret is in this config", conn.apiURL, conn.from)
}

func shellArgs(args []string) string {
	quoted := make([]string, len(args))
	for i, arg := range args {
		quoted[i] = shellQuote(arg)
	}
	return strings.Join(quoted, " ")
}

// explicitFlags renders the server flags the user set, in flag order, so the
// printed config runs the server the same way.
func explicitFlags(fs *flag.FlagSet) []string {
	var out []string
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "json" || f.Name == "debug" {
			return
		}
		if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
			if v, _ := strconv.ParseBool(f.Value.String()); v {
				out = append(out, "--"+f.Name)
			}
			return
		}
		out = append(out, "--"+f.Name, f.Value.String())
	})
	return out
}
