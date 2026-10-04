// Command aerolvm drives AerolVM sandboxes from a shell or an AI agent: the
// agent-friendly CLI and, as `aerolvm mcp`, an MCP server over stdio
// (plans/mcp-server-and-agent-cli.md).
//
// The CLI contract is the feature (§5.2): never interactive; stdout is data
// and stderr is everything else; --json on every verb; machine-readable
// errors; exit codes that agents already know from `docker exec` and GNU
// `timeout`; any sandbox addressed as <id-or-name>; retries are safe.
//
// It is a thin static client over the Go SDK and internal/agenttools. A test
// keeps every server package out of its dependency graph.
package main

import (
	"context"
	"os"
)

func main() {
	os.Exit(newApp().run(context.Background(), os.Args[1:]))
}
