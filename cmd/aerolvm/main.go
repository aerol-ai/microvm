// Command aerolvm drives AerolVM sandboxes from a terminal, a script or an AI
// agent: the agent-friendly CLI and, as `aerolvm mcp`, an MCP server over
// stdio (plans/mcp-server-and-agent-cli.md).
//
// The CLI contract is the feature (§5.2): never interactive, except for
// `shell`, which exists to be typed into and refuses to run without a
// terminal (shell.go); stdout is data
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

// main never reads os.Args[0]. Installed as kubectl-aerolvm (Krew, or a copy
// on PATH), `kubectl aerolvm get nodes` runs this binary under that name with
// the same arguments, and it must behave exactly as aerolvm
// (plans/kubectl-style-cluster-ops.md D13; TestKubectlPluginName).
func main() {
	os.Exit(newApp().run(context.Background(), os.Args[1:]))
}
