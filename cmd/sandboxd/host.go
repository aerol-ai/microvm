package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/aerol-ai/microvm/internal/nodeupgrade"
	"github.com/aerol-ai/microvm/scripts"
)

// `sandboxd host apply` re-renders this node's configuration with the
// install.sh built into this binary (plans/kubectl-style-cluster-ops.md §7),
// in --config-only mode: it never replaces a binary, installs a package or
// restarts a service. The upgrader runs the new binary's copy when a
// release changes host setup (§6.3 step 7); an operator runs it after
// editing node.json.
const hostSubcommand = "host"

const hostUsage = `usage: sandboxd host apply [--env-file <path>] [--node-json <path>]

Re-renders this node's configuration (sandboxd.env, the Caddyfile, the
systemd units) from node.json with the install.sh built into this sandboxd,
run as install.sh --config-only. It downloads nothing, replaces no binary,
installs no package and starts or restarts no service; restart sandboxd to
use the new settings. Run as root.
`

// hostApplyScript is the install.sh host apply runs; tests replace it.
var hostApplyScript = scripts.InstallSh

// runHostCLI runs `sandboxd host` with the args after it and returns the
// exit status.
func runHostCLI(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "apply" {
		for _, a := range args {
			if a == "-h" || a == "--help" || a == "help" {
				fmt.Fprint(stdout, hostUsage)
				return 0
			}
		}
		fmt.Fprintf(stderr, "sandboxd host: the only command is `sandboxd host apply`\n%s", hostUsage)
		return 2
	}
	fs := flag.NewFlagSet("sandboxd host apply", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	envFile := fs.String("env-file", nodeupgrade.DefaultEnvFile, "")
	nodeJSON := fs.String("node-json", "", "")
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, hostUsage)
			return 0
		}
		fmt.Fprintf(stderr, "sandboxd host apply: %v\n%s", err, hostUsage)
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "sandboxd host apply: unexpected argument %q\n%s", fs.Arg(0), hostUsage)
		return 2
	}
	paths, err := resolveUpgradePaths(*envFile)
	if err != nil {
		fmt.Fprintf(stderr, "sandboxd host apply: %v\n", err)
		return 1
	}
	if *nodeJSON == "" {
		*nodeJSON = paths.NodeJSON
	}
	err = nodeupgrade.HostApply(context.Background(), nodeupgrade.HostApplyOptions{
		Script:   hostApplyScript,
		NodeJSON: *nodeJSON,
		StateDir: paths.StateDir,
		Host:     newUpgradeHost(),
		Out:      stdout,
	})
	if err != nil {
		fmt.Fprintf(stderr, "sandboxd host apply: %v\n", err)
		return 1
	}
	return 0
}
