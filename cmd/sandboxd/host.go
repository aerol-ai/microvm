package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aerol-ai/microvm/internal/network/buildnet"
	"github.com/aerol-ai/microvm/internal/network/cni"
	"github.com/aerol-ai/microvm/internal/network/netns"
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
       sandboxd host build-network up|down [--cni-conf <path>] [--cni-plugin-dir <dir>] [--resolv-conf <path>]

apply re-renders this node's configuration (sandboxd.env, the Caddyfile,
the systemd units) from node.json with the install.sh built into this
sandboxd, run as install.sh --config-only. It downloads nothing, replaces
no binary, installs no package and starts or restarts no service; restart
sandboxd to use the new settings.

build-network up makes rootless BuildKit's network namespace (aerolvm.build)
on the sandboxes' bridge, or keeps the one there, and writes its
resolv.conf; down removes it. install.sh's aerolvm-build-net.service runs
it. The CNI settings default to SB_CONTAINERD_CNI_CONF_PATH and
SB_CONTAINERD_CNI_PLUGIN_DIR, as sandboxd reads them.

Run as root.
`

// hostApplyScript is the install.sh host apply runs; tests replace it.
var hostApplyScript = scripts.InstallSh

// runHostCLI runs `sandboxd host` with the args after it and returns the
// exit status.
func runHostCLI(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "build-network" {
		return runBuildNetworkCLI(args[1:], stdout, stderr)
	}
	if len(args) == 0 || args[0] != "apply" {
		for _, a := range args {
			if a == "-h" || a == "--help" || a == "help" {
				fmt.Fprint(stdout, hostUsage)
				return 0
			}
		}
		fmt.Fprintf(stderr, "sandboxd host: the commands are `sandboxd host apply` and `sandboxd host build-network`\n%s", hostUsage)
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

// Seams for the build-network command's tests: the real ones touch the
// host's namespaces and run CNI plugins.
var (
	buildNetworkHost = func(confPath, pluginDir string) (buildnet.Host, error) {
		runner, err := cni.NewExecRunner(cni.Config{PluginDir: pluginDir, ConfPath: confPath})
		if err != nil {
			return nil, err
		}
		return &netns.Host{Runner: runner}, nil
	}
	buildNetworkSubnet = cni.BridgeSubnet
	buildNetworkUp     = buildnet.Up
	buildNetworkDown   = buildnet.Down
)

// runBuildNetworkCLI runs `sandboxd host build-network up|down`.
func runBuildNetworkCLI(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || (args[0] != "up" && args[0] != "down") {
		for _, a := range args {
			if a == "-h" || a == "--help" || a == "help" {
				fmt.Fprint(stdout, hostUsage)
				return 0
			}
		}
		fmt.Fprintf(stderr, "sandboxd host build-network: want up or down\n%s", hostUsage)
		return 2
	}
	verb := args[0]
	fs := flag.NewFlagSet("sandboxd host build-network "+verb, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	conf := fs.String("cni-conf", envOr("SB_CONTAINERD_CNI_CONF_PATH", "/etc/cni/net.d/aerolvm.conflist"), "")
	plugins := fs.String("cni-plugin-dir", envOr("SB_CONTAINERD_CNI_PLUGIN_DIR", "/opt/cni/bin"), "")
	resolv := fs.String("resolv-conf", buildnet.DefaultResolvConf, "")
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, hostUsage)
			return 0
		}
		fmt.Fprintf(stderr, "sandboxd host build-network %s: %v\n%s", verb, err, hostUsage)
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "sandboxd host build-network %s: unexpected argument %q\n%s", verb, fs.Arg(0), hostUsage)
		return 2
	}
	host, err := buildNetworkHost(*conf, *plugins)
	if err != nil {
		fmt.Fprintf(stderr, "sandboxd host build-network %s: %v\n", verb, err)
		return 1
	}
	cfg := buildnet.Config{Host: host, ResolvConf: *resolv}
	ctx := context.Background()
	if verb == "down" {
		if err := buildNetworkDown(ctx, cfg); err != nil {
			fmt.Fprintf(stderr, "sandboxd host build-network down: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "build network %s removed\n", buildnet.Name)
		return 0
	}
	if cfg.Subnet, err = buildNetworkSubnet(*conf); err != nil {
		fmt.Fprintf(stderr, "sandboxd host build-network up: the sandboxes' range: %v\n", err)
		return 1
	}
	res, err := buildNetworkUp(ctx, cfg)
	if err != nil {
		fmt.Fprintf(stderr, "sandboxd host build-network up: %v\n", err)
		return 1
	}
	state := "kept"
	if res.Built {
		state = "built"
	}
	fmt.Fprintf(stdout, "build network %s %s: %s, address %s\n", buildnet.Name, state, res.Path, res.IP)
	return 0
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}
