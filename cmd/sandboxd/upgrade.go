package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/aerol-ai/microvm/internal/nodeupgrade"
	"github.com/aerol-ai/microvm/scripts"
)

// `sandboxd upgrade node` replaces this node's binaries safely
// (plans/kubectl-style-cluster-ops.md §6.3). The steps live in
// internal/nodeupgrade; this file is the command line. Every way a binary
// gets replaced runs it: by hand, install.sh's re-run (eng D7), and the
// rollout and single-node routes, which launch it with systemd-run
// (nodeupgrade.Launch) so stopping sandboxd does not stop it.
const upgradeSubcommand = "upgrade"

// upgradeUsage starts with nodeupgrade.UpgradeCommandMarker: install.sh
// looks for that text in the installed binary before it runs the command.
const upgradeUsage = `usage: sandboxd upgrade node <version> --sha256 <file>=<hash> [--sha256 <file>=<hash>]...
                             [--from <dir>] [--rollback] [--op <id>] [-o text|json]

Replaces this node's sandboxd, toolboxd and caddy with <version>'s. Each file
is checked against its SHA-256 before anything stops. sandboxd is stopped
(Firecracker VMs and mount helpers keep running), the database is backed up,
the files are swapped with the old ones kept as *.prev, and sandboxd is
started and waited on until it reports <version>. If it does not come up, the
old files are put back. Run as root.

  --sha256 <file>=<hash>   a file to install, by its release asset name
                           (sandboxd_linux_amd64, toolboxd_linux_amd64,
                           caddy_linux_amd64, release.json) and its line in
                           the release's checksums.txt; sandboxd and toolboxd
                           are required
  --from <dir>             take the files from <dir> instead of downloading
                           them from SB_RELEASE_URL/<version>/
  --rollback               allow an older version; with no --sha256, put back
                           the *.prev files the last upgrade kept
  --allow-unversioned      allow a dev or test build whose version is not a
                           release tag (the downgrade check cannot order it)
  --skip-host-apply        the host setup of <version> is already applied
                           (install.sh passes this)
  --op <id>                the operation ID; a repeated ID answers with what
                           it did
  --health-timeout <dur>   how long to wait for the new sandboxd (default 2m)
  --allow-downtime         on a Raft server, stop it even if the servers left
                           up would not be a majority; without it the upgrade
                           refuses, and hands off leadership first if this
                           node leads
  --env-file <path>        the node's env file (default /etc/sandboxd/sandboxd.env)
  -o text|json             output; json prints the operation record

Exit status: 0 when the node runs <version> (or already did), 1 when the
upgrade failed (the previous files are back), 2 for a usage error.
`

// Seams for tests: the machine the command acts on.
var (
	newUpgradeHost      = func() nodeupgrade.Host { return &nodeupgrade.SystemHost{} }
	resolveUpgradePaths = func(envFile string) (nodeupgrade.Paths, error) {
		return nodeupgrade.ResolvePaths(envFile, os.Getenv, func() (string, error) { return exec.LookPath("caddy") })
	}
	upgradeSignalContext = signalContext
)

type shaFlags map[string]string

func (s shaFlags) String() string { return "" }

func (s shaFlags) Set(v string) error {
	name, sum, ok := strings.Cut(v, "=")
	if !ok || name == "" || sum == "" {
		return fmt.Errorf("--sha256 takes <file>=<hash>, got %q", v)
	}
	if _, dup := s[name]; dup {
		return fmt.Errorf("--sha256 names %s twice", name)
	}
	s[name] = sum
	return nil
}

// parseUpgradeArgs parses the arguments after `upgrade`. Flags may come
// before or after the version.
func parseUpgradeArgs(args []string) (req nodeupgrade.Request, envFile, output string, err error) {
	if len(args) == 0 || args[0] != "node" {
		for _, a := range args {
			if a == "-h" || a == "--help" || a == "help" {
				return req, "", "", flag.ErrHelp
			}
		}
		return req, "", "", errors.New("the only upgrade command is `sandboxd upgrade node`")
	}
	sums := shaFlags{}
	fs := flag.NewFlagSet("sandboxd upgrade node", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Var(sums, "sha256", "")
	fs.StringVar(&req.From, "from", "", "")
	fs.BoolVar(&req.Rollback, "rollback", false, "")
	fs.BoolVar(&req.AllowUnversioned, "allow-unversioned", false, "")
	fs.BoolVar(&req.SkipHostApply, "skip-host-apply", false, "")
	fs.StringVar(&req.Op, "op", "", "")
	fs.DurationVar(&req.HealthTimeout, "health-timeout", 0, "")
	fs.BoolVar(&req.AllowDowntime, "allow-downtime", false, "")
	fs.StringVar(&envFile, "env-file", nodeupgrade.DefaultEnvFile, "")
	fs.StringVar(&output, "o", "text", "")
	fs.StringVar(&output, "output", "text", "")
	rest := args[1:]
	var positional []string
	for {
		if err := fs.Parse(rest); err != nil {
			return req, "", "", err
		}
		if fs.NArg() == 0 {
			break
		}
		positional = append(positional, fs.Arg(0))
		rest = fs.Args()[1:]
	}
	switch len(positional) {
	case 0:
		return req, "", "", errors.New("missing <version>")
	case 1:
		req.Version = positional[0]
	default:
		return req, "", "", fmt.Errorf("unexpected argument %q", positional[1])
	}
	if output != "text" && output != "json" {
		return req, "", "", fmt.Errorf("-o must be text or json, got %q", output)
	}
	if len(sums) > 0 {
		req.SHA256 = sums
	}
	return req, envFile, output, nil
}

// runUpgradeCLI runs `sandboxd upgrade` with the args after it and returns
// the exit status.
func runUpgradeCLI(args []string, stdout, stderr io.Writer) int {
	req, envFile, output, err := parseUpgradeArgs(args)
	if errors.Is(err, flag.ErrHelp) {
		fmt.Fprint(stdout, upgradeUsage)
		return 0
	}
	if err != nil {
		fmt.Fprintf(stderr, "sandboxd upgrade: %v\n%s", err, upgradeUsage)
		return 2
	}
	paths, err := resolveUpgradePaths(envFile)
	if err != nil {
		fmt.Fprintf(stderr, "sandboxd upgrade node: %v\n", err)
		return 1
	}
	// With -o json the record is the only thing on stdout, so a caller
	// (install.sh) can read it; progress goes to stderr.
	progress := stdout
	if output == "json" {
		progress = stderr
	}
	u := &nodeupgrade.Upgrader{
		Paths:               paths,
		Host:                newUpgradeHost(),
		Out:                 progress,
		SelfHostSetupSHA256: scripts.InstallShSHA256(),
		BeforeStop:          serverStopGuard(paths, progress),
	}
	ctx, cancel := upgradeSignalContext()
	defer cancel()
	st, runErr := u.Run(ctx, req)
	if output == "json" && st != nil {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(st)
	}
	if runErr != nil {
		if errors.Is(runErr, nodeupgrade.ErrUsage) {
			fmt.Fprintf(stderr, "sandboxd upgrade node: %v\n%s", runErr, upgradeUsage)
			return 2
		}
		fmt.Fprintf(stderr, "sandboxd upgrade node: %v\n", runErr)
		return 1
	}
	if output == "text" {
		switch st.Result {
		case nodeupgrade.ResultNoop:
			fmt.Fprintf(stdout, "%s is already installed (op %s)\n", st.Version, st.Op)
		default:
			fmt.Fprintf(stdout, "upgraded to %s (op %s); the previous files are kept as *.prev\n", st.Version, st.Op)
		}
	}
	return 0
}

// signalContext is cancelled by SIGINT or SIGTERM. A cancelled upgrade
// still runs its failure path, which puts the previous files back.
func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
}
