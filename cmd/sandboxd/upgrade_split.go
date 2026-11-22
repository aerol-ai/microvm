package main

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/aerol-ai/microvm/internal/nodeupgrade"
)

// Two upgrade commands for a VM in privilege mode split
// (plans/security-gaps-m1-m4.md M1 PR 10). There sandboxd runs as a user
// with no rights, so the root work of an upgrade happens outside it:
//
//   - `sandboxd upgrade recover` settles an upgrade the machine lost half
//     way, which sandboxd does itself at start in privilege mode single
//     (pkg/daemon recoverInterruptedUpgrade). sandboxd.service runs it as
//     root before sandboxd starts (ExecStartPre=-+).
//   - `sandboxd upgrade root-helper --from <dir>` installs the signed root
//     helper staged in <dir>: install.sh's path on a fresh node and on a
//     node it switches to split. `sandboxd upgrade node` installs the
//     helper the same way, with the same check.
const (
	upgradeRecoverCommand    = "recover"
	upgradeRootHelperCommand = "root-helper"
)

const upgradeSplitUsage = `usage: sandboxd upgrade recover [--env-file <path>]
       sandboxd upgrade root-helper --from <dir> [--dir <dir>] [--allow-older] [--env-file <path>]

recover settles an upgrade this machine lost half way (a reboot, a killed
upgrader): every new file in place marks it done, anything else puts the
previous files back. In privilege mode split sandboxd.service runs it as
root before sandboxd starts.

root-helper installs the root helper staged in <dir> (aerolvm-rootd,
aerolvm-rootd.manifest, aerolvm-rootd.sig) once its manifest is signed by a
release key built into this sandboxd and names that binary, and, unless
--allow-older, it is no older than the helper installed now. <dir> must be
root's and closed to others. The helper goes to --dir, else SB_ROOTD_BIN_DIR
(` + nodeupgrade.DefaultRootdDir + `); restart aerolvm-rootd.service to run it.
Sandboxes keep running across that restart.

Run as root.
`

// Seams for tests.
var (
	recoverUpgrades   = nodeupgrade.Recover
	installRootHelper = nodeupgrade.InstallRootHelper
)

func runUpgradeRecover(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sandboxd upgrade recover", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	envFile := fs.String("env-file", nodeupgrade.DefaultEnvFile, "")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, upgradeSplitUsage)
			return 0
		}
		fmt.Fprintf(stderr, "sandboxd upgrade recover: %v\n%s", err, upgradeSplitUsage)
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "sandboxd upgrade recover: unexpected argument %q\n%s", fs.Arg(0), upgradeSplitUsage)
		return 2
	}
	paths, err := resolveUpgradePaths(*envFile)
	if err != nil {
		fmt.Fprintf(stderr, "sandboxd upgrade recover: %v\n", err)
		return 1
	}
	ctx, cancel := upgradeSignalContext()
	defer cancel()
	results, err := recoverUpgrades(ctx, paths.StateDir, newUpgradeHost(), stdout)
	if err != nil {
		fmt.Fprintf(stderr, "sandboxd upgrade recover: %v\n", err)
		return 1
	}
	code := 0
	for _, r := range results {
		if r.Err != nil {
			fmt.Fprintf(stderr, "sandboxd upgrade recover: op %s (%s): %v\n", r.Op, r.Result, r.Err)
			code = 1
			continue
		}
		fmt.Fprintf(stdout, "op %s: %s\n", r.Op, r.Result)
	}
	return code
}

func runUpgradeRootHelper(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sandboxd upgrade root-helper", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	from := fs.String("from", "", "")
	allowOlder := fs.Bool("allow-older", false, "")
	into := fs.String("dir", "", "")
	envFile := fs.String("env-file", nodeupgrade.DefaultEnvFile, "")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, upgradeSplitUsage)
			return 0
		}
		fmt.Fprintf(stderr, "sandboxd upgrade root-helper: %v\n%s", err, upgradeSplitUsage)
		return 2
	}
	if fs.NArg() > 0 || *from == "" {
		fmt.Fprintf(stderr, "sandboxd upgrade root-helper: name the staged helper's folder with --from\n%s", upgradeSplitUsage)
		return 2
	}
	paths, err := resolveUpgradePaths(*envFile)
	if err != nil {
		fmt.Fprintf(stderr, "sandboxd upgrade root-helper: %v\n", err)
		return 1
	}
	dir := paths.RootdDir
	if *into != "" {
		dir = *into
	}
	if dir == "" {
		// The node is not split yet: install.sh installs the helper before
		// it writes SB_PRIVILEGE_MODE=split.
		dir = nodeupgrade.DefaultRootdDir
	}
	res, err := installRootHelper(*from, dir, *allowOlder)
	if err != nil {
		fmt.Fprintf(stderr, "sandboxd upgrade root-helper: %v\n", err)
		return 1
	}
	if res.Changed {
		fmt.Fprintf(stdout, "installed root helper %s (API %d) in %s; signature checked\n", res.Manifest.Version, res.Manifest.API, dir)
	} else {
		fmt.Fprintf(stdout, "root helper %s is already installed in %s\n", res.Manifest.Version, dir)
	}
	return 0
}
