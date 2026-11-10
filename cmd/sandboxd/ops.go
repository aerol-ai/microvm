package main

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/aerol-ai/microvm/internal/nodeops"
	"github.com/aerol-ai/microvm/internal/version"
)

// `sandboxd backup`, `restore` and `recover-quorum` are the node's day-2
// tools (plans/kubectl-style-cluster-ops.md §3.1, Phase 5): they replace
// scripts/sandboxd-backup.sh, sandboxd-restore.sh and
// raft-lost-quorum-recover.sh, which now only call them. The work lives in
// internal/nodeops; this file is the command line. Like upgrade, none of
// them falls through to the daemon boot.
const (
	backupSubcommand        = "backup"
	restoreSubcommand       = "restore"
	recoverQuorumSubcommand = "recover-quorum"
)

// Each usage starts with "usage: sandboxd <command>": the wrapper scripts
// look for that text in the installed binary before they run it, because a
// sandboxd from before the command would boot a second daemon instead.
const backupUsage = `usage: sandboxd backup --output <file.tar.gz> [--stop]
                       [--config-dir <dir>] [--state-db <path>] [--raft-dir <dir>]
                       [--key-file <path>] [--key-ring <path>] [--wrapped-key <path>]

Writes this node's database, Raft data, config directory (/etc/sandboxd) and
server key to one gzipped tar, mode 0600. The database is copied with VACUUM
INTO, so a backup taken while sandboxd runs is consistent. With key custody
"wrapped" the archive carries the wrapped key and no plaintext key line;
otherwise it carries the plaintext key file and ring, so store it as a
secret. Every path defaults to what this node's env files say. Run as root.

  --output <file>     the archive to write (required); replaced in one rename
  --stop              stop sandboxd for the copy and start it again after, so
                      the Raft files are copied at rest
  --config-dir <dir>  the config directory to read and back up (default /etc/sandboxd)
  --state-db, --raft-dir, --key-file, --key-ring, --wrapped-key
                      override a source path

Exit status: 0 on success, 1 when the backup failed, 2 for a usage error.
`

const restoreUsage = `usage: sandboxd restore --input <file.tar.gz> --force [--target-root <dir>] [--start]

Restores an archive from sandboxd backup (or sandboxd-backup.sh). The
database, its WAL, the Raft directory and the server-key files it replaces
are moved aside as <name>.pre-restore-<time>, never deleted; config files are
overwritten. The whole archive is checked before anything changes. Into /
it refuses while sandboxd runs. Run as root.

  --input <file>        the archive (required)
  --force               required: confirms this is the node to overwrite
  --target-root <dir>   restore under <dir> instead of / (default /)
  --start               start sandboxd afterwards and wait for /health
  --health-timeout <d>  how long --start waits (default 2m)

Exit status: 0 on success, 1 when the restore failed, 2 for a usage error.
`

const recoverQuorumUsage = `usage: sandboxd recover-quorum [--node-id <id>] [--raft-address <host:port>] [--start]
                               [--force] [--no-backup] [--backup-output <file>]
       sandboxd recover-quorum --rejoin [--start]

Last resort for a cluster that lost most of its servers for good
(setup/runbooks/lost-quorum-recovery.md). On the one surviving server you
chose, with sandboxd stopped on every survivor, it backs the node up and
writes peers.json, which makes this server the only voter when sandboxd
starts. Entries only this server had become committed. Run as root.

  --node-id <id>          this node's ID (default SB_NODE_ID)
  --raft-address <addr>   the Raft address other servers dial (default
                          SB_RAFT_ADVERTISE_ADDR)
  --raft-dir <dir>        the Raft data directory (default SB_RAFT_DATA_DIR)
  --force                 overwrite an existing peers.json
  --no-backup             skip the backup taken first
  --backup-output <file>  where that backup goes (default
                          <state dir>/backups/pre-recover-quorum-<host>-<time>.tar.gz)
  --start                 start sandboxd and wait until the recovery is applied
  --timeout <d>           how long --start waits (default 3m)
  --rejoin                on each other server, once the survivor leads: move
                          the stale Raft directory aside so the server rejoins
                          as a new voter
  --config-dir <dir>      where sandboxd.env and cluster.env are (default /etc/sandboxd)

Exit status: 0 on success, 1 when it failed, 2 for a usage error.
`

// newOpsHost is the machine the commands act on; tests replace it.
var newOpsHost = func() nodeops.Host { return newUpgradeHost() }

// opsFlags is a flag set that reads --help itself and keeps quiet.
func opsFlags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

// parseOps parses args and reports the exit status for a help or usage
// error; ok means go on.
func parseOps(fs *flag.FlagSet, args []string, usage string, stdout, stderr io.Writer) (code int, ok bool) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, usage)
			return 0, false
		}
		fmt.Fprintf(stderr, "%s: %v\n%s", fs.Name(), err, usage)
		return 2, false
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "%s: unexpected argument %q\n%s", fs.Name(), fs.Arg(0), usage)
		return 2, false
	}
	return 0, true
}

// opsExit turns a command's error into its exit status.
func opsExit(name string, err error, usage string, stderr io.Writer) int {
	if err == nil {
		return 0
	}
	if errors.Is(err, nodeops.ErrUsage) {
		fmt.Fprintf(stderr, "%s: %v\n%s", name, err, usage)
		return 2
	}
	fmt.Fprintf(stderr, "%s: %v\n", name, err)
	return 1
}

func runBackupCLI(args []string, stdout, stderr io.Writer) int {
	var o nodeops.BackupOptions
	fs := opsFlags("sandboxd backup")
	fs.StringVar(&o.Output, "output", "", "")
	fs.BoolVar(&o.Stop, "stop", false, "")
	fs.StringVar(&o.ConfigDir, "config-dir", "", "")
	fs.StringVar(&o.StateDB, "state-db", "", "")
	fs.StringVar(&o.RaftDir, "raft-dir", "", "")
	fs.StringVar(&o.KeyFile, "key-file", "", "")
	fs.StringVar(&o.KeyRing, "key-ring", "", "")
	fs.StringVar(&o.WrappedKey, "wrapped-key", "", "")
	if code, ok := parseOps(fs, args, backupUsage, stdout, stderr); !ok {
		return code
	}
	o.Host, o.Out, o.Version = newOpsHost(), stdout, version.Version
	ctx, cancel := upgradeSignalContext()
	defer cancel()
	_, err := nodeops.Backup(ctx, o)
	return opsExit("sandboxd backup", err, backupUsage, stderr)
}

func runRestoreCLI(args []string, stdout, stderr io.Writer) int {
	var o nodeops.RestoreOptions
	fs := opsFlags("sandboxd restore")
	fs.StringVar(&o.Input, "input", "", "")
	fs.StringVar(&o.TargetRoot, "target-root", "/", "")
	fs.BoolVar(&o.Force, "force", false, "")
	fs.BoolVar(&o.Start, "start", false, "")
	fs.DurationVar(&o.HealthTimeout, "health-timeout", 0, "")
	if code, ok := parseOps(fs, args, restoreUsage, stdout, stderr); !ok {
		return code
	}
	o.Host, o.Out, o.Err = newOpsHost(), stdout, stderr
	ctx, cancel := upgradeSignalContext()
	defer cancel()
	_, err := nodeops.Restore(ctx, o)
	return opsExit("sandboxd restore", err, restoreUsage, stderr)
}

func runRecoverQuorumCLI(args []string, stdout, stderr io.Writer) int {
	var o nodeops.QuorumOptions
	fs := opsFlags("sandboxd recover-quorum")
	fs.StringVar(&o.ConfigDir, "config-dir", "", "")
	fs.StringVar(&o.RaftDir, "raft-dir", "", "")
	fs.StringVar(&o.NodeID, "node-id", "", "")
	fs.StringVar(&o.RaftAddress, "raft-address", "", "")
	fs.BoolVar(&o.Force, "force", false, "")
	fs.BoolVar(&o.Rejoin, "rejoin", false, "")
	fs.BoolVar(&o.NoBackup, "no-backup", false, "")
	fs.StringVar(&o.BackupOutput, "backup-output", "", "")
	fs.BoolVar(&o.Start, "start", false, "")
	fs.DurationVar(&o.Timeout, "timeout", 0, "")
	if code, ok := parseOps(fs, args, recoverQuorumUsage, stdout, stderr); !ok {
		return code
	}
	o.Host, o.Out, o.Version = newOpsHost(), stdout, version.Version
	ctx, cancel := upgradeSignalContext()
	defer cancel()
	_, err := nodeops.RecoverQuorum(ctx, o)
	return opsExit("sandboxd recover-quorum", err, recoverQuorumUsage, stderr)
}

// opsCommands maps each subcommand to its runner, for main.
var opsCommands = map[string]func(args []string, stdout, stderr io.Writer) int{
	backupSubcommand:        runBackupCLI,
	restoreSubcommand:       runRestoreCLI,
	recoverQuorumSubcommand: runRecoverQuorumCLI,
}
