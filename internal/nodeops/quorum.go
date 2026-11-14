package nodeops

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/raftlogdir"
)

// peersFile is the file sandboxd's Raft setup reads at boot for lost-quorum
// recovery (internal/cluster/raft_recovery.go). Once applied, it is renamed
// peers.json.applied.<unix>.
const peersFile = "peers.json"

// raftStateNames are the files and directories internal/cluster/raft.go
// keeps in a Raft data directory. One of them means there is a log to
// recover; none means a wrong --raft-dir.
var raftStateNames = []string{"raft-stable.bolt", "raft-log.bolt", "raft-wal", "snapshots"}

// nodeIDPattern is internal/config's SB_NODE_ID rule.
var nodeIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// QuorumOptions is one `sandboxd recover-quorum`.
type QuorumOptions struct {
	ConfigDir string
	// RaftDir, NodeID and RaftAddress default to this node's own
	// (SB_RAFT_DATA_DIR, SB_NODE_ID, SB_RAFT_ADVERTISE_ADDR).
	RaftDir     string
	NodeID      string
	RaftAddress string
	// Force overwrites an existing peers.json.
	Force bool
	// Rejoin is the other half of the runbook, run on each lost server
	// once the survivor leads: its stale Raft directory is moved aside, so
	// it comes back as a new member instead of voting with an old
	// configuration.
	Rejoin bool
	// BackupOutput is where the backup taken before peers.json goes; empty
	// picks <state dir>/backups/pre-recover-quorum-<host>-<time>.tar.gz.
	BackupOutput string
	NoBackup     bool
	// Start starts sandboxd afterwards and waits until the recovery is
	// applied (or, with Rejoin, until /health answers).
	Start   bool
	Timeout time.Duration
	Version string
	Host    Host
	Out     io.Writer

	now      func() time.Time
	hostname func() (string, error)
	poll     time.Duration
}

// QuorumResult says what recover-quorum wrote.
type QuorumResult struct {
	PeersFile string
	Backup    string
	// Applied is the peers.json.applied.<unix> sandboxd renamed it to.
	Applied string
	// MovedAside is the stale Raft directory a rejoin kept.
	MovedAside string
	// MovedAsideLog is its log, kept beside its own directory when
	// SB_RAFT_WAL_DIR put it on a disk of its own.
	MovedAsideLog string
}

// peer is one server in peers.json, in the script's field order.
type peer struct {
	ID       string `json:"id"`
	Address  string `json:"address"`
	NonVoter bool   `json:"non_voter"`
	Suffrage string `json:"suffrage"`
}

// RecoverQuorum makes this server the only voter of its Raft log, for a
// cluster that lost most of its servers for good
// (setup/runbooks/lost-quorum-recovery.md). It writes peers.json, which
// sandboxd applies at its next start. It refuses while sandboxd runs here,
// on a node that keeps no Raft log, and with a node ID other than this
// node's, and it backs the node up first.
func RecoverQuorum(ctx context.Context, o QuorumOptions) (QuorumResult, error) {
	o.defaults()
	var res QuorumResult
	node, err := ReadNode(o.ConfigDir)
	if err != nil {
		return res, err
	}
	if !holdsRaft(node.NodeRole) {
		return res, fmt.Errorf("this node's role is %q; only a server keeps a Raft log", node.NodeRole)
	}
	fill(&o.RaftDir, node.RaftDir)
	if o.Rejoin {
		return rejoin(ctx, o, node)
	}
	fill(&o.NodeID, node.NodeID)
	fill(&o.RaftAddress, node.RaftAddress)
	if o.NodeID == "" || o.RaftAddress == "" {
		return res, usageErr("--node-id and --raft-address are required (this node's env files set neither SB_NODE_ID nor SB_RAFT_ADVERTISE_ADDR)")
	}
	if !nodeIDPattern.MatchString(o.NodeID) {
		return res, usageErr("--node-id %q is not a node ID", o.NodeID)
	}
	if node.NodeID != "" && o.NodeID != node.NodeID {
		// Raft knows this node by SB_NODE_ID. A peers.json naming another
		// ID leaves it out of its own configuration, with no leader ever.
		return res, usageErr("--node-id %s is not this node: its SB_NODE_ID is %s; run recover-quorum on the survivor itself", o.NodeID, node.NodeID)
	}
	if err := checkRaftAddress(o.RaftAddress); err != nil {
		return res, usageErr("--raft-address: %v", err)
	}
	if !hasRaftState(o.RaftDir) {
		return res, fmt.Errorf("no Raft data in %s; is this the right --raft-dir?", o.RaftDir)
	}
	if o.Host.UnitActive(ctx, sandboxdUnit) {
		return res, fmt.Errorf("sandboxd is running here; stop sandboxd on every surviving server first (%s)", stopHint(o.Host))
	}
	peers := filepath.Join(o.RaftDir, peersFile)
	if exists(peers) && !o.Force {
		return res, fmt.Errorf("%s already exists; pass --force to overwrite", peers)
	}

	// The runbook's step 2: back the survivor up before its log changes.
	// There is no clean way back from RecoverCluster except this archive.
	if !o.NoBackup {
		out := o.BackupOutput
		if out == "" {
			host, _ := o.hostname()
			out = filepath.Join(filepath.Dir(node.StateDB), "backups",
				fmt.Sprintf("pre-recover-quorum-%s-%s.tar.gz", host, o.now().UTC().Format(restoreStamp)))
		}
		b, err := Backup(ctx, BackupOptions{Output: out, ConfigDir: node.ConfigDir, RaftDir: o.RaftDir,
			Version: o.Version, Host: o.Host, Out: o.Out, now: o.now, hostname: o.hostname})
		if err != nil {
			return res, fmt.Errorf("backup before recovery: %w (pass --no-backup to skip it)", err)
		}
		res.Backup = b.Output
	}

	data, err := json.MarshalIndent([]peer{{ID: o.NodeID, Address: o.RaftAddress, Suffrage: "Voter"}}, "", "  ")
	if err != nil {
		return res, err
	}
	if err := writeFileAtomic(peers, append(data, '\n'), 0o600); err != nil {
		return res, err
	}
	res.PeersFile = peers
	fmt.Fprintf(o.Out, "wrote %s: %s at %s is the only voter\n", peers, o.NodeID, o.RaftAddress)
	if !o.Start {
		fmt.Fprintln(o.Out, "start sandboxd on this node only; successful recovery renames the file to peers.json.applied.<unix>")
		printRejoinSteps(o.Out, o.Host)
		return res, nil
	}
	started := o.now()
	if _, err := startAndWait(ctx, o.Host, o.Out, node.HealthURL, o.Timeout, o.poll); err != nil {
		return res, err
	}
	applied, err := waitApplied(ctx, o.RaftDir, started, o.Timeout, o.poll)
	if err != nil {
		return res, err
	}
	res.Applied = applied
	fmt.Fprintf(o.Out, "recovery applied (%s); this node leads a one-server cluster\n", filepath.Base(applied))
	printRejoinSteps(o.Out, o.Host)
	return res, nil
}

// rejoin moves a lost server's stale Raft directory aside, so it rejoins
// the recovered cluster as a new voter. Started with its old log, it would
// still count the old servers as voters and could elect a second leader
// with another lost server.
func rejoin(ctx context.Context, o QuorumOptions, node Node) (QuorumResult, error) {
	var res QuorumResult
	if v := strings.ToLower(readEnvValue(node.ConfigDir, "SB_CLUSTER_BOOTSTRAP")); v == "true" || v == "1" {
		// With an empty Raft directory and the bootstrap flag, sandboxd
		// starts a new one-server cluster of its own: a second leader.
		return res, fmt.Errorf("SB_CLUSTER_BOOTSTRAP=true in %s: with its Raft log moved aside this node would start a new cluster of its own; set SB_CLUSTER_BOOTSTRAP=false there first", node.ConfigDir)
	}
	if o.Host.UnitActive(ctx, sandboxdUnit) {
		return res, fmt.Errorf("sandboxd is running here; stop it first (%s)", stopHint(o.Host))
	}
	if exists(o.RaftDir) && !hasRaftState(o.RaftDir) && !emptyDir(o.RaftDir) {
		// A wrong --raft-dir (the state directory itself) must never be
		// moved away.
		return res, fmt.Errorf("%s holds no Raft data; is this the right --raft-dir?", o.RaftDir)
	}
	// A log SB_RAFT_WAL_DIR put on a disk of its own goes aside with its
	// directory, under the same name: left in place, it is a log the new
	// Raft directory does not name, and sandboxd refuses to start on it.
	walDir, err := raftlogdir.Recorded(o.RaftDir)
	if err != nil {
		return res, err
	}
	if walDir != "" && !exists(walDir) {
		walDir = ""
	}
	if exists(o.RaftDir) {
		stamp := fmt.Sprintf(".pre-rejoin.%d", o.now().Unix())
		suffix := stamp
		for i := 1; exists(o.RaftDir+suffix) || (walDir != "" && exists(walDir+suffix)); i++ {
			suffix = fmt.Sprintf("%s.%d", stamp, i)
		}
		if walDir != "" {
			if err := os.Rename(walDir, walDir+suffix); err != nil {
				return res, fmt.Errorf("move the Raft log aside: %w (SB_RAFT_WAL_DIR must be a directory on its disk, not the disk's mount point)", err)
			}
			res.MovedAsideLog = walDir + suffix
		}
		aside := o.RaftDir + suffix
		if err := os.Rename(o.RaftDir, aside); err != nil {
			if walDir != "" {
				// Back as it was: a Raft directory without its log is worse
				// than one not moved at all.
				_ = os.Rename(walDir+suffix, walDir)
			}
			return res, err
		}
		res.MovedAside = aside
		fmt.Fprintf(o.Out, "moved aside: %s -> %s (keep it until the cluster is healthy and backed up)\n", o.RaftDir, aside)
		if walDir != "" {
			fmt.Fprintf(o.Out, "moved aside: %s -> %s, its log\n", walDir, res.MovedAsideLog)
		}
	} else {
		fmt.Fprintf(o.Out, "%s does not exist; nothing to move aside\n", o.RaftDir)
	}
	if !o.Start {
		fmt.Fprintln(o.Out, "start sandboxd: it rejoins through gossip and the leader adds it as a voter")
		return res, nil
	}
	_, err = startAndWait(ctx, o.Host, o.Out, node.HealthURL, o.Timeout, o.poll)
	return res, err
}

func printRejoinSteps(out io.Writer, h Host) {
	if _, pod := h.(*PodHost); pod {
		fmt.Fprintln(out, `next, on every other server, one at a time and only once this node leads:
  kubectl annotate aerolnode <server> aerolvm.io/maintenance=true
  kubectl exec <server pod> -- sandboxd recover-quorum --rejoin
  kubectl annotate aerolnode <server> aerolvm.io/maintenance-
never start another server with its old Raft directory: it still counts the lost servers as voters`)
		return
	}
	fmt.Fprintln(out, `next, on every other server, one at a time and only once this node leads:
  sudo systemctl stop sandboxd
  sudo sandboxd recover-quorum --rejoin --start
never start another server with its old Raft directory: it still counts the lost servers as voters`)
}

func (o *QuorumOptions) defaults() {
	if o.Out == nil {
		o.Out = io.Discard
	}
	if o.now == nil {
		o.now = time.Now
	}
	if o.hostname == nil {
		o.hostname = os.Hostname
	}
	if o.Timeout <= 0 {
		o.Timeout = 3 * time.Minute
	}
	if o.poll <= 0 {
		o.poll = time.Second
	}
}

// checkRaftAddress wants the host:port the other servers dial: a wildcard
// bind address would make the node unreachable as the leader.
func checkRaftAddress(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if host == "" {
		return fmt.Errorf("%q has no host", addr)
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		return fmt.Errorf("%q is a bind address; give the address other servers dial (SB_RAFT_ADVERTISE_ADDR)", addr)
	}
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		return fmt.Errorf("%q has no valid port", addr)
	}
	return nil
}

func emptyDir(dir string) bool {
	entries, err := os.ReadDir(dir)
	return err == nil && len(entries) == 0
}

func hasRaftState(dir string) bool {
	for _, n := range raftStateNames {
		if exists(filepath.Join(dir, n)) {
			return true
		}
	}
	return false
}

// waitApplied waits for sandboxd to rename peers.json after applying it.
func waitApplied(ctx context.Context, dir string, since time.Time, timeout, poll time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	for {
		if !exists(filepath.Join(dir, peersFile)) {
			if m, _ := filepath.Glob(filepath.Join(dir, peersFile+".applied.*")); len(m) > 0 {
				newest := ""
				var newestAt int64
				for _, p := range m {
					at, err := strconv.ParseInt(strings.TrimPrefix(filepath.Base(p), peersFile+".applied."), 10, 64)
					if err == nil && at >= newestAt {
						newest, newestAt = p, at
					}
				}
				if newest != "" && newestAt >= since.Unix()-1 {
					return newest, nil
				}
			}
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("sandboxd did not apply %s within %s; see journalctl -u sandboxd", filepath.Join(dir, peersFile), timeout)
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(poll):
		}
	}
}

func readEnvValue(configDir, key string) string {
	env, err := readEnv(configDir)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(env[key])
}

// writeFileAtomic replaces path with data in one rename.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Chmod(mode)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	syncDir(filepath.Dir(path))
	return nil
}
