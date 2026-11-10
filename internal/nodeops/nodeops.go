// Package nodeops holds the node-local day-2 tools that used to be repo-only
// bash scripts (plans/kubectl-style-cluster-ops.md C4, §3.1, Phase 5):
// `sandboxd backup` (scripts/sandboxd-backup.sh), `sandboxd restore`
// (scripts/sandboxd-restore.sh) and `sandboxd recover-quorum`
// (scripts/raft-lost-quorum-recover.sh). The scripts are now thin wrappers
// over these commands, so the archive layout and every safety rule they had
// live here.
//
// The archive is the scripts' format, unchanged, so an archive from either
// side restores with the other: a gzipped tar of ./MANIFEST.txt,
// ./etc/sandboxd/, ./var/lib/sandboxd/state.db, ./var/lib/sandboxd/raft/ and
// the server-key files beside the database.
//
// Every effect outside the files these tools own (systemctl, sandboxd's
// health) goes through Host, so the tests run offline and unprivileged.
package nodeops

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/aerol-ai/microvm/internal/nodeupgrade"
)

// Host is what these tools need from the machine. nodeupgrade.SystemHost
// is the real one; tests pass a fake.
type Host interface {
	UnitActive(ctx context.Context, unit string) bool
	StopUnit(ctx context.Context, unit string) error
	StartUnit(ctx context.Context, unit string) error
	// HealthVersion asks sandboxd's /health and returns the version it
	// reports.
	HealthVersion(ctx context.Context, url string) (string, error)
}

var _ Host = (*nodeupgrade.SystemHost)(nil)

const (
	// DefaultConfigDir holds sandboxd.env and the cluster drop-in's
	// cluster.env.
	DefaultConfigDir = "/etc/sandboxd"

	sandboxdUnit = "sandboxd"

	defaultDBPath     = "/var/lib/sandboxd/state.db"
	defaultKeyFile    = "/var/lib/sandboxd/credential_encryption.key"
	defaultWrappedKey = "/var/lib/sandboxd/credential_encryption.key.wrapped"
)

// Node is this node's settings as sandboxd gets them from its env files:
// the paths the tools work on and the cluster identity recover-quorum
// writes.
type Node struct {
	ConfigDir  string
	StateDB    string
	RaftDir    string
	KeyFile    string
	KeyRing    string
	WrappedKey string
	// Custody is SB_CREDENTIAL_KEY_CUSTODY, lower case; empty means file.
	Custody string
	// EnvKey reports a non-empty SB_CREDENTIAL_ENCRYPTION_KEY.
	EnvKey bool
	// Cluster identity; empty on a single node.
	NodeID      string
	NodeRole    string
	RaftAddress string
	HealthURL   string
}

// ReadNode reads <configDir>/sandboxd.env, then <configDir>/cluster.env, as
// systemd hands them to sandboxd: a later file and a later line override an
// earlier one. A missing file is not an error; every default is
// install.sh's. Only the env files count, never this shell's environment:
// they are what the daemon sees.
func ReadNode(configDir string) (Node, error) {
	if configDir == "" {
		configDir = DefaultConfigDir
	}
	env, err := readEnv(configDir)
	if err != nil {
		return Node{}, err
	}
	get := func(key, def string) string {
		if v := strings.TrimSpace(env[key]); v != "" {
			return v
		}
		return def
	}
	n := Node{
		ConfigDir:  configDir,
		StateDB:    get("SB_DB_PATH", defaultDBPath),
		KeyFile:    get("SB_CREDENTIAL_ENCRYPTION_KEY_PATH", defaultKeyFile),
		WrappedKey: get("SB_CREDENTIAL_ENCRYPTION_KEY_WRAPPED_PATH", defaultWrappedKey),
		Custody:    strings.ToLower(get("SB_CREDENTIAL_KEY_CUSTODY", "")),
		EnvKey:     get("SB_CREDENTIAL_ENCRYPTION_KEY", "") != "",
		NodeID:     get("SB_NODE_ID", ""),
		NodeRole:   strings.ToLower(get("SB_NODE_ROLE", "")),
		HealthURL:  "http://127.0.0.1:" + get("SB_API_PORT", "21212") + "/health",
	}
	// The same defaults internal/config applies.
	n.RaftDir = get("SB_RAFT_DATA_DIR", filepath.Join(filepath.Dir(n.StateDB), "raft"))
	n.KeyRing = get("SB_CREDENTIAL_KEY_RING_PATH", n.KeyFile+".ring")
	n.RaftAddress = get("SB_RAFT_ADVERTISE_ADDR", get("SB_RAFT_BIND_ADDR", ""))
	return n, nil
}

// readEnv merges the two env files the sandboxd unit loads.
func readEnv(configDir string) (map[string]string, error) {
	merged := map[string]string{}
	for _, name := range []string{"sandboxd.env", "cluster.env"} {
		vals, err := nodeupgrade.ReadEnvFile(filepath.Join(configDir, name))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		for k, v := range vals {
			merged[k] = v
		}
	}
	return merged, nil
}

// holdsRaft reports whether a node with this SB_NODE_ROLE keeps a Raft log.
// Empty is mixed, which does; so does any list that names server or mixed.
func holdsRaft(role string) bool {
	if strings.TrimSpace(role) == "" {
		return true
	}
	for _, r := range strings.Split(role, ",") {
		switch strings.TrimSpace(r) {
		case "server", "mixed":
			return true
		}
	}
	return false
}
