// Package nodeupgrade replaces this node's binaries safely: `sandboxd
// upgrade node` (plans/kubectl-style-cluster-ops.md §6.3). Every way a
// binary gets replaced ends here: the command run by hand, install.sh's
// re-run (eng D7), and later the cluster rollout and single-node routes,
// which only launch the command under systemd-run (Launch). The command
// keeps the old files as *.prev, backs the database up before the new
// binary touches it, keeps Firecracker VMs running across the restart,
// and puts the old files back when the new set does not come up.
//
// Boot recovery (Recover) runs at sandboxd start: an upgrade the machine
// lost mid-swap (a reboot, a killed upgrader) is completed when every new
// file is in place and reverted otherwise, so a node never runs a
// half-swapped set.
//
// Every effect outside the files the upgrader owns (systemctl, the cgroup
// and proc trees, the network, executing a binary) goes through Host or a
// root path in Paths, so the tests run offline and unprivileged.
package nodeupgrade

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Defaults for a node install.sh set up.
const (
	DefaultEnvFile  = "/etc/sandboxd/sandboxd.env"
	DefaultNodeJSON = "/etc/sandboxd/node.json"
	// DefaultReleaseURL is the GitHub release download base install.sh
	// uses. A file is fetched from <base>/<version>/<asset>.
	DefaultReleaseURL = "https://github.com/aerol-ai/microvm/releases/download"

	defaultDBPath   = "/var/lib/sandboxd/state.db"
	defaultToolboxd = "/usr/local/bin/toolboxd"
	defaultCaddy    = "/usr/bin/caddy"
	defaultGateway  = "/run/aerolvm/egress-gateway.sock"

	sandboxdUnit = "sandboxd"
	caddyUnit    = "caddy"
	gatewayUnit  = "aerolvm-egress-gateway"

	// storeOpenedName is the boot marker sandboxd writes once its store has
	// opened and migrated (WriteStoreOpenedMarker).
	storeOpenedName = "store-opened"
	// hostSetupName records the hash of the install.sh that last set this
	// host up (host apply, or a caller that applied it itself).
	hostSetupName = "host-setup.sha256"
)

// Paths are the files and roots one upgrade works on.
type Paths struct {
	EnvFile  string
	NodeJSON string
	// StateDir holds the lock, each op's record, the staged files and the
	// database backups: /var/lib/sandboxd/upgrade.
	StateDir string
	DBPath   string
	// Installed binaries. Caddy is empty on a node without Caddy (local
	// mode, SB_ENABLE_CADDY=false).
	Sandboxd string
	Toolboxd string
	Caddy    string
	// CgroupRoot and ProcRoot are /sys/fs/cgroup and /proc.
	CgroupRoot string
	ProcRoot   string
	// HealthURL is sandboxd's /health on this host.
	HealthURL string
	// GatewaySocket is the egress gateway's control socket.
	GatewaySocket string
	// ReleaseURL is the download base when a request has no --from.
	ReleaseURL string
}

// StateDirFor is the upgrade state directory for a database path: the
// upgrade directory beside the database, so the upgrader and the daemon's
// boot recovery agree on it without another setting.
func StateDirFor(dbPath string) string {
	return filepath.Join(filepath.Dir(dbPath), "upgrade")
}

// StoreOpenedMarkerPath is the boot marker for a database path.
func StoreOpenedMarkerPath(dbPath string) string {
	return filepath.Join(filepath.Dir(dbPath), storeOpenedName)
}

// storeOpened is the marker's content: which build opened the store, when.
type storeOpened struct {
	Version string    `json:"version"`
	PID     int       `json:"pid"`
	At      time.Time `json:"at"`
}

// WriteStoreOpenedMarker records that this sandboxd opened and migrated its
// store (pkg/daemon calls it right after, before any reconcile, outbox or
// loop starts). The upgrader deletes the marker before it starts a new
// binary; if the new binary then fails and left no marker, nothing past the
// store ran and restoring the backup taken before the swap loses nothing.
// With a marker, boot work may already have reached peers, so the backup is
// never restored (§6.3 step 9), except on a single node whose boot ran
// one-way migrations the previous binary cannot read (oneway.go).
func WriteStoreOpenedMarker(dbPath, version string) error {
	data, err := json.Marshal(storeOpened{Version: version, PID: os.Getpid(), At: time.Now().UTC()})
	if err != nil {
		return err
	}
	return writeFileAtomic(StoreOpenedMarkerPath(dbPath), append(data, '\n'), 0o600)
}

// ResolvePaths reads the node's env file (as systemd hands it to sandboxd)
// and returns where everything lives. An env file that does not exist is
// not an error: the defaults are install.sh's. lookCaddy finds the caddy
// binary on PATH, as install.sh does.
func ResolvePaths(envFile string, getenv func(string) string, lookCaddy func() (string, error)) (Paths, error) {
	if envFile == "" {
		envFile = DefaultEnvFile
	}
	env, err := readEnvFile(envFile)
	if err != nil && !os.IsNotExist(err) {
		return Paths{}, err
	}
	get := func(key, def string) string {
		if v := strings.TrimSpace(getenv(key)); v != "" {
			return v
		}
		if v := strings.TrimSpace(env[key]); v != "" {
			return v
		}
		return def
	}
	dbPath := get("SB_DB_PATH", defaultDBPath)
	toolboxd := get("SB_TOOLBOX_BINARY_PATH", defaultToolboxd)
	p := Paths{
		EnvFile:  envFile,
		NodeJSON: filepath.Join(filepath.Dir(envFile), "node.json"),
		StateDir: StateDirFor(dbPath),
		DBPath:   dbPath,
		// install.sh puts both binaries in --install-prefix.
		Sandboxd:      filepath.Join(filepath.Dir(toolboxd), "sandboxd"),
		Toolboxd:      toolboxd,
		CgroupRoot:    "/sys/fs/cgroup",
		ProcRoot:      "/proc",
		HealthURL:     "http://127.0.0.1:" + get("SB_API_PORT", "21212") + "/health",
		GatewaySocket: get("SB_EGRESS_GATEWAY_SOCKET", defaultGateway),
		ReleaseURL:    strings.TrimRight(get("SB_RELEASE_URL", DefaultReleaseURL), "/"),
	}
	if !strings.EqualFold(get("SB_ENABLE_CADDY", "true"), "false") {
		p.Caddy = defaultCaddy
		if lookCaddy != nil {
			if c, err := lookCaddy(); err == nil && c != "" {
				p.Caddy = c
			}
		}
	}
	return p, nil
}

// ReadEnvFile is readEnvFile for the node's other tools, so they read the
// env files exactly as the upgrader (and systemd) does.
func ReadEnvFile(path string) (map[string]string, error) { return readEnvFile(path) }

// readEnvFile parses a systemd EnvironmentFile: KEY=VALUE lines, # and ;
// comments, optional quotes; a later line overrides an earlier one.
func readEnvFile(path string) (map[string]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	vals := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		k = strings.TrimSpace(k)
		if !ok || k == "" {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		vals[k] = v
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("env file %s: %w", path, err)
	}
	return vals, nil
}
