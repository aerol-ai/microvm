package nodeupgrade

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/aerol-ai/microvm/internal/store"
)

// One-way schema migrations on a single node (plans/kubectl-style-cluster-ops.md
// §6.3 step 9, §6.5, §6.8).
//
// In a cluster, one-way migrations run only at finalize, so before then the
// previous binary always reads the database, and the upgrader never
// restores a backup once the new binary got past opening its store: boot
// work may already have reached peers.
//
// With cluster mode off there is no finalize and there are no peers.
// sandboxd runs its one-way migrations at boot, right after open and before
// it writes the store-opened marker (pkg/daemon). If the new binary then
// fails, or the operator rolls back, the previous binary finds migration
// numbers it does not know and refuses to open the database
// (store.ErrSchemaFromNewerRelease), so it would crash-loop. So on a single
// node, when one-way migrations ran since the backup, a revert or a
// rollback restores that backup. Writes made since are lost; without the
// restore the previous binary could not run at all.

// clusterModeOn reports whether the node's env files turn cluster mode on:
// sandboxd.env, then cluster.env beside it (a later file wins, as systemd
// loads them), read the way sandboxd reads SB_ENABLE_CLUSTER. known is
// false when it cannot tell: an env file it cannot read, or cluster
// settings (a cluster.env, an SB_CLUSTER_* key) without the switch, which
// may then be set some other way. The caller keeps the cluster rule then,
// which never restores after boot work.
func clusterModeOn(envFile string) (on, known bool) {
	if envFile == "" {
		return false, false
	}
	env, err := readEnvFile(envFile)
	if err != nil {
		return false, false
	}
	clusterSettings := false
	extra, err := readEnvFile(filepath.Join(filepath.Dir(envFile), "cluster.env"))
	switch {
	case err == nil:
		clusterSettings = true
		for k, v := range extra {
			env[k] = v
		}
	case !os.IsNotExist(err):
		return false, false
	}
	raw := strings.TrimSpace(env["SB_ENABLE_CLUSTER"])
	if raw == "" {
		for k := range env {
			clusterSettings = clusterSettings || strings.HasPrefix(k, "SB_CLUSTER_")
		}
		return false, !clusterSettings
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		// sandboxd falls back to its default, off, on a value it cannot
		// parse.
		return false, true
	}
	return v, true
}

// appliedOneWay reads the one-way migrations recorded on the database at
// path. No path, or a missing file, has none. sandboxd is stopped when
// this runs, so the store's one-writer rule holds.
func appliedOneWay(ctx context.Context, path string) ([]int, error) {
	if path == "" {
		return []int{}, nil
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return []int{}, nil
	}
	db, err := sql.Open("sqlite3", path+"?_busy_timeout=10000")
	if err != nil {
		return nil, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	return store.AppliedOneWayMigrations(ctx, db)
}

// oneWaySince lists the one-way migrations recorded on the database at
// dbPath and not on backup: the ones run since the backup was taken.
func oneWaySince(ctx context.Context, backup, dbPath string) ([]int, error) {
	before, err := appliedOneWay(ctx, backup)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", backup, err)
	}
	now, err := appliedOneWay(ctx, dbPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", dbPath, err)
	}
	var out []int
	for _, n := range now {
		if !slices.Contains(before, n) {
			out = append(out, n)
		}
	}
	return out, nil
}

// singleNode reports whether this node runs with cluster mode off, as its
// env files say. Run records it in the op (State.SingleNode) when the op
// starts, so a failure and boot recovery apply the same rule.
func (u *Upgrader) singleNode() bool {
	on, known := clusterModeOn(u.Paths.EnvFile)
	return known && !on
}

// singleNodeOneWaySince lists the one-way migrations run on dbPath since
// backup ("" is no backup: the database did not exist then), for an op on
// a single node. It answers nil in a cluster, and when the databases
// cannot be read (with a warning), so every doubt keeps the cluster rule.
func (u *Upgrader) singleNodeOneWaySince(ctx context.Context, st *State, backup, dbPath string) []int {
	if !st.SingleNode || dbPath == "" {
		return nil
	}
	since, err := oneWaySince(ctx, backup, dbPath)
	if err != nil {
		u.logf("warning: could not compare the database with its backup for one-way schema migrations: %v", err)
		return nil
	}
	return since
}

// planRollbackRestore decides whether a single-node rollback puts a
// database backup back before the older binary starts: the backup taken
// just before this node last moved off st.Version, when one-way schema
// migrations ran since it. With that backup gone the older binary could
// not open the database, so the rollback is refused before anything
// stops.
func (u *Upgrader) planRollbackRestore(ctx context.Context, st *State, rolledBack *State) error {
	if !st.Rollback || !st.SingleNode {
		return nil
	}
	src := rolledBack
	if src == nil {
		src = u.lastUpgradeFrom(st.Version)
	}
	if src == nil {
		return nil
	}
	since := u.singleNodeOneWaySince(ctx, st, src.BackupPath, u.Paths.DBPath)
	if len(since) == 0 {
		return nil
	}
	if src.BackupPath == "" || !fileExists(src.BackupPath) {
		return fmt.Errorf("one-way schema migrations %v ran since op %s moved this node off %s, and that op's database backup (%s) is gone, so %s cannot open the database; a rollback is not possible",
			since, src.Op, st.Version, orNone(src.BackupPath), st.Version)
	}
	st.RestoreBackup = src.BackupPath
	u.logf("one-way schema migrations %v ran since op %s; the rollback puts its database backup %s back, and writes made since are lost", since, src.Op, src.BackupPath)
	return nil
}

// lastUpgradeFrom is the newest finished upgrade (not a rollback) that
// moved this node off version: the one a rollback to version undoes.
func (u *Upgrader) lastUpgradeFrom(version string) *State {
	states, err := listStates(u.Paths.StateDir)
	if err != nil {
		return nil
	}
	for i := len(states) - 1; i >= 0; i-- {
		s := states[i]
		if s.Phase == PhaseDone && !s.Rollback && s.FromVersion == version && (s.Result == ResultUpgraded || s.Result == ResultCompletedAtBoot) {
			return s
		}
	}
	return nil
}

func fileExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular()
}
