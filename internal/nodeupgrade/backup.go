package nodeupgrade

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	// The store's driver: the backup must read the file exactly as
	// sandboxd writes it.
	_ "github.com/mattn/go-sqlite3"
)

// backupSuffix names an op's database backup: <op>.state.db.
const backupSuffix = ".state.db"

// keepBackups is how many op backups stay on disk. The newest is the one a
// failure restores; the one before is kept for an operator. state.db can be
// large, so older ones go.
const keepBackups = 2

// VacuumInto is sqliteBackup for the node's other database tools (`sandboxd
// backup`, internal/nodeops), so every copy of state.db is taken the same
// way. dest is replaced if it exists and ends up 0600.
func VacuumInto(ctx context.Context, dbPath, dest string) error {
	return sqliteBackup(ctx, dbPath, dest)
}

// sqliteBackup copies the database to dest with VACUUM INTO: a consistent
// snapshot that folds in the WAL. sandboxd is stopped when it runs, so the
// one-writer rule of the store holds (internal/store: MaxOpenConns=1).
func sqliteBackup(ctx context.Context, dbPath, dest string) error {
	if err := os.Remove(dest); err != nil && !os.IsNotExist(err) {
		return err
	}
	db, err := sql.Open("sqlite3", dbPath+"?_busy_timeout=10000")
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, "VACUUM INTO ?", dest); err != nil {
		_ = os.Remove(dest)
		return fmt.Errorf("VACUUM INTO %s: %w", dest, err)
	}
	if err := os.Chmod(dest, 0o600); err != nil {
		return err
	}
	if f, err := os.Open(dest); err == nil {
		_ = f.Sync()
		_ = f.Close()
	}
	return nil
}

// checkBackupPath refuses a backup that is not one of the upgrade's own: a
// regular file named <op>.state.db directly in the upgrade folder. The
// path comes from an op's record, and a record is a file on disk, so it
// is never trusted to name a file somewhere else. The last name is not
// followed (Lstat): a link there is refused, not read.
func checkBackupPath(stateDir, backup string) error {
	if err := checkBackupPlace(stateDir, backup); err != nil {
		return err
	}
	fi, err := os.Lstat(filepath.Clean(backup))
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file (mode %s)", backup, fi.Mode())
	}
	return nil
}

// checkBackupPlace is checkBackupPath's rule for the name alone: an
// <op>.state.db directly in the upgrade folder.
func checkBackupPlace(stateDir, backup string) error {
	clean := filepath.Clean(backup)
	if !filepath.IsAbs(clean) || filepath.Dir(clean) != filepath.Clean(stateDir) || !strings.HasSuffix(filepath.Base(clean), backupSuffix) {
		return fmt.Errorf("%q is not a database backup in the upgrade folder %s", backup, stateDir)
	}
	return nil
}

// restoreBackup puts a backup back as the database. The old WAL and
// shared-memory files go first: left beside the restored file, SQLite would
// replay the failed boot's frames onto it. The backup must be one of the
// upgrade folder's own (checkBackupPath); the database path is the node's,
// from its settings, never from a record.
func restoreBackup(stateDir, backup, dbPath string) error {
	if err := checkBackupPath(stateDir, backup); err != nil {
		return err
	}
	if strings.TrimSpace(dbPath) == "" {
		return errors.New("no database path to restore to")
	}
	mode := os.FileMode(0o600)
	if st, err := os.Stat(dbPath); err == nil {
		mode = st.Mode().Perm()
	}
	// The database's folder is sandboxd's, and in privilege mode split
	// sandboxd's user can write it: a link left at the temporary name must
	// not make root write the backup wherever it points. So the name is
	// cleared and made afresh, never followed (O_EXCL, O_NOFOLLOW).
	tmp := dbPath + ".restore"
	if err := os.Remove(tmp); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := copyFileExcl(backup, tmp, mode); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	for _, side := range []string{dbPath + "-wal", dbPath + "-shm"} {
		if err := os.Remove(side); err != nil && !os.IsNotExist(err) {
			_ = os.Remove(tmp)
			return err
		}
	}
	if err := os.Rename(tmp, dbPath); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	syncDir(filepath.Dir(dbPath))
	return nil
}

// dbBytes is the space a backup of the database needs at most: the file
// and its WAL.
func dbBytes(dbPath string) uint64 {
	return uint64(fileSize(dbPath) + fileSize(dbPath+"-wal"))
}

// pruneBackups keeps the newest keepBackups op backups in dir.
func pruneBackups(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	type b struct {
		path string
		mod  int64
	}
	var all []b
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), backupSuffix) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		all = append(all, b{filepath.Join(dir, e.Name()), info.ModTime().UnixNano()})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].mod > all[j].mod })
	for i := keepBackups; i < len(all); i++ {
		_ = os.Remove(all[i].path)
	}
}
