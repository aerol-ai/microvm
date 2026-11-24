package nodeupgrade

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	// The store's driver: the backup must read the file exactly as
	// sandboxd writes it.
	"github.com/mattn/go-sqlite3"
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

// VacuumIntoNoFollow is VacuumInto for a database whose folder another user
// owns (privilege mode split: sandboxd's user owns its data folder, and
// could swap state.db, or a file SQLite opens beside it, for a link or a
// FIFO).
//
// It refuses a database that is not a regular file. It opens the file
// itself first, with no link followed and without waiting on a FIFO
// (O_NONBLOCK), and checks the file it opened is the one it looked at.
// SQLite then opens the database again by name: it takes no file handle,
// and it resolves links itself (so /proc/self/fd/N would only name the
// file again), and it finds the -wal file by the database's name. So
// SQLite is asked which file it opened (a link's target is refused), and
// that open is given vacuumOpenLimit: a FIFO swapped in after the checks
// would hold it forever, past any deadline, as no context reaches a
// blocked open(2). The copy then runs in the one read transaction that
// open began, through the files SQLite already holds (copyPages), so
// nothing after the time limit opens a file by name.
func VacuumIntoNoFollow(ctx context.Context, dbPath, dest string) error {
	fi, err := os.Lstat(dbPath)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file (%v): the database is copied only from its own file", dbPath, fi.Mode().Type())
	}
	if testHookVacuumOpen != nil {
		testHookVacuumOpen("open")
	}
	f, err := os.OpenFile(dbPath, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("open %s without following a link: %w", dbPath, err)
	}
	st, err := f.Stat()
	_ = f.Close()
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || !os.SameFile(fi, st) {
		return fmt.Errorf("%s changed between the look at it and its open; run the backup again", dbPath)
	}
	// The files SQLite opens by the database's name.
	for _, side := range []string{"-wal", "-shm", "-journal"} {
		sfi, err := os.Lstat(dbPath + side)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if err == nil && !sfi.Mode().IsRegular() {
			return fmt.Errorf("%s is not a regular file (%v): the database is copied only from its own files", dbPath+side, sfi.Mode().Type())
		}
	}
	if testHookVacuumOpen != nil {
		testHookVacuumOpen("sqlite")
	}
	return vacuumIntoChecked(ctx, dbPath, dest)
}

// vacuumOpenLimit bounds SQLite's open of a database in another user's
// folder: the open and the first read, which open the database, its -wal
// and -shm files and look for a hot -journal. It is longer than the busy
// timeout (10s) a read can wait on a writer's lock.
var vacuumOpenLimit = 30 * time.Second

// testHookVacuumOpen, when set, runs in VacuumIntoNoFollow between its look
// and its open ("open"), between its checks and SQLite's open ("sqlite"),
// and once the read transaction is held, before the copy ("copy"): tests
// swap files there.
var testHookVacuumOpen func(stage string)

// vacuumIntoChecked is the open-and-ask half of VacuumIntoNoFollow. The
// pages are copied first to a file of root's beside dest, and VACUUM INTO
// makes dest from that file, so dest is the same compact copy VacuumInto
// makes.
func vacuumIntoChecked(ctx context.Context, dbPath, dest string) error {
	dir, err := filepath.EvalSymlinks(filepath.Dir(dbPath))
	if err != nil {
		return err
	}
	want := filepath.Join(dir, filepath.Base(dbPath))
	// Read-only (mode=ro): a link swapped in after the look must not make
	// SQLite create a file where it points (its default mode is rwc).
	dsn := "file:" + (&url.URL{Path: dbPath}).EscapedPath() + "?mode=ro&_busy_timeout=10000"
	pages := dest + ".pages"
	if err := os.Remove(pages); err != nil && !os.IsNotExist(err) {
		return err
	}
	defer removeDB(pages)
	err = copyPagesWithin(ctx, dsn, pages, func(opened string) error {
		if opened != want {
			return fmt.Errorf("the database %s opened as %s: a link in its place is refused", dbPath, opened)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return vacuumInto(ctx, pages+"?_busy_timeout=10000", dest, nil)
}

// copyPagesWithin runs copyPages, and gives up when SQLite's open has not
// finished within vacuumOpenLimit or ctx ends. A blocked open(2) cannot be
// cancelled, so it is left behind: it ends with this process (`sandboxd
// backup` and the upgrader are commands that exit), and, should the FIFO
// ever be opened for writing, its copy stops at its cancelled context.
func copyPagesWithin(ctx context.Context, dsn, dest string, check func(opened string) error) error {
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	opened := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- copyPages(cctx, dsn, dest, check, opened) }()
	limit := time.NewTimer(vacuumOpenLimit)
	defer limit.Stop()
	select {
	case <-opened:
	case err := <-done:
		return err
	case <-limit.C:
		return fmt.Errorf("SQLite did not open the database within %s: a FIFO in place of it or its -wal or -journal file holds the open; run the backup again", vacuumOpenLimit)
	case <-ctx.Done():
		return ctx.Err()
	}
	// The copy reads only through the files SQLite holds open, and stops
	// at cctx between steps.
	return <-done
}

// copyPagesStep is how many pages one backup step copies: the copy checks
// its context between steps.
const copyPagesStep = 1024

// copyPages copies the database dsn names, page by page, to a new database
// at dest, with SQLite's online backup. It opens a read transaction first
// and closes opened when it holds one: every file SQLite opens by name, it
// opens before then. The backup steps run inside that transaction (a step
// begins its own only when the source has none), so they read through the
// open files alone, and see one consistent state of the database and its
// WAL.
func copyPages(ctx context.Context, dsn, dest string, check func(opened string) error, opened chan<- struct{}) error {
	src, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return err
	}
	defer src.Close()
	src.SetMaxOpenConns(1)
	sc, err := src.Conn(ctx)
	if err != nil {
		return err
	}
	defer sc.Close()
	var seq int
	var name, file string
	if err := sc.QueryRowContext(ctx, "PRAGMA database_list").Scan(&seq, &name, &file); err != nil {
		return err
	}
	if err := check(file); err != nil {
		return err
	}
	if _, err := sc.ExecContext(ctx, "BEGIN"); err != nil {
		return err
	}
	defer func() { _, _ = sc.ExecContext(context.WithoutCancel(ctx), "ROLLBACK") }()
	var tables int
	if err := sc.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_schema").Scan(&tables); err != nil {
		return err
	}
	close(opened)
	if testHookVacuumOpen != nil {
		testHookVacuumOpen("copy")
	}

	dst, err := sql.Open("sqlite3", dest)
	if err != nil {
		return err
	}
	defer dst.Close()
	dst.SetMaxOpenConns(1)
	dc, err := dst.Conn(ctx)
	if err != nil {
		return err
	}
	defer dc.Close()
	return dc.Raw(func(d any) error {
		return sc.Raw(func(s any) error {
			b, err := d.(*sqlite3.SQLiteConn).Backup("main", s.(*sqlite3.SQLiteConn), "main")
			if err != nil {
				return err
			}
			left := -1
			for {
				if err := ctx.Err(); err != nil {
					_ = b.Close()
					return err
				}
				fin, err := b.Step(copyPagesStep)
				if err != nil {
					_ = b.Close()
					return err
				}
				if fin {
					return b.Finish()
				}
				// Step reports a busy database as no progress; the source
				// is held by this read, so only dest could be, briefly.
				if n := b.Remaining(); n == left {
					time.Sleep(10 * time.Millisecond)
				} else {
					left = n
				}
			}
		})
	})
}

// removeDB removes a database file of root's and the files SQLite made
// beside it.
func removeDB(path string) {
	for _, p := range []string{path, path + "-wal", path + "-shm", path + "-journal"} {
		_ = os.Remove(p)
	}
}

// sqliteBackup copies the database to dest with VACUUM INTO: a consistent
// snapshot that folds in the WAL. sandboxd is stopped when it runs, so the
// one-writer rule of the store holds (internal/store: MaxOpenConns=1).
func sqliteBackup(ctx context.Context, dbPath, dest string) error {
	return vacuumInto(ctx, dbPath+"?_busy_timeout=10000", dest, nil)
}

// vacuumInto is sqliteBackup from a data source name. check, when set, sees
// the file SQLite opened (PRAGMA database_list) before anything is copied.
func vacuumInto(ctx context.Context, dsn, dest string, check func(opened string) error) error {
	if err := os.Remove(dest); err != nil && !os.IsNotExist(err) {
		return err
	}
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if check != nil {
		var seq int
		var name, file string
		if err := db.QueryRowContext(ctx, "PRAGMA database_list").Scan(&seq, &name, &file); err != nil {
			return err
		}
		if err := check(file); err != nil {
			return err
		}
	}
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
