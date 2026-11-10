package nodeops

import (
	"context"
	"crypto/rand"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
)

// BenchmarkBackupLargeStateDB measures `sandboxd backup` on a big state.db
// with the store's real schema (eng review T15): the VACUUM INTO copy is
// what a node's upgrade waits on with sandboxd stopped (§6.3 step 5).
// Benchmarks never run in `make test`. Size it with AEROL_BENCH_SCALE:
// scale 1 is 10,000 sandboxes (each with a sealed env), 5,000 snapshots
// and 20,000 secret-audit chunks of 1 KiB.
//
//	AEROL_BENCH_SCALE=10 go test -run '^$' -bench BackupLargeStateDB -benchtime 1x ./internal/nodeops/
func BenchmarkBackupLargeStateDB(b *testing.B) {
	scale := 1
	if v, err := strconv.Atoi(os.Getenv("AEROL_BENCH_SCALE")); err == nil && v > 0 {
		scale = v
	}
	dir := b.TempDir()
	etc, lib := filepath.Join(dir, "etc"), filepath.Join(dir, "lib")
	if err := os.MkdirAll(etc, 0o700); err != nil {
		b.Fatal(err)
	}
	dbPath := filepath.Join(lib, "state.db")
	if err := os.WriteFile(filepath.Join(etc, "sandboxd.env"), []byte("SB_DB_PATH="+dbPath+"\n"), 0o600); err != nil {
		b.Fatal(err)
	}
	if err := os.MkdirAll(lib, 0o700); err != nil {
		b.Fatal(err)
	}
	built := time.Now()
	fillStateDB(b, dbPath, 10000*scale, 5000*scale, 20000*scale)
	b.Logf("built %s (%s) in %s", dbPath, humanBytes(fileSize(dbPath)+fileSize(dbPath+"-wal")), time.Since(built).Round(time.Millisecond))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res, err := Backup(context.Background(), BackupOptions{ConfigDir: etc, Output: filepath.Join(dir, "out", "b.tgz"), Host: &fakeHost{}})
		if err != nil {
			b.Fatal(err)
		}
		b.ReportMetric(float64(res.DBBytes)/(1<<20), "db_MiB")
		b.ReportMetric(float64(res.DBTook.Milliseconds()), "vacuum_ms")
		b.ReportMetric(float64(res.Took.Milliseconds()), "backup_ms")
		b.ReportMetric(float64(res.Bytes)/(1<<20), "archive_MiB")
	}
}

// fillStateDB makes the store's schema and fills it in one transaction.
func fillStateDB(b *testing.B, path string, sandboxes, snapshots, auditChunks int) {
	s, err := store.Open(path)
	if err != nil {
		b.Fatal(err)
	}
	if err := s.Close(); err != nil {
		b.Fatal(err)
	}
	db, err := sql.Open("sqlite3", path+"?_journal_mode=WAL&_synchronous=OFF")
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	tx, err := db.Begin()
	if err != nil {
		b.Fatal(err)
	}
	blob := func(n int) []byte {
		p := make([]byte, n)
		_, _ = rand.Read(p) // sealed values do not compress
		return p
	}
	now := time.Now().UTC()
	exec := func(q string, rows int, args func(i int) []any) {
		st, err := tx.Prepare(q)
		if err != nil {
			b.Fatal(err)
		}
		defer st.Close()
		for i := 0; i < rows; i++ {
			if _, err := st.Exec(args(i)...); err != nil {
				b.Fatalf("%s: %v", q, err)
			}
		}
	}
	exec(`INSERT INTO sandboxes (id, image, status, public_url, container_id, container_ip, cpu, memory_mb, disk_gb, os_user,
		name, tags_json, network_allow_out_json, toolbox_token_sealed, created_at, updated_at, last_active_at, owner_ref, runtime)
		VALUES (?, 'ghcr.io/acme/agent:1.4.2', 'running', ?, ?, ?, 1, 2048, 10, 'root', ?, '{"team":"agents","env":"prod"}',
		'["pypi.org","registry.npmjs.org"]', ?, ?, ?, ?, 'pat', 'docker')`, sandboxes, func(i int) []any {
		id := fmt.Sprintf("sb-%012d", i)
		return []any{id, "https://" + id + ".sandbox.example.com", fmt.Sprintf("%064x", i), fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255),
			"name-" + id, blob(64), now, now, now}
	})
	exec(`INSERT INTO sandbox_env (sandbox_id, sealed_blob, created_at) VALUES (?, ?, ?)`, sandboxes, func(i int) []any {
		return []any{fmt.Sprintf("sb-%012d", i), blob(1024), now}
	})
	exec(`INSERT INTO sandbox_snapshots (owner_ref, name, image, image_id, source_sandbox_id, created_at, image_digest)
		VALUES ('pat', ?, ?, ?, ?, ?, ?)`, snapshots, func(i int) []any {
		return []any{fmt.Sprintf("snap-%010d", i), fmt.Sprintf("aerolvm/snapshot:%010d", i), fmt.Sprintf("sha256:%064x", i),
			fmt.Sprintf("sb-%012d", i), now, fmt.Sprintf("sha256:%064x", i+1)}
	})
	exec(`INSERT INTO secret_audit_index (sandbox_id, incarnation_id, chunk_seq, first_offset, last_offset, min_time, max_time, last_time, n, entries)
		VALUES (?, 'inc-1', ?, ?, ?, ?, ?, ?, 64, ?)`, auditChunks, func(i int) []any {
		t := now.UnixNano() + int64(i)
		return []any{fmt.Sprintf("sb-%012d", i%max(sandboxes, 1)), i, int64(i) * 4096, int64(i)*4096 + 4095, t, t, t, blob(1024)}
	})
	if err := tx.Commit(); err != nil {
		b.Fatal(err)
	}
	if _, err := db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		b.Fatal(err)
	}
}
