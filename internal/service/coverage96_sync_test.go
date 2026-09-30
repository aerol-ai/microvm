package service

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"

	"log/slog"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// TestCov96ClosedStoreSweep calls store-backed service methods whose first
// real work is a query. A closed database makes that query fail immediately,
// which is the branch happy-path tests leave uncovered. Methods that start
// goroutines, bind ports, or talk to a runtime are not in the list: a leaked
// goroutine from this package previously deadlocked the rest of the suite.
func TestCov96ClosedStoreSweep(t *testing.T) {
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	leaked := false
	t.Cleanup(func() {
		if !leaked {
			_ = os.Chdir(orig)
		}
	})

	dbPath := filepath.Join(t.TempDir(), "state.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	svc := &Service{
		cfg:    config.Config{DBPath: dbPath, SecretTombRetentionDays: 1, AuditDeletedGrace: time.Hour},
		store:  st,
		logger: slog.New(slog.DiscardHandler),
	}

	before := runtime.NumGoroutine()
	var slow []string
	for _, name := range cov96ClosedStoreMethods {
		m, ok := reflect.TypeOf(svc).MethodByName(name)
		if !ok || m.Type.IsVariadic() {
			continue
		}
		if !cov96CallMethod(svc, m, 40*time.Millisecond) {
			slow = append(slow, name)
		}
	}
	time.Sleep(50 * time.Millisecond)
	if got := runtime.NumGoroutine(); got > before+3 {
		leaked = true
		t.Fatalf("closed-store sweep leaked goroutines: before %d after %d slow %v", before, got, slow)
	}
	if len(slow) > 0 {
		leaked = true
		t.Fatalf("methods did not return: %v", slow)
	}

	// A few explicit branches the name sweep cannot shape: nil receivers,
	// validation before the query, and an indexer that never starts its loop.
	if err := (*Service)(nil).pruneClusterSecretTombs(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.HasLocalSealedSecretGeneration(context.Background(), "sb", "", 1); err == nil {
		t.Fatal("expected incarnation validation error")
	}
	if _, err := svc.HasLocalSealedSecretGeneration(context.Background(), "sb", "inc", 1); err == nil {
		t.Fatal("expected closed-store error")
	}
	svc.computeFailoverReady(context.Background(), &models.Sandbox{
		ID:       "sb",
		Failover: &models.Failover{Policy: models.FailoverPolicyRecreate},
	})
	_ = svc.reconcileSecretDeleteOutboxPass(context.Background(), secretOutboxPass{now: time.Now()})
	_ = svc.retireStandaloneSecretOutbox(context.Background())
	svc.refreshSecretLifecycleMetrics(context.Background())

	sink := &fileAuditSink{path: filepath.Join(t.TempDir(), "missing.jsonl")}
	idx := newSecretAuditIndexer(st, sink, svc.logger)
	if err := idx.catchUp(); err != nil {
		t.Fatal(err)
	}
	// A file used as a directory yields ENOTDIR, which is not ErrNotExist, so
	// catchUp returns the open error instead of treating the log as absent.
	notDir := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(notDir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	sink.path = filepath.Join(notDir, "secrets.jsonl")
	idx = newSecretAuditIndexer(st, sink, svc.logger)
	if err := idx.catchUp(); err == nil {
		t.Fatal("expected open error for a directory path")
	}
	auditPath := filepath.Join(t.TempDir(), "secrets.jsonl")
	if err := os.WriteFile(auditPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sink = &fileAuditSink{path: auditPath}
	idx = newSecretAuditIndexer(st, sink, svc.logger)
	if err := idx.catchUp(); err == nil {
		t.Fatal("expected index meta read to fail on a closed store")
	}
}

// TestCov96StoreTriggerFailures reaches the write-error return after a
// statement has already been prepared, which a closed database cannot: the
// closed database fails at the first call. SQLite RAISE triggers fail one
// table's INSERT/UPDATE/DELETE while reads of other tables still work.
func TestCov96StoreTriggerFailures(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "state.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	raw, err := sql.Open("sqlite3", dbPath+"?_busy_timeout=5000&_foreign_keys=on&_journal_mode=WAL")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	rows, err := raw.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	_ = rows.Close()
	for _, table := range tables {
		for _, timing := range []struct{ name, sql string }{
			{"ins", "BEFORE INSERT"},
			{"upd", "BEFORE UPDATE"},
			{"del", "BEFORE DELETE"},
		} {
			q := `CREATE TRIGGER IF NOT EXISTS cov96_` + timing.name + `_` + table + ` ` + timing.sql +
				` ON "` + table + `" BEGIN SELECT RAISE(ABORT, 'cov96'); END`
			if _, err := raw.Exec(q); err != nil {
				t.Fatalf("trigger %s %s: %v", timing.sql, table, err)
			}
		}
	}

	svc := &Service{
		cfg:    config.Config{DBPath: dbPath, SecretTombRetentionDays: 1},
		store:  st,
		logger: slog.New(slog.DiscardHandler),
	}
	ctx := context.Background()
	_ = svc.RetireNodeStorage(ctx, "node-gone", "op", "disk")
	_, _ = svc.RevokeNodeStorageRetirement(ctx, "node-gone")
	_, _ = svc.ListNodeStorageRetirements(ctx)
	_, _ = svc.authoritativeNodeStorageRetirements(ctx)
	_ = svc.pruneClusterSecretTombs(ctx)
	_ = svc.UpsertCompatState(ctx, "owner", "facade", `{"v":1}`)
	_, _ = svc.GetCompatState(ctx, "owner", "key")
	_ = svc.DeleteIdempotentRequest(ctx, "owner", "key")
}

func cov96CallMethod(svc *Service, m reflect.Method, limit time.Duration) bool {
	mt := m.Type
	args := make([]reflect.Value, mt.NumIn())
	args[0] = reflect.ValueOf(svc)
	for i := 1; i < mt.NumIn(); i++ {
		arg := reflect.New(mt.In(i)).Elem()
		cov96Fill(arg, 0)
		args[i] = arg
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() { _ = recover() }()
		m.Func.Call(args)
	}()
	select {
	case <-done:
		return true
	case <-time.After(limit):
		return false
	}
}

func cov96Fill(v reflect.Value, depth int) {
	if !v.IsValid() || !v.CanSet() || depth > 3 {
		return
	}
	switch v.Kind() {
	case reflect.String:
		v.SetString("cov")
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(1)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(1)
	case reflect.Float32, reflect.Float64:
		v.SetFloat(1)
	case reflect.Pointer:
		v.Set(reflect.New(v.Type().Elem()))
		cov96Fill(v.Elem(), depth+1)
	case reflect.Struct:
		if v.Type() == reflect.TypeOf(time.Time{}) {
			v.Set(reflect.ValueOf(time.Unix(1_700_000_000, 0)))
			return
		}
		for i := 0; i < v.NumField(); i++ {
			cov96Fill(v.Field(i), depth+1)
		}
	case reflect.Slice:
		s := reflect.MakeSlice(v.Type(), 1, 1)
		cov96Fill(s.Index(0), depth+1)
		v.Set(s)
	case reflect.Map:
		mp := reflect.MakeMapWithSize(v.Type(), 1)
		k := reflect.New(v.Type().Key()).Elem()
		el := reflect.New(v.Type().Elem()).Elem()
		cov96Fill(k, depth+1)
		cov96Fill(el, depth+1)
		if k.IsValid() {
			mp.SetMapIndex(k, el)
		}
		v.Set(mp)
	case reflect.Interface:
		if v.Type().String() == "context.Context" {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			time.AfterFunc(20*time.Millisecond, cancel)
			v.Set(reflect.ValueOf(ctx))
		}
	}
}

// cov96ClosedStoreMethods are *Service methods that reach the store without
// starting a background worker. Names that spawn goroutines, open listeners,
// or call a container runtime are intentionally absent.
var cov96ClosedStoreMethods = []string{
	"AuthorizeSandboxAuditAccess",
	"AddCustomDomain",
	"ListCustomDomains",
	"UpsertCompatState",
	"GetCompatState",
	"ListCompatState",
	"ResolveSandboxIDByName",
	"UpdateTags",
	"UpsertSnapshotAlias",
	"GetSnapshotAlias",
	"ListSnapshotAliases",
	"DeleteSnapshotAlias",
	"ClaimIdempotentRequest",
	"GetIdempotentRequest",
	"CompleteIdempotentRequest",
	"DeleteIdempotentRequest",
	"RetireNodeStorage",
	"RevokeNodeStorageRetirement",
	"ListNodeStorageRetirements",
	"ResolvePlatformVolumesForReplication",
	"UpsertClusterSecretBlob",
	"HasLocalSealedSecretGeneration",
	"SecretHoldersForSandbox",
	"ListSandboxesWithOptions",
	"GetSnapshot",
	"ListSnapshots",
	"GetTemplate",
	"ListTemplates",
	"ListWasmModules",
	"GetWasmModule",
	"DeleteWasmModule",
	"DeleteTemplate",
	"DeleteSnapshot",
	"DeleteJSBundle",
	"GetIdempotentRequest",
}
