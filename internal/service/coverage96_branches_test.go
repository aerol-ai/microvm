package service

import (
	"archive/tar"
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// cb96Sink records events and can refuse durable writes. Injecting it keeps
// ensureSecretAuditSink from starting the file writer and its goroutines.
type cb96Sink struct {
	mu         sync.Mutex
	events     []SecretAuditEvent
	durableErr error
}

func (s *cb96Sink) Emit(ev SecretAuditEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, ev)
}

func (s *cb96Sink) EmitDurable(ev SecretAuditEvent) error {
	if s.durableErr != nil {
		return s.durableErr
	}
	s.Emit(ev)
	return nil
}

func cb96OpenStore(t *testing.T) (*storepkg.Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.db")
	st, err := storepkg.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st, path
}

// cb96SQL runs raw statements against the store's sqlite file through a
// second connection, which is how the tests break one table at a time.
func cb96SQL(t *testing.T, path string, stmts ...string) {
	t.Helper()
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("exec %q: %v", stmt, err)
		}
	}
}

func cb96Service(st *storepkg.Store, cfg config.Config) *Service {
	return &Service{
		store:       st,
		cfg:         cfg,
		logger:      slog.New(slog.DiscardHandler),
		secretAudit: &cb96Sink{},
	}
}

func TestCB96NodeStorageRetirementBranches(t *testing.T) {
	ctx := context.Background()

	if identityMembers(nil) != nil {
		t.Fatal("nil cluster should have no members")
	}
	noop := cluster.NewNoop("node-self", "", "")
	_ = identityMembers(noop)
	(*Service)(nil).invalidateNodeStorageRetirements()

	// Standalone: the local table is the authority, and every read/write
	// surfaces a closed store.
	st, _ := cb96OpenStore(t)
	svc := cb96Service(st, config.Config{})
	if err := svc.RetireNodeStorage(ctx, "node-gone", "op", "disk shredded"); err != nil {
		t.Fatalf("standalone retire: %v", err)
	}
	if recs, err := svc.ListNodeStorageRetirements(ctx); err != nil || len(recs) != 1 {
		t.Fatalf("standalone list = %+v, %v", recs, err)
	}
	if got := svc.nodeStorageRetirements(ctx); len(got) != 1 {
		t.Fatalf("standalone cached set = %v", got)
	}
	// Retired entries exist but no cluster is attached: nothing to reap.
	svc.reapLiveNodeStorageRetirements(ctx)
	if _, ok := svc.nodeStorageRetirementWriter(); ok {
		t.Fatal("standalone node exposed a replicated writer")
	}
	if _, ok := svc.authoritativeRetirementReader(); ok {
		t.Fatal("standalone node exposed an authoritative reader")
	}
	if _, err := svc.clusterNodeStorageRetirements(ctx); err == nil {
		t.Fatal("standalone cluster registry read should fail")
	}

	closed, _ := cb96OpenStore(t)
	closedSvc := cb96Service(closed, config.Config{})
	_ = closed.Close()
	if err := closedSvc.RetireNodeStorage(ctx, "node-gone", "op", ""); err == nil {
		t.Fatal("retire on closed store succeeded")
	}
	if _, err := closedSvc.RevokeNodeStorageRetirement(ctx, "node-gone"); err == nil {
		t.Fatal("revoke on closed store succeeded")
	}
	if _, err := closedSvc.authoritativeNodeStorageRetirements(ctx); err == nil {
		t.Fatal("authoritative read on closed store succeeded")
	}
	if got := closedSvc.nodeStorageRetirements(ctx); got != nil {
		t.Fatalf("closed store retirements = %v", got)
	}
	closedSvc.reapLiveNodeStorageRetirements(ctx)
	(&Service{}).reapLiveNodeStorageRetirements(ctx)

	// Cluster mode with no client attached.
	detached := cb96Service(st, config.Config{EnableCluster: true})
	if _, ok := detached.nodeStorageRetirementWriter(); ok {
		t.Fatal("detached cluster exposed a writer")
	}
	if _, ok := detached.authoritativeRetirementReader(); ok {
		t.Fatal("detached cluster exposed an authoritative reader")
	}
	if _, ok := detached.nodeStorageRetirementReader(); ok {
		t.Fatal("detached cluster exposed a reader")
	}

	// Clustered read failure keeps obligations pending for the tick.
	failing := &retirementCluster{Noop: cluster.NewNoop("node-self", "", "")}
	failing.sharedRegistry().err = errors.New("raft unavailable")
	failSvc := cb96Service(st, config.Config{EnableCluster: true})
	failSvc.cluster = failing
	if got := failSvc.nodeStorageRetirements(ctx); got != nil {
		t.Fatalf("failed replicated read = %v", got)
	}

	// A live node with a cached attestation whose revoke fails, then one
	// whose revoke succeeds.
	reg := &retirementCluster{
		Noop: cluster.NewNoop("node-self", "", ""),
		members: []cluster.Member{
			{NodeID: "", Alive: true},
			{NodeID: "node-dead", Alive: false},
			{NodeID: "node-back", Alive: true},
		},
	}
	reg.sharedRegistry().retire(cluster.NodeStorageRetirement{NodeID: "node-back", AttestedUnixNano: time.Now().UnixNano()})
	reapSvc := cb96Service(st, config.Config{EnableCluster: true})
	reapSvc.cluster = reg
	if got := reapSvc.nodeStorageRetirements(ctx); len(got) != 1 {
		t.Fatalf("replicated retirements = %v", got)
	}
	reg.sharedRegistry().err = errors.New("leader lost")
	reapSvc.reapLiveNodeStorageRetirements(ctx)
	reg.sharedRegistry().err = nil
	reapSvc.reapLiveNodeStorageRetirements(ctx)
	if recs, _ := reg.NodeStorageRetirements(ctx); len(recs) != 0 {
		t.Fatalf("live node attestation not revoked: %+v", recs)
	}
}

func TestCB96RecordStorageRetirementDischarge(t *testing.T) {
	if got := (*Service)(nil).recordStorageRetirementDischarge("sb", "inc", 1, []string{"n"}); got != nil {
		t.Fatalf("nil service = %v", got)
	}
	sink := &cb96Sink{durableErr: errors.New("disk full")}
	svc := &Service{logger: slog.New(slog.DiscardHandler), secretAudit: sink}
	if got := svc.recordStorageRetirementDischarge("sb", "inc", 1, []string{"node-a"}); len(got) != 0 {
		t.Fatalf("failed durable evidence must not discharge: %v", got)
	}
	sink.durableErr = nil
	if got := svc.recordStorageRetirementDischarge("sb", "inc", 1, []string{"node-a", "node-b"}); len(got) != 2 {
		t.Fatalf("recorded = %v", got)
	}
}

func TestCB96ServiceSmallHelpers(t *testing.T) {
	if ctx := contextWithStoredSpecReplay(nil); !isStoredSpecReplay(ctx) {
		t.Fatal("nil context lost the replay marker")
	}
	if isStoredSpecReplay(nil) {
		t.Fatal("nil context reported replay")
	}
	if err := validateUniqueMountTargets([]models.MountSpec{{Target: ""}, {Target: "/a"}}); err != nil {
		t.Fatalf("blank target: %v", err)
	}
	if got := hostFromURL("a]:b"); got != "a" {
		t.Fatalf("hostFromURL = %q", got)
	}
	if err := NormalizeCreateFailover(&models.CreateSandboxRequest{Failover: &models.Failover{Policy: "bogus-policy"}}); err == nil {
		t.Fatal("invalid failover accepted")
	}
	svc := &Service{cfg: config.Config{ImageGCWhitelist: []string{"", "alpine:3"}}}
	if svc.imageGCWhitelisted("busybox") {
		t.Fatal("busybox whitelisted")
	}
	svc.refreshPendingImageGCOnUse(context.Background(), "")
	if _, err := (&Service{}).imageRemoverForEngine(models.ContainerEngineDocker); !errors.Is(err, models.ErrContainerEngineNotRegistered) {
		t.Fatalf("docker remover without docker = %v", err)
	}
	(&Service{cluster: &emptySelfCluster{Noop: cluster.NewNoop("x", "", "")}, logger: slog.New(slog.DiscardHandler)}).reconcileStaleOwnership(context.Background())
}

func TestCB96AuthorizePeerSecretDeleteErrors(t *testing.T) {
	ctx := context.Background()
	st, path := cb96OpenStore(t)
	svc := cb96Service(st, config.Config{EnableCluster: true})

	if err := svc.DeleteClusterSecretsLocal(ctx, "sb", "inc", 1, " "); !errors.Is(err, ErrClusterSecretOriginatorDenied) {
		t.Fatalf("empty peer = %v", err)
	}
	// No record, no covering tomb, and no cluster client attached.
	if err := svc.DeleteClusterSecretsLocal(ctx, "sb", "inc", 1, "node-b"); !errors.Is(err, ErrClusterSecretPlacementUnavailable) {
		t.Fatalf("detached cluster = %v", err)
	}
	svc.cluster = &authPlacementsCluster{Noop: cluster.NewNoop("node-a", "", ""), err: errors.New("leader lost")}
	if err := svc.DeleteClusterSecretsLocal(ctx, "sb", "inc", 1, "node-b"); !errors.Is(err, ErrClusterSecretPlacementUnavailable) {
		t.Fatalf("placement read failure = %v", err)
	}

	cb96SQL(t, path, `DROP TABLE cluster_secret_tombs`)
	if err := svc.DeleteClusterSecretsLocal(ctx, "sb", "inc", 1, "node-b"); err == nil {
		t.Fatal("tomb read failure accepted")
	}
	cb96SQL(t, path, `DROP TABLE cluster_secrets`)
	if err := svc.DeleteClusterSecretsLocal(ctx, "sb", "inc", 1, "node-b"); err == nil {
		t.Fatal("record read failure accepted")
	}
}

func TestCB96SecretRecipientsForDeleteOutboxReadFailure(t *testing.T) {
	ctx := context.Background()
	st, path := cb96OpenStore(t)
	svc := cb96Service(st, config.Config{})
	cb96SQL(t, path, `DROP TABLE cluster_secret_put_outbox`)
	if _, err := svc.secretRecipientsForDelete(ctx, "sb", "inc"); err == nil {
		t.Fatal("put outbox read failure accepted")
	}
	if err := svc.DeleteClusterSecrets(ctx, "sb", "inc"); err == nil {
		t.Fatal("delete proceeded without resolving recipients")
	}
}

func TestCB96StagedResealTakeoverRejectsOtherIncarnation(t *testing.T) {
	ctx := context.Background()
	st, _ := cb96OpenStore(t)
	ref := secrets.FormatRef("sb-stage", "inc-a", secrets.RefVersion)
	if _, err := st.PutClusterSecret(ctx, storepkg.ClusterSecretRecord{
		Ref: ref, SandboxID: "sb-stage", Version: secrets.RefVersion, Recipients: []string{"node-b"},
		SealedPayload: []byte("sealed"), SealGeneration: 5,
	}); err != nil {
		t.Fatal(err)
	}
	svc := cb96Service(st, config.Config{EnableCluster: true})
	placement := cluster.PlacementSecrets{Ref: ref, Version: secrets.RefVersion, SealGeneration: 1, IncarnationID: "inc-other"}
	if _, ok := svc.stagedResealTakeoverHandle(ctx, "sb-stage", placement, "node-b"); ok {
		t.Fatal("staged handle crossed incarnations")
	}
}

func TestCB96OpenClusterSecretsDerivesAuditIncarnation(t *testing.T) {
	svc := &Service{secretAudit: &cb96Sink{}}
	ref := secrets.FormatRef("sb-open", "inc-open", secrets.RefVersion)
	_, err := svc.OpenClusterSecretsForNode(context.Background(), "", models.CreateSandboxRequest{},
		cluster.PlacementSecrets{Ref: ref, Version: secrets.RefVersion, SealGeneration: 1}, "node-a")
	if !errors.Is(err, secrets.ErrVersionMismatch) {
		t.Fatalf("placement without incarnation = %v", err)
	}
}

func TestCB96RetireStandaloneSecretOutboxFaults(t *testing.T) {
	ctx := context.Background()
	prev := secretLifecycleNow
	secretLifecycleNow = func() time.Time { return time.Now().Add(48 * time.Hour) }
	t.Cleanup(func() { secretLifecycleNow = prev })

	seed := func(t *testing.T) (*storepkg.Store, string) {
		st, path := cb96OpenStore(t)
		if err := st.UpsertSecretDeleteOutbox(ctx, "sb-del", "inc-del", []string{"node-b"}, 1); err != nil {
			t.Fatal(err)
		}
		if err := st.UpsertSecretPutOutbox(ctx, "sb-put", "inc-put", 1, []string{"node-c"}); err != nil {
			t.Fatal(err)
		}
		return st, path
	}
	cfg := config.Config{SecretOutboxStandaloneGrace: time.Hour}

	st, _ := seed(t)
	if err := cb96Service(st, cfg).retireStandaloneSecretOutbox(ctx); err != nil {
		t.Fatalf("retire: %v", err)
	}

	st, path := seed(t)
	cb96SQL(t, path, `CREATE TRIGGER cb96_del BEFORE DELETE ON cluster_secret_delete_outbox BEGIN SELECT RAISE(ABORT, 'cb96'); END`)
	if err := cb96Service(st, cfg).retireStandaloneSecretOutbox(ctx); err == nil {
		t.Fatal("delete-outbox delete failure swallowed")
	}

	st, path = seed(t)
	cb96SQL(t, path, `CREATE TRIGGER cb96_put BEFORE DELETE ON cluster_secret_put_outbox BEGIN SELECT RAISE(ABORT, 'cb96'); END`)
	if err := cb96Service(st, cfg).retireStandaloneSecretOutbox(ctx); err == nil {
		t.Fatal("put-outbox delete failure swallowed")
	}

	st, path = seed(t)
	cb96SQL(t, path, `DROP TABLE cluster_secret_put_outbox`)
	if err := cb96Service(st, cfg).retireStandaloneSecretOutbox(ctx); err == nil {
		t.Fatal("put-outbox list failure swallowed")
	}
}

// cb96ManualSink opens a real audit log synchronously without starting the
// writer goroutine: the tests drive appendBatchLocked/writeEventBatch
// themselves and must never call Emit's blocking siblings (Sync, EmitDurable).
func cb96ManualSink(t *testing.T) *fileAuditSink {
	t.Helper()
	s, err := cb96OpenManualSink(t, filepath.Join(t.TempDir(), "audit"), secretAuditBootVerifyFull)
	if err != nil {
		t.Fatalf("open manual sink: %v", err)
	}
	return s
}

func cb96OpenManualSink(t *testing.T, auditDir, bootVerify string) (*fileAuditSink, error) {
	t.Helper()
	if err := os.MkdirAll(auditDir, 0o700); err != nil {
		t.Fatal(err)
	}
	s := &fileAuditSink{
		ch:               make(chan auditWriteReq, 8),
		spillCh:          make(chan SecretAuditEvent, 8),
		done:             make(chan struct{}),
		path:             filepath.Join(auditDir, secretAuditFileName),
		lockPath:         filepath.Join(auditDir, auditlog.LockFileName),
		gapPath:          filepath.Join(auditDir, "secrets.gap"),
		tipPath:          filepath.Join(auditDir, "secrets.tip"),
		spillPath:        filepath.Join(auditDir, auditlog.SpillFileName),
		spillWorkingPath: filepath.Join(auditDir, secretAuditSpillWorking),
		tornPath:         filepath.Join(auditDir, secretAuditTornName),
		verifiedPath:     filepath.Join(auditDir, secretAuditVerifiedName),
		witnessTipPath:   filepath.Join(auditDir, secretAuditWitnessTipFile),
		bootVerify:       bootVerify,
	}
	if err := s.withAuditFileLock(s.openLocked); err != nil {
		return nil, err
	}
	t.Cleanup(func() {
		if s.file != nil {
			_ = s.file.Close()
		}
	})
	return s, nil
}

func cb96Append(t *testing.T, s *fileAuditSink, events ...SecretAuditEvent) {
	t.Helper()
	if err := s.writeEventBatch(events, true, false); err != nil {
		t.Fatalf("append: %v", err)
	}
}

func cb96Open(sandboxID string) SecretAuditEvent {
	return SecretAuditEvent{SandboxID: sandboxID, IncarnationID: "inc", Kind: secretAuditKindSecretOpen,
		Result: secretAuditResultSuccess, Reason: secretAuditReasonOK}
}

func cb96LinkedLine(t *testing.T, prev string, ev SecretAuditEvent) (SecretAuditEvent, []byte) {
	t.Helper()
	if ev.Time.IsZero() {
		ev.Time = time.Now().UTC()
	}
	ensureSecretAuditEventID(&ev)
	auditlog.LinkEvent(prev, &ev)
	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	return ev, raw
}

func TestCB96SecretAuditIndexerDirectPaths(t *testing.T) {
	ctx := context.Background()
	st, path := cb96OpenStore(t)
	sink := cb96ManualSink(t)
	idx := newSecretAuditIndexer(st, sink, slog.New(slog.DiscardHandler))

	(*secretAuditIndexer)(nil).markBroken(errors.New("x"))
	ev, raw := cb96LinkedLine(t, auditlog.GenesisPrevHash, SecretAuditEvent{Kind: secretAuditKindSecretOpen, Result: secretAuditResultSuccess})
	line := secretAuditIndexedLine{offset: 0, length: int64(len(raw)) + 1, raw: raw, ev: ev}

	// Not ready: both hooks leave the work to the maintainer.
	idx.onAppended([]secretAuditIndexedLine{line})
	idx.onPruned(secretAuditPruneShift{exact: true})
	idx.reportCorrupt(errors.New("not ready yet"))

	// Ready but the batch was already indexed, then a batch that does not
	// continue the index.
	idx.setReady(storepkg.SecretAuditIndexMeta{Generation: "g", IndexedThrough: 10_000}, 0)
	idx.onAppended([]secretAuditIndexedLine{line})
	idx.meta.IndexedThrough = 5
	idx.onAppended([]secretAuditIndexedLine{line})
	if idx.isReady() {
		t.Fatal("non-contiguous append left the index ready")
	}

	// A batch whose hashes do not link latches the chain break.
	bad := line
	bad.ev.EventHash = "not-the-hash"
	idx.setReady(storepkg.SecretAuditIndexMeta{Generation: "g"}, 0)
	idx.onAppended([]secretAuditIndexedLine{bad})
	if !idx.broken.Load() {
		t.Fatal("chain break not latched")
	}

	// Store failures on write and shift degrade the index.
	idx2 := newSecretAuditIndexer(st, sink, slog.New(slog.DiscardHandler))
	cb96SQL(t, path, `DROP TABLE secret_audit_index_meta`)
	idx2.setReady(storepkg.SecretAuditIndexMeta{Generation: "g"}, 0)
	idx2.onAppended([]secretAuditIndexedLine{line})
	if idx2.isReady() {
		t.Fatal("write failure left the index ready")
	}
	idx2.setReady(storepkg.SecretAuditIndexMeta{Generation: "g", IndexedThrough: 10}, 0)
	idx2.onPruned(secretAuditPruneShift{exact: true, generation: "g2", floor: 50, checkpointLen: 20})
	if idx2.isReady() {
		t.Fatal("shift failure left the index ready")
	}
	if err := idx2.catchUp(); err == nil {
		t.Fatal("catch-up with a broken meta table succeeded")
	}

	// A stopped maintainer returns immediately.
	idx3 := newSecretAuditIndexer(st, sink, nil)
	close(idx3.stop)
	if err := idx3.catchUp(); err != nil {
		t.Fatalf("stopped catch-up: %v", err)
	}
	_ = ctx
}

func TestCB96SecretAuditIndexerCatchUpFaults(t *testing.T) {
	// The audit path is a directory: opening it for its generation fails
	// with something other than not-exist.
	st, _ := cb96OpenStore(t)
	dir := t.TempDir()
	dirSink := &fileAuditSink{path: dir, lockPath: filepath.Join(t.TempDir(), "lock")}
	if err := newSecretAuditIndexer(st, dirSink, nil).catchUp(); err == nil {
		t.Fatal("catch-up over a directory succeeded")
	}

	// One complete record followed by an unterminated tail: the first pass
	// indexes the record, the second finds nothing complete to index.
	st2, _ := cb96OpenStore(t)
	sink := cb96ManualSink(t)
	cb96Append(t, sink, cb96Open("sb-tail"))
	f, err := os.OpenFile(sink.path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(`{"partial":`)
	_ = f.Close()
	idx := newSecretAuditIndexer(st2, sink, slog.New(slog.DiscardHandler))
	if err := idx.catchUp(); err != nil {
		t.Fatalf("catch-up over a torn tail: %v", err)
	}
	if !idx.isReady() {
		t.Fatal("index not ready after catch-up")
	}

	// An oversized record cannot be indexed.
	st3, _ := cb96OpenStore(t)
	longSink := cb96ManualSink(t)
	big := make([]byte, secretAuditMaxLineBytes+16)
	for i := range big {
		big[i] = 'x'
	}
	big[len(big)-1] = '\n'
	if err := os.WriteFile(longSink.path, big, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := newSecretAuditIndexer(st3, longSink, nil).catchUp(); err == nil {
		t.Fatal("oversized record indexed")
	}

	// Chunk inserts fail after the reset succeeded.
	st4, path4 := cb96OpenStore(t)
	sink4 := cb96ManualSink(t)
	cb96Append(t, sink4, cb96Open("sb-chunk"))
	cb96SQL(t, path4, `CREATE TRIGGER cb96_idx BEFORE INSERT ON secret_audit_index BEGIN SELECT RAISE(ABORT, 'cb96'); END`)
	if err := newSecretAuditIndexer(st4, sink4, nil).catchUp(); err == nil {
		t.Fatal("chunk insert failure swallowed")
	}

	// The reset itself fails.
	st5, path5 := cb96OpenStore(t)
	sink5 := cb96ManualSink(t)
	cb96Append(t, sink5, cb96Open("sb-reset"))
	cb96SQL(t, path5, `CREATE TRIGGER cb96_reset BEFORE INSERT ON secret_audit_index_meta BEGIN SELECT RAISE(ABORT, 'cb96'); END`)
	if err := newSecretAuditIndexer(st5, sink5, nil).catchUp(); err == nil {
		t.Fatal("reset failure swallowed")
	}
}

func TestCB96SecretAuditReadPaths(t *testing.T) {
	ctx := context.Background()

	// Heap Pop is part of the container/heap contract even though the page
	// selection only pushes and fixes.
	h := auditIndexCandHeap{{time: 1}, {time: 2}}
	if got := h.Pop().(auditIndexCand); got.time != 2 || len(h) != 1 {
		t.Fatalf("pop = %+v, len %d", got, len(h))
	}
	if err := verifySecretAuditRecord(SecretAuditEvent{PrevHash: "p"}); err == nil {
		t.Fatal("record without event hash verified")
	}

	sink := cb96ManualSink(t)
	cb96Append(t, sink, cb96Open("sb-read"), cb96Open("sb-read"))
	f, err := os.Open(sink.path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	q := secretAuditPageQuery{sandboxID: "sb-read", limit: 10}
	chunk := func(entries ...auditlog.IndexEntry) []storepkg.SecretAuditIndexChunk {
		c, err := storepkg.NewSecretAuditIndexChunk(storepkg.SecretAuditIndexKey{SandboxID: "sb-read"}, 0, entries)
		if err != nil {
			t.Fatal(err)
		}
		return []storepkg.SecretAuditIndexChunk{c}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := readIndexedSecretAudit(cancelled, f, chunk(auditlog.IndexEntry{Offset: 0, Length: 10, TimeNano: 1}), q, newSecretAuditPageCollector(10)); err == nil {
		t.Fatal("cancelled indexed read succeeded")
	}
	if err := readIndexedSecretAudit(ctx, f, chunk(auditlog.IndexEntry{Offset: 0, Length: secretAuditMaxLineBytes + 1, TimeNano: 1}), q, newSecretAuditPageCollector(10)); !errors.Is(err, errSecretAuditIndexCorrupt) {
		t.Fatalf("bad length = %v", err)
	}
	if err := readIndexedSecretAudit(ctx, f, chunk(auditlog.IndexEntry{Offset: 1 << 30, Length: 10, TimeNano: 1}), q, newSecretAuditPageCollector(10)); !errors.Is(err, errSecretAuditIndexCorrupt) {
		t.Fatalf("offset past EOF = %v", err)
	}
	if err := readIndexedSecretAudit(ctx, f, chunk(auditlog.IndexEntry{Offset: 3, Length: 10, TimeNano: 1}), q, newSecretAuditPageCollector(10)); !errors.Is(err, errSecretAuditIndexCorrupt) {
		t.Fatalf("mid-record offset = %v", err)
	}
	st, _ := f.Stat()
	if err := scanSecretAuditRange(cancelled, f, 0, st.Size(), q, newSecretAuditPageCollector(10)); err == nil {
		t.Fatal("cancelled scan succeeded")
	}

	long := filepath.Join(t.TempDir(), "long.jsonl")
	big := make([]byte, secretAuditMaxLineBytes+16)
	for i := range big {
		big[i] = 'y'
	}
	big[len(big)-1] = '\n'
	if err := os.WriteFile(long, big, 0o600); err != nil {
		t.Fatal(err)
	}
	lf, err := os.Open(long)
	if err != nil {
		t.Fatal(err)
	}
	defer lf.Close()
	if err := scanSecretAuditRange(ctx, lf, 0, int64(len(big)), q, newSecretAuditPageCollector(10)); err == nil {
		t.Fatal("oversized record scanned")
	}

	if err := (&Service{cfg: config.Config{SecretAuditRetentionDays: -1}}).PruneSecretAudit(ctx); err != nil {
		t.Fatalf("disabled retention: %v", err)
	}
}

func TestCB96VerifySecretAuditChainOutcomes(t *testing.T) {
	ctx := context.Background()

	// No file yet.
	missing := cb96ManualSink(t)
	_ = missing.file.Close()
	missing.file = nil
	_ = os.Remove(missing.path)
	svc := &Service{secretAudit: missing, secretAuditFile: missing}
	if rep, err := svc.VerifySecretAuditChain(ctx); err != nil || !rep.OK {
		t.Fatalf("missing file = %+v, %v", rep, err)
	}

	// The path is a directory.
	dirSink := &fileAuditSink{path: t.TempDir(), lockPath: filepath.Join(t.TempDir(), "lock")}
	if _, err := (&Service{secretAudit: dirSink, secretAuditFile: dirSink}).VerifySecretAuditChain(ctx); err == nil {
		t.Fatal("directory verified")
	}

	// Unterminated tail.
	torn := cb96ManualSink(t)
	cb96Append(t, torn, cb96Open("sb-torn"))
	tf, err := os.OpenFile(torn.path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = tf.WriteString(`{"x":`)
	_ = tf.Close()
	if rep, err := (&Service{secretAudit: torn, secretAuditFile: torn}).VerifySecretAuditChain(ctx); err != nil || rep.OK {
		t.Fatalf("torn tail = %+v, %v", rep, err)
	}

	// The writer's tip disagrees with the verified head.
	drift := cb96ManualSink(t)
	cb96Append(t, drift, cb96Open("sb-drift"))
	drift.chainHead = "someone-elses-head"
	if rep, err := (&Service{secretAudit: drift, secretAuditFile: drift}).VerifySecretAuditChain(ctx); err != nil || rep.OK || rep.WriterTipMatches {
		t.Fatalf("tip drift = %+v, %v", rep, err)
	}
}

func TestCB96ListSecretAuditLocalIndexBranches(t *testing.T) {
	ctx := context.Background()

	// The index is ready but its store is gone.
	st, _ := cb96OpenStore(t)
	sink := cb96ManualSink(t)
	cb96Append(t, sink, cb96Open("sb-list"))
	idx := newSecretAuditIndexer(st, sink, nil)
	idx.setReady(storepkg.SecretAuditIndexMeta{Generation: "g"}, 0)
	svc := &Service{store: st, secretAudit: sink, secretAuditFile: sink, secretAuditIndex: idx}
	_ = st.Close()
	if _, _, err := svc.ListSecretAuditLocal(ctx, "sb-list", SecretAuditQuery{IncarnationID: "inc"}); err == nil {
		t.Fatal("index read on a closed store succeeded")
	}

	// The stored index names another generation: reopen once, then scan.
	st2, _ := cb96OpenStore(t)
	sink2 := cb96ManualSink(t)
	cb96Append(t, sink2, cb96Open("sb-gen"))
	if err := st2.ResetSecretAuditIndex(ctx, storepkg.SecretAuditIndexMeta{Generation: "another-generation"}); err != nil {
		t.Fatal(err)
	}
	idx2 := newSecretAuditIndexer(st2, sink2, nil)
	idx2.setReady(storepkg.SecretAuditIndexMeta{Generation: "another-generation"}, 0)
	svc2 := &Service{store: st2, secretAudit: sink2, secretAuditFile: sink2, secretAuditIndex: idx2}
	events, _, err := svc2.ListSecretAuditLocal(ctx, "sb-gen", SecretAuditQuery{IncarnationID: "inc"})
	if err != nil || len(events) != 1 {
		t.Fatalf("generation mismatch fallback = %d events, %v", len(events), err)
	}
}

func TestCB96AcquireSecretAuditQuerySlotWaits(t *testing.T) {
	held := 0
	for len(secretAuditLocalQuerySlots) < cap(secretAuditLocalQuerySlots) {
		secretAuditLocalQuerySlots <- struct{}{}
		held++
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := acquireSecretAuditQuerySlot(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled wait = %v", err)
	}
	go func() {
		time.Sleep(5 * time.Millisecond)
		<-secretAuditLocalQuerySlots
	}()
	release, err := acquireSecretAuditQuerySlot(context.Background())
	if err != nil {
		t.Fatalf("slot never freed: %v", err)
	}
	release()
	for i := 0; i < held-1; i++ {
		<-secretAuditLocalQuerySlots
	}
}

func TestCB96SanitizeSpillRecord(t *testing.T) {
	if gap := spillMalformedGap(nil); gap.Kind != secretAuditKindGap {
		t.Fatalf("empty seed gap = %+v", gap)
	}
	s := &fileAuditSink{
		spillVerify: func(string, time.Time) (string, string, error) { return "sb-spill", "inc", nil },
		spillActor:  func() string { return "node-a" },
	}
	gap := s.sanitizeSpillRecord(auditlog.SpillRecord{Event: auditlog.Event{Kind: secretAuditKindGap}}, time.Time{})
	if gap.Dropped != 1 || gap.Kind != secretAuditKindGap {
		t.Fatalf("gap = %+v", gap)
	}
	longDest := make([]byte, secretAuditSpillDestMax+10)
	for i := range longDest {
		longDest[i] = 'd'
	}
	eg := s.sanitizeSpillRecord(auditlog.SpillRecord{Event: auditlog.Event{Kind: secretAuditKindEgress, Destination: string(longDest)}}, time.Now())
	if len(eg.Destination) != secretAuditSpillDestMax || eg.SandboxID != "sb-spill" {
		t.Fatalf("egress = %+v", eg)
	}
}

type cb96Witness struct {
	mu      sync.Mutex
	head    string
	ok      bool
	lastErr error
	shipErr error
}

func (w *cb96Witness) WitnessHeads(_ context.Context, heads []controlplane.AuditHead) (controlplane.WitnessReceipt, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.shipErr != nil {
		return controlplane.WitnessReceipt{}, w.shipErr
	}
	if len(heads) > 0 {
		w.head, w.ok = heads[len(heads)-1].HeadHex, true
	}
	return controlplane.WitnessReceipt{ReceiptID: "r-1"}, nil
}

func (w *cb96Witness) LastWitnessedHead(context.Context, string) (string, bool, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.head, w.ok, w.lastErr
}

// cb96WitnessService wires a closed manual sink (Sync is then a no-op) and an
// external witness.
func cb96WitnessService(t *testing.T, w controlplane.Witness, events int) (*Service, *fileAuditSink) {
	t.Helper()
	sink := cb96ManualSink(t)
	for i := 0; i < events; i++ {
		cb96Append(t, sink, cb96Open("sb-wit"))
	}
	sink.closed.Store(true)
	return &Service{secretAudit: sink, secretAuditFile: sink, auditWitness: w, logger: slog.New(slog.DiscardHandler)}, sink
}

func TestCB96WitnessShipBranches(t *testing.T) {
	ctx := context.Background()
	if err := (&Service{}).shipSecretAuditHeadNow(ctx); err != nil {
		t.Fatalf("no audit file: %v", err)
	}

	failing, _ := cb96WitnessService(t, &cb96Witness{shipErr: errors.New("witness down")}, 1)
	if err := failing.shipSecretAuditHeadNow(ctx); err == nil {
		t.Fatal("witness ship failure swallowed")
	}

	// The local tip already names the head but the witness disagrees, so the
	// same head is re-submitted (with a nil context).
	w := &cb96Witness{head: "stale", ok: true}
	svc, sink := cb96WitnessService(t, w, 1)
	head, eventID := sink.chainTip()
	if err := persistWitnessReceipt("", svc.secretAuditWitnessTipPath(), witnessReceiptRecord{HeadHex: head, EventID: eventID}); err != nil {
		t.Fatal(err)
	}
	//nolint:staticcheck // the nil context is the branch under test
	if err := svc.shipSecretAuditHeadNow(nil); err != nil {
		t.Fatalf("re-ship: %v", err)
	}
	if w.head != head {
		t.Fatalf("witness head = %q, want %q", w.head, head)
	}

	// The receipt cannot be persisted.
	blocked, bsink := cb96WitnessService(t, &cb96Witness{}, 1)
	if err := os.MkdirAll(bsink.witnessTipPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := blocked.shipSecretAuditHeadNow(ctx); err == nil {
		t.Fatal("receipt persist failure swallowed")
	}
	if _, err := readWitnessTip(bsink.witnessTipPath); err == nil {
		t.Fatal("directory read as a witness tip")
	}
}

func TestCB96VerifySecretAuditWitnessBranches(t *testing.T) {
	corrupt := func(t *testing.T, w controlplane.Witness) *Service {
		svc, sink := cb96WitnessService(t, w, 1)
		f, err := os.OpenFile(sink.path, os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.WriteString("{not json}\n")
		_ = f.Close()
		return svc
	}
	if ok, _, _, err := corrupt(t, nil).VerifySecretAuditWitness(); ok || err == nil {
		t.Fatalf("corrupt chain without witness = %v, %v", ok, err)
	}
	if ok, _, _, err := corrupt(t, &cb96Witness{head: "h", ok: true}).VerifySecretAuditWitness(); ok || err == nil {
		t.Fatalf("corrupt chain with witness = %v, %v", ok, err)
	}

	// An unreadable local receipt fails closed.
	svc, sink := cb96WitnessService(t, &cb96Witness{head: "h", ok: true}, 1)
	if err := os.MkdirAll(svc.secretAuditWitnessPath(), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := svc.VerifySecretAuditWitness(); err == nil {
		t.Fatal("unreadable receipt verified")
	}
	if !svc.emptyLocalChainIsErasure("", false) {
		t.Fatal("unreadable receipt not treated as erasure")
	}
	sink.bootScan.records = 1
	if _, _, _, err := svc.verifySecretAuditWitnessAtBoot(svc.witness()); err == nil {
		t.Fatal("boot check ignored an unreadable receipt")
	}
	if ok, _, _, _ := svc.judgeWitnessAncestry("local", "receipt", "remote", true, false, "remote"); !ok {
		t.Fatal("retention checkpoint ancestry rejected")
	}

	// Boot with an empty chain: fine while nothing remembers one, erasure
	// once the witness does.
	empty, _ := cb96WitnessService(t, &cb96Witness{}, 0)
	if ok, _, _, err := empty.verifySecretAuditWitnessAtBoot(empty.witness()); !ok || err != nil {
		t.Fatalf("empty boot = %v, %v", ok, err)
	}
	erased, _ := cb96WitnessService(t, &cb96Witness{head: "remembered", ok: true}, 0)
	if ok, _, _, err := erased.verifySecretAuditWitnessAtBoot(erased.witness()); ok || err != nil {
		t.Fatalf("erased boot = %v, %v", ok, err)
	}
}

func TestCB96RequireCurrentWitnessAndValidate(t *testing.T) {
	empty, _ := cb96WitnessService(t, &cb96Witness{}, 0)
	if head, err := empty.requireCurrentSecretAuditWitness(context.Background()); err != nil || (head != "" && head != auditlog.GenesisPrevHash) {
		t.Fatalf("empty chain = %q, %v", head, err)
	}
	full, sink := cb96WitnessService(t, &cb96Witness{}, 2)
	//nolint:staticcheck // the nil context is the branch under test
	head, err := full.requireCurrentSecretAuditWitness(nil)
	if want, _ := sink.chainTip(); err != nil || head != want {
		t.Fatalf("current head = %q, %v (want %q)", head, err, want)
	}

	// No file yet: the injected sink keeps ensureSecretAuditSink inert.
	noFile := &Service{secretAudit: &cb96Sink{}, auditWitness: &cb96Witness{}}
	if err := noFile.ValidateSecretAuditWitness(); err != nil {
		t.Fatalf("validate without file: %v", err)
	}
	bootstrap, _ := cb96WitnessService(t, &cb96Witness{shipErr: errors.New("witness down")}, 1)
	if err := bootstrap.ValidateSecretAuditWitness(); err == nil {
		t.Fatal("failed empty-witness bootstrap accepted")
	}
}

type cb96Exporter struct {
	mu    sync.Mutex
	err   error
	calls int
}

func (e *cb96Exporter) ExportEvents(context.Context, controlplane.AuditEventBatch) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.calls++
	return "", e.err
}

func TestCB96ExportSecretAuditBatchBranches(t *testing.T) {
	ctx := context.Background()
	exportSvc := func(sink *fileAuditSink, ex *cb96Exporter) *Service {
		return &Service{secretAudit: sink, secretAuditFile: sink, auditExporter: ex, logger: slog.New(slog.DiscardHandler)}
	}

	dirSink := &fileAuditSink{path: t.TempDir(), lockPath: filepath.Join(t.TempDir(), "lock")}
	if _, err := exportSvc(dirSink, &cb96Exporter{}).exportSecretAuditBatchOnce(ctx); err == nil {
		t.Fatal("directory exported")
	}
	if _, err := (&Service{secretAudit: dirSink, secretAuditFile: dirSink}).secretAuditFullyExported(); err == nil {
		t.Fatal("directory reported as exported")
	}

	missing := cb96ManualSink(t)
	_ = os.Remove(missing.path)
	if n, err := exportSvc(missing, &cb96Exporter{}).exportSecretAuditBatchOnce(ctx); err != nil || n != 0 {
		t.Fatalf("missing file = %d, %v", n, err)
	}

	// A cursor past EOF restarts from zero; a trailing blank line is skipped;
	// the node id comes from the cluster client.
	sink := cb96ManualSink(t)
	cb96Append(t, sink, cb96Open("sb-exp"))
	f, err := os.OpenFile(sink.path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("\n")
	_ = f.Close()
	rf, err := os.Open(sink.path)
	if err != nil {
		t.Fatal(err)
	}
	gen, err := auditFileGeneration(rf)
	_ = rf.Close()
	if err != nil {
		t.Fatal(err)
	}
	cursorPath := filepath.Join(filepath.Dir(sink.path), secretAuditExportOffset)
	if err := persistAuditExportCursor(cursorPath, auditExportCursor{Generation: gen, Offset: 1 << 30, Head: "h"}); err != nil {
		t.Fatal(err)
	}
	ex := &cb96Exporter{}
	svc := exportSvc(sink, ex)
	svc.cluster = cluster.NewNoop("node-exp", "", "")
	if n, err := svc.exportSecretAuditBatchOnce(ctx); err != nil || n != 1 {
		t.Fatalf("export = %d, %v", n, err)
	}

	// The receiver fails: back off.
	ex.err = errors.New("receiver down")
	_ = os.Remove(cursorPath)
	if _, err := svc.exportSecretAuditBatchOnce(ctx); err == nil {
		t.Fatal("receiver failure swallowed")
	}

	// The cursor cannot be persisted.
	ex.err = nil
	svc.auditExportNotBefore = time.Time{}
	if err := os.MkdirAll(cursorPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.exportSecretAuditBatchOnce(ctx); err == nil {
		t.Fatal("cursor persist failure swallowed")
	}

	// A record longer than the scanner buffer.
	longSink := cb96ManualSink(t)
	cb96Append(t, longSink, cb96Open("sb-long"))
	lf, err := os.OpenFile(longSink.path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	big := make([]byte, 1024*1024+32)
	for i := range big {
		big[i] = 'z'
	}
	big[len(big)-1] = '\n'
	_, _ = lf.Write(big)
	_ = lf.Close()
	if _, err := exportSvc(longSink, &cb96Exporter{}).exportSecretAuditBatchOnce(ctx); err == nil {
		t.Fatal("oversized record exported")
	}

	// An unreadable audit file.
	locked := cb96ManualSink(t)
	cb96Append(t, locked, cb96Open("sb-locked"))
	if err := os.Chmod(locked.path, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked.path, 0o600) })
	if _, err := (&Service{secretAudit: locked, secretAuditFile: locked}).secretAuditFullyExported(); err == nil && os.Geteuid() != 0 {
		t.Fatal("unreadable file reported as exported")
	}

	closedFile, err := os.CreateTemp(t.TempDir(), "closed")
	if err != nil {
		t.Fatal(err)
	}
	_ = closedFile.Close()
	if _, err := auditFileGeneration(closedFile); err == nil {
		t.Fatal("generation of a closed file")
	}

	if err := (*Service)(nil).ConfigureAuditExporter(); err != nil {
		t.Fatalf("nil configure: %v", err)
	}
	if err := (*Service)(nil).AuditExportHealthy(ctx); err != nil {
		t.Fatalf("nil health: %v", err)
	}
	(&Service{cfg: config.Config{AuditExportBackend: "no-such-backend"}, logger: slog.New(slog.DiscardHandler)}).ConfigureHTTPAuditExporter()
}

func TestCB96AuditIngestBranches(t *testing.T) {
	if _, err := (*Service)(nil).IssueEgressAuditCapability("sb", "inc", time.Minute); err == nil {
		t.Fatal("nil service minted a capability")
	}
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, auditIngestKeyFile), 0o700); err != nil {
		t.Fatal(err)
	}
	unreadable := &Service{cfg: config.Config{DBPath: filepath.Join(dir, "state.db"), EgressAttributionEnabled: true}}
	if got := unreadable.auditIngestToken(); got != "" {
		t.Fatalf("token from an unreadable key = %q", got)
	}

	// The binding check cannot reach its store: 503, not 401.
	st, _ := cb96OpenStore(t)
	svc := cb96Service(st, config.Config{})
	_ = st.Close()
	ing := &auditIngestServer{svc: svc, token: "cb96-token"}
	capability, err := auditlog.MintEgressCapability(ing.token, "sb-ing", "inc-ing", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/egress", strings.NewReader(`{"destination":"example.com:443"}`))
	req.RemoteAddr = "127.0.0.1:4000"
	req.Header.Set(auditIngestHeaderCap, capability)
	rec := httptest.NewRecorder()
	ing.handleEgress(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("binding failure status = %d", rec.Code)
	}
}

func cb96AppendRaw(t *testing.T, path, text string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(text); err != nil {
		t.Fatal(err)
	}
}

func cb96Repeat(b byte, n int) string {
	buf := make([]byte, n)
	for i := range buf {
		buf[i] = b
	}
	return string(buf)
}

func TestCB96SecretAuditCheckpointBoot(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "audit")
	first, err := cb96OpenManualSink(t, dir, secretAuditBootVerifyCheckpoint)
	if err != nil {
		t.Fatal(err)
	}
	cb96Append(t, first, cb96Open("sb-cp"), cb96Open("sb-cp"))
	first.persistVerifiedLocked()
	cp := loadVerifiedCheckpoint(first.verifiedPath)
	if cp == nil {
		t.Fatal("no verified checkpoint written")
	}
	_ = first.file.Close()
	first.file = nil

	// Garbage after the checkpoint fails the incremental scan.
	cb96AppendRaw(t, first.path, "{garbage}\n")
	if _, _, err := scanSecretAuditChainFromCheckpoint(first.path, cp, nil); err == nil {
		t.Fatal("garbage after checkpoint verified")
	}
	if _, err := cb96OpenManualSink(t, dir, secretAuditBootVerifyCheckpoint); err == nil {
		t.Fatal("checkpoint boot accepted a corrupt tail")
	}

	// An unreadable file fails both the checkpoint and the full scan.
	if err := os.Chmod(first.path, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(first.path, 0o600) })
	if os.Geteuid() != 0 {
		if _, _, err := scanSecretAuditChainFromCheckpoint(first.path, cp, nil); err == nil {
			t.Fatal("unreadable file scanned from checkpoint")
		}
		if _, err := scanSecretAuditChainWith(first.path, secretAuditScanOptions{}); err == nil {
			t.Fatal("unreadable file scanned")
		}
	}

	// A closed append handle cannot be stat'ed for the checkpoint, fsynced,
	// or appended to.
	closed := cb96ManualSink(t)
	cb96Append(t, closed, cb96Open("sb-closed"))
	_ = closed.file.Close()
	closed.persistVerifiedLocked()
	if err := closed.syncFile(); err == nil {
		t.Fatal("sync of a closed file succeeded")
	}
	if err := closed.writeEventBatch([]SecretAuditEvent{cb96Open("sb-closed")}, true, true); err == nil {
		t.Fatal("append to a closed file succeeded")
	}
}

func TestCB96SecretAuditSmallFileHelpers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tail.jsonl")
	if err := os.WriteFile(path, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := repairSecretAuditTail(path, secretAuditChainScan{tornBytes: 1, validEnd: -1}); err == nil {
		t.Fatal("negative truncate succeeded")
	}
	br := bufio.NewReader(strings.NewReader("line\n"))
	if line, _, terminated, _, err := readSecretAuditLineMax(br, 0); err != nil || !terminated || string(line) != "line\n" {
		t.Fatalf("default max read = %q, %v, %v", line, terminated, err)
	}
	gap := filepath.Join(t.TempDir(), "gap")
	if err := os.WriteFile(gap, []byte("-5\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if n := loadGapCount(gap); n != 0 {
		t.Fatalf("negative gap count = %d", n)
	}

	// A pending gap recorded before the crash is restored at open.
	dir := filepath.Join(t.TempDir(), "audit")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "secrets.gap"), []byte("3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := cb96OpenManualSink(t, dir, secretAuditBootVerifyFull)
	if err != nil {
		t.Fatal(err)
	}
	if s.pendingGap.Load() != 3 {
		t.Fatalf("pending gap = %d", s.pendingGap.Load())
	}
}

func TestCB96DrainSpillPaths(t *testing.T) {
	spillLines := func() string {
		return `{"kind":"gap","result":"gap","dropped":2}` + "\n" +
			"not json\n" +
			cb96Repeat('q', auditIngestMaxBody+10) + "\n" +
			"\n"
	}

	// Fresh spill with the default working path.
	s := cb96ManualSink(t)
	s.spillWorkingPath = ""
	cb96AppendRaw(t, s.spillPath, spillLines())
	if !s.drainSpill() {
		t.Fatal("drain failed")
	}

	// Resume an interrupted drain from its persisted offset.
	resume := cb96ManualSink(t)
	body := `{"kind":"gap","result":"gap"}` + "\n" + `{"kind":"gap","result":"gap","dropped":4}` + "\n"
	cb96AppendRaw(t, resume.spillWorkingPath, body)
	if err := persistSpillOffset(resume.spillWorkingPath+".off", int64(len(`{"kind":"gap","result":"gap"}`)+1)); err != nil {
		t.Fatal(err)
	}
	if !resume.drainSpill() {
		t.Fatal("resumed drain failed")
	}

	// The writer is poisoned: the batch cannot be appended.
	poisoned := cb96ManualSink(t)
	poisoned.writePoison = errors.New("ambiguous append")
	cb96AppendRaw(t, poisoned.spillPath, spillLines())
	if poisoned.drainSpill() {
		t.Fatal("drain succeeded through a poisoned writer")
	}

	// The offset sidecar cannot be written.
	blocked := cb96ManualSink(t)
	cb96AppendRaw(t, blocked.spillPath, spillLines())
	if err := os.MkdirAll(blocked.spillWorkingPath+".off", 0o700); err != nil {
		t.Fatal(err)
	}
	if blocked.drainSpill() {
		t.Fatal("drain succeeded without persisting its offset")
	}

	// The working segment exists but cannot be opened.
	unreadable := cb96ManualSink(t)
	cb96AppendRaw(t, unreadable.spillWorkingPath, body)
	if err := os.Chmod(unreadable.spillWorkingPath, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(unreadable.spillWorkingPath, 0o600) })
	if os.Geteuid() != 0 && unreadable.drainSpill() {
		t.Fatal("drain opened an unreadable segment")
	}

	// A fresh spill cannot be renamed onto a non-empty working directory.
	stuck := cb96ManualSink(t)
	stuck.spillWorkingPath = filepath.Join(t.TempDir(), "working-dir")
	if err := os.MkdirAll(filepath.Join(stuck.spillWorkingPath, "child"), 0o700); err != nil {
		t.Fatal(err)
	}
	cb96AppendRaw(t, stuck.spillPath, spillLines())
	if stuck.drainSpill() {
		t.Fatal("drain renamed onto a directory")
	}
}

func TestCB96PruneLockedOversizedRecords(t *testing.T) {
	cutoff := time.Now().Add(time.Hour)

	s := cb96ManualSink(t)
	cb96AppendRaw(t, s.path, cb96Repeat('r', secretAuditMaxLineBytes+8)+"\n")
	if err := s.pruneLocked(cutoff, "", ""); err == nil {
		t.Fatal("prune accepted an oversized record")
	}
	cursor := filepath.Join(t.TempDir(), "export_offset")
	if err := s.pruneLocked(cutoff, cursor, ""); err == nil {
		t.Fatal("prune read the generation of an oversized first record")
	}
}

// cb96Cluster is a Noop with scripted placements and membership views.
type cb96Cluster struct {
	*cluster.Noop
	flipAfter     int
	authErrAfter  int
	authCalls     int
	afterFirst    map[string]cluster.Placement
	beginErr      error
	deleteErr     error
	placements    map[string]cluster.Placement
	placementsNil bool
	local         []cluster.Member
	members       []cluster.Member
	authErr       error
}

func (c *cb96Cluster) PlacementOf(id string) (cluster.Placement, bool) {
	p, ok := c.placements[id]
	return p, ok
}

func (c *cb96Cluster) PlacementsByIDs(ids []string) map[string]cluster.Placement {
	if c.placementsNil {
		return nil
	}
	out := map[string]cluster.Placement{}
	for _, id := range ids {
		if p, ok := c.placements[id]; ok {
			out[id] = p
		}
	}
	return out
}

func (c *cb96Cluster) AuthoritativePlacementsByIDs(_ context.Context, ids []string) (map[string]cluster.Placement, error) {
	if c.authErr != nil {
		return nil, c.authErr
	}
	c.authCalls++
	if c.authErrAfter > 0 && c.authCalls > c.authErrAfter {
		return nil, errors.New("cb96 authoritative read failed")
	}
	if c.afterFirst != nil && c.authCalls > max(1, c.flipAfter) {
		out := map[string]cluster.Placement{}
		for _, id := range ids {
			if p, ok := c.afterFirst[id]; ok {
				out[id] = p
			}
		}
		return out, nil
	}
	return c.PlacementsByIDs(ids), nil
}

func (c *cb96Cluster) LocalMembers() []cluster.Member { return c.local }
func (c *cb96Cluster) Members() []cluster.Member      { return c.members }

// cb96Pusher is a full-fanout-only pusher (no min-ACK fast path).
type cb96Pusher struct {
	onPush func()
	err    error
}

func (p *cb96Pusher) PushSecretBlobToPeers(context.Context, secrets.SecretBlob, []string) ([]string, error) {
	if p.onPush != nil {
		p.onPush()
	}
	return nil, p.err
}

func (p *cb96Pusher) DeleteSecretOnPeers(context.Context, string, string, []string, int64) ([]string, error) {
	return nil, nil
}

func (p *cb96Pusher) ProbeSecretOnPeers(context.Context, string, string, []string, int64) ([]string, error) {
	return nil, nil
}

// cb96Provider returns a scripted handle from Put.
type cb96Provider struct {
	handle secrets.Handle
	err    error
	bag    secrets.Secrets
}

func (p *cb96Provider) Put(context.Context, string, secrets.Secrets, []string) (secrets.Handle, error) {
	return p.handle, p.err
}

func (p *cb96Provider) Open(context.Context, string, secrets.Handle, string) (secrets.Secrets, error) {
	return p.bag, nil
}

func (p *cb96Provider) Delete(context.Context, string) error { return nil }

func cb96SecretReq() models.CreateSandboxRequest {
	return models.CreateSandboxRequest{
		Image:    "private.example.com/app:latest",
		Registry: &models.RegistryAuth{Server: "private.example.com", Username: "u", Password: "pw"},
		Failover: &models.Failover{Policy: models.FailoverPolicyRecreate},
	}
}

func TestCB96SecretHolderCacheEdges(t *testing.T) {
	// Sets stored without maps get them lazily.
	bare := secretHolderKey{sandboxID: "cb96-h-bare", incarnationID: "inc"}
	secretFanoutHolders.Store(bare, &holderNodeSet{})
	addSecretHolderNodes(bare.sandboxID, bare.incarnationID, 0, "", "n1")
	if got := secretHolderCount(bare.sandboxID, bare.incarnationID); got != 1 {
		t.Fatalf("holders after lazy init = %d", got)
	}
	bare2 := secretHolderKey{sandboxID: "cb96-h-bare2", incarnationID: "inc"}
	secretFanoutHolders.Store(bare2, &holderNodeSet{})
	resetSecretHoldersForGeneration(bare2.sandboxID, bare2.incarnationID, 0, "n1")
	if got := secretHolderCount(bare2.sandboxID, bare2.incarnationID); got != 1 {
		t.Fatalf("holders after lazy reset = %d", got)
	}

	// A non-authoritative reset never rolls a newer generation back.
	resetSecretHoldersForGeneration("cb96-h-gen", "inc", 5, "n1")
	resetSecretHoldersForGeneration("cb96-h-gen", "inc", 3, "n2")
	if got := secretHolderGeneration("cb96-h-gen", "inc"); got != 5 {
		t.Fatalf("generation after stale reset = %d", got)
	}

	// Foreign and nil entries are dropped rather than dereferenced.
	secretFanoutHolders.Store(secretHolderKey{sandboxID: "cb96-h-junk", incarnationID: "a"}, "junk")
	clearSecretFanoutHolders("cb96-h-junk")
	if _, ok := secretFanoutHolders.Load(secretHolderKey{sandboxID: "cb96-h-junk", incarnationID: "a"}); ok {
		t.Fatal("foreign holder entry survived clear")
	}
	nilKey := secretHolderKey{sandboxID: "cb96-h-nil", incarnationID: "a"}
	secretFanoutHolders.Store(nilKey, (*holderNodeSet)(nil))
	clearSecretFanoutHoldersForIncarnation(nilKey.sandboxID, nilKey.incarnationID)
	if _, ok := secretFanoutHolders.Load(nilKey); ok {
		t.Fatal("nil holder entry survived clear")
	}

	if got := pendingRecipientsAfterAck([]string{"", "self", "a", "b"}, []string{"a", " "}, "self"); len(got) != 1 || got[0] != "b" {
		t.Fatalf("pending after ack = %v", got)
	}
}

func TestCB96ValidatePeerSecretBlobEnvelopeMismatches(t *testing.T) {
	ctx := context.Background()
	st, _ := cb96OpenStore(t)
	svc := cb96Service(st, config.Config{})
	svc.AttachCluster(cluster.NewNoop("node-b", "http://b", ""))

	envelope := func(fields map[string]any) []byte {
		base := map[string]any{"version": secrets.EnvelopeVersion, "recipients": []string{"node-a", "node-b"}, "payload": []byte("p")}
		for k, v := range fields {
			base[k] = v
		}
		raw, err := json.Marshal(base)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	blob := func(sandboxID string, version int, payload []byte) secrets.SecretBlob {
		return secrets.SecretBlob{
			Ref: secrets.FormatRef(sandboxID, "inc", version), SandboxID: sandboxID, IncarnationID: "inc", Version: version,
			Recipients: []string{"node-a", "node-b"}, SealedPayload: payload, SealGeneration: 1,
		}
	}
	cases := map[string]secrets.SecretBlob{
		"incomplete binding": blob("sb-a", 1, envelope(nil)),
		"sandbox mismatch": blob("sb-a", 1, envelope(map[string]any{
			"sandbox_id": "sb-other", "incarnation_id": "inc", "ref": secrets.FormatRef("sb-a", "inc", 1), "ref_version": 1, "generation": 1,
		})),
		"incarnation mismatch": blob("sb-a", 1, envelope(map[string]any{
			"sandbox_id": "sb-a", "incarnation_id": "inc-other", "ref": secrets.FormatRef("sb-a", "inc", 1), "ref_version": 1, "generation": 1,
		})),
		"ref version mismatch": blob("sb-a", 2, envelope(map[string]any{
			"sandbox_id": "sb-a", "incarnation_id": "inc", "ref": secrets.FormatRef("sb-a", "inc", 2), "ref_version": 1, "generation": 1,
		})),
	}
	for name, b := range cases {
		if err := validatePeerSecretBlob(ctx, svc, b, "node-a"); !errors.Is(err, ErrInvalidClusterSecretBlob) {
			t.Fatalf("%s: err = %v", name, err)
		}
	}

	// A structurally valid blob reaches the store, which is broken.
	cipher := newTestCipher(t)
	binding := secrets.SealBinding{SandboxID: "sb-a", IncarnationID: "inc", Ref: secrets.FormatRef("sb-a", "inc", 1), Version: 1, Generation: 1}
	sealed, err := secrets.SealEnvelopeBound(cipher, secrets.Secrets{Env: map[string]string{"K": "V"}}, []string{"node-a", "node-b"}, binding)
	if err != nil {
		t.Fatal(err)
	}
	good := blob("sb-a", 1, sealed)

	st2, path2 := cb96OpenStore(t)
	svc2 := cb96Service(st2, config.Config{})
	svc2.AttachCluster(cluster.NewNoop("node-b", "http://b", ""))
	cb96SQL(t, path2, `CREATE TRIGGER cb96_put_secret BEFORE INSERT ON cluster_secrets BEGIN SELECT RAISE(ABORT, 'cb96 put'); END`)
	if err := svc2.UpsertClusterSecretBlob(ctx, good, "node-a"); err == nil || errors.Is(err, ErrInvalidClusterSecretBlob) {
		t.Fatalf("upsert through failing insert = %v", err)
	}

	st3, path3 := cb96OpenStore(t)
	svc3 := cb96Service(st3, config.Config{})
	svc3.AttachCluster(cluster.NewNoop("node-b", "http://b", ""))
	cb96SQL(t, path3, `DROP TABLE cluster_secrets`)
	if err := validatePeerSecretBlob(ctx, svc3, good, "node-a"); err == nil {
		t.Fatal("validation ignored a failed generation read")
	}

	if _, _, err := (&Service{}).liveSecretPlacement("sb-a"); !errors.Is(err, ErrClusterSecretPlacementUnavailable) {
		t.Fatalf("placement without cluster = %v", err)
	}
}

func TestCB96PutClusterSecretsHandleValidation(t *testing.T) {
	ctx := secrets.ContextWithIncarnationID(context.Background(), "inc")
	req := cb96SecretReq()
	svc := &Service{logger: slog.New(slog.DiscardHandler)}

	svc.secretProvider = &cb96Provider{err: errors.New("provider down")}
	if _, err := svc.putClusterSecretsForRecipients(ctx, "sb-p", req, nil); err == nil || !strings.Contains(err.Error(), "provider down") {
		t.Fatalf("provider error = %v", err)
	}
	svc.secretProvider = &cb96Provider{handle: secrets.Handle{}}
	if _, err := svc.putClusterSecretsForRecipients(ctx, "sb-p", req, nil); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("empty handle = %v", err)
	}
	svc.secretProvider = &cb96Provider{handle: secrets.Handle{Ref: secrets.FormatRef("sb-p", "inc-other", 1), Version: secrets.RefVersion, SealGeneration: 1}}
	if _, err := svc.putClusterSecretsForRecipients(ctx, "sb-p", req, nil); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("foreign handle = %v", err)
	}

	// No incarnation anywhere: minting reads the sandbox row, which fails.
	st, _ := cb96OpenStore(t)
	closed := &Service{store: st, secretProvider: &cb96Provider{}, logger: slog.New(slog.DiscardHandler)}
	_ = st.Close()
	if _, err := closed.putClusterSecretsForRecipients(context.Background(), "sb-p", req, nil); err == nil {
		t.Fatal("put minted an incarnation over a closed store")
	}

	// Empty recipients default to self; an empty bag short-circuits.
	withCluster := &Service{cluster: cluster.NewNoop("self", "", ""), logger: slog.New(slog.DiscardHandler)}
	if out, err := withCluster.sealAndDistributeForIncarnation(context.Background(), "sb-p", models.CreateSandboxRequest{}, nil, "inc"); err != nil || out.Ref != "" {
		t.Fatalf("empty bag = %+v, %v", out, err)
	}
}

func TestCB96SealFanoutFailures(t *testing.T) {
	ctx := context.Background()
	cipher := newTestCipher(t)
	newSvc := func(t *testing.T) (*Service, string) {
		st, path := cb96OpenStore(t)
		svc := cb96Service(st, config.Config{EnableCluster: true, SecretFanoutMinACKWait: 20 * time.Millisecond})
		svc.cipher = cipher
		svc.cluster = cluster.NewNoop("node-a", "http://a", "")
		svc.secretProvider = secrets.NewLocalProvider(cipher, newSecretBlobStore(st))
		return svc, path
	}

	// Full-fanout pusher gets no ACK and the retract cannot write its tomb.
	svc, path := newSvc(t)
	svc.testSecretPeerPusher = &cb96Pusher{err: errors.New("peers down"), onPush: func() {
		cb96SQL(t, path, `DROP TABLE cluster_secret_tombs`)
	}}
	_, err := svc.sealAndDistributeForIncarnation(ctx, "cb96-fan-1", cb96SecretReq(), []string{"node-a", "node-b"}, "inc")
	if err == nil || !strings.Contains(err.Error(), "retract unreplicated secret") {
		t.Fatalf("fan-out with failed retract = %v", err)
	}

	// The placement handle disagrees with the stored blob.
	svc2, _ := newSvc(t)
	out, err := svc2.putClusterSecretsForRecipientsAndIncarnation(ctx, "cb96-fan-2", cb96SecretReq(), []string{"node-a", "node-b"}, "inc")
	if err != nil {
		t.Fatal(err)
	}
	svc2.testSecretPeerPusher = &cb96Pusher{}
	out.SealGeneration++
	if err := svc2.fanoutSecretAfterSeal(ctx, "cb96-fan-2", cb96SecretReq(), []string{"node-a", "node-b"}, out); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched handle = %v", err)
	}
}

func TestCB96SecretRetirementAndRefanoutFaults(t *testing.T) {
	ctx := context.Background()
	cipher := newTestCipher(t)
	seed := func(t *testing.T, cfg config.Config) (*Service, *storepkg.Store, string, storepkg.ClusterSecretRecord) {
		st, path := cb96OpenStore(t)
		svc := cb96Service(st, cfg)
		svc.cipher = cipher
		svc.cluster = cluster.NewNoop("node-a", "http://a", "")
		svc.secretProvider = secrets.NewLocalProvider(cipher, newSecretBlobStore(st))
		if _, err := svc.putClusterSecretsForRecipientsAndIncarnation(ctx, "cb96-ret", cb96SecretReq(), []string{"node-a", "node-b"}, "inc"); err != nil {
			t.Fatal(err)
		}
		rows, err := st.ListClusterSecretsBatch(ctx, "", 10)
		if err != nil || len(rows) != 1 {
			t.Fatalf("rows = %v, %v", rows, err)
		}
		return svc, st, path, rows[0]
	}

	// Cluster retirement cannot read authoritative placements.
	svc, _, _, rec := seed(t, config.Config{EnableCluster: true})
	svc.cluster = &cb96Cluster{Noop: cluster.NewNoop("node-a", "", ""), authErr: errors.New("leader lost")}
	if err := svc.runSecretRetirementScan(ctx); err == nil || !strings.Contains(err.Error(), "leader lost") {
		t.Fatalf("retirement placement error = %v", err)
	}
	if err := svc.runSecretRefanoutScanForNodes(ctx, nil, map[string]struct{}{"node-b": {}}); err == nil {
		t.Fatal("async re-fanout ignored a placement failure")
	}

	// Envelope recipients disagree with the durable row.
	tampered := rec
	tampered.Recipients = []string{"node-a"}
	if _, err := svc.prepareSecretRefanoutRecord(ctx, tampered, false, map[string]cluster.Placement{}, nil); err == nil || !strings.Contains(err.Error(), "recipients") {
		t.Fatalf("recipient mismatch = %v", err)
	}

	// A superseded generation cannot be retired over a closed store.
	placement := cluster.Placement{
		SandboxID: rec.SandboxID, IncarnationID: "inc", SecretRef: rec.Ref, SecretSealGeneration: rec.SealGeneration + 1,
		SecretRecipients: []string{"node-a", "node-b"},
	}
	svc2, st2, _, rec2 := seed(t, config.Config{EnableCluster: true})
	_ = st2.Close()
	if _, err := svc2.prepareSecretRefanoutRecord(ctx, rec2, false, map[string]cluster.Placement{rec2.SandboxID: placement}, nil); err == nil || !strings.Contains(err.Error(), "superseded") {
		t.Fatalf("closed-store retire = %v", err)
	}
	if err := svc2.retireStaleSecretRow(ctx, rec2, "inc"); err == nil {
		t.Fatal("stale retire ignored a closed store")
	}
	if _, err := svc2.standaloneLiveIncarnations(ctx, []storepkg.ClusterSecretRecord{rec2, {}}); err == nil {
		t.Fatal("standalone lifecycles ignored a closed store")
	}
	if err := svc2.runSecretRefanoutScanForNodes(ctx, nil, nil); err == nil {
		t.Fatal("async re-fanout ignored a closed store")
	}

	// Standalone retirement cannot read the local sandbox table.
	svc3, _, path3, _ := seed(t, config.Config{})
	cb96SQL(t, path3, `DROP TABLE sandboxes`)
	if err := svc3.runSecretRetirementScan(ctx); err == nil || !strings.Contains(err.Error(), "standalone") {
		t.Fatalf("standalone lifecycle error = %v", err)
	}

	// An empty store finishes the synchronous pass without scheduling work.
	st4, _ := cb96OpenStore(t)
	if err := cb96Service(st4, config.Config{}).ReFanoutClusterSecretsForNodes(ctx, nil); err != nil {
		t.Fatalf("empty re-fanout = %v", err)
	}

	dup := &Service{cfg: config.Config{EnableCluster: true}, cluster: &cb96Cluster{Noop: cluster.NewNoop("x", "", ""), placements: map[string]cluster.Placement{"a": {SandboxID: "a"}}}}
	got, err := dup.authoritativeSecretPlacements(ctx, []string{"a", " a ", ""})
	if err != nil || len(got) != 1 {
		t.Fatalf("deduped placements = %v, %v", got, err)
	}
}

func TestCB96SealDistributeSmallHelpers(t *testing.T) {
	ctx := context.Background()
	noop := &Service{cluster: cluster.NewNoop("self", "", "")}
	if noop.secretPeerPusher() != nil {
		t.Fatal("noop cluster exposed a peer pusher")
	}
	if got := noop.SelectReplacementRecipients("  ", 2); got != nil {
		t.Fatalf("blank sandbox recipients = %v", got)
	}
	if got := (&Service{}).selectReplacementRecipients("sb", "owner", 2); got != nil {
		t.Fatalf("no-cluster recipients = %v", got)
	}

	var nilSvc *Service
	nilSvc.invalidateAuditIdentity("sb")
	(&Service{}).invalidateAuditIdentity(" ")
	if nilSvc.pruneAuditIdentityFences(time.Now()) != 0 {
		t.Fatal("nil service pruned fences")
	}
	nilSvc.finalizeAuditIdentity("sb", "inc", "owner")
	(&Service{}).finalizeAuditIdentity("sb", " ", "owner")

	st, _ := cb96OpenStore(t)
	svc := cb96Service(st, config.Config{})
	if gen, ok := svc.localSealedSecretGeneration(ctx, "sb", " "); gen != 0 || ok {
		t.Fatal("blank incarnation reported a sealed row")
	}
	if gen, ok := svc.localSealedSecretGeneration(ctx, "sb", "inc"); gen != 0 || ok {
		t.Fatal("missing row reported a sealed row")
	}
	cipher := newTestCipher(t)
	svc.cipher = cipher
	svc.cluster = cluster.NewNoop("node-a", "", "")
	svc.secretProvider = secrets.NewLocalProvider(cipher, newSecretBlobStore(st))
	if _, err := svc.putClusterSecretsForRecipientsAndIncarnation(ctx, "cb96-gen", cb96SecretReq(), []string{"node-a"}, "inc"); err != nil {
		t.Fatal(err)
	}
	if gen, ok := svc.localSealedSecretGeneration(ctx, "cb96-gen", "inc"); gen != 1 || !ok {
		t.Fatalf("sealed generation = %d, %v", gen, ok)
	}
	_ = st.Close()
	if _, err := svc.HasLocalSealedSecretGeneration(ctx, "cb96-gen", "inc", 1); err == nil {
		t.Fatal("generation probe ignored a closed store")
	}
	if _, err := svc.prepareAuditIncarnation(ctx, "cb96-prep", ""); err == nil {
		t.Fatal("prepare ignored a closed store")
	}
}

func TestCB96FailoverReadinessBranches(t *testing.T) {
	ctx := context.Background()
	recreate := func(id, inc string) *models.Sandbox {
		return &models.Sandbox{ID: id, AuditIncarnationID: inc, Failover: &models.Failover{Policy: models.FailoverPolicyRecreate}}
	}

	// No cluster, and a row without its own lifecycle falls back to the seal
	// lookup; the batched sealed-row read then fails closed.
	st, _ := cb96OpenStore(t)
	svc := cb96Service(st, config.Config{})
	row := recreate("cb96-fr-1", "")
	svc.failoverReadyBatch(ctx, []*models.Sandbox{row})
	_ = st.Close()
	closedRow := recreate("cb96-fr-2", "inc")
	svc.failoverReadyBatch(ctx, []*models.Sandbox{closedRow})
	if closedRow.FailoverReady == nil || *closedRow.FailoverReady {
		t.Fatalf("closed store readiness = %v", closedRow.FailoverReady)
	}

	// Empty gossip view falls back to Members().
	fc := &cb96Cluster{Noop: cluster.NewNoop("self", "", ""), members: []cluster.Member{{NodeID: "self", Alive: true}}}
	members, _ := (&Service{cluster: fc}).failoverReadySnapshots([]string{"x"})
	if len(members) != 1 {
		t.Fatalf("members fallback = %v", members)
	}

	// A holder cache already at the local generation but empty is reseeded
	// with self; standalone single-recipient rows are then ready.
	const sb, inc = "cb96-fr-3", "inc"
	setSecretHolderTargets(sb, inc, 1, []string{"self"})
	ref := secrets.FormatRef(sb, inc, secrets.RefVersion)
	in := failoverReadyInputs{
		selfID:      "self",
		alive:       map[string]struct{}{"self": {}},
		placements:  map[string]cluster.Placement{},
		incarnation: map[string]string{sb: inc},
		seals:       map[string]storepkg.ClusterSecretSealSummary{ref: {SealGeneration: 1, Recipients: []string{"self"}}},
	}
	ready := (&Service{}).computeFailoverReadyRow(recreate(sb, inc), &in)
	if ready == nil || !*ready {
		t.Fatalf("standalone single-recipient readiness = %v", ready)
	}
}

type cb96MinACKPusher struct{ cb96Pusher }

func (p *cb96MinACKPusher) PushSecretBlobToAnyPeer(context.Context, secrets.SecretBlob, []string) ([]string, error) {
	return nil, errors.New("no peer answered")
}

func TestCB96SealDistributeGuards(t *testing.T) {
	ctx := context.Background()
	resetSecretHoldersForGeneration("", "inc", 1, "n1")
	replaceSecretHoldersForGeneration("cb96-replace", "inc", 2, "n1")
	if got := secretHolderGeneration("cb96-replace", "inc"); got != 2 {
		t.Fatalf("authoritative replace generation = %d", got)
	}

	if (&Service{}).secretPeerPusher() != nil {
		t.Fatal("no cluster exposed a peer pusher")
	}
	if (&Service{}).SelectReplacementRecipients("sb", 2) != nil {
		t.Fatal("no cluster selected recipients")
	}
	fc := &cb96Cluster{Noop: cluster.NewNoop("self", "", ""), members: []cluster.Member{{NodeID: "self", Alive: true}}}
	withCluster := &Service{cluster: fc}
	_ = withCluster.selectReplacementRecipients("sb", "self", 1)
	if members, placements := withCluster.failoverReadySnapshots(nil); len(members) != 1 || len(placements) != 0 {
		t.Fatalf("snapshot without ids = %v, %v", members, placements)
	}

	st, _ := cb96OpenStore(t)
	if err := cb96Service(st, config.Config{}).runSecretRefanoutScanForNodes(ctx, nil, nil); err != nil {
		t.Fatalf("empty async re-fanout = %v", err)
	}

	// The min-ACK fast path gets no peer, so the create is not acknowledged.
	cipher := newTestCipher(t)
	svc := cb96Service(st, config.Config{EnableCluster: true, SecretFanoutMinACKWait: 20 * time.Millisecond})
	svc.cipher = cipher
	svc.cluster = cluster.NewNoop("node-a", "http://a", "")
	svc.secretProvider = secrets.NewLocalProvider(cipher, newSecretBlobStore(st))
	out, err := svc.putClusterSecretsForRecipientsAndIncarnation(ctx, "cb96-minack", cb96SecretReq(), []string{"node-a", "node-b"}, "inc")
	if err != nil {
		t.Fatal(err)
	}
	svc.testSecretPeerPusher = &cb96MinACKPusher{}
	if err := svc.fanoutSecretAfterSeal(ctx, "cb96-minack", cb96SecretReq(), []string{"node-a", "node-b"}, out); err == nil || !strings.Contains(err.Error(), "no backup ACK") {
		t.Fatalf("min-ACK without peers = %v", err)
	}
}

func (c *cb96Cluster) PlacementsForShards(cluster.PlacementShardFilter) []cluster.Placement {
	out := make([]cluster.Placement, 0, len(c.placements))
	for _, p := range c.placements {
		out = append(out, p)
	}
	return out
}

type cb96PingRuntime struct {
	*fakeCapacityRuntime
	err error
}

func (r *cb96PingRuntime) Ping(context.Context) error { return r.err }

func TestCB96ServiceHelperBranches(t *testing.T) {
	ctx := context.Background()

	fc := &cb96Cluster{Noop: cluster.NewNoop("self", "", ""), placements: map[string]cluster.Placement{"sb": {SandboxID: "sb", IncarnationID: " inc "}}}
	if got := (&Service{cluster: fc}).placementIncarnation("sb", cluster.PlacementSecrets{}); got != "inc" {
		t.Fatalf("placement incarnation = %q", got)
	}

	cipher := newTestCipher(t)
	garbage, err := cipher.Encrypt([]byte("not json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&Service{cipher: cipher, secretAudit: &cb96Sink{}}).UnsealRegistry("sb", garbage); !errors.Is(err, secrets.ErrDecryptFailed) {
		t.Fatalf("unseal garbage = %v", err)
	}

	if err := (&Service{}).repairSealedEnv(ctx, &models.Sandbox{}); err != nil {
		t.Fatal(err)
	}
	st, _ := cb96OpenStore(t)
	if err := cb96Service(st, config.Config{}).repairSealedEnv(ctx, &models.Sandbox{ID: "sb", AuditIncarnationID: "inc"}); err != nil {
		t.Fatalf("empty env repair = %v", err)
	}

	bypass := &Service{cfg: config.Config{HTTPWakeDirectBypassEnabled: true}}
	if !bypass.netstatsPollIsStale(time.Now()) {
		t.Fatal("zero poll interval was not stale")
	}
	last := time.Now().Add(-time.Hour)
	if got := bypass.activityFloorFor(&models.Sandbox{ID: "sb", LastActiveAt: last}, false); !got.Equal(last) {
		t.Fatalf("activity floor = %v", got)
	}
	now := time.Now()
	sb := &models.Sandbox{Status: models.SandboxStatusStarted, CreatedAt: now.Add(-time.Hour), LastActiveAt: now.Add(-time.Hour),
		Lifecycle: models.Lifecycle{StopIfIdleFor: 30 * time.Minute}}
	if got := lifecycleActionForWithFloor(sb, now, 0, now.Add(-time.Minute)); got != lifecycleNone {
		t.Fatalf("recent activity floor action = %v", got)
	}

	withRefs := &Service{}
	withRefs.reservedModuleRefsOnce.Do(func() {})
	withRefs.reservedModuleRefs = []string{"std"}
	if got := withRefs.appendResolvableReservedModules(ctx, []string{"a", "std"}); len(got) != 2 {
		t.Fatalf("reserved refs = %v", got)
	}

	capSvc := cb96Service(st, config.Config{ContainerEngine: "podman"})
	if snap := capSvc.Capacity(); snap.ContainerEngine != "podman" {
		t.Fatalf("capacity engine = %q", snap.ContainerEngine)
	}

	// Ingress keep-set: no cluster, and a mixed placement view.
	expectedHTTP, tcp, tls := map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}
	(&Service{cfg: config.Config{EnableCluster: true}}).addClusterIngressExpectedRoutes(expectedHTTP, tcp, tls)
	ingress := &Service{cfg: config.Config{EnableCluster: true}, cluster: &cb96Cluster{Noop: cluster.NewNoop("self", "", ""), placements: map[string]cluster.Placement{
		"":     {},
		"mine": {SandboxID: "mine", OwnerNodeID: "self", PublicTraffic: true},
		"priv": {SandboxID: "priv", OwnerNodeID: "peer"},
		"pub":  {SandboxID: "pub", OwnerNodeID: "peer", PublicTraffic: true, ExposedPorts: map[int]string{8080: ""}},
	}}}
	ingress.addClusterIngressExpectedRoutes(expectedHTTP, tcp, tls)
	if _, ok := expectedHTTP["sandbox-pub-port-8080"]; !ok {
		t.Fatalf("expected routes = %v", expectedHTTP)
	}
	noSelf := &Service{cfg: config.Config{EnableCluster: true}, cluster: &emptySelfCluster{Noop: cluster.NewNoop("x", "", "")},
		caddy: caddy.New(config.Config{EnableCaddy: true, CaddyAdminURL: "http://127.0.0.1:1", HTTPClientTimeout: time.Second})}
	if err := noSelf.ReconcileClusterIngress(ctx); err != nil {
		t.Fatalf("ingress reconcile without identity = %v", err)
	}
}

func TestCB96HealthDriverBranches(t *testing.T) {
	ctx := context.Background()
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(admin.Close)

	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.docker = &fakeCapacityRuntime{}
	svc.caddy = caddy.New(config.Config{EnableCaddy: true, CaddyAdminURL: admin.URL, HTTPClientTimeout: time.Second})
	svc.cfg.EnableFirecracker = true
	svc.cfg.EnableWasm = true
	svc.firecracker = nil
	svc.wasm = nil
	health, err := svc.Health(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(health.Caddy, "500") || !strings.Contains(health.Firecracker, "not registered") || !strings.Contains(health.Wasm, "not registered") {
		t.Fatalf("health = %+v", health)
	}

	svc.firecracker = &cb96PingRuntime{fakeCapacityRuntime: &fakeCapacityRuntime{}, err: errors.New("vmm down")}
	health, err = svc.Health(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if health.Firecracker != "vmm down" {
		t.Fatalf("firecracker health = %q", health.Firecracker)
	}
}

func TestCB96SecretAuditSinkEdges(t *testing.T) {
	// Emit on a closed sink returns without queueing.
	closed := cb96ManualSink(t)
	closed.closed.Store(true)
	closed.Emit(cb96Open("sb"))
	if len(closed.ch) != 0 {
		t.Fatal("closed sink queued an event")
	}

	// An unset in-memory head links from genesis.
	fresh := cb96ManualSink(t)
	fresh.chainMu.Lock()
	fresh.chainHead = ""
	fresh.chainMu.Unlock()
	cb96Append(t, fresh, cb96Open("sb"))

	// Prune of a file in a missing directory is a no-op.
	gone := cb96ManualSink(t)
	gone.path = filepath.Join(t.TempDir(), "missing", "secrets.log")
	if err := gone.pruneLocked(time.Now(), "", ""); err != nil {
		t.Fatalf("prune missing file = %v", err)
	}

	// The witness gate still runs after sink validation.
	svc, _ := cb96WitnessService(t, &cb96Witness{lastErr: errors.New("witness unreachable")}, 1)
	if err := svc.ValidateSecretAuditSink(); err == nil {
		t.Fatal("sink validation ignored the witness gate")
	}
}

func TestCB96PruneLockedRewriteWhitespaceAndWitness(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "audit")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	old := cb96Open("sb-old")
	old.Time = now.Add(-48 * time.Hour)
	ev1, raw1 := cb96LinkedLine(t, auditlog.GenesisPrevHash, old)
	ev2, raw2 := cb96LinkedLine(t, ev1.EventHash, cb96Open("sb-new"))
	_, raw3 := cb96LinkedLine(t, ev2.EventHash, cb96Open("sb-new"))
	body := string(raw1) + "\n" + string(raw2) + "   \n" + string(raw3) + "\n"
	cb96AppendRaw(t, filepath.Join(dir, secretAuditFileName), body)
	s, err := cb96OpenManualSink(t, dir, secretAuditBootVerifyFull)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	var shifts []secretAuditPruneShift
	s.onPruneShift = func(shift secretAuditPruneShift) { shifts = append(shifts, shift) }
	if err := s.pruneLocked(now.Add(-24*time.Hour), "", ev2.EventHash); err != nil {
		t.Fatalf("prune: %v", err)
	}
	if len(shifts) != 1 || shifts[0].exact {
		t.Fatalf("shifts = %+v, want one inexact shift", shifts)
	}
}

func TestCB96ClusterSecretMaintenanceHelpers(t *testing.T) {
	ctx := context.Background()
	if err := (&Service{cfg: config.Config{AuditDeletedGrace: time.Hour}}).pruneClusterAuditACL(ctx); err != nil {
		t.Fatalf("audit ACL prune without cluster = %v", err)
	}

	st, path := cb96OpenStore(t)
	if _, err := st.DeleteClusterSecretsOriginatorWithOutbox(ctx, "cb96-tomb", "inc", nil); err != nil {
		t.Fatal(err)
	}
	cb96SQL(t, path, `UPDATE cluster_secret_tombs SET deleted_at = '2000-01-01 00:00:00+00:00'`)
	svc := cb96Service(st, config.Config{SecretTombRetentionDays: 1})
	if err := svc.pruneClusterSecretTombs(ctx); err != nil {
		t.Fatalf("tomb prune = %v", err)
	}
	if gen, err := st.ClusterSecretTombGenerationForIncarnation(ctx, "cb96-tomb", "inc"); err != nil || gen != 0 {
		t.Fatalf("tomb after prune = %d, %v", gen, err)
	}

	retireHolderEntry(secretHolderEntry{}, 0)
	if page, next, _ := secretHolderPage("", 0); page != nil || next != "" {
		t.Fatalf("zero-limit page = %v, %q", page, next)
	}
	if _, ok := (&Service{cfg: config.Config{EnableCluster: true}}).secretHolderPlacements(nil); ok {
		t.Fatal("holder placements without cluster reported ok")
	}
	withCluster := &Service{cfg: config.Config{EnableCluster: true}, cluster: cluster.NewNoop("self", "", "")}
	if got, ok := withCluster.secretHolderPlacements(nil); !ok || len(got) != 0 {
		t.Fatalf("empty page placements = %v, %v", got, ok)
	}
}

func TestCB96RefreshSecretHolderAuthoritativeReadFails(t *testing.T) {
	const sb, inc = "cb96-refresh", "inc"
	resetSecretHoldersForGeneration(sb, inc, 2, "self")
	setSecretHolderTargets(sb, inc, 2, []string{"self", "node-b"})
	t.Cleanup(func() { clearSecretFanoutHolders(sb) })

	fc := &cb96Cluster{
		Noop:       cluster.NewNoop("self", "", ""),
		placements: map[string]cluster.Placement{sb: {SandboxID: sb, IncarnationID: inc, SecretSealGeneration: 1}},
		local:      []cluster.Member{{NodeID: "self", Alive: true}, {NodeID: "node-b", Alive: true}},
		authErr:    errors.New("leader lost"),
	}
	svc := &Service{cfg: config.Config{EnableCluster: true}, cluster: fc, testSecretPeerPusher: &cb96Pusher{}, logger: slog.New(slog.DiscardHandler)}
	svc.refreshSecretHolderPossession(context.Background())
	if got := secretHolderGeneration(sb, inc); got != 2 {
		t.Fatalf("holder generation after failed refresh = %d", got)
	}
}

func TestCB96ExpandAndResealProviderFailures(t *testing.T) {
	ctx := context.Background()
	members := []cluster.Member{{NodeID: "self", Alive: true}, {NodeID: "node-c", Alive: true}}
	bag := secrets.Secrets{Env: map[string]string{"K": "V"}}
	ref := secrets.FormatRef("cb96-rs", "inc", secrets.RefVersion)
	placement := cluster.Placement{
		SandboxID: "cb96-rs", IncarnationID: "inc", OwnerNodeID: "self",
		SecretRef: ref, SecretVersion: secrets.RefVersion, SecretSealGeneration: 1,
		SecretRecipients: []string{"self", "node-dead"},
	}
	newSvc := func(t *testing.T, p secrets.Provider) (*Service, *storepkg.Store) {
		st, _ := cb96OpenStore(t)
		fc := &cb96Cluster{Noop: cluster.NewNoop("self", "", ""), local: members}
		svc := cb96Service(st, config.Config{EnableCluster: true, SecretRecipientBackupCount: 1})
		svc.cluster = fc
		svc.secretProvider = p
		return svc, st
	}
	t.Cleanup(func() { clearSecretFanoutHolders("cb96-rs") })

	svc, _ := newSvc(t, &cb96Provider{bag: bag, err: errors.New("kms down")})
	if err := svc.expandAndResealDeadSecretTargetsForPlacement(ctx, svc.cluster, placement); err == nil || !strings.Contains(err.Error(), "reseal put") {
		t.Fatalf("put failure = %v", err)
	}
	svc, _ = newSvc(t, &cb96Provider{bag: bag})
	if err := svc.expandAndResealDeadSecretTargetsForPlacement(ctx, svc.cluster, placement); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("incomplete handle = %v", err)
	}
	svc, _ = newSvc(t, &cb96Provider{bag: bag, handle: secrets.Handle{Ref: ref, Version: secrets.RefVersion, SealGeneration: 2}})
	if err := svc.expandAndResealDeadSecretTargetsForPlacement(ctx, svc.cluster, placement); err == nil || !strings.Contains(err.Error(), "load resealed blob") {
		t.Fatalf("missing resealed blob = %v", err)
	}

	// No handle on the placement: the local row supplies it, and the CAS
	// generation falls back to the durable maximum.
	cipher := newTestCipher(t)
	svc, st := newSvc(t, nil)
	svc.cipher = cipher
	svc.secretProvider = secrets.NewLocalProvider(cipher, newSecretBlobStore(st))
	if _, err := svc.putClusterSecretsForRecipientsAndIncarnation(ctx, "cb96-rs", cb96SecretReq(), []string{"self"}, "inc"); err != nil {
		t.Fatal(err)
	}
	svc.secretProvider = &cb96Provider{bag: bag, err: errors.New("kms down")}
	unbound := placement
	unbound.SecretRef, unbound.SecretVersion, unbound.SecretSealGeneration = "", 0, 0
	if err := svc.expandAndResealDeadSecretTargetsForPlacement(ctx, svc.cluster, unbound); err == nil || !strings.Contains(err.Error(), "reseal put") {
		t.Fatalf("unbound placement reseal = %v", err)
	}

	// A narrowed set with no other live candidate is already the best set.
	lonely, _ := newSvc(t, &cb96Provider{bag: bag})
	lonely.cluster = &cb96Cluster{Noop: cluster.NewNoop("self", "", ""), local: members[:1]}
	narrowed := placement
	narrowed.SecretRecipients = []string{"self"}
	if err := lonely.expandAndResealDeadSecretTargetsForPlacement(ctx, lonely.cluster, narrowed); err != nil {
		t.Fatalf("already-best recipients = %v", err)
	}
}

type cb96ArtifactCluster struct {
	*cluster.Noop
	allocErr error
	readErr  error
}

func (c *cb96ArtifactCluster) AllocateArtifactCatalogEpoch(context.Context, string, string, string) (int64, error) {
	return 0, c.allocErr
}

func (c *cb96ArtifactCluster) ArtifactCatalog(context.Context, cluster.ArtifactCatalogRequest) (cluster.ArtifactCatalogPage, error) {
	return cluster.ArtifactCatalogPage{}, c.readErr
}

func (c *cb96ArtifactCluster) PublishArtifactCatalog(context.Context, cluster.ArtifactCatalogSnapshot) error {
	return nil
}

func TestCB96ArtifactCatalogBranches(t *testing.T) {
	ctx := context.Background()
	var nilSvc *Service
	nilSvc.MarkArtifactCatalogDirty(cluster.ArtifactKindTemplate)
	nilSvc.ReconcileArtifactCatalog(ctx)

	var state artifactCatalogState
	if rev, needed := state.begin(cluster.ArtifactKindTemplate); rev != 1 || !needed {
		t.Fatalf("first begin = %d, %v", rev, needed)
	}

	if _, ok := (&Service{}).localArtifactRows(ctx, cluster.ArtifactKindTemplate); ok {
		t.Fatal("template rows without a store reported ok")
	}
	st, _ := cb96OpenStore(t)
	closedSvc := cb96Service(st, config.Config{})
	_ = st.Close()
	if _, ok := closedSvc.localArtifactRows(ctx, cluster.ArtifactKindTemplate); ok {
		t.Fatal("template rows over a closed store reported ok")
	}

	req := cluster.ArtifactCatalogRequest{Kind: cluster.ArtifactKindTemplate}
	if _, ok := (&Service{cfg: config.Config{EnableCluster: true}}).ClusterArtifactCatalog(ctx, req); ok {
		t.Fatal("catalogue without cluster reported ok")
	}
	failing := &Service{cfg: config.Config{EnableCluster: true}, logger: slog.New(slog.DiscardHandler),
		cluster: &cb96ArtifactCluster{Noop: cluster.NewNoop("self", "", ""), readErr: errors.New("raft down"), allocErr: errors.New("no epoch")}}
	if _, ok := failing.ClusterArtifactCatalog(ctx, req); ok {
		t.Fatal("failed catalogue read reported ok")
	}
	if _, ok := failing.ensurePublisherEpoch(ctx, cluster.ArtifactKindTemplate, "self"); ok {
		t.Fatal("failed epoch allocation reported ok")
	}
	if _, ok := (&Service{}).ensurePublisherEpoch(ctx, cluster.ArtifactKindTemplate, "self"); ok {
		t.Fatal("epoch without allocator reported ok")
	}

	if _, _, ok := (&Service{cfg: config.Config{EnableCluster: true}}).artifactCatalogPublisher(); ok {
		t.Fatal("publisher without cluster reported ok")
	}
	anon := &Service{cfg: config.Config{EnableCluster: true}, cluster: &emptySelfCluster{Noop: cluster.NewNoop("x", "", "")}}
	if _, _, ok := anon.artifactCatalogPublisher(); ok {
		t.Fatal("publisher without node identity reported ok")
	}
}

func TestCB96ListSecretAuditLimits(t *testing.T) {
	ctx := context.Background()
	st, _ := cb96OpenStore(t)
	sink := cb96ManualSink(t)
	cb96Append(t, sink, cb96Open("sb-q"), cb96Open("sb-q"))
	svc := &Service{store: st, secretAudit: sink, secretAuditFile: sink, logger: slog.New(slog.DiscardHandler)}

	page, err := svc.ListSecretAudit(ctx, "sb-q", SecretAuditQuery{IncarnationID: "inc", Limit: 1})
	if err != nil || len(page.Events) != 1 || page.NextCursor == "" {
		t.Fatalf("limited page = %+v, %v", page, err)
	}
	page, err = svc.ListSecretAudit(ctx, "sb-q", SecretAuditQuery{IncarnationID: "inc", Limit: maxSecretAuditLimit + 1})
	if err != nil || len(page.Events) != 2 {
		t.Fatalf("clamped page = %+v, %v", page, err)
	}

	idx := newSecretAuditIndexer(st, sink, nil)
	idx.setReady(storepkg.SecretAuditIndexMeta{Generation: "g"}, 0)
	broken := &Service{store: st, secretAudit: sink, secretAuditFile: sink, secretAuditIndex: idx}
	_ = st.Close()
	if _, err := broken.ListSecretAudit(ctx, "sb-q", SecretAuditQuery{IncarnationID: "inc"}); err == nil {
		t.Fatal("list ignored a failed local read")
	}
}

func TestCB96TemplateAndWasmTarGuards(t *testing.T) {
	if !(*Service)(nil).WaitForTemplateRebuilds(time.Millisecond) {
		t.Fatal("nil service reported a stuck rebuild")
	}
	st, _ := cb96OpenStore(t)
	if err := cb96Service(st, config.Config{}).MarkSnapshotCorrupt(context.Background(), "tpl-missing", "bad"); err != nil {
		t.Fatalf("mark missing template = %v", err)
	}

	var buf strings.Builder
	tw := tar.NewWriter(&buf)
	for i := 0; i <= wasmSnapshotTarMaxEntries; i++ {
		if err := tw.WriteHeader(&tar.Header{Name: fmt.Sprintf("d%d/", i), Typeflag: tar.TypeDir, Mode: 0o700}); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := extractWasmCheckpointTar(strings.NewReader(buf.String()), filepath.Join(t.TempDir(), "mem.snap")); err == nil || !strings.Contains(err.Error(), "too many entries") {
		t.Fatalf("oversized tar = %v", err)
	}
}

func TestCB96MiscSmallGuards(t *testing.T) {
	HoldSecretAuditQuerySlotsForTest()()
	HoldSecretAuditVerifyForTest()()

	if inc, err := (&Service{}).localSandboxAuditIncarnation(context.Background(), nil); inc != "" || err != nil {
		t.Fatalf("nil sandbox incarnation = %q, %v", inc, err)
	}
	if got := sandboxCustomHostnames(&models.Sandbox{CustomDomains: []models.CustomDomain{{Hostname: ""}}}); got != nil {
		t.Fatalf("blank custom hostnames = %v", got)
	}
	if _, err := bundleFromCreateRequest(models.CreateJSBundleRequest{MainModule: "main.js", Modules: map[string]string{"other.js": "export default {}"}}); err == nil {
		t.Fatal("bundle without its main module validated")
	}

	ready := &Service{}
	ready.netstatsReady.Store(true)
	if err := ready.EnsureNetstatsReady(context.Background()); err != nil {
		t.Fatalf("ready netstats = %v", err)
	}

	// The index has nothing to catch up on until the log exists.
	st, _ := cb96OpenStore(t)
	sink := cb96ManualSink(t)
	sink.path = filepath.Join(t.TempDir(), "absent.log")
	if err := newSecretAuditIndexer(st, sink, nil).catchUp(); err != nil {
		t.Fatalf("catch-up without a log = %v", err)
	}
}

func TestCB96FinalizeStaleLocalSandboxStoreFaults(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name      string
		wasm      bool
		sameInc   bool
		fault     string
		wantInErr string
	}{
		{name: "audit acl", fault: `DROP TABLE sandbox_audit_acl`},
		{name: "stale secrets", fault: `DROP TABLE cluster_secret_tombs`, wantInErr: "stale-lifecycle"},
		{name: "wasm kv", wasm: true, sameInc: true, fault: `DROP TABLE wasm_state_kv`},
		{name: "wasm pushes", wasm: true, sameInc: true, fault: `DROP TABLE wasm_checkpoint_pushes`},
		{name: "row delete", sameInc: true, fault: `CREATE TRIGGER cb96_keep_sandbox BEFORE DELETE ON sandboxes BEGIN SELECT RAISE(ABORT, 'cb96 keep'); END`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.db")
			svc, st, _ := newServiceRuntimeHarnessAtPath(t, path, &recordingRuntime{})
			svc.cfg.EnableCluster = true
			svc.AttachCluster(cluster.NewNoop("self", "http://self", ""))
			sb := wave30SeedSandbox(t, st, "cb96-stale", "inc-local")
			if tc.wasm {
				sb.Runtime = models.RuntimeWasm
				if err := st.Upsert(ctx, sb); err != nil {
					t.Fatal(err)
				}
			}
			placement := cluster.Placement{SandboxID: sb.ID, OwnerNodeID: "other", IncarnationID: "inc-remote"}
			if tc.sameInc {
				placement.IncarnationID = "inc-local"
			}
			cb96SQL(t, path, tc.fault)
			err := svc.finalizeStaleLocalSandbox(ctx, sb, placement, true)
			if err == nil || (tc.wantInErr != "" && !strings.Contains(err.Error(), tc.wantInErr)) {
				t.Fatalf("finalize = %v", err)
			}
		})
	}
}

func (c *cb96Cluster) BeginDeletePlacementExact(context.Context, string, string, string) error {
	return c.beginErr
}

func (c *cb96Cluster) DeletePlacementExact(context.Context, string, string, string) error {
	return c.deleteErr
}

func TestCB96ReconcileGoneContainerFaults(t *testing.T) {
	ctx := context.Background()
	type setup struct {
		cfgCluster bool
		cluster    *cb96Cluster
		runtime    string
		fault      string
		unmountErr bool
		wantErr    bool
	}
	self := func(owner string) *cb96Cluster {
		return &cb96Cluster{Noop: cluster.NewNoop("self", "http://self", ""), placements: map[string]cluster.Placement{
			"cb96-gone": {SandboxID: "cb96-gone", OwnerNodeID: owner, IncarnationID: "inc"},
		}}
	}
	withBeginErr := self("self")
	withBeginErr.beginErr = errors.New("fence refused")
	moved := func() *cb96Cluster {
		c := self("self")
		c.afterFirst = map[string]cluster.Placement{"cb96-gone": {SandboxID: "cb96-gone", OwnerNodeID: "other", IncarnationID: "inc"}}
		return c
	}
	withDeleteErr := self("self")
	withDeleteErr.deleteErr = errors.New("delete refused")
	cases := map[string]setup{
		"forced unmount error":    {unmountErr: true},
		"row delete":              {fault: `CREATE TRIGGER cb96_keep BEFORE DELETE ON sandboxes BEGIN SELECT RAISE(ABORT, 'cb96 keep'); END`, wantErr: true},
		"obsolete owner":          {cfgCluster: true, cluster: moved()},
		"obsolete finalize fails": {cfgCluster: true, cluster: moved(), fault: `DROP TABLE sandbox_audit_acl`, wantErr: true},
		"delete fence":            {cfgCluster: true, cluster: withBeginErr, wantErr: true},
		"placement delete":        {cfgCluster: true, cluster: withDeleteErr, wantErr: true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.db")
			st, err := storepkg.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = st.Close() })
			svc := &Service{
				cfg:    config.Config{EnableCluster: tc.cfgCluster},
				logger: slog.New(slog.DiscardHandler),
				store:  st,
				docker: &fakeReconcileRuntime{},
				caddy:  caddy.New(config.Config{EnableCaddy: false, HTTPClientTimeout: time.Second}),
			}
			mgr, err := mounts.New(slog.New(slog.DiscardHandler), mounts.Config{
				RootDir: filepath.Join(t.TempDir(), "mounts"), CredDir: filepath.Join(t.TempDir(), "cred"), WaitTimeout: time.Second,
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(mgr.Close)
			svc.mounts = mgr
			if tc.cluster != nil {
				svc.AttachCluster(tc.cluster)
			}
			if tc.unmountErr {
				svc.testForceUnmountErr = errors.New("busy")
			}
			rt := tc.runtime
			if rt == "" {
				rt = models.RuntimeDocker
			}
			now := time.Now().UTC()
			if err := st.Create(ctx, &models.Sandbox{
				ID: "cb96-gone", Image: "alpine", Status: models.SandboxStatusStarted, Runtime: rt,
				ContainerID: "ctr-gone", AuditIncarnationID: "inc", CPU: 1, MemoryMB: 128,
				CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
			}); err != nil {
				t.Fatal(err)
			}
			if tc.fault != "" {
				cb96SQL(t, path, tc.fault)
			}
			err = svc.Reconcile(ctx)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Reconcile = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestCB96DestroySandboxOwnershipBranches(t *testing.T) {
	ctx := context.Background()
	owned := func(owner string) map[string]cluster.Placement {
		return map[string]cluster.Placement{"cb96-destroy": {SandboxID: "cb96-destroy", OwnerNodeID: owner, IncarnationID: "inc-cb96-destroy"}}
	}
	cases := map[string]*cb96Cluster{
		"first ownership read fails":  {authErr: errors.New("raft down")},
		"second ownership read fails": {placements: owned("self"), authErrAfter: 2},
		"ownership moves mid-destroy": {placements: owned("self"), afterFirst: owned("other"), flipAfter: 2},
	}
	for name, fc := range cases {
		t.Run(name, func(t *testing.T) {
			svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
			svc.cfg.EnableCluster = true
			fc.Noop = cluster.NewNoop("self", "http://self", "")
			svc.AttachCluster(fc)
			wave30SeedSandbox(t, st, "cb96-destroy", "inc-cb96-destroy")
			err := svc.DestroySandbox(ctx, "cb96-destroy")
			if name == "ownership moves mid-destroy" {
				if err != nil {
					t.Fatalf("stale finalize = %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("destroy ignored a failed ownership read")
			}
		})
	}

	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	sb := wave30SeedSandbox(t, st, "cb96-fc", "inc-fc")
	sb.Runtime = models.RuntimeFirecracker
	if err := st.Upsert(ctx, sb); err != nil {
		t.Fatal(err)
	}
	svc.firecracker = nil
	if err := svc.DestroySandbox(ctx, "cb96-fc"); err == nil {
		t.Fatal("destroy without a firecracker driver succeeded")
	}
}

func TestCB96ResizeSandboxFailures(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	svc, st, _ := newServiceRuntimeHarnessAtPath(t, path, resizeOKRuntime{&recordingRuntime{}})
	wave30SeedSandbox(t, st, "cb96-resize", "inc-resize")

	if _, err := svc.ResizeSandbox(ctx, "cb96-resize", models.ResizeSandboxRequest{CPU: 4096}); err == nil {
		t.Fatal("resize past host capacity was admitted")
	}
	cb96SQL(t, path, `CREATE TRIGGER cb96_freeze BEFORE UPDATE ON sandboxes BEGIN SELECT RAISE(ABORT, 'cb96 frozen'); END`)
	if _, err := svc.ResizeSandbox(ctx, "cb96-resize", models.ResizeSandboxRequest{MemoryMB: 64}); err == nil {
		t.Fatal("resize ignored a failed row write")
	}
}

func TestCB96PortLifecycleSnapshotStoreFaults(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	svc, st, _ := newServiceRuntimeHarnessAtPath(t, path, &recordingRuntime{})
	seedStartedSandbox(t, st, "cb96-port")
	seedStartedSandbox(t, st, "cb96-toolbox")

	if _, err := svc.ExposePort(ctx, "cb96-port", 8080, ""); err != nil {
		t.Fatalf("ExposePort: %v", err)
	}
	cb96SQL(t, path,
		`CREATE TRIGGER cb96_ports BEFORE DELETE ON exposed_ports BEGIN SELECT RAISE(ABORT, 'cb96 ports'); END`,
		`CREATE TRIGGER cb96_snap BEFORE INSERT ON sandbox_snapshots BEGIN SELECT RAISE(ABORT, 'cb96 snap'); END`,
		`CREATE TRIGGER cb96_sb BEFORE UPDATE ON sandboxes BEGIN SELECT RAISE(ABORT, 'cb96 sb'); END`,
	)
	if err := svc.UnexposePort(ctx, "cb96-port", 8080); err == nil {
		t.Fatal("unexpose ignored a failed row delete")
	}
	if _, err := svc.RegisterSnapshot(ctx, &models.SandboxSnapshot{Name: "cb96-snap", Image: "alpine:3.20"}); err == nil {
		t.Fatal("register snapshot ignored a failed insert")
	}
	if _, err := svc.UpdateLifecycle(ctx, "cb96-port", models.Lifecycle{}); err == nil {
		t.Fatal("lifecycle update ignored a failed row write")
	}
	if _, err := svc.ToolboxTarget(ctx, "cb96-toolbox"); err == nil {
		t.Fatal("toolbox target ignored a failed touch")
	}
}

func TestCB96HandleDestroyEventFaults(t *testing.T) {
	ctx := context.Background()
	owned := func(owner string) map[string]cluster.Placement {
		return map[string]cluster.Placement{"cb96-evt": {SandboxID: "cb96-evt", OwnerNodeID: owner, IncarnationID: "inc-evt"}}
	}
	cases := []struct {
		name    string
		cluster *cb96Cluster
		wasm    bool
		fault   string
	}{
		{name: "ownership read", cluster: &cb96Cluster{authErr: errors.New("raft down")}},
		{name: "delete fence", cluster: &cb96Cluster{placements: owned("self"), beginErr: errors.New("fence refused")}},
		{name: "cluster secrets", fault: `DROP TABLE cluster_secrets`},
		{name: "wasm artifacts", wasm: true, fault: `DROP TABLE wasm_state_kv`},
		{name: "placement delete", cluster: &cb96Cluster{placements: owned("self"), deleteErr: errors.New("delete refused")}},
		{name: "row delete", fault: `CREATE TRIGGER cb96_keep_evt BEFORE DELETE ON sandboxes BEGIN SELECT RAISE(ABORT, 'cb96 keep'); END`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.db")
			svc, st, _ := newServiceRuntimeHarnessAtPath(t, path, &recordingRuntime{})
			if tc.cluster != nil {
				svc.cfg.EnableCluster = true
				tc.cluster.Noop = cluster.NewNoop("self", "http://self", "")
				svc.AttachCluster(tc.cluster)
			}
			sb := wave30SeedSandbox(t, st, "cb96-evt", "inc-evt")
			if tc.wasm {
				sb.Runtime = models.RuntimeWasm
				if err := st.Upsert(ctx, sb); err != nil {
					t.Fatal(err)
				}
			}
			if tc.fault != "" {
				cb96SQL(t, path, tc.fault)
			}
			if err := svc.handleDestroyEvent(ctx, sb); err == nil {
				t.Fatal("destroy event ignored a failed teardown step")
			}
		})
	}
}

func TestCB96TemplateArtifactTarShapes(t *testing.T) {
	tarOf := func(t *testing.T, entries ...*tar.Header) []byte {
		t.Helper()
		var buf strings.Builder
		tw := tar.NewWriter(&buf)
		for _, h := range entries {
			if err := tw.WriteHeader(h); err != nil {
				t.Fatal(err)
			}
			if h.Typeflag == tar.TypeReg {
				if _, err := tw.Write([]byte(strings.Repeat("x", int(h.Size)))); err != nil {
					t.Fatal(err)
				}
			}
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		return []byte(buf.String())
	}
	reg := func(name string, size int64) *tar.Header {
		return &tar.Header{Name: name, Typeflag: tar.TypeReg, Size: size, Mode: 0o644}
	}

	artifactsOnly := tarOf(t, reg(templateRootfsFilename, 1), reg(snapshotMemoryFilename, 1), reg(snapshotStateFilename, 1))
	if _, err := extractTemplateArtifactsFromLayer(strings.NewReader(string(artifactsOnly)), t.TempDir()); err == nil || !strings.Contains(err.Error(), templateManifestFilename) {
		t.Fatalf("layer without manifest = %v", err)
	}

	var truncated strings.Builder
	tw := tar.NewWriter(&truncated)
	if err := tw.WriteHeader(reg(templateManifestFilename, 4096)); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("{")); err != nil {
		t.Fatal(err)
	}
	if _, err := extractTemplateArtifactsFromLayer(strings.NewReader(truncated.String()), t.TempDir()); err == nil || !strings.Contains(err.Error(), "read manifest") {
		t.Fatalf("truncated manifest = %v", err)
	}

	junkLayer := tarOf(t, reg("junk", 3))
	var save strings.Builder
	ow := tar.NewWriter(&save)
	if err := ow.WriteHeader(&tar.Header{Name: "sha/", Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
		t.Fatal(err)
	}
	if err := ow.WriteHeader(&tar.Header{Name: "sha/layer.tar", Typeflag: tar.TypeReg, Size: int64(len(junkLayer)), Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	if _, err := ow.Write(junkLayer); err != nil {
		t.Fatal(err)
	}
	if err := ow.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := extractTemplateArtifactsFromSave(strings.NewReader(save.String()), t.TempDir()); err == nil || !strings.Contains(err.Error(), "layer tar") {
		t.Fatalf("save with an invalid layer = %v", err)
	}
}

func TestCB96WasmCheckpointPersistFails(t *testing.T) {
	ctx := context.Background()
	st, path := cb96OpenStore(t)
	now := time.Now().UTC()
	sb := &models.Sandbox{ID: "cb96-wasm-cp", Runtime: models.RuntimeWasm, Status: models.SandboxStatusStarted,
		Durability: models.DurabilityPassivatable, CreatedAt: now, UpdatedAt: now}
	if err := st.Create(ctx, sb); err != nil {
		t.Fatal(err)
	}
	cb96SQL(t, path, `CREATE TRIGGER cb96_cp BEFORE UPDATE ON sandboxes BEGIN SELECT RAISE(ABORT, 'cb96 cp'); END`)
	svc := cb96Service(st, config.Config{EnableWasm: true})
	host := &fakeCheckpointRuntime{checkpointPath: filepath.Join(t.TempDir(), "cp"), cloneGen: "gen-1"}
	if err := svc.checkpointWasmSandbox(ctx, host, sb); err == nil {
		t.Fatal("passivate checkpoint ignored a failed row write")
	}
	if err := svc.checkpointLiveWasmSandbox(ctx, host, sb); err == nil {
		t.Fatal("live checkpoint ignored a failed row write")
	}
}

func TestCB96EvacuateWasmSkipsIneligible(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true
	svc.SetWasmRuntime(&fakeCheckpointDrainRuntime{listManagedErr: errors.New("engine unavailable")})
	svc.AttachCluster(&wasmMigrationTargetClusterStub{
		Noop:    cluster.NewNoop("node-a", "http://self", ""),
		owner:   cluster.OwnerInfo{NodeID: "node-b"},
		members: []cluster.Member{{NodeID: "node-a", APIURL: "http://self", Alive: true, Role: config.NodeRoleWorker}},
		drained: map[string]bool{},
	})
	now := time.Now().UTC()
	for id, durability := range map[string]string{"cb96-ephemeral": models.DurabilityEphemeral, "cb96-remote": models.DurabilityDurable} {
		if err := st.Create(ctx, &models.Sandbox{ID: id, Runtime: models.RuntimeWasm, Status: models.SandboxStatusPassivated,
			Durability: durability, ModuleRef: "file:///tmp/x.wasm", CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	if err := svc.EvacuateLocalWasmSandboxesForDrain(ctx); err != nil {
		t.Fatalf("evacuate with nothing locally owned = %v", err)
	}
}

func TestCB96StopRebuildToolboxGuards(t *testing.T) {
	ctx := context.Background()

	path := filepath.Join(t.TempDir(), "state.db")
	svc, st, _ := newServiceRuntimeHarnessAtPath(t, path, &recordingRuntime{})
	seedStartedSandbox(t, st, "cb96-stop")
	cb96SQL(t, path, `CREATE TRIGGER cb96_stop BEFORE UPDATE ON sandboxes BEGIN SELECT RAISE(ABORT, 'cb96 stop'); END`)
	if _, err := svc.StopSandbox(ctx, "cb96-stop"); err == nil {
		t.Fatal("stop ignored a failed row write")
	}

	tst, tpath := cb96OpenStore(t)
	tpl := seedReadyTemplate(t, tst, t.TempDir(), "cb96-tpl")
	cb96SQL(t, tpath, `CREATE TRIGGER cb96_tpl BEFORE UPDATE ON firecracker_templates BEGIN SELECT RAISE(ABORT, 'cb96 tpl'); END`)
	if _, err := cb96Service(tst, config.Config{}).RequestTemplateRebuild(ctx, tpl.ID); err == nil {
		t.Fatal("operator rebuild ignored a failed unhealthy mark")
	}

	bare := cb96Service(tst, config.Config{})
	if _, err := bare.roundTripWasmToolbox(ctx, &models.Sandbox{ID: "cb96-w", Runtime: models.RuntimeWasm}, http.MethodGet, "/", nil, nil, nil); err == nil {
		t.Fatal("wasm toolbox without a driver succeeded")
	}
	bare.wasm = &fakeToolboxHost{}
	if _, err := bare.roundTripWasmToolbox(ctx, &models.Sandbox{ID: "cb96-w", Runtime: models.RuntimeWasm}, "bad method", "/", nil, nil, nil); err == nil {
		t.Fatal("wasm toolbox accepted an invalid method")
	}
	if _, err := bare.newNetworkToolboxRequest(ctx, "cb96-missing", http.MethodGet, "/", nil, nil, nil); err == nil {
		t.Fatal("network toolbox request for a missing sandbox succeeded")
	}
}

func TestCB96PlatformVolumeResolutionFailures(t *testing.T) {
	ctx := context.Background()
	mount := func(name, path string) *models.CreateSandboxRequest {
		return &models.CreateSandboxRequest{Image: "alpine", PlatformVolumes: []models.PlatformVolumeMount{{Name: name, Path: path}}}
	}

	noTenant := enabledVolumeService(t)
	noTenant.cfg.PATToken = ""
	if _, err := noTenant.resolvePlatformVolumes(ctx, mount("data", "/data"), models.RuntimeDocker); err == nil || !strings.Contains(err.Error(), "scope platform volume") {
		t.Fatalf("unscoped resolve = %v", err)
	}
	if err := noTenant.ResolvePlatformVolumesForReplication(ctx, mount("data", "/data")); err == nil || !strings.Contains(err.Error(), "scope platform volume") {
		t.Fatalf("unscoped replication = %v", err)
	}
	if err := enabledVolumeService(t).ResolvePlatformVolumesForReplication(ctx, mount("../bad", "/data")); err == nil {
		t.Fatal("replication accepted an unsafe volume name")
	}

	noBucket := enabledVolumeService(t)
	noBucket.cfg.PlatformVolumes.S3Bucket = ""
	if _, err := noBucket.resolvePlatformVolumes(ctx, mount("data", "/data"), models.RuntimeDocker); err == nil || !strings.Contains(err.Error(), "bucket") {
		t.Fatalf("bucketless resolve = %v", err)
	}
	if _, err := enabledVolumeService(t).resolvePlatformVolumes(ctx, mount("data", ""), models.RuntimeDocker); err == nil || !strings.Contains(err.Error(), "mount path") {
		t.Fatalf("pathless resolve = %v", err)
	}

	st, path := cb96OpenStore(t)
	rowFail := enabledVolumeService(t)
	rowFail.store = st
	cb96SQL(t, path, `CREATE TRIGGER cb96_vol BEFORE INSERT ON volumes BEGIN SELECT RAISE(ABORT, 'cb96 vol'); END`)
	if _, err := rowFail.resolvePlatformVolumes(ctx, mount("data", "/data"), models.RuntimeDocker); err == nil || !strings.Contains(err.Error(), "cb96 vol") {
		t.Fatalf("row insert failure = %v", err)
	}

	enabledVolumeService(t).cleanupCreatedPlatformVolumes(ctx, []models.VolumeAttachment{
		{Tenant: "t-a", VolumeID: "vol-dup", CreatedVolume: true},
		{Tenant: "t-a", VolumeID: "vol-dup", CreatedVolume: true},
	})
}

func TestCB96WasmModuleCatalogFaults(t *testing.T) {
	ctx := context.Background()
	st, path := cb96OpenStore(t)
	svc := cb96Service(st, config.Config{EnableWasm: true, WasmModulesDir: t.TempDir()})
	svc.SetWasmModuleResolver(stubWasmModuleResolver{path: "/tmp/cb96.wasm", digest: "cb96dig"})
	if _, err := svc.CreateWasmModule(ctx, models.CreateWasmModuleRequest{ModuleRef: "file:///tmp/a.wasm"}); err != nil {
		t.Fatalf("seed module: %v", err)
	}
	if _, err := svc.CreateWasmModule(ctx, models.CreateWasmModuleRequest{ModuleRef: "file:///tmp/b.wasm"}); !errors.Is(err, storepkg.ErrWasmModuleIDConflict) {
		t.Fatalf("digest collision with a different ref = %v", err)
	}

	svc.SetWasmModuleResolver(stubWasmModuleResolver{path: "/tmp/cb96.wasm", digest: "cb96other"})
	cb96SQL(t, path, `CREATE TRIGGER cb96_mod BEFORE INSERT ON wasm_modules BEGIN SELECT RAISE(ABORT, 'cb96 mod'); END`)
	if _, err := svc.CreateWasmModule(ctx, models.CreateWasmModuleRequest{ModuleRef: "file:///tmp/c.wasm"}); err == nil || !strings.Contains(err.Error(), "cb96 mod") {
		t.Fatalf("catalogue insert failure = %v", err)
	}
	cb96SQL(t, path, `DROP TABLE wasm_modules`)
	if _, err := svc.CreateWasmModule(ctx, models.CreateWasmModuleRequest{ModuleRef: "file:///tmp/c.wasm"}); err == nil {
		t.Fatal("catalogue lookup failure was ignored")
	}
}

func TestCB96NetworkLimitsAndLeaseGuards(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	svc, st, _ := newServiceRuntimeHarnessAtPath(t, path, &recordingRuntime{})
	seedStartedSandbox(t, st, "cb96-net")
	cb96SQL(t, path, `CREATE TRIGGER cb96_net BEFORE UPDATE ON sandboxes BEGIN SELECT RAISE(ABORT, 'cb96 net'); END`)
	if _, err := svc.SetNetworkLimits(ctx, "cb96-net", 1024, 1024); err == nil {
		t.Fatal("network limits ignored a failed row write")
	}

	var nilSvc *Service
	nilSvc.invalidateAuditOwnershipLease("cb96")
	if n := nilSvc.pruneAuditOwnershipLeaseFences(time.Now()); n != 0 {
		t.Fatalf("nil service pruned %d fences", n)
	}
	(&Service{}).invalidateAuditOwnershipLease("  ")
	if _, err := (&Service{}).resolveAuditBinding(ctx, "cb96"); !errors.Is(err, errAuditIngestBindingStale) {
		t.Fatalf("storeless audit binding = %v", err)
	}
}

func TestCB96CustomDomainGuards(t *testing.T) {
	ctx := context.Background()
	st, path := cb96OpenStore(t)
	svc := cb96Service(st, config.Config{
		EnableCustomDomains:        true,
		Domain:                     "aerol.cloud",
		CustomDomainsMaxPerSandbox: models.MaxCustomDomainsPerSandbox,
		HTTPClientTimeout:          time.Second,
	})
	svc.caddy = caddy.New(svc.cfg)
	svc.dnsResolver = matchingDNSResolver{}

	private := mustCreateSandboxRow(t, st, "cb96-private")
	off := false
	private.AllowPublicTraffic = &off
	if err := st.Upsert(ctx, private); err != nil {
		t.Fatal(err)
	}
	if err := svc.AddCustomDomain(ctx, "cb96-private", "api.acme.com", 0); !errors.Is(err, ErrPublicTrafficDisabled) {
		t.Fatalf("custom domain on a private sandbox = %v", err)
	}

	mustCreateSandboxRow(t, st, "cb96-cd")
	if err := svc.AddCustomDomain(ctx, "cb96-cd", "api.acme.com", 0); err != nil {
		t.Fatalf("AddCustomDomain: %v", err)
	}
	cb96SQL(t, path, `CREATE TRIGGER cb96_cd BEFORE DELETE ON sandbox_custom_domains BEGIN SELECT RAISE(ABORT, 'cb96 cd'); END`)
	if err := svc.RemoveCustomDomain(ctx, "cb96-cd", "api.acme.com"); err == nil || !strings.Contains(err.Error(), "cb96 cd") {
		t.Fatalf("remove with a failed row delete = %v", err)
	}
}

func TestCB96AutoImportRetrySkips(t *testing.T) {
	fs := newFakeStore()
	fs.seed("cb96-cleared", false)
	fs.seed("cb96-nospec", true)
	fs.seed("cb96-ineligible", true)
	fs.setErr = errors.New("flag clear refused")
	imp, err := NewAutoImporter(validImportCfg("http://127.0.0.1:1"))
	if err != nil || imp == nil {
		t.Fatalf("importer: %v", err)
	}
	r := NewAutoImportReconciler(imp, fs, &fakeSpecResolver{specs: map[string]*models.CreateSandboxRequest{
		"cb96-ineligible": {Image: "alpine"},
	}}, slog.New(slog.DiscardHandler), 1)
	for _, id := range []string{"cb96-cleared", "cb96-nospec", "cb96-ineligible"} {
		if got := r.retryOne(context.Background(), id); got != retrySkipped {
			t.Fatalf("retryOne(%s) = %v, want skipped", id, got)
		}
	}
}

func TestCB96SecretHoldersStoreFaults(t *testing.T) {
	ctx := context.Background()
	for _, fault := range []string{`DROP TABLE cluster_secret_put_outbox`, `DROP TABLE cluster_secret_delete_outbox`, `DROP TABLE sandboxes`} {
		t.Run(fault, func(t *testing.T) {
			st, path := cb96OpenStore(t)
			sb := wave30SeedSandbox(t, st, "cb96-holders", "inc-holders")
			putHolders(t, st, sb, []string{"node-a"}, 1)
			cb96SQL(t, path, fault)
			if _, err := cb96Service(st, config.Config{}).SecretHoldersForSandbox(ctx, sb.ID); err == nil {
				t.Fatal("holder view ignored a failed read")
			}
		})
	}
}

func TestCB96AutoImporterTransportFailures(t *testing.T) {
	req := AutoImportRequest{UpstreamHost: "ghcr.io", UpstreamRepo: "org/app", UpstreamTag: "latest", UpstreamDigest: "sha256:abc"}

	garbled := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("{not json"))
	}))
	t.Cleanup(garbled.Close)
	imp, err := NewAutoImporter(validImportCfg(garbled.URL))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := imp.Import(context.Background(), req); err == nil || !strings.Contains(err.Error(), "decode response") {
		t.Fatalf("garbled response = %v", err)
	}

	gone := httptest.NewServer(http.NotFoundHandler())
	goneURL := gone.URL
	gone.Close()
	imp, err = NewAutoImporter(validImportCfg(goneURL))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := imp.Import(context.Background(), req); err == nil || !strings.Contains(err.Error(), "POST") {
		t.Fatalf("unreachable importer = %v", err)
	}

	var nilPusher *WasmCheckpointPusher
	if got := nilPusher.DestRefTagged("cb96", "latest"); got != "" {
		t.Fatalf("nil pusher ref = %q", got)
	}
}

func TestCB96TemplatePushOneStateFaults(t *testing.T) {
	ctx := context.Background()
	fs := newFakeTemplatePushStore()
	rec, _ := newTestTemplateReconciler(t, fs, &fakeTemplatePushDocker{})
	if got := rec.pushOne(ctx, nil); got != templatePushSkipped {
		t.Fatalf("nil template = %v", got)
	}

	fs.stateErr = map[string]error{
		models.TemplatePushStateActive:  errors.New("active refused"),
		models.TemplatePushStatePushing: errors.New("claim refused"),
	}
	unhealthy := &models.Template{ID: "cb96-unhealthy", Status: models.TemplateStatusUnhealthy, PushState: models.TemplatePushStatePending}
	fs.seed(unhealthy)
	if got := rec.pushOne(ctx, unhealthy); got != templatePushSkipped {
		t.Fatalf("non-ready template = %v", got)
	}
	ready := &models.Template{ID: "cb96-ready", Image: "img:1", Status: models.TemplateStatusReady, PushState: models.TemplatePushStatePending}
	fs.seed(ready)
	if got := rec.pushOne(ctx, ready); got != templatePushFailed {
		t.Fatalf("unclaimable template = %v", got)
	}

	fs.stateErr = map[string]error{models.TemplatePushStateError: errors.New("error state refused")}
	if got := rec.pushOne(ctx, ready); got != templatePushFailed {
		t.Fatalf("template without artifacts = %v", got)
	}

	seam := (&Service{}).TemplatePushStore(fs)
	if err := seam.UpdateTemplatePushDistribution(ctx, "cb96-missing", "ref", "digest"); err == nil {
		t.Fatal("seam swallowed a distribution write failure")
	}
}

func TestCB96DeleteJSBundleByNodeRef(t *testing.T) {
	ctx := context.Background()
	svc := newBundleService(t)
	got, err := svc.CreateJSBundle(ctx, models.CreateJSBundleRequest{Name: "cb96", Source: jsBundleSrc})
	if err != nil {
		t.Fatal(err)
	}
	ref := models.JSBundleRefForNode(got.ModuleRef, "node-a")
	if err := svc.DeleteJSBundle(ctx, ref); err != nil {
		t.Fatalf("delete by node-bound ref (%s) = %v", ref, err)
	}
	if _, err := svc.GetJSBundle(ctx, got.Digest); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("bundle after delete = %v", err)
	}
}

type cb96ACLErrCluster struct{ *cluster.Noop }

func (cb96ACLErrCluster) AuditACLForSandbox(context.Context, string, string) (cluster.AuditACL, bool, error) {
	return cluster.AuditACL{}, false, errors.New("acl index unavailable")
}

func TestCB96AuthorizeSandboxAuditAccessFaults(t *testing.T) {
	ctx := context.Background()
	tenant := controlplane.ContextWithAccess(ctx, controlplane.Access{Identity: controlplane.Identity{OwnerRef: "tenant-a"}})

	st, _ := cb96OpenStore(t)
	svc := cb96Service(st, config.Config{})
	mustCreateSandboxRow(t, st, "cb96-noinc")
	if _, err := svc.AuthorizeSandboxAuditAccess(ctx, "cb96-noinc", ""); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("row without a lifecycle = %v", err)
	}
	if _, err := svc.AuthorizeSandboxAuditAccess(ctx, "cb96-unknown", ""); !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("unknown sandbox without cluster = %v", err)
	}

	withACL := cb96Service(st, config.Config{})
	withACL.cluster = cb96ACLErrCluster{cluster.NewNoop("self", "http://self", "")}
	if _, err := withACL.AuthorizeSandboxAuditAccess(tenant, "cb96-unknown", "inc-x"); err == nil || !strings.Contains(err.Error(), "acl index") {
		t.Fatalf("tenant authorize with a failing cluster ACL = %v", err)
	}

	broken, path := cb96OpenStore(t)
	cb96SQL(t, path, `DROP TABLE sandbox_audit_acl`)
	bsvc := cb96Service(broken, config.Config{})
	for name, call := range map[string]func() error{
		"latest retained": func() error { _, err := bsvc.AuthorizeSandboxAuditAccess(ctx, "cb96-gone", ""); return err },
		"operator acl":    func() error { _, err := bsvc.AuthorizeSandboxAuditAccess(ctx, "cb96-gone", "inc-x"); return err },
		"tenant acl":      func() error { _, err := bsvc.AuthorizeSandboxAuditAccess(tenant, "cb96-gone", "inc-x"); return err },
	} {
		if err := call(); err == nil || errors.Is(err, storepkg.ErrNotFound) {
			t.Fatalf("%s with a broken ACL table = %v", name, err)
		}
	}
}

func TestCB96SecretHandleForOwnershipReplay(t *testing.T) {
	ctx := context.Background()
	spec := models.CreateSandboxRequest{Image: "alpine", Env: map[string]string{"TOKEN": "v"}}

	st, _ := cb96OpenStore(t)
	sb := wave30SeedSandbox(t, st, "cb96-replay", "inc-replay")
	putHolders(t, st, sb, []string{"self"}, 3)
	svc := cb96Service(st, config.Config{EnableCluster: true})
	self := cluster.NewNoop("self", "http://self", "")
	handle, err := svc.secretHandleForOwnershipReplay(ctx, self, sb, spec)
	if err != nil {
		t.Fatalf("replay with a matching local seal: %v", err)
	}
	if handle.SealGeneration != 3 || handle.IncarnationID != "inc-replay" || handle.Ref == "" {
		t.Fatalf("replay handle = %+v, want the durable local seal", handle)
	}

	broken, path := cb96OpenStore(t)
	bsb := wave30SeedSandbox(t, broken, "cb96-replay", "inc-replay")
	cb96SQL(t, path, `DROP TABLE cluster_secrets`)
	placed := &cb96Cluster{Noop: self, placements: map[string]cluster.Placement{
		"cb96-replay": {SandboxID: "cb96-replay", OwnerNodeID: "self", IncarnationID: "inc-placed"},
	}}
	if _, err := cb96Service(broken, config.Config{EnableCluster: true}).secretHandleForOwnershipReplay(ctx, placed, bsb, spec); err == nil || !strings.Contains(err.Error(), "load durable secret") {
		t.Fatalf("replay with an unreadable seal = %v", err)
	}
}

func TestCB96GCZombieKeepsCustomDomainRoutes(t *testing.T) {
	fake := newGCCaddyFake()
	sb := &models.Sandbox{
		ID:                 "cb96-public",
		AllowPublicTraffic: func() *bool { v := true; return &v }(),
		Status:             models.SandboxStatusStarted,
		CustomDomains:      []models.CustomDomain{{Hostname: ""}, {Hostname: "api.example.com"}},
	}
	keep := caddy.IngressCustomDomainHTTPRouteID(sb.ID, "api.example.com")
	fake.httpRouteIDs[caddy.SandboxRouteID(sb.ID)] = struct{}{}
	fake.httpRouteIDs[keep] = struct{}{}
	fake.httpRouteIDs["sandbox-cb96-stale"] = struct{}{}
	server := httptest.NewServer(fake.handler(t))
	t.Cleanup(server.Close)

	svc := &Service{
		logger: slog.New(slog.DiscardHandler),
		caddy: caddy.New(config.Config{
			CaddyAdminURL: server.URL, CaddyServerID: "srv0", EnableCaddy: true, HTTPClientTimeout: 5 * time.Second,
		}),
	}
	svc.gcZombieCaddyEntries(context.Background(), []*models.Sandbox{sb})
	if got := fake.keys(fake.httpRouteIDs); !equalSorted(got, []string{caddy.SandboxRouteID(sb.ID), keep}) {
		t.Fatalf("http routes after gc = %v", got)
	}
}

func TestCB96PendingImageGCRowDeleteFails(t *testing.T) {
	ctx := context.Background()
	st, path := cb96OpenStore(t)
	removed := 0
	svc := cb96Service(st, config.Config{ImageBuildGCEnabled: true})
	svc.docker = &countingFakeRuntime{removed: &removed}
	seedSandbox(t, st, "cb96-img-user", models.SandboxStatusStarted, 1, 256)
	past := time.Now().UTC().Add(-time.Hour)
	for _, image := range []string{"ubuntu:22.04", "cb96-free:1"} {
		if err := st.SchedulePendingImageGC(ctx, models.ContainerEngineDocker, image, past); err != nil {
			t.Fatal(err)
		}
	}
	cb96SQL(t, path, `CREATE TRIGGER cb96_gc BEFORE DELETE ON pending_image_gc BEGIN SELECT RAISE(ABORT, 'cb96 gc'); END`)
	svc.runPendingImageGC(ctx)
	if removed != 1 {
		t.Fatalf("RemoveImage calls = %d, want 1 (only the unreferenced image)", removed)
	}
	due, err := st.ListPendingImageGCDue(ctx, time.Now().UTC(), 0)
	if err != nil || len(due) != 2 {
		t.Fatalf("rows after failed deletes = %v, %v; want both retained", due, err)
	}
}

func TestCB96LifecycleSweepAutoDestroyFails(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{destroyErr: errors.New("runtime wedged")}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	old := time.Now().UTC().Add(-time.Hour)
	sb := &models.Sandbox{ID: "cb96-expired", Image: "alpine", Status: models.SandboxStatusStarted, Runtime: models.RuntimeDocker,
		ContainerID: "ctr-expired", AuditIncarnationID: "inc-expired", CPU: 1, MemoryMB: 256,
		Lifecycle: models.Lifecycle{DestroyAtAge: time.Minute}, CreatedAt: old, UpdatedAt: old, LastActiveAt: old}
	if err := st.Create(ctx, sb); err != nil {
		t.Fatal(err)
	}
	svc.runLifecycleSweep(ctx)
	if got, err := st.Get(ctx, sb.ID); err != nil || got.Status == models.SandboxStatusDestroyed {
		t.Fatalf("sandbox after failed auto-destroy = %+v, %v", got, err)
	}
}
