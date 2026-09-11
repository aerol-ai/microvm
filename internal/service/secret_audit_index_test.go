package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/auditlog"
)

// indexedAuditFixture is one Service with the read index on, plus a second
// storeless Service over the same JSONL that can only scan. The scan path is
// the oracle: every page the index serves must equal the page the scan
// serves for the same query.
type indexedAuditFixture struct {
	svc  *Service
	scan *Service
	sink *fileAuditSink
	idx  *secretAuditIndexer
	st   *storepkg.Store
	db   string
}

func newIndexedAuditFixture(t *testing.T) *indexedAuditFixture {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	st, err := storepkg.Open(dbPath)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return reopenIndexedAuditFixture(t, st, dbPath)
}

func reopenIndexedAuditFixture(t *testing.T, st *storepkg.Store, dbPath string) *indexedAuditFixture {
	t.Helper()
	// A large queue so bulk fixtures never overflow into gap markers.
	// A large queue so bulk fixtures never overflow into gap markers, and a
	// retention long enough that fixtures dated in the past are not pruned
	// by the sweep that runs at sink start.
	svc := &Service{cfg: config.Config{DBPath: dbPath, SecretAuditRetentionDays: 3650, AuditIndexEnabled: true, AuditQueueMax: 16384}, store: st}
	t.Cleanup(svc.CloseSecretAuditSink)
	sink, ok := svc.secretAuditSink().(*fileAuditSink)
	if !ok {
		t.Fatalf("sink = %T, want file sink (init err %v)", svc.secretAudit, svc.secretAuditInitErr)
	}
	if svc.secretAuditIndex == nil {
		t.Fatal("index not wired")
	}
	scan := &Service{cfg: config.Config{DBPath: dbPath}, secretAudit: unavailableSecretAuditSink{}}
	return &indexedAuditFixture{svc: svc, scan: scan, sink: sink, idx: svc.secretAuditIndex, st: st, db: dbPath}
}

func (f *indexedAuditFixture) waitReady(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !f.idx.isReady() {
		if time.Now().After(deadline) {
			t.Fatal("index never became ready")
		}
		time.Sleep(5 * time.Millisecond)
	}
	f.assertCaughtUp(t)
}

func (f *indexedAuditFixture) waitNotReady(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for f.idx.isReady() {
		if time.Now().After(deadline) {
			t.Fatal("index never degraded")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// assertCaughtUp proves the index covers the whole file, so pages need no
// tail scan at all.
func (f *indexedAuditFixture) assertCaughtUp(t *testing.T) {
	t.Helper()
	meta, ok, err := f.st.GetSecretAuditIndexMeta(context.Background())
	if err != nil || !ok {
		t.Fatalf("meta ok=%v err=%v", ok, err)
	}
	st, err := os.Stat(f.sink.path)
	if err != nil {
		if os.IsNotExist(err) && meta.IndexedThrough == 0 {
			return
		}
		t.Fatal(err)
	}
	if meta.IndexedThrough != st.Size() {
		t.Fatalf("indexed through %d, file is %d bytes", meta.IndexedThrough, st.Size())
	}
	fh, err := os.Open(f.sink.path)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	if gen, err := auditFileGeneration(fh); err != nil || gen != meta.Generation {
		t.Fatalf("index generation %q, file %q (err %v)", meta.Generation, gen, err)
	}
}

// pageAll walks every page for a query on svc and returns the event ids in
// order plus the cursors it saw.
func pageAll(t *testing.T, svc *Service, sandboxID string, q SecretAuditQuery) ([]string, []string) {
	t.Helper()
	var ids, cursors []string
	for pages := 0; ; pages++ {
		events, next, err := svc.ListSecretAuditLocal(context.Background(), sandboxID, q)
		if err != nil {
			t.Fatalf("page %d of %s %+v: %v", pages, sandboxID, q, err)
		}
		for _, ev := range events {
			ids = append(ids, ev.EventID)
		}
		if next == "" {
			return ids, cursors
		}
		cursors = append(cursors, next)
		q.Cursor = next
		if pages > 10_000 {
			t.Fatal("paging does not terminate")
		}
	}
}

// assertSamePages is the equivalence oracle: index and scan answer alike.
func (f *indexedAuditFixture) assertSamePages(t *testing.T, sandboxID string, q SecretAuditQuery) []string {
	t.Helper()
	indexedBefore := secretAuditQueryIndexedTotal.Value()
	fallbackBefore := secretAuditQueryScanFallbackTotal.Value()
	gotIDs, gotCursors := pageAll(t, f.svc, sandboxID, q)
	if secretAuditQueryIndexedTotal.Value() == indexedBefore {
		t.Fatalf("query %s %+v was not served by the index", sandboxID, q)
	}
	if secretAuditQueryScanFallbackTotal.Value() != fallbackBefore {
		t.Fatalf("query %s %+v fell back to a scan", sandboxID, q)
	}
	wantIDs, wantCursors := pageAll(t, f.scan, sandboxID, q)
	if strings.Join(gotIDs, ",") != strings.Join(wantIDs, ",") {
		t.Fatalf("index/scan disagree for %s %+v:\n index: %v\n scan:  %v", sandboxID, q, gotIDs, wantIDs)
	}
	if strings.Join(gotCursors, "|") != strings.Join(wantCursors, "|") {
		t.Fatalf("index/scan cursors disagree for %s %+v", sandboxID, q)
	}
	return gotIDs
}

func indexedFixtureEvent(sandboxID, inc, kind string, i int, at time.Time) SecretAuditEvent {
	return SecretAuditEvent{
		Time:          at,
		SandboxID:     sandboxID,
		IncarnationID: inc,
		EventID:       fmt.Sprintf("%s-%s-%03d", sandboxID, kind, i),
		Kind:          kind,
		Result:        secretAuditResultSuccess,
		Reason:        secretAuditReasonOK,
		Actor:         "node-a",
	}
}

// emitMixedWorkload writes an interleaved, deliberately out-of-order stream:
// several sandboxes, two lifecycles of one of them, both kinds, a gap
// marker, and timestamps that do not increase with file position (as spill
// drains and worker ingest produce).
func (f *indexedAuditFixture) emitMixedWorkload(t *testing.T, base time.Time, perSandbox int) {
	t.Helper()
	rng := rand.New(rand.NewSource(7))
	var events []SecretAuditEvent
	for _, sb := range []string{"sb-a", "sb-b", "sb-c"} {
		for i := range perSandbox {
			inc := "inc-1"
			if sb == "sb-a" && i%2 == 1 {
				inc = "inc-2"
			}
			kind := secretAuditKindSecretOpen
			if i%3 == 0 {
				kind = secretAuditKindEgress
			}
			// Same-nanosecond bursts exercise the (time, key) tie-break.
			at := base.Add(time.Duration(i/4) * time.Millisecond)
			events = append(events, indexedFixtureEvent(sb, inc, kind, i, at))
		}
	}
	events = append(events, SecretAuditEvent{
		Time: base.Add(time.Duration(perSandbox/8) * time.Millisecond), EventID: "gap-1",
		Kind: secretAuditKindGap, Result: secretAuditResultGap, Reason: secretAuditReasonOverflow, Dropped: 3,
	})
	rng.Shuffle(len(events), func(i, j int) { events[i], events[j] = events[j], events[i] })
	for _, ev := range events {
		f.sink.Emit(ev)
	}
	if err := f.sink.Sync(); err != nil {
		t.Fatal(err)
	}
}

func TestSecretAuditIndexServesPagesIdenticallyToScan(t *testing.T) {
	f := newIndexedAuditFixture(t)
	f.waitReady(t)
	base := time.Unix(1_800_000_000, 0).UTC()
	f.emitMixedWorkload(t, base, 120)
	f.waitReady(t)

	ids := f.assertSamePages(t, "sb-a", SecretAuditQuery{Limit: 7})
	// 120 events for sb-a plus the gap marker (it surfaces on every page walk).
	if len(ids) != 121 {
		t.Fatalf("sb-a walked %d ids, want 121", len(ids))
	}
	if ids := f.assertSamePages(t, "sb-a", SecretAuditQuery{Limit: 10, IncarnationID: "inc-2"}); len(ids) != 61 {
		t.Fatalf("sb-a/inc-2 walked %d ids, want 61", len(ids))
	}
	if ids := f.assertSamePages(t, "sb-b", SecretAuditQuery{Limit: 50, Kind: secretAuditKindEgress}); len(ids) != 41 {
		t.Fatalf("sb-b egress walked %d ids, want 41", len(ids))
	}
	f.assertSamePages(t, "sb-c", SecretAuditQuery{Limit: 1})
	f.assertSamePages(t, "sb-c", SecretAuditQuery{Limit: 1000})
	// Unknown kind filters, unknown sandboxes: still equivalent, still indexed.
	if ids := f.assertSamePages(t, "sb-c", SecretAuditQuery{Kind: "nope"}); len(ids) != 1 {
		t.Fatalf("unknown kind walked %v, want just the gap marker", ids)
	}
	if ids := f.assertSamePages(t, "sb-none", SecretAuditQuery{}); len(ids) != 1 || ids[0] != "gap-1" {
		t.Fatalf("unknown sandbox walked %v, want just the gap marker", ids)
	}
	// A cursor exactly on a same-nanosecond burst.
	first, next, err := f.svc.ListSecretAuditLocal(context.Background(), "sb-b", SecretAuditQuery{Limit: 3})
	if err != nil || len(first) != 3 || next == "" {
		t.Fatalf("first page = %d events, cursor %q, err %v", len(first), next, err)
	}
	f.assertSamePages(t, "sb-b", SecretAuditQuery{Limit: 3, Cursor: next})
	if chunks, entries, err := f.st.SecretAuditIndexStats(context.Background()); err != nil || entries != 361 || chunks != 5 {
		t.Fatalf("index stats chunks=%d entries=%d err=%v (want 5 lists, 361 entries)", chunks, entries, err)
	}
}

func TestSecretAuditIndexIsUsedWithoutTailScanWhenCaughtUp(t *testing.T) {
	f := newIndexedAuditFixture(t)
	f.waitReady(t)
	base := time.Unix(1_800_000_000, 0).UTC()
	// A large body of other sandboxes' evidence must not be touched by a
	// page for one small sandbox.
	for i := range 3000 {
		f.sink.Emit(indexedFixtureEvent("sb-noise", "inc", secretAuditKindEgress, i, base.Add(time.Duration(i)*time.Microsecond)))
	}
	for i := range 5 {
		f.sink.Emit(indexedFixtureEvent("sb-small", "inc", secretAuditKindSecretOpen, i, base.Add(time.Duration(i)*time.Second)))
	}
	if err := f.sink.Sync(); err != nil {
		t.Fatal(err)
	}
	f.waitReady(t)
	meta, _, _ := f.st.GetSecretAuditIndexMeta(context.Background())
	st, _ := os.Stat(f.sink.path)
	if meta.IndexedThrough != st.Size() {
		t.Fatalf("index lags: %d of %d", meta.IndexedThrough, st.Size())
	}
	ids := f.assertSamePages(t, "sb-small", SecretAuditQuery{Limit: 2})
	if len(ids) != 5 {
		t.Fatalf("sb-small ids = %v", ids)
	}
	// The read went straight to five records: prove it by making every other
	// record unreadable and asking again.
	raw, err := os.ReadFile(f.sink.path)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimRight(raw, "\n"), []byte("\n"))
	for i, line := range lines {
		if !bytes.Contains(line, []byte(`"sb-small"`)) {
			lines[i] = bytes.Repeat([]byte("x"), len(line)) // same length: offsets unchanged
		}
	}
	if err := os.WriteFile(f.sink.path, append(bytes.Join(lines, []byte("\n")), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	// The first line changed, so the file's generation changed; pin the
	// index to it so the reader accepts the offsets.
	fh, _ := os.Open(f.sink.path)
	gen, _ := auditFileGeneration(fh)
	_ = fh.Close()
	expect := meta
	meta.Generation = gen
	if err := f.st.WriteSecretAuditIndex(context.Background(), expect, meta, nil); err != nil {
		t.Fatal(err)
	}
	f.idx.mu.Lock()
	f.idx.meta.Generation = gen
	f.idx.mu.Unlock()
	got, _ := pageAll(t, f.svc, "sb-small", SecretAuditQuery{Limit: 2})
	if strings.Join(got, ",") != strings.Join(ids, ",") {
		t.Fatalf("indexed read touched other records: %v vs %v", got, ids)
	}
	if _, _, err := f.scan.ListSecretAuditLocal(context.Background(), "sb-small", SecretAuditQuery{Limit: 2}); err != nil {
		t.Fatalf("scan skips unparseable records that cannot match: %v", err)
	}
}

func TestSecretAuditIndexFollowsRetentionShiftWithoutRebuild(t *testing.T) {
	f := newIndexedAuditFixture(t)
	f.waitReady(t)
	now := time.Now().UTC()
	old := now.Add(-40 * 24 * time.Hour)
	for i := range 30 {
		f.sink.Emit(indexedFixtureEvent("sb-old", "inc", secretAuditKindSecretOpen, i, old.Add(time.Duration(i)*time.Second)))
	}
	// One sandbox straddles the cutoff: its first events are dropped.
	for i := range 10 {
		f.sink.Emit(indexedFixtureEvent("sb-span", "inc", secretAuditKindEgress, i, old.Add(time.Duration(i)*time.Second)))
	}
	if err := f.sink.Sync(); err != nil {
		t.Fatal(err)
	}
	for i := 10; i < 20; i++ {
		f.sink.Emit(indexedFixtureEvent("sb-span", "inc", secretAuditKindEgress, i, now.Add(time.Duration(i)*time.Second)))
	}
	for i := range 25 {
		f.sink.Emit(indexedFixtureEvent("sb-new", "inc", secretAuditKindSecretOpen, i, now.Add(time.Duration(i)*time.Second)))
	}
	if err := f.sink.Sync(); err != nil {
		t.Fatal(err)
	}
	f.waitReady(t)
	rebuilds := secretAuditIndexRebuildsTotal.Value()
	if err := f.sink.Prune(now.Add(-24 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	if !f.idx.isReady() {
		t.Fatal("retention degraded the index; it should have been shifted")
	}
	if secretAuditIndexRebuildsTotal.Value() != rebuilds {
		t.Fatal("retention triggered a rebuild instead of a shift")
	}
	f.assertCaughtUp(t)
	if ids := f.assertSamePages(t, "sb-old", SecretAuditQuery{}); len(ids) != 0 {
		t.Fatalf("pruned sandbox still has %v", ids)
	}
	if ids := f.assertSamePages(t, "sb-span", SecretAuditQuery{Limit: 4}); len(ids) != 10 || ids[0] != "sb-span-egress-010" {
		t.Fatalf("straddling sandbox after prune = %v", ids)
	}
	if ids := f.assertSamePages(t, "sb-new", SecretAuditQuery{Limit: 6}); len(ids) != 25 {
		t.Fatalf("kept sandbox after prune = %d ids", len(ids))
	}
	if chunks, entries, err := f.st.SecretAuditIndexStats(context.Background()); err != nil || entries != 35 || chunks != 2 {
		t.Fatalf("stats after shift chunks=%d entries=%d err=%v", chunks, entries, err)
	}
	// Appends after the shift continue from the re-based coverage.
	f.sink.Emit(indexedFixtureEvent("sb-new", "inc", secretAuditKindSecretOpen, 99, now.Add(time.Hour)))
	if err := f.sink.Sync(); err != nil {
		t.Fatal(err)
	}
	if ids := f.assertSamePages(t, "sb-new", SecretAuditQuery{Limit: 100}); len(ids) != 26 || ids[25] != "sb-new-secret_open-099" {
		t.Fatalf("append after shift = %v", ids)
	}
	if secretAuditIndexRebuildsTotal.Value() != rebuilds {
		t.Fatal("append after shift caused a rebuild")
	}

	// A rewrite that is not a pure prefix drop (a blank line inside the kept
	// region) cannot be shifted; it must rebuild, and stay correct.
	fh, err := os.OpenFile(f.sink.path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fh.WriteString("\n"); err != nil {
		t.Fatal(err)
	}
	_ = fh.Close()
	f.sink.Emit(indexedFixtureEvent("sb-new", "inc", secretAuditKindSecretOpen, 100, now.Add(2*time.Hour)))
	if err := f.sink.Sync(); err != nil {
		t.Fatal(err)
	}
	f.waitReady(t) // the offset gap degraded the index; the maintainer caught up
	if err := f.sink.Prune(now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	f.waitReady(t)
	if secretAuditIndexRebuildsTotal.Value() == rebuilds {
		t.Fatal("inexact rewrite did not rebuild the index")
	}
	if ids := f.assertSamePages(t, "sb-new", SecretAuditQuery{Limit: 9}); len(ids) != 27 {
		t.Fatalf("after rebuild = %d ids", len(ids))
	}
	f.assertSamePages(t, "sb-span", SecretAuditQuery{Limit: 3})
}

func TestSecretAuditIndexRebuildsWhenStoredMetaDisagreesWithFile(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	st, err := storepkg.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	f := reopenIndexedAuditFixture(t, st, dbPath)
	f.waitReady(t)
	base := time.Unix(1_800_000_000, 0).UTC()
	f.emitMixedWorkload(t, base, 40)
	f.waitReady(t)
	f.svc.CloseSecretAuditSink()

	ctx := context.Background()
	for _, tamper := range []func(m storepkg.SecretAuditIndexMeta) storepkg.SecretAuditIndexMeta{
		func(m storepkg.SecretAuditIndexMeta) storepkg.SecretAuditIndexMeta { m.Generation = "bogus"; return m },
		func(m storepkg.SecretAuditIndexMeta) storepkg.SecretAuditIndexMeta { m.IndexedThrough += 100; return m },
		func(m storepkg.SecretAuditIndexMeta) storepkg.SecretAuditIndexMeta {
			m.LastEventHash = strings.Repeat("0", 64)
			return m
		},
		func(m storepkg.SecretAuditIndexMeta) storepkg.SecretAuditIndexMeta { m.LastLineOffset -= 7; return m },
	} {
		meta, _, err := st.GetSecretAuditIndexMeta(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := st.WriteSecretAuditIndex(ctx, meta, tamper(meta), nil); err != nil {
			t.Fatal(err)
		}
		rebuilds := secretAuditIndexRebuildsTotal.Value()
		f = reopenIndexedAuditFixture(t, st, dbPath)
		f.waitReady(t)
		if secretAuditIndexRebuildsTotal.Value() != rebuilds+1 {
			t.Fatalf("boot with tampered meta did not rebuild (rebuilds %d → %d)", rebuilds, secretAuditIndexRebuildsTotal.Value())
		}
		if ids := f.assertSamePages(t, "sb-a", SecretAuditQuery{Limit: 9}); len(ids) != 41 {
			t.Fatalf("after rebuild = %d ids", len(ids))
		}
		f.svc.CloseSecretAuditSink()
	}
	// A clean restart validates with one read and does not rebuild.
	rebuilds := secretAuditIndexRebuildsTotal.Value()
	f = reopenIndexedAuditFixture(t, st, dbPath)
	f.waitReady(t)
	if secretAuditIndexRebuildsTotal.Value() != rebuilds {
		t.Fatal("clean restart rebuilt a valid index")
	}
	f.assertSamePages(t, "sb-b", SecretAuditQuery{Limit: 13, Kind: secretAuditKindSecretOpen})
}

func TestSecretAuditIndexLagIsScannedThenCaughtUp(t *testing.T) {
	f := newIndexedAuditFixture(t)
	f.waitReady(t)
	base := time.Unix(1_800_000_000, 0).UTC()
	for i := range 20 {
		f.sink.Emit(indexedFixtureEvent("sb-lag", "inc", secretAuditKindSecretOpen, i, base.Add(time.Duration(i)*time.Second)))
	}
	if err := f.sink.Sync(); err != nil {
		t.Fatal(err)
	}
	f.waitReady(t)
	// Simulate a batch the hook never saw (crash between append and index).
	hook := f.sink.afterAppend
	f.sink.afterAppend = nil
	for i := 20; i < 30; i++ {
		f.sink.Emit(indexedFixtureEvent("sb-lag", "inc", secretAuditKindSecretOpen, i, base.Add(time.Duration(i)*time.Second)))
	}
	if err := f.sink.Sync(); err != nil {
		t.Fatal(err)
	}
	// Lagging but ready: the page must still be complete (tail scan).
	if ids := f.assertSamePages(t, "sb-lag", SecretAuditQuery{Limit: 8}); len(ids) != 30 {
		t.Fatalf("lagging read = %d ids, want 30", len(ids))
	}
	meta, _, _ := f.st.GetSecretAuditIndexMeta(context.Background())
	st, _ := os.Stat(f.sink.path)
	if meta.IndexedThrough >= st.Size() {
		t.Fatal("test setup: index did not lag")
	}
	// The next hooked append finds the gap, degrades, and the maintainer
	// re-covers everything from where the index stopped.
	f.sink.afterAppend = hook
	f.sink.Emit(indexedFixtureEvent("sb-lag", "inc", secretAuditKindSecretOpen, 30, base.Add(30*time.Second)))
	if err := f.sink.Sync(); err != nil {
		t.Fatal(err)
	}
	f.waitReady(t)
	if ids := f.assertSamePages(t, "sb-lag", SecretAuditQuery{Limit: 8}); len(ids) != 31 {
		t.Fatalf("caught-up read = %d ids, want 31", len(ids))
	}
}

func TestSecretAuditIndexCorruptEntryFallsBackAndRebuilds(t *testing.T) {
	f := newIndexedAuditFixture(t)
	f.waitReady(t)
	base := time.Unix(1_800_000_000, 0).UTC()
	f.emitMixedWorkload(t, base, 12)
	f.waitReady(t)
	ctx := context.Background()
	want, _ := pageAll(t, f.scan, "sb-c", SecretAuditQuery{Limit: 5})
	if len(want) != 13 {
		t.Fatalf("oracle = %v", want)
	}
	key := storepkg.SecretAuditIndexKey{SandboxID: "sb-c", IncarnationID: "inc-1"}
	_, chunks, _, err := f.st.ReadSecretAuditIndex(ctx, key, -1<<62)
	if err != nil || len(chunks) != 2 { // sb-c's list and the gap list
		t.Fatalf("read sb-c chunks = %d err=%v", len(chunks), err)
	}
	otherKey := storepkg.SecretAuditIndexKey{SandboxID: "sb-b", IncarnationID: "inc-1"}
	_, other, _, err := f.st.ReadSecretAuditIndex(ctx, otherKey, -1<<62)
	if err != nil || len(other) == 0 {
		t.Fatalf("read sb-b chunks: %v", err)
	}
	var own, theirs storepkg.SecretAuditIndexChunk
	for _, c := range chunks {
		if c.SecretAuditIndexKey == key {
			own = c
		}
	}
	for _, c := range other {
		if c.SecretAuditIndexKey == otherKey {
			theirs = c
		}
	}
	if own.N == 0 || theirs.N == 0 {
		t.Fatalf("test setup: own=%d theirs=%d entries", own.N, theirs.N)
	}
	// A blob that does not decode, then a list that decodes but names
	// another sandbox's records. The index must never silently drop or
	// mislabel: both serve this page from the file and force a rebuild.
	garbage := own
	garbage.Entries = []byte{0xff, 0xff}
	stolen := theirs
	stolen.SecretAuditIndexKey = key
	stolen.Seq = own.Seq
	for name, bad := range map[string]storepkg.SecretAuditIndexChunk{"undecodable blob": garbage, "mislabeled list": stolen} {
		meta, _, _ := f.st.GetSecretAuditIndexMeta(ctx)
		if err := f.st.WriteSecretAuditIndex(ctx, meta, meta, []storepkg.SecretAuditIndexChunk{bad}); err != nil {
			t.Fatal(err)
		}
		f.idx.mu.Lock()
		f.idx.meta = meta
		f.idx.mu.Unlock()
		rebuilds := secretAuditIndexRebuildsTotal.Value()
		fallback := secretAuditQueryScanFallbackTotal.Value()
		got, _, err := f.svc.ListSecretAuditLocal(ctx, "sb-c", SecretAuditQuery{Limit: 100})
		if err != nil || len(got) != 13 {
			t.Fatalf("%s: read = %d events err=%v", name, len(got), err)
		}
		if secretAuditQueryScanFallbackTotal.Value() == fallback {
			t.Fatalf("%s: did not fall back to the scan", name)
		}
		f.waitReady(t)
		if secretAuditIndexRebuildsTotal.Value() == rebuilds {
			t.Fatalf("%s: did not trigger a rebuild", name)
		}
		f.assertSamePages(t, "sb-c", SecretAuditQuery{Limit: 5})
	}
}

func TestSecretAuditIndexChainBreakDisablesIndexButReadsStillServe(t *testing.T) {
	f := newIndexedAuditFixture(t)
	f.waitReady(t)
	base := time.Unix(1_800_000_000, 0).UTC()
	for i := range 5 {
		f.sink.Emit(indexedFixtureEvent("sb-ok", "inc", secretAuditKindSecretOpen, i, base.Add(time.Duration(i)*time.Second)))
	}
	if err := f.sink.Sync(); err != nil {
		t.Fatal(err)
	}
	f.waitReady(t)
	// A record appended behind the writer's back with a hash that does not
	// link: the index must refuse to describe a broken chain.
	forged := indexedFixtureEvent("sb-forged", "inc", secretAuditKindSecretOpen, 0, base.Add(time.Hour))
	auditlog.LinkEvent(strings.Repeat("a", 64), &forged)
	line, _ := jsonMarshalForTest(forged)
	fh, err := os.OpenFile(f.sink.path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fh.Write(append(line, '\n')); err != nil {
		t.Fatal(err)
	}
	_ = fh.Close()
	breaks := secretAuditIndexChainBreaks.Value()
	f.sink.Emit(indexedFixtureEvent("sb-ok", "inc", secretAuditKindSecretOpen, 5, base.Add(5*time.Second)))
	if err := f.sink.Sync(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for secretAuditIndexChainBreaks.Value() == breaks {
		if time.Now().After(deadline) {
			t.Fatal("chain break was not detected")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if f.idx.isReady() || !f.idx.broken.Load() {
		t.Fatal("index must stay disabled after a chain break")
	}
	// The forged record is self-consistent: only the chain exposes it. Once
	// the chain is known broken, no local read is served — as before, when
	// every read re-verified the chain and would have failed here too.
	for _, sb := range []string{"sb-ok", "sb-forged"} {
		if _, _, err := f.svc.ListSecretAuditLocal(context.Background(), sb, SecretAuditQuery{}); !errors.Is(err, ErrSecretAuditChainBroken) {
			t.Fatalf("read of %s after chain break err = %v", sb, err)
		}
	}
	report, err := f.svc.VerifySecretAuditChain(context.Background())
	if err != nil || report.OK || !strings.Contains(report.Error, "prev_hash mismatch") {
		t.Fatalf("verification of a broken chain = %+v err=%v", report, err)
	}
	// The maintainer does not retry a broken chain.
	f.idx.wake()
	time.Sleep(50 * time.Millisecond)
	if f.idx.isReady() {
		t.Fatal("broken index came back without a restart")
	}
}

func TestSecretAuditIndexSurvivesTornTailRepairAndEmptyStart(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	st, err := storepkg.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	f := reopenIndexedAuditFixture(t, st, dbPath)
	f.waitReady(t) // no file yet: ready on the empty generation
	meta, ok, _ := st.GetSecretAuditIndexMeta(context.Background())
	if !ok || meta.Generation != secretAuditEmptyGeneration {
		t.Fatalf("empty-start meta = %+v ok=%v", meta, ok)
	}
	base := time.Unix(1_700_000_000, 0).UTC() // in the past: the repair marker sorts last
	for i := range 4 {
		f.sink.Emit(indexedFixtureEvent("sb-t", "inc", secretAuditKindSecretOpen, i, base.Add(time.Duration(i)*time.Second)))
	}
	if err := f.sink.Sync(); err != nil {
		t.Fatal(err)
	}
	f.waitReady(t) // the first append pinned the real generation
	f.assertSamePages(t, "sb-t", SecretAuditQuery{Limit: 3})
	f.svc.CloseSecretAuditSink()

	// Crash mid-append: an unterminated partial record after the indexed end.
	fh, err := os.OpenFile(f.sink.path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fh.WriteString(`{"time":"2026-01-01T00:00:00Z","sandbox_id":"sb-t","event_id":"torn`); err != nil {
		t.Fatal(err)
	}
	_ = fh.Close()
	rebuilds := secretAuditIndexRebuildsTotal.Value()
	f = reopenIndexedAuditFixture(t, st, dbPath)
	f.waitReady(t)
	if secretAuditIndexRebuildsTotal.Value() != rebuilds {
		t.Fatal("torn-tail repair should not invalidate the index (the tear was never indexed)")
	}
	ids := f.assertSamePages(t, "sb-t", SecretAuditQuery{Limit: 2})
	if len(ids) != 5 || ids[4] == "" {
		t.Fatalf("after torn-tail repair = %v (want 4 events + torn_tail marker)", ids)
	}
	events, _, err := f.svc.ListSecretAuditLocal(context.Background(), "sb-t", SecretAuditQuery{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if last := events[len(events)-1]; last.Reason != secretAuditReasonTornTail {
		t.Fatalf("torn-tail marker not surfaced: %+v", last)
	}
}

func TestSecretAuditIndexDisabledOrStorelessScans(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "state.db")
	st, err := storepkg.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	off := &Service{cfg: config.Config{DBPath: dbPath, AuditIndexEnabled: false}, store: st}
	t.Cleanup(off.CloseSecretAuditSink)
	sink := off.secretAuditSink().(*fileAuditSink)
	if off.secretAuditIndex != nil || sink.afterAppend != nil || sink.onPruneShift != nil {
		t.Fatal("index wired while disabled")
	}
	sink.Emit(indexedFixtureEvent("sb", "inc", secretAuditKindSecretOpen, 0, time.Now().UTC()))
	if err := sink.Sync(); err != nil {
		t.Fatal(err)
	}
	fallback := secretAuditQueryScanFallbackTotal.Value()
	if events, _, err := off.ListSecretAuditLocal(context.Background(), "sb", SecretAuditQuery{}); err != nil || len(events) != 1 {
		t.Fatalf("disabled-index read = %v, %v", events, err)
	}
	if secretAuditQueryScanFallbackTotal.Value() != fallback+1 {
		t.Fatal("disabled index did not count as a scan")
	}
	if _, ok, _ := st.GetSecretAuditIndexMeta(context.Background()); ok {
		t.Fatal("disabled index wrote meta")
	}
	// Nil indexer methods are safe no-ops.
	var nilIdx *secretAuditIndexer
	nilIdx.Close()
	nilIdx.onAppended(nil)
	nilIdx.onPruned(secretAuditPruneShift{})
	nilIdx.reportCorrupt(nil)
	if nilIdx.isReady() {
		t.Fatal("nil index ready")
	}
}

func TestSecretAuditQueryBusyFailsFastInsteadOfQueueing(t *testing.T) {
	held := cap(secretAuditLocalQuerySlots)
	for range held {
		secretAuditLocalQuerySlots <- struct{}{}
	}
	defer func() {
		for range held {
			<-secretAuditLocalQuerySlots
		}
	}()
	svc := &Service{cfg: config.Config{DBPath: filepath.Join(t.TempDir(), "state.db")}}
	t.Cleanup(svc.CloseSecretAuditSink)
	busy := secretAuditQueryBusyTotal.Value()
	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, err := svc.ListSecretAuditLocal(ctx, "sb", SecretAuditQuery{})
	if !errors.Is(err, ErrSecretAuditBusy) {
		t.Fatalf("saturated read err = %v, want ErrSecretAuditBusy", err)
	}
	if waited := time.Since(started); waited > time.Second {
		t.Fatalf("saturated read waited %v; it must fail fast, not queue to the deadline", waited)
	}
	if secretAuditQueryBusyTotal.Value() != busy+1 {
		t.Fatal("busy rejection not counted")
	}
	// A caller whose context is already gone gets its own error, as before.
	gone, cancelGone := context.WithCancel(context.Background())
	cancelGone()
	if _, _, err := svc.ListSecretAuditLocal(gone, "sb", SecretAuditQuery{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled read err = %v", err)
	}
}

func TestVerifySecretAuditChainOnDemand(t *testing.T) {
	f := newIndexedAuditFixture(t)
	f.waitReady(t)
	// Nothing written yet: trivially verified.
	report, err := f.svc.VerifySecretAuditChain(context.Background())
	if err != nil || !report.OK || report.Records != 0 {
		t.Fatalf("empty verification = %+v err=%v", report, err)
	}
	base := time.Unix(1_800_000_000, 0).UTC()
	f.emitMixedWorkload(t, base, 10)
	f.waitReady(t)
	report, err = f.svc.VerifySecretAuditChain(context.Background())
	if err != nil || !report.OK || report.Records != 31 || !report.WriterTipMatches || !report.IndexReady || report.Generation == "" || report.Bytes == 0 {
		t.Fatalf("verification = %+v err=%v", report, err)
	}
	head, _ := f.sink.chainTip()
	if report.Head != head {
		t.Fatalf("verified head %q != writer tip %q", report.Head, head)
	}
	if secretAuditChainVerifyOK.Value() != 1 || secretAuditChainVerifiedUnix.Value() == 0 {
		t.Fatal("verification metrics not updated")
	}
	// Only one verification runs at a time per node.
	secretAuditVerifyMu.Lock()
	_, err = f.svc.VerifySecretAuditChain(context.Background())
	secretAuditVerifyMu.Unlock()
	if !errors.Is(err, ErrSecretAuditBusy) {
		t.Fatalf("concurrent verification err = %v", err)
	}
	// Flip one byte of one record's payload: the chain no longer verifies,
	// even though every page read that does not touch it still succeeds.
	raw, err := os.ReadFile(f.sink.path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Replace(raw, []byte(`"event_id":"sb-b-egress-000"`), []byte(`"event_id":"sb-b-egress-00X"`), 1)
	if bytes.Equal(tampered, raw) {
		t.Fatal("test setup: record not found")
	}
	if err := os.WriteFile(f.sink.path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	report, err = f.svc.VerifySecretAuditChain(context.Background())
	if err != nil || report.OK || !strings.Contains(report.Error, "event_hash mismatch") {
		t.Fatalf("tampered verification = %+v err=%v", report, err)
	}
	if secretAuditChainVerifyOK.Value() != 0 {
		t.Fatal("failed verification left the ok metric at 1")
	}
	if _, _, err := f.svc.ListSecretAuditLocal(context.Background(), "sb-b", SecretAuditQuery{Kind: secretAuditKindEgress}); err == nil || !strings.Contains(err.Error(), "integrity verification") {
		t.Fatalf("read of tampered record err = %v", err)
	}
	if _, _, err := f.svc.ListSecretAuditLocal(context.Background(), "sb-a", SecretAuditQuery{}); err != nil {
		t.Fatalf("read of untouched records after tamper: %v", err)
	}
	if _, err := (*Service)(nil).VerifySecretAuditChain(context.Background()); err == nil {
		t.Fatal("nil service verified")
	}
	none := &Service{secretAudit: unavailableSecretAuditSink{}}
	if _, err := none.VerifySecretAuditChain(nil); err == nil {
		t.Fatal("unconfigured sink verified")
	}
}

func TestSecretAuditIndexKeyAndKindClassification(t *testing.T) {
	if key, ok := secretAuditIndexKeyFor(SecretAuditEvent{SandboxID: "sb", IncarnationID: "i", Kind: secretAuditKindEgress}); !ok || key != (storepkg.SecretAuditIndexKey{SandboxID: "sb", IncarnationID: "i"}) {
		t.Fatalf("event key = %+v ok=%v", key, ok)
	}
	if key, ok := secretAuditIndexKeyFor(SecretAuditEvent{SandboxID: "sb", Result: secretAuditResultGap}); !ok || key != (storepkg.SecretAuditIndexKey{}) {
		t.Fatalf("gap key = %+v ok=%v", key, ok)
	}
	if _, ok := secretAuditIndexKeyFor(SecretAuditEvent{Kind: secretAuditKindRetentionCheckpoint}); ok {
		t.Fatal("checkpoint indexed")
	}
	for kind, want := range map[string]byte{
		secretAuditKindSecretOpen:          auditlog.IndexKindSecretOpen,
		secretAuditKindEgress:              auditlog.IndexKindEgress,
		secretAuditKindGap:                 auditlog.IndexKindGap,
		secretAuditKindRetentionCheckpoint: auditlog.IndexKindRetentionCheckpoint,
		"future":                           auditlog.IndexKindOther,
	} {
		if got := secretAuditIndexKind(SecretAuditEvent{Kind: kind}); got != want {
			t.Fatalf("kind %q = %d, want %d", kind, got, want)
		}
	}
	if secretAuditIndexKind(SecretAuditEvent{Kind: secretAuditKindEgress, Result: secretAuditResultGap}) != auditlog.IndexKindGap {
		t.Fatal("gap result must classify as gap")
	}
	if secretAuditIndexKindFilter("future") != auditlog.IndexKindOther || secretAuditIndexKindFilter(secretAuditKindEgress) != auditlog.IndexKindEgress {
		t.Fatal("kind filter mapping")
	}
}

func jsonMarshalForTest(ev SecretAuditEvent) ([]byte, error) {
	return json.Marshal(ev)
}

func TestSecretAuditIndexHelperErrorPaths(t *testing.T) {
	dir := t.TempDir()
	// A directory where the file should be: open succeeds, generation fails.
	if _, _, _, err := openSecretAuditGeneration(dir); err == nil {
		t.Fatal("generation of a directory succeeded")
	}
	if _, _, _, err := openSecretAuditGeneration(filepath.Join(dir, "missing")); !os.IsNotExist(err) {
		t.Fatalf("missing file err = %v", err)
	}
	path := filepath.Join(dir, "secrets.jsonl")
	record := `{"time":"2026-01-01T00:00:00Z","sandbox_id":"sb","event_id":"e1","result":"success","prev_hash":"0","event_hash":"abc"}` + "\n"
	if err := os.WriteFile(path, []byte(record+"   \n"+record), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	n := int64(len(record))
	for name, meta := range map[string]storepkg.SecretAuditIndexMeta{
		"nothing indexed":  {IndexedThrough: 0},
		"matching hash":    {IndexedThrough: n, LastLineOffset: 0, LastEventHash: "abc"},
		"trailing blank":   {IndexedThrough: n + 4, LastLineOffset: 0, LastEventHash: "abc"},
		"wrong hash":       {IndexedThrough: n, LastLineOffset: 0, LastEventHash: "zzz"},
		"negative length":  {IndexedThrough: 5, LastLineOffset: 10, LastEventHash: "abc"},
		"past end of file": {IndexedThrough: 10 * n, LastLineOffset: 9 * n, LastEventHash: "abc"},
		"mid-record":       {IndexedThrough: n, LastLineOffset: 3, LastEventHash: "abc"},
		"oversized":        {IndexedThrough: secretAuditMaxLineBytes + 10, LastLineOffset: 0, LastEventHash: "abc"},
	} {
		want := name == "nothing indexed" || name == "matching hash" || name == "trailing blank"
		if got := secretAuditIndexLastLineMatches(f, meta); got != want {
			t.Fatalf("%s: matches = %v, want %v", name, got, want)
		}
	}
	// Reading a slice: an interior blank line is skipped (coverage ends on
	// the last record); a trailing blank is folded into the preceding record
	// so coverage still ends on a record boundary.
	lines, err := readSecretAuditLinesBetween(f, 0, 2*n+4, 1<<20)
	if err != nil || len(lines) != 2 || lines[0].length != n || lines[1].offset != n+4 || lines[1].end() != 2*n+4 {
		t.Fatalf("lines = %d err=%v", len(lines), err)
	}
	if lines, err := readSecretAuditLinesBetween(f, 0, n+4, 1<<20); err != nil || len(lines) != 1 || lines[0].length != n+4 {
		t.Fatalf("trailing blank fold: lines = %d err=%v", len(lines), err)
	}
	if lines, err := readSecretAuditLinesBetween(f, 2*n+4, 2*n+4, 1<<20); err != nil || len(lines) != 0 {
		t.Fatalf("empty range = %+v err=%v", lines, err)
	}
	// An unterminated tail is left alone; malformed complete records fail.
	if err := os.WriteFile(path, []byte(record+`{"partial`), 0o600); err != nil {
		t.Fatal(err)
	}
	if lines, err := readSecretAuditLinesBetween(f, 0, n+9, 1<<20); err != nil || len(lines) != 1 {
		t.Fatalf("torn tail lines = %+v err=%v", lines, err)
	}
	if err := os.WriteFile(path, []byte("not-json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSecretAuditLinesBetween(f, 0, 9, 1<<20); err == nil {
		t.Fatal("malformed record indexed")
	}
	if err := os.WriteFile(path, append(bytes.Repeat([]byte("x"), secretAuditMaxLineBytes+1), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSecretAuditLinesBetween(f, 0, secretAuditMaxLineBytes+2, 1<<20); err == nil {
		t.Fatal("oversized record indexed")
	}

	// lookup on a not-ready index says so without touching the store.
	idx := newSecretAuditIndexer(nil, nil, nil)
	if _, _, ok, err := idx.lookup(context.Background(), storepkg.SecretAuditIndexKey{SandboxID: "sb"}, 0); ok || err != nil {
		t.Fatalf("not-ready lookup ok=%v err=%v", ok, err)
	}
	// A closed store makes the maintainer fail and back off, not spin.
	dbPath := filepath.Join(t.TempDir(), "state.db")
	st, err := storepkg.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	f2 := reopenIndexedAuditFixture(t, st, dbPath)
	f2.waitReady(t)
	f2.sink.Emit(indexedFixtureEvent("sb", "inc", secretAuditKindSecretOpen, 0, time.Now().UTC()))
	if err := f2.sink.Sync(); err != nil {
		t.Fatal(err)
	}
	f2.waitReady(t)
	_ = st.Close()
	slept := make(chan time.Duration, 4)
	f2.idx.testSleep = func(d time.Duration) {
		select {
		case slept <- d:
		default:
		}
		time.Sleep(10 * time.Millisecond) // keep the retry loop from spinning hot
	}
	f2.sink.Emit(indexedFixtureEvent("sb", "inc", secretAuditKindSecretOpen, 1, time.Now().UTC()))
	_ = f2.sink.Sync()
	select {
	case d := <-slept:
		if d != secretAuditIndexRetryMin {
			t.Fatalf("first retry delay = %v", d)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("maintainer did not back off after a store failure")
	}
	if f2.idx.isReady() {
		t.Fatal("index ready with a closed store")
	}
	// Reads still work: the scan does not need the store.
	if events, _, err := f2.svc.ListSecretAuditLocal(context.Background(), "sb", SecretAuditQuery{}); err != nil || len(events) != 2 {
		t.Fatalf("scan with closed store = %d events err=%v", len(events), err)
	}
	f2.svc.CloseSecretAuditSink()
	// Shift / append hooks after Close are no-ops.
	f2.idx.onPruned(secretAuditPruneShift{exact: true})
	f2.idx.onAppended([]secretAuditIndexedLine{{length: 1}})
}
