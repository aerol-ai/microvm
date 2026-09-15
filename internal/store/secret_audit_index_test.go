package store

import (
	"context"
	"errors"
	"fmt"
	"math"
	"testing"

	"github.com/aerol-ai/microvm/pkg/auditlog"
)

func encodeIndexChunk(t *testing.T, key SecretAuditIndexKey, seq int64, entries ...auditlog.IndexEntry) SecretAuditIndexChunk {
	t.Helper()
	c, err := NewSecretAuditIndexChunk(key, seq, entries)
	if err != nil || c.N != len(entries) {
		t.Fatalf("chunk encode: n=%d want %d err=%v", c.N, len(entries), err)
	}
	return c
}

func decodeChunks(t *testing.T, chunks []SecretAuditIndexChunk) map[SecretAuditIndexKey][]auditlog.IndexEntry {
	t.Helper()
	out := map[SecretAuditIndexKey][]auditlog.IndexEntry{}
	for _, c := range chunks {
		entries, err := c.Decode()
		if err != nil {
			t.Fatalf("decode %+v: %v", c.SecretAuditIndexKey, err)
		}
		out[c.SecretAuditIndexKey] = append(out[c.SecretAuditIndexKey], entries...)
	}
	return out
}

func TestSecretAuditIndexMetaWriteIsOptimistic(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	if _, ok, err := st.GetSecretAuditIndexMeta(ctx); err != nil || ok {
		t.Fatalf("fresh meta ok=%v err=%v", ok, err)
	}
	if err := st.ResetSecretAuditIndex(ctx, SecretAuditIndexMeta{}); err == nil {
		t.Fatal("reset without generation accepted")
	}
	base := SecretAuditIndexMeta{Generation: "g1", LastEventHash: auditlog.GenesisPrevHash}
	if err := st.ResetSecretAuditIndex(ctx, base); err != nil {
		t.Fatal(err)
	}
	key := SecretAuditIndexKey{SandboxID: "sb-a", IncarnationID: "inc-1"}
	first := encodeIndexChunk(t, key, 0, auditlog.IndexEntry{Offset: 0, Length: 100, TimeNano: 10, Kind: auditlog.IndexKindSecretOpen})
	next := SecretAuditIndexMeta{Generation: "g1", IndexedThrough: 100, LastLineOffset: 0, LastEventHash: "h1"}
	if err := st.WriteSecretAuditIndex(ctx, base, next, []SecretAuditIndexChunk{first}); err != nil {
		t.Fatal(err)
	}
	// Same expectation again: the index has moved, so the write must refuse.
	if err := st.WriteSecretAuditIndex(ctx, base, next, nil); !errors.Is(err, ErrSecretAuditIndexStale) {
		t.Fatalf("stale write err = %v", err)
	}
	if err := st.WriteSecretAuditIndex(ctx, next, SecretAuditIndexMeta{Generation: "g2", IndexedThrough: 1}, nil); err != nil {
		t.Fatal(err)
	}
	if err := st.WriteSecretAuditIndex(ctx, SecretAuditIndexMeta{Generation: "g2", IndexedThrough: 1}, SecretAuditIndexMeta{Generation: "g2", IndexedThrough: 2, AllowBreak: true}, nil); err != nil {
		t.Fatal(err)
	}
	got, ok, err := st.GetSecretAuditIndexMeta(ctx)
	if err != nil || !ok || got.Generation != "g2" || got.IndexedThrough != 2 || !got.AllowBreak {
		t.Fatalf("meta = %+v ok=%v err=%v", got, ok, err)
	}
	if err := st.WriteSecretAuditIndex(ctx, got, got, []SecretAuditIndexChunk{{SecretAuditIndexKey: key, Seq: 9}}); err == nil {
		t.Fatal("empty chunk accepted")
	}
	if err := st.WriteSecretAuditIndex(ctx, got, SecretAuditIndexMeta{}, nil); err == nil {
		t.Fatal("write without generation accepted")
	}
	// Reset drops every chunk.
	if err := st.ResetSecretAuditIndex(ctx, SecretAuditIndexMeta{Generation: "g3"}); err != nil {
		t.Fatal(err)
	}
	if chunks, entries, err := st.SecretAuditIndexStats(ctx); err != nil || chunks != 0 || entries != 0 {
		t.Fatalf("after reset chunks=%d entries=%d err=%v", chunks, entries, err)
	}
}

func TestSecretAuditIndexReadScopesAndIncludesGapMarkers(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	meta := SecretAuditIndexMeta{Generation: "g", LastEventHash: auditlog.GenesisPrevHash}
	if err := st.ResetSecretAuditIndex(ctx, meta); err != nil {
		t.Fatal(err)
	}
	a1 := SecretAuditIndexKey{SandboxID: "sb-a", IncarnationID: "inc-1"}
	a2 := SecretAuditIndexKey{SandboxID: "sb-a", IncarnationID: "inc-2"}
	b := SecretAuditIndexKey{SandboxID: "sb-b", IncarnationID: "inc-1"}
	gap := SecretAuditIndexKey{}
	chunks := []SecretAuditIndexChunk{
		encodeIndexChunk(t, a1, 0, auditlog.IndexEntry{Offset: 0, Length: 10, TimeNano: 100}, auditlog.IndexEntry{Offset: 10, Length: 10, TimeNano: 200}),
		encodeIndexChunk(t, a1, 1, auditlog.IndexEntry{Offset: 20, Length: 10, TimeNano: 300}),
		encodeIndexChunk(t, a2, 0, auditlog.IndexEntry{Offset: 30, Length: 10, TimeNano: 400}),
		encodeIndexChunk(t, b, 0, auditlog.IndexEntry{Offset: 40, Length: 10, TimeNano: 500}),
		encodeIndexChunk(t, gap, 0, auditlog.IndexEntry{Offset: 50, Length: 10, TimeNano: 150, Kind: auditlog.IndexKindGap}),
	}
	next := SecretAuditIndexMeta{Generation: "g", IndexedThrough: 60, LastLineOffset: 50, LastEventHash: "h"}
	if err := st.WriteSecretAuditIndex(ctx, meta, next, chunks); err != nil {
		t.Fatal(err)
	}

	if _, _, _, err := st.ReadSecretAuditIndex(ctx, SecretAuditIndexKey{}, math.MinInt64); err == nil {
		t.Fatal("read without sandbox id accepted")
	}
	// One lifecycle: both its chunks in seq order, plus the gap list.
	gotMeta, got, ok, err := st.ReadSecretAuditIndex(ctx, a1, math.MinInt64)
	if err != nil || !ok || gotMeta.IndexedThrough != 60 {
		t.Fatalf("read a1: meta=%+v ok=%v err=%v", gotMeta, ok, err)
	}
	lists := decodeChunks(t, got)
	if len(lists[a1]) != 3 || len(lists[gap]) != 1 || len(lists) != 2 {
		t.Fatalf("a1 lists = %+v", lists)
	}
	if lists[a1][0].Offset != 0 || lists[a1][2].Offset != 20 {
		t.Fatalf("a1 chunk order wrong: %+v", lists[a1])
	}
	// Any lifecycle of the sandbox.
	_, got, _, err = st.ReadSecretAuditIndex(ctx, SecretAuditIndexKey{SandboxID: "sb-a"}, math.MinInt64)
	if err != nil {
		t.Fatal(err)
	}
	lists = decodeChunks(t, got)
	if len(lists[a1]) != 3 || len(lists[a2]) != 1 || len(lists[gap]) != 1 || len(lists[b]) != 0 {
		t.Fatalf("sb-a any-incarnation lists = %+v", lists)
	}
	// A cursor past a chunk's newest entry skips it in SQL; gap lists too.
	_, got, _, err = st.ReadSecretAuditIndex(ctx, a1, 250)
	if err != nil {
		t.Fatal(err)
	}
	lists = decodeChunks(t, got)
	if len(lists[a1]) != 1 || lists[a1][0].TimeNano != 300 || len(lists[gap]) != 0 {
		t.Fatalf("cursor-filtered lists = %+v", lists)
	}
	// Unknown sandbox: only the gap list, and the meta still describes coverage.
	gotMeta, got, ok, err = st.ReadSecretAuditIndex(ctx, SecretAuditIndexKey{SandboxID: "nope"}, math.MinInt64)
	if err != nil || !ok || gotMeta.Generation != "g" {
		t.Fatalf("unknown sandbox: meta=%+v ok=%v err=%v", gotMeta, ok, err)
	}
	if lists = decodeChunks(t, got); len(lists) != 1 || len(lists[gap]) != 1 {
		t.Fatalf("unknown sandbox lists = %+v", lists)
	}
	// Before any build, a read reports no index rather than an empty one.
	fresh := newTestStore(t)
	if _, _, ok, err := fresh.ReadSecretAuditIndex(ctx, a1, math.MinInt64); err != nil || ok {
		t.Fatalf("fresh read ok=%v err=%v", ok, err)
	}

	tails, err := st.LatestSecretAuditIndexChunks(ctx, []SecretAuditIndexKey{a1, b, {SandboxID: "nope"}})
	if err != nil {
		t.Fatal(err)
	}
	if tails[a1].Seq != 1 || tails[a1].N != 1 || tails[b].Seq != 0 || len(tails) != 2 {
		t.Fatalf("tails = %+v", tails)
	}
	if empty, err := st.LatestSecretAuditIndexChunks(ctx, nil); err != nil || len(empty) != 0 {
		t.Fatalf("no-key tails = %+v err=%v", empty, err)
	}
}

func TestSecretAuditIndexShiftAfterRetentionPrefixDrop(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	meta := SecretAuditIndexMeta{Generation: "g1", LastEventHash: auditlog.GenesisPrevHash}
	if err := st.ResetSecretAuditIndex(ctx, meta); err != nil {
		t.Fatal(err)
	}
	old := SecretAuditIndexKey{SandboxID: "sb-old", IncarnationID: "i"}
	span := SecretAuditIndexKey{SandboxID: "sb-span", IncarnationID: "i"}
	young := SecretAuditIndexKey{SandboxID: "sb-young", IncarnationID: "i"}
	chunks := []SecretAuditIndexChunk{
		// Entirely inside the dropped prefix [0, 300).
		encodeIndexChunk(t, old, 0, auditlog.IndexEntry{Offset: 0, Length: 100, TimeNano: 1}, auditlog.IndexEntry{Offset: 100, Length: 100, TimeNano: 2}),
		// Straddles the floor: first entry dropped, next two kept.
		encodeIndexChunk(t, span, 0, auditlog.IndexEntry{Offset: 200, Length: 100, TimeNano: 3}, auditlog.IndexEntry{Offset: 300, Length: 100, TimeNano: 9}, auditlog.IndexEntry{Offset: 400, Length: 100, TimeNano: 4}),
		encodeIndexChunk(t, span, 1, auditlog.IndexEntry{Offset: 600, Length: 100, TimeNano: 5}),
		// Entirely kept.
		encodeIndexChunk(t, young, 0, auditlog.IndexEntry{Offset: 500, Length: 100, TimeNano: 6}),
	}
	next := SecretAuditIndexMeta{Generation: "g1", IndexedThrough: 700, LastLineOffset: 600, LastEventHash: "h6"}
	if err := st.WriteSecretAuditIndex(ctx, meta, next, chunks); err != nil {
		t.Fatal(err)
	}
	// Retention dropped 300 bytes and prepended a 50-byte checkpoint.
	const floor, delta = 300, 50 - 300
	shifted := SecretAuditIndexMeta{Generation: "g2", IndexedThrough: 700 + delta, LastLineOffset: 600 + delta, LastEventHash: "h6"}
	if err := st.ShiftSecretAuditIndex(ctx, floor, delta, SecretAuditIndexMeta{}); err == nil {
		t.Fatal("shift without generation accepted")
	}
	if err := st.ShiftSecretAuditIndex(ctx, floor, delta, shifted); err != nil {
		t.Fatal(err)
	}
	gotMeta, got, ok, err := st.ReadSecretAuditIndex(ctx, span, math.MinInt64)
	if err != nil || !ok || gotMeta != mergeUpdated(gotMeta, shifted) {
		t.Fatalf("meta after shift = %+v ok=%v err=%v", gotMeta, ok, err)
	}
	lists := decodeChunks(t, got)
	want := []auditlog.IndexEntry{{Offset: 300 + delta, Length: 100, TimeNano: 9}, {Offset: 400 + delta, Length: 100, TimeNano: 4}, {Offset: 600 + delta, Length: 100, TimeNano: 5}}
	if fmt.Sprint(lists[span]) != fmt.Sprint(want) {
		t.Fatalf("span after shift = %+v, want %+v", lists[span], want)
	}
	for _, c := range got {
		if c.SecretAuditIndexKey == span && c.Seq == 0 {
			if c.FirstOffset != 300+delta || c.LastOffset != 400+delta || c.MinTime != 4 || c.MaxTime != 9 || c.LastTime != 4 || c.N != 2 {
				t.Fatalf("trimmed chunk summary = %+v", c)
			}
		}
	}
	_, got, _, err = st.ReadSecretAuditIndex(ctx, old, math.MinInt64)
	if err != nil {
		t.Fatal(err)
	}
	if lists = decodeChunks(t, got); len(lists[old]) != 0 {
		t.Fatalf("pruned list survived: %+v", lists[old])
	}
	_, got, _, err = st.ReadSecretAuditIndex(ctx, young, math.MinInt64)
	if err != nil {
		t.Fatal(err)
	}
	if lists = decodeChunks(t, got); len(lists[young]) != 1 || lists[young][0].Offset != 500+delta {
		t.Fatalf("young list after shift = %+v", lists[young])
	}
	if chunks, entries, err := st.SecretAuditIndexStats(ctx); err != nil || chunks != 3 || entries != 4 {
		t.Fatalf("stats chunks=%d entries=%d err=%v", chunks, entries, err)
	}
	// A straddling chunk that loses every entry must not decode as corrupt.
	if err := st.ShiftSecretAuditIndex(ctx, 10_000, 0, shifted); err != nil {
		t.Fatal(err)
	}
	if chunks, _, err := st.SecretAuditIndexStats(ctx); err != nil || chunks != 0 {
		t.Fatalf("stats after full prune chunks=%d err=%v", chunks, err)
	}
	// Corrupt entries in a straddling chunk fail the shift instead of
	// silently producing a wrong index; the caller rebuilds.
	if err := st.WriteSecretAuditIndex(ctx, shifted, shifted, []SecretAuditIndexChunk{{SecretAuditIndexKey: span, Seq: 0, FirstOffset: 0, LastOffset: 10, N: 1, Entries: []byte{0xff}}}); err != nil {
		t.Fatal(err)
	}
	if err := st.ShiftSecretAuditIndex(ctx, 5, 0, shifted); err == nil {
		t.Fatal("corrupt straddling chunk shifted")
	}
}

func mergeUpdated(got, want SecretAuditIndexMeta) SecretAuditIndexMeta {
	want.UpdatedAt = got.UpdatedAt
	return want
}

func TestSecretAuditIndexChunkAppendUsesColumnsAsBase(t *testing.T) {
	key := SecretAuditIndexKey{SandboxID: "sb", IncarnationID: "i"}
	c, err := NewSecretAuditIndexChunk(key, 0, []auditlog.IndexEntry{{Offset: 1000, Length: 10, TimeNano: 50, Kind: 2}})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Append([]auditlog.IndexEntry{{Offset: 1010, Length: 20, TimeNano: 40}, {Offset: 1030, Length: 5, TimeNano: 60}}); err != nil {
		t.Fatal(err)
	}
	if c.FirstOffset != 1000 || c.LastOffset != 1030 || c.MinTime != 40 || c.MaxTime != 60 || c.LastTime != 60 || c.N != 3 {
		t.Fatalf("chunk = %+v", c)
	}
	got, err := c.Decode()
	if err != nil || len(got) != 3 || got[0].Offset != 1000 || got[1].Offset != 1010 || got[2].Offset != 1030 || got[0].Kind != 2 {
		t.Fatalf("decoded = %+v err=%v", got, err)
	}
	// Re-basing the row is enough: the blob is relative.
	c.FirstOffset -= 300
	c.LastOffset -= 300
	if got, _ = c.Decode(); got[2].Offset != 730 {
		t.Fatalf("rebased decode = %+v", got)
	}
	if err := c.Append([]auditlog.IndexEntry{{Offset: 10, Length: 1}}); err == nil {
		t.Fatal("entry before the chunk base accepted")
	}
	if err := c.Append([]auditlog.IndexEntry{{Offset: 730, Length: 1}}); err == nil {
		t.Fatal("entry at the last offset accepted")
	}
	c.N++ // column disagrees with the blob
	if _, err := c.Decode(); !errors.Is(err, auditlog.ErrIndexEntriesCorrupt) {
		t.Fatalf("n mismatch decode err = %v", err)
	}
	if empty, err := NewSecretAuditIndexChunk(key, 3, nil); err != nil || empty.N != 0 || empty.Seq != 3 {
		t.Fatalf("empty chunk = %+v err=%v", empty, err)
	}
}

func TestSecretAuditIndexStoreErrorsSurface(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	meta := SecretAuditIndexMeta{Generation: "g", LastEventHash: auditlog.GenesisPrevHash}
	if err := st.ResetSecretAuditIndex(ctx, meta); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if err := st.ResetSecretAuditIndex(ctx, meta); err == nil {
		t.Fatal("reset on a closed store succeeded")
	}
	if err := st.WriteSecretAuditIndex(ctx, meta, meta, nil); err == nil {
		t.Fatal("write on a closed store succeeded")
	}
	if err := st.ShiftSecretAuditIndex(ctx, 0, 0, meta); err == nil {
		t.Fatal("shift on a closed store succeeded")
	}
	if _, _, err := st.GetSecretAuditIndexMeta(ctx); err == nil {
		t.Fatal("meta read on a closed store succeeded")
	}
	if _, _, _, err := st.ReadSecretAuditIndex(ctx, SecretAuditIndexKey{SandboxID: "sb"}, 0); err == nil {
		t.Fatal("read on a closed store succeeded")
	}
	if _, err := st.LatestSecretAuditIndexChunks(ctx, []SecretAuditIndexKey{{SandboxID: "sb"}}); err == nil {
		t.Fatal("tail read on a closed store succeeded")
	}
	if _, _, err := st.SecretAuditIndexStats(ctx); err == nil {
		t.Fatal("stats on a closed store succeeded")
	}
}
