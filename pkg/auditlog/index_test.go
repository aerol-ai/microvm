package auditlog

import (
	"errors"
	"math"
	"testing"
)

func TestIndexEntriesRoundTripIncludingBackwardTime(t *testing.T) {
	entries := []IndexEntry{
		{Offset: 0, Length: 120, TimeNano: 1_700_000_000_000_000_000, Kind: IndexKindSecretOpen},
		{Offset: 120, Length: 300, TimeNano: 1_700_000_000_000_000_500, Kind: IndexKindEgress},
		// Spill drains and worker ingest land older events after newer ones.
		{Offset: 420, Length: 90, TimeNano: 1_699_999_999_000_000_000, Kind: IndexKindGap},
		{Offset: 510, Length: 1, TimeNano: math.MaxInt64, Kind: IndexKindOther},
		{Offset: 511, Length: 7, TimeNano: math.MinInt64, Kind: IndexKindRetentionCheckpoint},
	}
	buf, last, err := AppendIndexEntries(nil, IndexEntry{}, false, entries[:2])
	if err != nil {
		t.Fatal(err)
	}
	if last != entries[1] {
		t.Fatalf("last = %+v, want %+v", last, entries[1])
	}
	buf, last, err = AppendIndexEntries(buf, last, true, entries[2:])
	if err != nil {
		t.Fatal(err)
	}
	if last != entries[4] {
		t.Fatalf("last = %+v", last)
	}
	got, err := DecodeIndexEntries(buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(entries) {
		t.Fatalf("decoded %d entries, want %d", len(got), len(entries))
	}
	for i := range entries {
		if got[i] != entries[i] {
			t.Fatalf("entry %d = %+v, want %+v", i, got[i], entries[i])
		}
	}
	// Realistic lists (steady append, ~300B lines, ms apart) must stay a
	// few bytes per entry — that is the whole reason for delta encoding.
	steady := make([]IndexEntry, 1000)
	for i := range steady {
		steady[i] = IndexEntry{Offset: int64(i) * 300, Length: 300, TimeNano: 1_700_000_000_000_000_000 + int64(i)*1_000_000, Kind: IndexKindEgress}
	}
	packed, _, err := AppendIndexEntries(nil, IndexEntry{}, false, steady)
	if err != nil {
		t.Fatal(err)
	}
	if per := float64(len(packed)) / float64(len(steady)); per > 10 {
		t.Fatalf("encoding is not compact: %.1f bytes per entry", per)
	}
	if empty, err := DecodeIndexEntries(nil); err != nil || len(empty) != 0 {
		t.Fatalf("empty decode = %v, %v", empty, err)
	}
}

func TestIndexEntriesRejectBadInput(t *testing.T) {
	if _, _, err := AppendIndexEntries(nil, IndexEntry{}, false, []IndexEntry{{Offset: 5, Length: 0}}); err == nil {
		t.Fatal("zero length accepted")
	}
	if _, _, err := AppendIndexEntries(nil, IndexEntry{}, false, []IndexEntry{{Offset: -1, Length: 1}}); err == nil {
		t.Fatal("negative offset accepted")
	}
	if _, _, err := AppendIndexEntries(nil, IndexEntry{Offset: 10, Length: 1}, true, []IndexEntry{{Offset: 10, Length: 1}}); err == nil {
		t.Fatal("non-increasing offset accepted")
	}
	buf, _, err := AppendIndexEntries(nil, IndexEntry{}, false, []IndexEntry{{Offset: 3, Length: 9, TimeNano: 42, Kind: 1}})
	if err != nil {
		t.Fatal(err)
	}
	for cut := 1; cut < len(buf); cut++ {
		if _, err := DecodeIndexEntries(buf[:cut]); !errors.Is(err, ErrIndexEntriesCorrupt) {
			t.Fatalf("truncated at %d: err = %v", cut, err)
		}
	}
	// A zero-length entry can never be produced, so it marks corruption.
	if _, err := DecodeIndexEntries([]byte{1, 0, 0, 0}); !errors.Is(err, ErrIndexEntriesCorrupt) {
		t.Fatalf("zero length decode err = %v", err)
	}
	// Two entries at the same offset (delta 0 after the first) are corrupt.
	if _, err := DecodeIndexEntries([]byte{3, 9, 0, 1, 0, 9, 0, 1}); !errors.Is(err, ErrIndexEntriesCorrupt) {
		t.Fatalf("repeated offset decode err = %v", err)
	}
}
