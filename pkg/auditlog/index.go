package auditlog

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// IndexEntry locates one record inside the local audit JSONL and carries
// just enough of it to page and filter without touching the file: the read
// path decides which lines a page needs from entries alone, then reads only
// those lines. Offsets are byte positions in the current file generation.
type IndexEntry struct {
	Offset   int64 // first byte of the record
	Length   int64 // bytes through the trailing newline
	TimeNano int64 // Event.Time as UnixNano
	Kind     byte  // IndexKind*; anything unclassified is IndexKindOther
}

// Index kind classes. Only decisive exclusions may use them: a filter for
// "egress" skips IndexKindSecretOpen entries but must still read
// IndexKindOther and IndexKindGap ones and decide on the record itself.
const (
	IndexKindOther byte = iota
	IndexKindSecretOpen
	IndexKindEgress
	IndexKindGap
	IndexKindRetentionCheckpoint
)

// ErrIndexEntriesCorrupt reports a posting list that does not decode. The
// index is derived data; the caller rebuilds it from the JSONL.
var ErrIndexEntriesCorrupt = errors.New("audit index entries are corrupt")

// AppendIndexEntries delta-encodes entries after prev. Within one posting
// list offsets are strictly increasing (file order) and times nearly so, so
// each entry costs a few bytes rather than the 25+ of a fixed layout — the
// index stays a small fraction of the log it describes. prev is the last
// entry already in buf; pass hasPrev=false for an empty list.
func AppendIndexEntries(buf []byte, prev IndexEntry, hasPrev bool, entries []IndexEntry) ([]byte, IndexEntry, error) {
	last := prev
	if !hasPrev {
		last = IndexEntry{}
	}
	for _, e := range entries {
		if e.Length <= 0 {
			return buf, last, fmt.Errorf("index entry at offset %d has length %d", e.Offset, e.Length)
		}
		if hasPrev && e.Offset <= last.Offset {
			return buf, last, fmt.Errorf("index entry offset %d is not after %d", e.Offset, last.Offset)
		}
		if !hasPrev && e.Offset < 0 {
			return buf, last, fmt.Errorf("index entry offset %d is negative", e.Offset)
		}
		buf = binary.AppendUvarint(buf, uint64(e.Offset-last.Offset))
		buf = binary.AppendUvarint(buf, uint64(e.Length))
		buf = binary.AppendVarint(buf, e.TimeNano-last.TimeNano)
		buf = append(buf, e.Kind)
		last = e
		hasPrev = true
	}
	return buf, last, nil
}

// DecodeIndexEntries is the inverse of AppendIndexEntries for a whole list.
func DecodeIndexEntries(buf []byte) ([]IndexEntry, error) {
	var out []IndexEntry
	var last IndexEntry
	for len(buf) > 0 {
		dOff, n := binary.Uvarint(buf)
		if n <= 0 {
			return nil, ErrIndexEntriesCorrupt
		}
		buf = buf[n:]
		length, n := binary.Uvarint(buf)
		if n <= 0 || length == 0 {
			return nil, ErrIndexEntriesCorrupt
		}
		buf = buf[n:]
		dTime, n := binary.Varint(buf)
		if n <= 0 {
			return nil, ErrIndexEntriesCorrupt
		}
		buf = buf[n:]
		if len(buf) == 0 {
			return nil, ErrIndexEntriesCorrupt
		}
		e := IndexEntry{
			Offset:   last.Offset + int64(dOff),
			Length:   int64(length),
			TimeNano: last.TimeNano + dTime,
			Kind:     buf[0],
		}
		buf = buf[1:]
		if len(out) > 0 && e.Offset <= last.Offset {
			return nil, ErrIndexEntriesCorrupt
		}
		out = append(out, e)
		last = e
	}
	return out, nil
}
