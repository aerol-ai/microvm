package auditlog

import "testing"

func TestCoverage97CorruptIndexAndEmptySpill(t *testing.T) {
	// A truncated uvarint is how a torn index page shows up. n <= 0 is the
	// corrupt-buffer return, not a short-but-valid entry.
	if _, err := DecodeIndexEntries([]byte{0x80}); err == nil {
		t.Fatal("truncated uvarint decoded")
	}
	if got := SpillFileIn(""); got != (SpillFile{}) {
		t.Fatalf("empty dir = %+v", got)
	}
}
