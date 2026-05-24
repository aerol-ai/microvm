package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestReadBypassMarkerMissingReadsFalse: first boot has no marker file
// — the safer default is "previous run had bypass off", so no rollback
// force-reconcile fires.
func TestReadBypassMarkerMissingReadsFalse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bypass_last_enabled")
	if readBypassMarker(path) {
		t.Fatalf("missing marker read as true; want false")
	}
}

// TestWriteThenReadBypassMarkerRoundTrip: each boolean value written
// must round-trip exactly. The marker is the only source of truth for
// the rollback decision; a flip in storage would silently misfire the
// force-reconcile pass.
func TestWriteThenReadBypassMarkerRoundTrip(t *testing.T) {
	for _, want := range []bool{true, false} {
		path := filepath.Join(t.TempDir(), "bypass_last_enabled")
		if err := writeBypassMarker(path, want); err != nil {
			t.Fatalf("writeBypassMarker(%v): %v", want, err)
		}
		if got := readBypassMarker(path); got != want {
			t.Fatalf("readBypassMarker = %v, want %v", got, want)
		}
	}
}

// TestWriteBypassMarkerOverwritesPriorValue: a write must replace any
// existing content. Operator toggling true→false→true must not leave
// stale state behind.
func TestWriteBypassMarkerOverwritesPriorValue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bypass_last_enabled")
	if err := writeBypassMarker(path, true); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := writeBypassMarker(path, false); err != nil {
		t.Fatalf("second write: %v", err)
	}
	if readBypassMarker(path) {
		t.Fatalf("read after true→false write reports true; rollback would not fire on subsequent flip")
	}
}

// TestWriteBypassMarkerAtomicViaTmpRename: the tmp-then-rename pattern
// must not leak the .tmp file on success — otherwise the next boot's
// `cat ${dir}/bypass_last_enabled.tmp` could mislead an operator.
func TestWriteBypassMarkerAtomicViaTmpRename(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bypass_last_enabled")
	if err := writeBypassMarker(path, true); err != nil {
		t.Fatalf("writeBypassMarker: %v", err)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("stat .tmp after success: err=%v (want IsNotExist)", err)
	}
}

// TestReadBypassMarkerTrimsTrailingNewline: writeBypassMarker appends
// a newline so an operator's `cat` is readable. readBypassMarker must
// tolerate that newline (and any incidental surrounding whitespace —
// e.g. if an operator hand-edits the marker for testing).
func TestReadBypassMarkerTrimsTrailingNewline(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bypass_last_enabled")
	cases := []struct {
		name    string
		content string
		want    bool
	}{
		{"newline_terminated_true", "true\n", true},
		{"untrimmed_true_with_spaces", " true \n", true},
		{"tab_padded_true", "\ttrue\t\n", true},
		{"plain_false_no_newline", "false", false},
		{"empty_file_reads_false", "", false},
		{"junk_value_reads_false", "yes\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(tc.content), 0o644); err != nil {
				t.Fatalf("seed marker: %v", err)
			}
			if got := readBypassMarker(path); got != tc.want {
				t.Fatalf("readBypassMarker(%q) = %v, want %v", tc.content, got, tc.want)
			}
		})
	}
}
