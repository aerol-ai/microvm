package wasm

import (
	"io/fs"
	"testing"
)

func TestSharedModes(t *testing.T) {
	t.Cleanup(func() { sharedWithGroup.Store(false) })
	if sharedFileMode(0o600) != 0o600 || sharedDirMode(0o700) != 0o700 {
		t.Fatal("modes changed with sharing off")
	}
	ShareFilesWithGroup()
	for _, tc := range []struct{ in, want fs.FileMode }{{0o600, 0o660}, {0o644, 0o664}, {0o400, 0o440}, {0o200, 0o220}} {
		if got := sharedFileMode(tc.in); got != tc.want {
			t.Errorf("file %o -> %o, want %o", tc.in, got, tc.want)
		}
	}
	if got := sharedDirMode(0o700); got != 0o770 {
		t.Errorf("dir 0700 -> %o", got)
	}
}
