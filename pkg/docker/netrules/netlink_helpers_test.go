package netrules

import (
	"errors"
	"fmt"
	"syscall"
	"testing"
)

func TestIsNetlinkNotExist(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "enoent", err: syscall.ENOENT, want: true},
		{name: "wrapped_enoent", err: fmt.Errorf("wrap: %w", syscall.ENOENT), want: true},
		{name: "no_such_file", err: errors.New("No Such File"), want: true},
		{name: "no_such_file_or_directory", err: errors.New("open: no such file or directory"), want: true},
		{name: "other", err: errors.New("permission denied"), want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isNetlinkNotExist(tc.err); got != tc.want {
				t.Fatalf("isNetlinkNotExist(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestContainsFoldAndEqualFoldASCII(t *testing.T) {
	t.Parallel()
	if !containsFold("AbC", "") {
		t.Fatal("empty substr should match")
	}
	if containsFold("ab", "abc") {
		t.Fatal("shorter haystack must not match")
	}
	if !containsFold("xxNo Such Fileyy", "no such file") {
		t.Fatal("case-insensitive substring miss")
	}
	if equalFoldASCII("ab", "abc") {
		t.Fatal("length mismatch must be false")
	}
	if equalFoldASCII("aB", "Ac") {
		t.Fatal("unequal after fold")
	}
	if !equalFoldASCII("AbC", "aBc") {
		t.Fatal("fold equality failed")
	}
}
