package models

import (
	"strings"
	"testing"
	"unicode"
)

// FuzzValidateSandboxID asserts the invariant the mount manager and per-sandbox
// state dirs rely on: any ID ValidateSandboxID accepts is a delimiter-safe path
// component (no separators, no "..", bounded length).
func FuzzValidateSandboxID(f *testing.F) {
	for _, s := range []string{"sb-0123456789abcdef", "../etc", "sb/x", "a", "", "sb..x", strings.Repeat("a", 200)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, id string) {
		if ValidateSandboxID(id) != nil {
			return // rejected — nothing to prove
		}
		if id == "" || len(id) > 128 {
			t.Fatalf("accepted out-of-range id %q", id)
		}
		for _, r := range id {
			ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_'
			if !ok {
				t.Fatalf("accepted id %q with unsafe rune %q", id, r)
			}
		}
		if strings.ContainsAny(id, `/\`) || strings.Contains(id, "..") {
			t.Fatalf("accepted traversal-capable id %q", id)
		}
	})
}

// FuzzValidateMountSource asserts the mount-source-injection invariant: any
// source validateSource accepts must not be option-shaped (leading '-') or
// carry control characters, for every mount type.
func FuzzValidateMountSource(f *testing.F) {
	for _, s := range []string{"s3://bucket", "user@host:/p", "-oProxyCommand=x @h:/", "remote:path", "host:/exp", "s3://-x", "\x00", "u@h:/x\n-o"} {
		f.Add(s)
	}
	types := []MountType{MountTypeS3, MountTypeNFS, MountTypeSSHFS, MountTypeRclone}
	f.Fuzz(func(t *testing.T, source string) {
		for _, mt := range types {
			if validateSource(mt, source) != nil {
				continue
			}
			// validateSource trims surrounding whitespace (incl. control-class
			// whitespace like \v) before validating, so assert against the
			// trimmed value it actually uses.
			trimmed := strings.TrimSpace(source)
			if strings.HasPrefix(trimmed, "-") {
				t.Fatalf("%s accepted option-shaped source %q", mt, source)
			}
			if strings.IndexFunc(trimmed, unicode.IsControl) >= 0 {
				t.Fatalf("%s accepted control-char source %q", mt, source)
			}
		}
	})
}
