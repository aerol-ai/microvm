//go:build !linux

package xfsquota

import (
	"errors"
	"testing"
)

// Off Linux every call fails, so a create with the setting on fails
// instead of running without its limit.
func TestDiskQuotaNeedsLinux(t *testing.T) {
	q := Ops{}
	for name, err := range map[string]error{
		"Enforced": q.Enforced("/x"),
		"Assign":   q.Assign("/x", 1),
		"Limit":    q.Limit("/x", 1, 1),
	} {
		if !errors.Is(err, ErrNeedsLinux) {
			t.Errorf("%s = %v, want ErrNeedsLinux", name, err)
		}
	}
}

// InProject has nothing to read off Linux either.
func TestInProjectNeedsLinux(t *testing.T) {
	if ok, err := InProject("/x", 1); ok || !errors.Is(err, ErrNeedsLinux) {
		t.Fatalf("InProject = %v, %v", ok, err)
	}
}
