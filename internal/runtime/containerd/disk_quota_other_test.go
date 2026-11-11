//go:build !linux

package containerd

import (
	"errors"
	"testing"
)

// Off Linux every call fails, so a create with the setting on fails
// instead of running without its limit.
func TestDiskQuotaNeedsLinux(t *testing.T) {
	q := xfsProjectQuota{}
	for name, err := range map[string]error{
		"Enforced": q.Enforced("/x"),
		"Assign":   q.Assign("/x", 1),
		"Limit":    q.Limit("/x", 1, 1),
	} {
		if !errors.Is(err, errDiskQuotaNeedsLinux) {
			t.Errorf("%s = %v, want errDiskQuotaNeedsLinux", name, err)
		}
	}
}
