package netrules

import (
	"errors"
	"syscall"
)

// isNetlinkNotExist reports whether err means the rule (or object) is
// already gone. Shared by the linux netlink backend's Delete flush path
// and unit-tested off linux so Codecov sees it without CAP_NET_ADMIN.
func isNetlinkNotExist(err error) bool {
	return errors.Is(err, syscall.ENOENT) ||
		(err != nil && (containsFold(err.Error(), "no such file") ||
			containsFold(err.Error(), "no such file or directory")))
}

func containsFold(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i+len(substr) <= len(s); i++ {
		if equalFoldASCII(s[i:i+len(substr)], substr) {
			return true
		}
	}
	return false
}

func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
