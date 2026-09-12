package isolate

import (
	"testing"
)

func TestJailRealizable(t *testing.T) {
	// Platform-specific: linux → true, others → false. Just exercise the export.
	_ = JailRealizable()
}
