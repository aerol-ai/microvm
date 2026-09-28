package netrules

import (
	"testing"
)

func TestIptablesVersionDefaultSeam(t *testing.T) {
	_, _ = iptablesVersion()
}
