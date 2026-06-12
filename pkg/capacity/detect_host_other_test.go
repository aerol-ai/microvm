//go:build !linux

package capacity

import (
	"strings"
	"testing"
)

// These tests pin the non-Linux fallback in meminfo_other.go. They must be
// build-tagged: on Linux CI the probe and host-memory detection succeed via
// /proc/meminfo, so an untagged version would (correctly) fail there.

func TestDetectHost_NonLinuxReturnsError(t *testing.T) {
	_, err := DetectHost()
	if err == nil {
		t.Fatal("DetectHost on non-linux build should fail without /proc/meminfo")
	}
	if !strings.Contains(err.Error(), "host memory") {
		t.Fatalf("DetectHost error = %v, want host memory wrapper", err)
	}
}

func TestNewProcMeminfoProbe_NonLinux(t *testing.T) {
	probe := NewProcMeminfoProbe()
	if _, err := probe.FreeMB(); err == nil {
		t.Fatal("FreeMB on non-linux should error")
	}
}
