//go:build linux

package main

import (
	"strings"
	"syscall"
	"testing"
)

// FreezeRoot and ThawRoot are FIFREEZE / FITHAW on the root filesystem. The
// ioctl seam stands in for the kernel: a real freeze needs CAP_SYS_ADMIN and
// would stop the test machine's own writes.

func stubIoctl(t *testing.T, errno syscall.Errno) *[]uintptr {
	t.Helper()
	orig := ioctlPtr
	t.Cleanup(func() { ioctlPtr = orig })
	var requests []uintptr
	ioctlPtr = func(_, request, _ uintptr) syscall.Errno {
		requests = append(requests, request)
		return errno
	}
	return &requests
}

func TestLinuxQuiesceOpsFreezeAndThawTheRoot(t *testing.T) {
	requests := stubIoctl(t, 0)
	ops := linuxQuiesceOps{}
	if err := ops.FreezeRoot(); err != nil {
		t.Fatalf("FreezeRoot: %v", err)
	}
	if err := ops.ThawRoot(); err != nil {
		t.Fatalf("ThawRoot: %v", err)
	}
	if got := *requests; len(got) != 2 || got[0] != ioctlFIFREEZE || got[1] != ioctlFITHAW {
		t.Fatalf("ioctl requests = %#x, want FIFREEZE then FITHAW", got)
	}
}

// The kernel answers EINVAL to FITHAW on a filesystem that is not frozen.
func TestLinuxQuiesceOpsThawOfAnUnfrozenRootSucceeds(t *testing.T) {
	stubIoctl(t, syscall.EINVAL)
	if err := (linuxQuiesceOps{}).ThawRoot(); err != nil {
		t.Fatalf("ThawRoot on an unfrozen root = %v, want nil", err)
	}
	// The same answer to FIFREEZE is a real failure.
	if err := (linuxQuiesceOps{}).FreezeRoot(); err == nil || !strings.Contains(err.Error(), "invalid argument") {
		t.Fatalf("FreezeRoot with EINVAL = %v, want the error", err)
	}
}

func TestLinuxQuiesceOpsFreezeOfAMissingMountFails(t *testing.T) {
	orig := rootFSPath
	t.Cleanup(func() { rootFSPath = orig })
	rootFSPath = t.TempDir() + "/missing"
	if err := (linuxQuiesceOps{}).FreezeRoot(); err == nil || !strings.Contains(err.Error(), "open ") {
		t.Fatalf("FreezeRoot of a missing path = %v, want an open error", err)
	}
}
