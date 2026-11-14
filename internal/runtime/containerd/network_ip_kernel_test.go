//go:build linux && kerneltest

package containerd

// The address probe against real namespaces, in a privileged Linux
// container:
//
//	go test -tags kerneltest -run KernelAddress ./internal/runtime/containerd/

import (
	"context"
	"os"
	"runtime"
	"strings"
	"testing"

	cntr "github.com/containerd/containerd/v2/client"
	"github.com/vishvananda/netns"
)

// A pinned netns with no IPv4 is what a running gVisor sandbox leaves (runsc
// takes the address into its own stack): the probe reports no address, so
// the create uses the one it prepaid. It must not go on to the task's pids,
// which under runsc are pids inside the sandbox; here the pid is this test,
// whose netns has addresses of its own.
func TestKernelAddressPinnedNetnsWithoutIPv4NeverReadsPids(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root in a privileged container")
	}
	runtime.LockOSThread()
	orig, err := netns.Get()
	if err != nil {
		t.Fatalf("this thread's netns: %v", err)
	}
	defer orig.Close()
	empty, err := netns.New() // this thread, into a namespace with no address
	if err != nil {
		t.Fatalf("new netns: %v", err)
	}
	defer empty.Close()
	defer func() {
		if err := netns.Set(orig); err != nil {
			t.Fatalf("back to the original netns: %v (the thread stays locked and ends with the test)", err)
		}
		runtime.UnlockOSThread()
	}()
	path := "/proc/thread-self/ns/net"
	ip, err := containerIPv4FromTask(context.Background(), ipLookupTask{
		spec: netnsSpec(path),
		pids: []cntr.ProcessInfo{{Pid: uint32(os.Getpid())}},
	})
	if err == nil || !strings.Contains(err.Error(), "no container IPv4") {
		t.Fatalf("pinned netns without IPv4 = %q, %v; want no address, from the pinned netns alone", ip, err)
	}
}

// The pid fallback's refusal must hold when the thread asking is not in the
// daemon's namespace but the main thread is (and the other way round, which
// is what a wedged main thread made: /proc/<pid>/ns/net names the main
// thread's namespace). Here this thread moves to a new namespace and asks
// about this process's pid, which /proc shows in the main thread's.
func TestKernelAddressPidFallbackRefusesTheMainThreadsNetns(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root in a privileged container")
	}
	runtime.LockOSThread()
	orig, err := netns.Get()
	if err != nil {
		t.Fatalf("this thread's netns: %v", err)
	}
	defer orig.Close()
	other, err := netns.New()
	if err != nil {
		t.Fatalf("new netns: %v", err)
	}
	defer other.Close()
	defer func() {
		if err := netns.Set(orig); err != nil {
			t.Fatalf("back to the original netns: %v (the thread stays locked and ends with the test)", err)
		}
		runtime.UnlockOSThread()
	}()
	ip, err := containerIPv4FromTask(context.Background(), ipLookupTask{
		specErr: os.ErrNotExist,
		pids:    []cntr.ProcessInfo{{Pid: uint32(os.Getpid())}},
	})
	if err == nil || !strings.Contains(err.Error(), "host network namespace") {
		t.Fatalf("a pid in the main thread's netns = %q, %v; want the host refusal", ip, err)
	}
}
