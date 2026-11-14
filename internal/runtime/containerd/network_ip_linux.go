//go:build linux

package containerd

import (
	"context"
	"fmt"

	cntr "github.com/containerd/containerd/v2/client"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

func containerIPv4FromTask(ctx context.Context, task cntr.Task) (string, error) {
	if task == nil {
		return "", fmt.Errorf("task is nil")
	}
	// The spec's pinned netns is the answer whenever there is one, for runc
	// and runsc alike. Under runsc it holds no address once the sandbox runs
	// (gVisor takes the address into its own network stack), and the caller
	// then uses the address it prepaid. Never the pids then: runsc's are pids
	// inside the sandbox, so pid 1 named whatever is pid 1 here, which in a
	// worker pod is sandboxd itself.
	if spec, err := task.Spec(ctx); err == nil {
		if path := specNetworkNamespacePath(spec); path != "" {
			ns, err := netns.GetFromPath(path)
			if err != nil {
				return "", fmt.Errorf("open the pinned netns %s: %w", path, err)
			}
			defer ns.Close()
			return firstIPv4InNetns(ns)
		}
	}
	pids, err := task.Pids(ctx)
	if err != nil || len(pids) == 0 || pids[0].Pid <= 0 {
		return "", fmt.Errorf("task has no running pid")
	}
	ns, err := netns.GetFromPid(int(pids[0].Pid))
	if err != nil {
		return "", fmt.Errorf("netns from pid: %w", err)
	}
	defer ns.Close()
	// A task process in the daemon's own network namespace is not the
	// sandbox's network — it is how runsc looks from the host. Reporting the
	// first address found there would hand out the node's IP as the
	// sandbox's; failing lets the caller use the IP it provisioned instead.
	// The daemon's namespace is this thread's and its main thread's (what
	// /proc/<pid>/ns/net shows): they are the same unless a thread was left
	// in another, and either one is reason to refuse.
	if sameNetns(ns, netns.Get) || sameNetns(ns, func() (netns.NsHandle, error) { return netns.GetFromPath("/proc/self/ns/net") }) {
		return "", fmt.Errorf("task pid shares the host network namespace; refusing to report the host's address as the sandbox's")
	}
	return firstIPv4InNetns(ns)
}

// sameNetns reports whether ns is the namespace open returns.
func sameNetns(ns netns.NsHandle, open func() (netns.NsHandle, error)) bool {
	other, err := open()
	if err != nil {
		return false
	}
	defer other.Close()
	return ns.Equal(other)
}

func firstIPv4InNetns(ns netns.NsHandle) (string, error) {
	handle, err := netlink.NewHandleAt(ns)
	if err != nil {
		return "", fmt.Errorf("netlink handle: %w", err)
	}
	defer handle.Close()
	links, err := handle.LinkList()
	if err != nil {
		return "", err
	}
	for _, link := range links {
		if link.Attrs().Name == "lo" {
			continue
		}
		addrs, err := handle.AddrList(link, netlink.FAMILY_V4)
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ip := addr.IP.To4(); ip != nil && !ip.IsLoopback() {
				return ip.String(), nil
			}
		}
	}
	return "", fmt.Errorf("no container IPv4 found")
}
