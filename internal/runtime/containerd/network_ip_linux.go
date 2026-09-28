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
	// The spec's pinned netns first: it is correct for runc and runsc alike.
	if spec, err := task.Spec(ctx); err == nil {
		if path := specNetworkNamespacePath(spec); path != "" {
			if ns, err := netns.GetFromPath(path); err == nil {
				ip, ipErr := firstIPv4InNetns(ns)
				ns.Close()
				if ipErr == nil {
					return ip, nil
				}
			}
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
	if host, herr := netns.Get(); herr == nil {
		same := ns.Equal(host)
		host.Close()
		if same {
			return "", fmt.Errorf("task pid shares the host network namespace; refusing to report the host's address as the sandbox's")
		}
	}
	return firstIPv4InNetns(ns)
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
