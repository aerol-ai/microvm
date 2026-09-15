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
	pids, err := task.Pids(ctx)
	if err != nil || len(pids) == 0 || pids[0].Pid <= 0 {
		return "", fmt.Errorf("task has no running pid")
	}
	ns, err := netns.GetFromPid(int(pids[0].Pid))
	if err != nil {
		return "", fmt.Errorf("netns from pid: %w", err)
	}
	defer ns.Close()

	handle, err := netlink.NewHandleAt(ns)
	if err != nil {
		return "", fmt.Errorf("netlink handle: %w", err)
	}
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
