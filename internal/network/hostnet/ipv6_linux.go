//go:build linux

package hostnet

import (
	"errors"
	"fmt"
	"runtime"

	"github.com/vishvananda/netns"
)

// Seams over vishvananda/netns: entering a namespace needs CAP_SYS_ADMIN,
// which unit tests do not have (the kerneltest covers the real thing).
var (
	nsFromPath = netns.GetFromPath
	nsCurrent  = netns.Get
	nsSet      = netns.Set
)

// disableIPv6InNetns enters the netns at path on one locked OS thread,
// writes the sysctls there (/proc/sys/net is the reading thread's
// namespace), and returns the thread to the host namespace. It runs on a
// goroutine of its own so the caller's thread is never moved.
func disableIPv6InNetns(path string) error {
	target, err := nsFromPath(path)
	if err != nil {
		return fmt.Errorf("disable ipv6: open netns %s: %w", path, err)
	}
	defer target.Close()
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		orig, err := nsCurrent()
		if err != nil {
			runtime.UnlockOSThread()
			errc <- fmt.Errorf("disable ipv6: host netns: %w", err)
			return
		}
		defer orig.Close()
		if err := nsSet(target); err != nil {
			runtime.UnlockOSThread()
			errc <- fmt.Errorf("disable ipv6: enter netns %s: %w", path, err)
			return
		}
		werr := writeNetnsDisableIPv6()
		if rerr := nsSet(orig); rerr != nil {
			// Stay locked: the goroutine ends and the runtime retires the
			// thread instead of handing out one left in a sandbox's
			// namespace.
			errc <- errors.Join(werr, fmt.Errorf("disable ipv6: return to the host netns: %w", rerr))
			return
		}
		runtime.UnlockOSThread()
		errc <- werr
	}()
	return <-errc
}
