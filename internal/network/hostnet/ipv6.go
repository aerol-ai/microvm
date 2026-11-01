package hostnet

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Sandboxes are IPv4-only. Every host rule that keeps a sandbox off its
// neighbours and off the node is IPv4 (netrules' floor and node chains, the
// Firecracker isolation chain, the egress gateway), so a sandbox with IPv6
// up reached a neighbour on the same bridge over link-local addresses past
// all of them (found live on cluster-3-mixed-routing: fe80::…%eth0 answered
// while the IPv4 address timed out). Turning IPv6 off inside every sandbox
// is the first layer; the second is the node's IPv6 fence
// (internal/network/ipv6fence), which drops IPv6 on the sandbox bridges and
// TAPs whatever a sandbox does to its own stack.

// The sysctls that turn IPv6 off in a network namespace. "all" also flips
// every interface already there (lo loses ::1); "default" is what an
// interface created or moved in later starts with, so a veth the CNI plugin
// adds after the write never gets a link-local address.
const (
	SysctlAllDisableIPv6     = "net.ipv6.conf.all.disable_ipv6"
	SysctlDefaultDisableIPv6 = "net.ipv6.conf.default.disable_ipv6"
)

// ipv6ConfRoot is where the kernel publishes the IPv6 interface sysctls of
// the reading thread's network namespace. It is absent when the kernel has
// no IPv6 at all (built without it, or booted with ipv6.disable=1). A var
// for tests.
var ipv6ConfRoot = "/proc/sys/net/ipv6/conf"

// HostHasIPv6 reports whether this kernel has IPv6. Without it no sandbox can
// have IPv6 either, and a runtime asked to set an IPv6 sysctl fails the
// create (runc cannot open the missing /proc/sys entry), so every caller
// below does nothing.
func HostHasIPv6() bool {
	_, err := os.Stat(filepath.Join(ipv6ConfRoot, "all", "disable_ipv6"))
	return err == nil
}

// SandboxIPv6Sysctls are the OCI (and Docker HostConfig) sysctls every
// sandbox is created with, so it starts with IPv6 off in its own network
// namespace before its first process runs. gVisor reads the "all" one from
// the spec too: runsc copies no IPv6 address or route into its own network
// stack when it is set. Nil when the host has no IPv6. A fresh map per call:
// callers merge it into a spec they own.
func SandboxIPv6Sysctls() map[string]string {
	if !HostHasIPv6() {
		return nil
	}
	return map[string]string{
		SysctlAllDisableIPv6:     "1",
		SysctlDefaultDisableIPv6: "1",
	}
}

// DisableIPv6InNetns turns IPv6 off inside the network namespace
// bind-mounted at path (all and default). Idempotent. A no-op when the host
// has no IPv6, and on platforms without network namespaces.
func DisableIPv6InNetns(path string) error {
	if !HostHasIPv6() {
		return nil
	}
	if strings.TrimSpace(path) == "" {
		return errors.New("disable ipv6: netns path is required")
	}
	return disableIPv6InNetns(path)
}

// DisableIPv6OnLink turns IPv6 off on one host interface, so the host has no
// link-local address on it that a sandbox at the other end could reach. A
// no-op when the host has no IPv6. An interface that does not exist is an
// error: the caller just created it.
func DisableIPv6OnLink(name string) error {
	if !HostHasIPv6() {
		return nil
	}
	if !validLinkName(name) {
		return fmt.Errorf("disable ipv6: invalid interface name %q", name)
	}
	return writeDisableIPv6(filepath.Join(ipv6ConfRoot, name, "disable_ipv6"))
}

// writeNetnsDisableIPv6 writes all, then default, in the calling thread's
// network namespace.
func writeNetnsDisableIPv6() error {
	for _, conf := range []string{"all", "default"} {
		if err := writeDisableIPv6(filepath.Join(ipv6ConfRoot, conf, "disable_ipv6")); err != nil {
			return err
		}
	}
	return nil
}

func writeDisableIPv6(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return fmt.Errorf("disable ipv6: %w", err)
	}
	_, err = f.WriteString("1\n")
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("disable ipv6: write %s: %w", path, err)
	}
	return nil
}

// validLinkName is a Linux interface name that is safe to join into a
// /proc/sys path: 1..15 bytes, no slash, not "." or "..".
func validLinkName(name string) bool {
	if name == "" || len(name) > 15 || name == "." || name == ".." {
		return false
	}
	return !strings.ContainsAny(name, "/\x00 \t\n")
}
