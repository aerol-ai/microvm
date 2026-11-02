package docker

import "github.com/aerol-ai/microvm/internal/network/hostnet"

// sandboxCapDrop is removed from every non-privileged sandbox container.
// NET_RAW lets a sandbox send packets with a neighbour's source IP, which
// defeats per-IP egress rules and the egress gateway's source-IP identity
// (plans/egress-domain-filtering.md P0-2, CEO D8). ping stops working inside
// sandboxes; that is the accepted cost.
var sandboxCapDrop = []string{"NET_RAW"}

// sandboxHostConfig is the HostConfig base shared by cold creates and warm
// parks, so both paths drop the same capabilities. A privileged sandbox gets
// every capability by design, so no drop is sent for it; gateway mode refuses
// privileged nodes instead (plan §5.3, CEO D18).
func sandboxHostConfig(privileged bool, binds []string) map[string]any {
	hostConfig := map[string]any{
		"Privileged": privileged,
		"Binds":      binds,
	}
	if !privileged {
		hostConfig["CapDrop"] = append([]string(nil), sandboxCapDrop...)
	}
	return hostConfig
}

// sandboxIPv6Sysctls is a var so tests can stand in a host with or without
// IPv6.
var sandboxIPv6Sysctls = hostnet.SandboxIPv6Sysctls

// setSandboxIPv6Off starts a container that owns its network namespace with
// IPv6 off in it: runc writes the sysctls before the first process, and
// gVisor (Runtime runsc) reads the "all" one from the spec and keeps IPv6 out
// of its own network stack. Every host rule between sandboxes is IPv4, so a
// link-local address on eth0 was a way past all of them. dockerd may set
// the same on a network without IPv6; saying it here does not depend on the
// dockerd version. Not for a container that joins another's namespace (a
// pause-netns adopt: the pause container got it) or the host's (docker
// refuses net.* sysctls there, and such a sandbox has no isolation to keep),
// and nothing on a host without IPv6, where runc would fail on the missing
// /proc/sys entry.
func setSandboxIPv6Off(hostConfig map[string]any, network string) {
	if network == "host" {
		return
	}
	if sysctls := sandboxIPv6Sysctls(); len(sysctls) > 0 {
		hostConfig["Sysctls"] = sysctls
	}
}

// hasSandboxIPv6Off reports whether a container was created with IPv6 off
// (setSandboxIPv6Off), or whether there is nothing to turn off on this host.
func hasSandboxIPv6Off(sysctls map[string]string) bool {
	for k, v := range sandboxIPv6Sysctls() {
		if sysctls[k] != v {
			return false
		}
	}
	return true
}
