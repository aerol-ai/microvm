//go:build linux

package hostnet

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

var sysctlPaths = []string{
	"/proc/sys/net/ipv4/ip_forward",
	"/proc/sys/net/bridge/bridge-nf-call-iptables",
	"/proc/sys/net/bridge/bridge-nf-call-ip6tables",
}

// execModprobe is a test seam over `modprobe`.
var execModprobe = func(module string) error {
	return exec.Command("modprobe", module).Run()
}

func ensureForwardingSysctls() error {
	// The bridge-nf-call-* sysctls only exist once br_netfilter is loaded.
	// Without them the bridge sysctl writes silently no-op and sandbox↔sandbox
	// bridge traffic bypasses iptables — neighbor isolation (a §8 exit gate)
	// fails open. Load the module first, then write, then VERIFY the bridge
	// hooks actually took: fail loud rather than ship sandboxes with no
	// east-west isolation.
	needBridge := false
	for _, path := range sysctlPaths {
		if strings.Contains(path, "bridge-nf-call") {
			if _, err := os.Stat(path); os.IsNotExist(err) {
				needBridge = true
			}
		}
	}
	if needBridge {
		_ = execModprobe("br_netfilter")
	}
	for _, path := range sysctlPaths {
		if err := writeSysctl(path, "1"); err != nil {
			return err
		}
	}
	for _, path := range sysctlPaths {
		if !strings.Contains(path, "bridge-nf-call") {
			continue
		}
		if _, err := os.Stat(path); err != nil {
			return fmt.Errorf("bridge netfilter sysctl %s absent after modprobe br_netfilter; sandbox east-west isolation would fail open: %w", path, err)
		}
	}
	return nil
}

func flushConntrackForIP(ip string) error {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return nil
	}
	// Best-effort: conntrack may be absent on minimal hosts.
	_ = runConntrackDelete(ip)
	return nil
}

func writeSysctl(path, value string) error {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("sysctl %s: %w", path, err)
	}
	if err := os.WriteFile(path, []byte(value), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func runConntrackDelete(ip string) error {
	// Flush BOTH directions on IP release. -s catches flows the released IP
	// originated; -d catches inbound/DNAT flows (caddy→containerIP:port) where
	// it was the original destination. Without -d, a reused IP inherits stale
	// ingress conntrack and its first inbound connection is misrouted/dropped
	// ("blackhole", plan §4 item #8). Both are best-effort — conntrack -D exits
	// non-zero when nothing matched, which the caller ignores.
	_ = execConntrack("-D", "-s", ip)
	return execConntrack("-D", "-d", ip)
}
