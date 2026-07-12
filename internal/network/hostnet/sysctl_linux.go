//go:build linux

package hostnet

import (
	"fmt"
	"os"
	"strings"
)

var sysctlPaths = []string{
	"/proc/sys/net/ipv4/ip_forward",
	"/proc/sys/net/bridge/bridge-nf-call-iptables",
	"/proc/sys/net/bridge/bridge-nf-call-ip6tables",
}

func ensureForwardingSysctls() error {
	for _, path := range sysctlPaths {
		if err := writeSysctl(path, "1"); err != nil {
			return err
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
	return execConntrack("-D", "-s", ip)
}
