// Package resolvconf builds the resolv.conf a sandbox gets: the host's
// upstream resolvers, without loopback stubs the sandbox can't reach. Both a
// container (containerd bind-mounts it) and a Firecracker guest (toolboxd-init
// installs it) need one, since stock images such as alpine ship none.
package resolvconf

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

// HostPath is the host resolver configuration Generate is usually given.
const HostPath = "/etc/resolv.conf"

// Fallback is what a sandbox gets when the host names no usable resolver.
const Fallback = "nameserver 8.8.8.8\n"

// Generate copies upstream resolvers from the given host resolv.conf,
// stripping loopback stubs like systemd-resolved's 127.0.0.53 that are
// unreachable from a sandbox's network. A missing source falls back to a
// public resolver so the sandbox still resolves DNS.
func Generate(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return Fallback, nil
	}
	defer f.Close()

	var nameservers []string
	var search []string
	var options []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch strings.ToLower(fields[0]) {
		case "nameserver":
			ip := strings.TrimSpace(fields[1])
			if isLoopback(ip) {
				continue
			}
			if net.ParseIP(ip) != nil {
				nameservers = append(nameservers, ip)
			}
		case "search":
			search = append(search, fields[1:]...)
		case "options":
			options = append(options, fields[1:]...)
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	if len(nameservers) == 0 {
		nameservers = []string{"8.8.8.8"}
	}
	var b strings.Builder
	if len(search) > 0 {
		fmt.Fprintf(&b, "search %s\n", strings.Join(search, " "))
	}
	if len(options) > 0 {
		fmt.Fprintf(&b, "options %s\n", strings.Join(options, " "))
	}
	for _, ns := range nameservers {
		fmt.Fprintf(&b, "nameserver %s\n", ns)
	}
	return b.String(), nil
}

func isLoopback(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return parsed.IsLoopback()
}
