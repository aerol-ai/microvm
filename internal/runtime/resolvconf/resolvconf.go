// Package resolvconf builds the resolv.conf a sandbox gets: the host's
// upstream resolvers, without loopback stubs the sandbox can't reach. Both a
// container (containerd bind-mounts it) and a Firecracker guest (toolboxd-init
// installs it) need one, since stock images such as alpine ship none.
package resolvconf

import (
	"bufio"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
)

// HostPath is the host resolver configuration Generate is usually given.
const HostPath = "/etc/resolv.conf"

// SystemdUpstreamPath is where systemd-resolved lists its upstream
// resolvers. dockerd hands those to containers on the default bridge when
// HostPath holds only the 127.0.0.53 stub.
const SystemdUpstreamPath = "/run/systemd/resolve/resolv.conf"

// Fallback is what a sandbox gets when the host names no usable resolver.
const Fallback = "nameserver " + fallbackNameserver + "\n"

const fallbackNameserver = "8.8.8.8"

// Config is a sandbox's resolver settings: what Render writes, in the
// order Generate has always written it. The root helper takes these as
// typed values from the agent and renders the file itself
// (internal/rootd), so both sides share this one renderer.
type Config struct {
	Nameservers []string
	Search      []string
	Options     []string
}

// Render writes c as a resolv.conf: search, then options, then one line
// per nameserver. It adds nothing: an empty Config renders as "".
func (c Config) Render() string {
	var b strings.Builder
	if len(c.Search) > 0 {
		fmt.Fprintf(&b, "search %s\n", strings.Join(c.Search, " "))
	}
	if len(c.Options) > 0 {
		fmt.Fprintf(&b, "options %s\n", strings.Join(c.Options, " "))
	}
	for _, ns := range c.Nameservers {
		fmt.Fprintf(&b, "nameserver %s\n", ns)
	}
	return b.String()
}

// Generate copies upstream resolvers from the given host resolv.conf,
// stripping loopback stubs like systemd-resolved's 127.0.0.53 that are
// unreachable from a sandbox's network. A missing source falls back to a
// public resolver so the sandbox still resolves DNS.
func Generate(path string) (string, error) {
	c, err := Parse(path)
	if err != nil {
		return "", err
	}
	return c.Render(), nil
}

// Parse reads the settings Generate copies from a host resolv.conf: its
// nameservers without loopback stubs (8.8.8.8 when none is left, or when
// the file is missing), its search domains and its options.
func Parse(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{Nameservers: []string{fallbackNameserver}}, nil
	}
	defer f.Close()

	var c Config
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
				c.Nameservers = append(c.Nameservers, ip)
			}
		case "search":
			c.Search = append(c.Search, fields[1:]...)
		case "options":
			c.Options = append(c.Options, fields[1:]...)
		}
	}
	if err := sc.Err(); err != nil {
		return Config{}, err
	}
	if len(c.Nameservers) == 0 {
		c.Nameservers = []string{fallbackNameserver}
	}
	return c, nil
}

func isLoopback(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return parsed.IsLoopback()
}

// Nameservers returns the non-loopback nameserver addresses path lists:
// the resolvers a sandbox is handed (Generate). A missing or unreadable
// file has none.
func Nameservers(path string) []netip.Addr {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || strings.ToLower(fields[0]) != "nameserver" {
			continue
		}
		ip, err := netip.ParseAddr(fields[1])
		if err != nil || ip.Unmap().IsLoopback() {
			continue
		}
		out = append(out, ip.Unmap())
	}
	return out
}
