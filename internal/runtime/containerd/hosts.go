package containerd

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

type sandboxHostFiles struct {
	Dir        string
	ResolvConf string
	Hosts      string
	Hostname   string
}

func prepareSandboxHostFiles(runDir, sandboxID string) (*sandboxHostFiles, error) {
	dir := filepath.Join(runDir, "hosts", sandboxID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	resolvBody, err := generateResolvConf()
	if err != nil {
		return nil, err
	}
	resolvPath := filepath.Join(dir, "resolv.conf")
	if err := os.WriteFile(resolvPath, []byte(resolvBody), 0o644); err != nil {
		return nil, err
	}
	hostsPath := filepath.Join(dir, "hosts")
	if err := os.WriteFile(hostsPath, []byte("127.0.0.1 localhost\n::1 localhost ip6-localhost ip6-loopback\n"), 0o644); err != nil {
		return nil, err
	}
	hostnamePath := filepath.Join(dir, "hostname")
	if err := os.WriteFile(hostnamePath, []byte(sandboxID+"\n"), 0o644); err != nil {
		return nil, err
	}
	return &sandboxHostFiles{
		Dir:        dir,
		ResolvConf: resolvPath,
		Hosts:      hostsPath,
		Hostname:   hostnamePath,
	}, nil
}

// generateResolvConf copies upstream resolvers from the host, stripping
// loopback stubs like systemd-resolved's 127.0.0.53 that are unreachable
// from a container netns.
func generateResolvConf() (string, error) {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return "nameserver 8.8.8.8\n", nil
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
			if isLoopbackResolver(ip) {
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

func isLoopbackResolver(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return parsed.IsLoopback()
}
