package containerd

import (
	"os"
	"path/filepath"

	"github.com/aerol-ai/microvm/internal/runtime/resolvconf"
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
	resolvBody, err := resolvconf.Generate(resolvconf.HostPath)
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
