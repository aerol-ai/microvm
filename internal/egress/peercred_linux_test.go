//go:build linux

package egress

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnixPeerCheck(t *testing.T) {
	a, _ := net.Pipe()
	t.Cleanup(func() { _ = a.Close() })
	if err := UnixPeerCheck(nil, "")(a); err == nil || !strings.Contains(err.Error(), "not a unix socket") {
		t.Fatalf("pipe: %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "peer.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	errc := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		defer c.Close()
		uid := uint32(os.Getuid())
		if err := UnixPeerCheck([]uint32{uid}, "")(c); err != nil {
			errc <- err
			return
		}
		if err := UnixPeerCheck([]uint32{uid + 1}, "")(c); err == nil {
			errc <- errNotAllowed
			return
		}
		data, err := os.ReadFile("/proc/self/cgroup")
		if err != nil {
			errc <- err
			return
		}
		line := strings.TrimSpace(strings.Split(string(data), "\n")[0])
		if line == "" {
			errc <- errEmptyCgroup
			return
		}
		// A fragment of this process's own cgroup file matches; a unit
		// name that is not there does not.
		if err := UnixPeerCheck([]uint32{uid}, line)(c); err != nil {
			errc <- err
			return
		}
		errc <- UnixPeerCheck([]uint32{uid}, "not-a-unit.service")(c)
	}()

	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := <-errc; err == nil || !strings.Contains(err.Error(), "not in") {
		t.Fatalf("cgroup miss = %v", err)
	}
}

var (
	errNotAllowed  = errString("peer uid was allowed")
	errEmptyCgroup = errString("empty cgroup file")
)

type errString string

func (e errString) Error() string { return string(e) }
