package procid

import (
	"bufio"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func mustWrite(t *testing.T, p, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustLink(t *testing.T, target, p string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, p); err != nil {
		t.Fatal(err)
	}
}

// TestOwnersSkipsVanishedProcesses: processes come and go between the cgroup
// scan and the per-process reads. One that exits before its exe is read is
// skipped, a cgroup.procs that vanishes is skipped, and an interpreter whose
// cmdline is gone still counts as itself, just without a script.
func TestOwnersSkipsVanishedProcesses(t *testing.T) {
	r, local, remote := fakeProc(t)
	root := filepath.Dir(r.Proc)
	mustWrite(t, filepath.Join(r.Cgroup, "sandbox/extra/cgroup.procs"), "104\n105\n")
	mustLink(t, filepath.Join(r.Cgroup, "sandbox/gone/missing"), filepath.Join(r.Cgroup, "sandbox/gone/cgroup.procs"))
	mustLink(t, filepath.Join(root, "rootfs/usr/local/bin/python3.12"), filepath.Join(r.Proc, "104/exe"))
	mustLink(t, "socket:[555]", filepath.Join(r.Proc, "104/fd/3"))
	mustLink(t, filepath.Join(root, "rootfs/exited"), filepath.Join(r.Proc, "105/exe"))
	mustLink(t, "socket:[555]", filepath.Join(r.Proc, "105/fd/3"))

	owners, err := r.Owners(100, local, remote)
	if err != nil {
		t.Fatal(err)
	}
	var pids []int
	for _, o := range owners {
		pids = append(pids, o.PID)
		if o.PID == 104 && o.Script != "" {
			t.Fatalf("an interpreter without a cmdline has no script: %+v", o)
		}
	}
	slices.Sort(pids)
	if !slices.Equal(pids, []int{101, 102, 104}) {
		t.Fatalf("owner pids = %v", pids)
	}
}

// TestOwnersNeedsTheCgroupFile: a process whose sockets can be read but whose
// cgroup can't is an error, not "no owner".
func TestOwnersNeedsTheCgroupFile(t *testing.T) {
	r, local, remote := fakeProc(t)
	tcp, err := os.ReadFile(filepath.Join(r.Proc, "100/net/tcp"))
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(r.Proc, "200/net/tcp"), string(tcp))
	_, err = r.Owners(200, local, remote)
	if err == nil || errors.Is(err, ErrNotFound) || !strings.Contains(err.Error(), "sandbox cgroup") {
		t.Fatalf("err = %v", err)
	}
}

type failingListener struct{ net.Listener }

func (failingListener) Accept() (net.Conn, error) {
	return nil, errors.New("accept: too many open files")
}

// TestRemoteFailures: a lookup that can't be sent, an answer that doesn't
// parse, a listener that fails and a trace that errors all surface as
// errors, never as a match.
func TestRemoteFailures(t *testing.T) {
	r, local, remote := fakeProc(t)
	dir, err := os.MkdirTemp("", "pid")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	// sandboxd accepted nothing and reads nothing: a request bigger than
	// the socket buffer can't be written before the deadline.
	stuck, err := net.Listen("unix", filepath.Join(dir, "stuck.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stuck.Close() })
	big := make([]string, 4096)
	for i := range big {
		big[i] = "/" + strings.Repeat("p", 1024)
	}
	c := Client{Path: filepath.Join(dir, "stuck.sock"), Timeout: 50 * time.Millisecond}
	if _, err := c.Match("sb", local, remote, big); err == nil || !strings.Contains(err.Error(), "sandboxd lookup") {
		t.Fatalf("unsent request: %v", err)
	}

	garbled, err := net.Listen("unix", filepath.Join(dir, "garbled.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = garbled.Close() })
	go func() {
		conn, err := garbled.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = bufio.NewReader(conn).ReadString('\n')
		_, _ = io.WriteString(conn, "not json\n")
	}()
	if _, err := (Client{Path: filepath.Join(dir, "garbled.sock")}).Match("sb", local, remote, nil); err == nil || !strings.Contains(err.Error(), "sandboxd lookup") {
		t.Fatalf("garbled answer: %v", err)
	}

	if err := (&Server{}).Serve(failingListener{}); err == nil {
		t.Fatal("an accept error other than a closed listener must end Serve with it")
	}

	srv := &Server{Resolver: r, Authorize: func(string) (int, []string, error) { return 999, []string{"/usr/bin/git"}, nil }}
	resp := srv.answer(Request{SandboxID: "sb", Local: local, Remote: remote, Paths: []string{"/usr/bin/git"}})
	if resp.Error == "" || resp.NotFound || len(resp.Matched) != 0 {
		t.Fatalf("a trace error must be an error answer: %+v", resp)
	}
}

func TestLimitedReader(t *testing.T) {
	l := &limitedReader{r: strings.NewReader("abcdef"), n: 4}
	buf := make([]byte, 16)
	if n, err := l.Read(buf); n != 4 || err != nil || string(buf[:n]) != "abcd" {
		t.Fatalf("first read = %d %q %v", n, buf[:n], err)
	}
	if n, err := l.Read(buf); n != 0 || err == nil {
		t.Fatalf("past the limit = %d %v", n, err)
	}
}
