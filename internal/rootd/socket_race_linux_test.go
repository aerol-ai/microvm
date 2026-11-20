//go:build linux

package rootd

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// raceEnv makes this test binary the agent's side of
// TestListenSymlinkRace.
const raceEnv = "AEROLVM_ROOTD_TEST_RACE_PARENT"

// TestListenSymlinkRace is review H1's proof, kept as a regression test.
// A compromised agent (uid 65531, in the socket's group) watches a socket
// folder it can write, as /run/aerolvm is on Kubernetes, and swaps
// whatever root makes there for a link to a root-only file before root
// chgrps and chmods it. On c5dbb884e it won within a few hundred tries.
// Now listen refuses the folder, every time, and the file stays root's.
func TestListenSymlinkRace(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to run the agent as another user")
	}
	const agent, group = 65531, 4242
	dir := shortDir(t)
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(dir, "run-aerolvm")
	if err := os.Mkdir(parent, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o777); err != nil { // as kubelet makes an emptyDir
		t.Fatal(err)
	}
	target := filepath.Join(dir, "root-only")
	if err := os.WriteFile(target, []byte("root only\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "rootd.test")
	copyFile(t, exe, bin)
	cmd := exec.Command(bin, "-test.run=^TestListenRaceAgent$")
	cmd.Env = append(os.Environ(), raceEnv+"="+parent, "AEROLVM_ROOTD_TEST_RACE_TARGET="+target)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: agent, Gid: agent, Groups: []uint32{group}}}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	time.Sleep(200 * time.Millisecond) // let the agent set its watch

	sock := filepath.Join(parent, "root.sock")
	for i := range 3000 {
		ln, _, err := listen(sock, group)
		if err == nil {
			_ = ln.Close()
			t.Fatalf("try %d: listen served from a folder others can write", i+1)
		}
		var st unix.Stat_t
		if err := unix.Stat(target, &st); err != nil {
			t.Fatal(err)
		}
		if st.Mode&0o7777 != 0o600 || st.Gid != 0 {
			t.Fatalf("try %d: the agent won: %s is mode %o gid %d", i+1, target, st.Mode&0o7777, st.Gid)
		}
	}
}

// TestListenRaceAgent is the agent's side: on every name root makes in the
// folder, it puts a link to the target in its place (in a private folder,
// as c5dbb884e made, or as the socket itself).
func TestListenRaceAgent(t *testing.T) {
	parent, target := os.Getenv(raceEnv), os.Getenv("AEROLVM_ROOTD_TEST_RACE_TARGET")
	if parent == "" {
		t.Skip("runs only as TestListenSymlinkRace's agent")
	}
	fd, err := unix.InotifyInit1(0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unix.InotifyAddWatch(fd, parent, unix.IN_CREATE); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1<<16)
	for n := 0; ; {
		nr, err := unix.Read(fd, buf)
		if err != nil {
			t.Fatal(err)
		}
		for off := 0; off < nr; {
			ev := (*unix.InotifyEvent)(unsafe.Pointer(&buf[off]))
			name := strings.TrimRight(string(buf[off+unix.SizeofInotifyEvent:off+unix.SizeofInotifyEvent+int(ev.Len)]), "\x00")
			off += unix.SizeofInotifyEvent + int(ev.Len)
			n++
			p := filepath.Join(parent, name)
			link := filepath.Join(parent, ".l"+strconv.Itoa(n))
			_ = unix.Symlink(target, link)
			if ev.Mask&unix.IN_ISDIR != 0 {
				// A private folder: take it, and plant the link as the
				// socket root will chmod there.
				if unix.Rename(p, filepath.Join(parent, ".old"+strconv.Itoa(n))) != nil || unix.Mkdir(p, 0o777) != nil {
					continue
				}
				_ = unix.Chmod(p, 0o777)
				inner := filepath.Join(p, ".l")
				_ = unix.Symlink(target, inner)
				for end := time.Now().Add(20 * time.Millisecond); time.Now().Before(end); {
					var st unix.Stat_t
					if unix.Lstat(filepath.Join(p, "s"), &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFSOCK {
						_ = unix.Rename(inner, filepath.Join(p, "s"))
						break
					}
				}
				continue
			}
			_ = unix.Rename(link, p) // a socket made in the folder itself
		}
	}
}

// asAgent runs a shell line as the agent: uid 65531, in the socket's group.
func asAgent(t *testing.T, script string) (string, error) {
	t.Helper()
	cmd := exec.Command("sh", "-c", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65531, Gid: 65531, Groups: []uint32{4242}}}
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// TestListenUnderAStickyFolder: a root-owned sticky folder above the
// socket's (as /tmp) is allowed, since the agent cannot rename root's
// folder in it; an open one is not. And a link the agent puts in an open
// folder on the way makes root create nothing where it points (review
// N2; in a sticky folder the kernel's protected_symlinks already stops
// root following it).
func TestListenUnderAStickyFolder(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to run the agent as another user")
	}
	dir := shortDir(t)
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(dir, "run")
	if err := os.Mkdir(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	sockDir := filepath.Join(parent, "rootd")
	if err := os.Mkdir(sockDir, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := unix.Chmod(parent, 0o777); err != nil {
		t.Fatal(err)
	}
	if ln, _, err := listen(filepath.Join(sockDir, "root.sock"), 4242); err == nil {
		_ = ln.Close()
		t.Fatal("listen took a socket folder under one anyone can write")
	}

	if err := unix.Chmod(parent, 0o1777); err != nil {
		t.Fatal(err)
	}
	ln, _, err := listen(filepath.Join(sockDir, "root.sock"), 4242)
	if err != nil {
		t.Fatalf("a sticky folder above: %v", err)
	}
	defer ln.Close()
	if out, err := asAgent(t, "mv "+sockDir+" "+parent+"/stolen"); err == nil {
		t.Fatalf("the agent renamed root's socket folder: %s", out)
	}

	elsewhere := filepath.Join(dir, "elsewhere")
	if err := os.Mkdir(elsewhere, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := unix.Chmod(parent, 0o777); err != nil {
		t.Fatal(err)
	}
	if out, err := asAgent(t, "ln -s "+elsewhere+" "+parent+"/aerolvm"); err != nil {
		t.Fatalf("agent link: %s %v", out, err)
	}
	if ln, _, err := listen(filepath.Join(parent, "aerolvm", "rootd", "root.sock"), 4242); err == nil {
		_ = ln.Close()
		t.Fatal("listen followed the agent's link")
	}
	if _, err := os.Lstat(filepath.Join(elsewhere, "rootd")); err == nil {
		t.Fatal("root made a folder through the agent's link")
	}
}
