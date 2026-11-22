package hostproc

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

const confineChildEnv = "HOSTPROC_CONFINE_CHILD"

// confineTestUID is "nobody" on Debian, which the golang image is.
const confineTestUID = 65534

// TestConfineChild is the child half of TestDropPrivilegesAndSeccomp: it
// drops, installs a filter that answers getppid with EPERM, and prints what
// the kernel says about every one of its threads.
func TestConfineChild(t *testing.T) {
	if os.Getenv(confineChildEnv) != "1" {
		t.Skip("child half of TestDropPrivilegesAndSeccomp")
	}
	// Threads exist before the drop, as in a worker: they must all drop.
	done := make(chan struct{})
	for range 4 {
		go func() {
			runtime.LockOSThread()
			<-done
		}()
	}
	if err := DropPrivileges(confineTestUID, confineTestUID); err != nil {
		fmt.Println("drop:", err)
		os.Exit(0)
	}
	table := SyscallTable()
	allow := make([]string, 0, len(table))
	for name := range table {
		switch name {
		case "getppid", "execve", "execveat", "seccomp":
			continue
		}
		allow = append(allow, name)
	}
	prog, _, err := BuildSeccomp(SeccompArch(), table, SeccompPolicy{
		Allow:   allow,
		Actions: map[string]uint32{"getppid": SeccompRetErrno(uint16(syscall.EPERM))},
		Default: SeccompRetErrno(uint16(syscall.EPERM)),
	})
	if err != nil {
		fmt.Println("build:", err)
		os.Exit(0)
	}
	if err := InstallSeccomp(prog); err != nil {
		fmt.Println("install:", err)
		os.Exit(0)
	}
	_, _, errno := syscall.RawSyscall(syscall.SYS_GETPPID, 0, 0, 0)
	fmt.Println("getppid:", errno)
	tasks, _ := filepath.Glob("/proc/self/task/*/status")
	for _, task := range tasks {
		raw, err := os.ReadFile(task)
		if err != nil {
			fmt.Println("task:", err)
			continue
		}
		for _, line := range strings.Split(string(raw), "\n") {
			for _, key := range []string{"Uid:", "Gid:", "Groups:", "NoNewPrivs:", "Seccomp:"} {
				if strings.HasPrefix(line, key) {
					fmt.Println(strings.Join(strings.Fields(line), " "))
				}
			}
		}
	}
	close(done)
	os.Exit(0)
}

// TestDropPrivilegesAndSeccomp runs the drop in a child, since it cannot
// be undone. As root every thread ends up as nobody, with no groups,
// no_new_privs and the filter; as any other user the drop is refused.
func TestDropPrivilegesAndSeccomp(t *testing.T) {
	if runtime.GOOS != "linux" {
		if err := DropPrivileges(confineTestUID, confineTestUID); !errors.Is(err, ErrConfineUnsupported) {
			t.Fatalf("DropPrivileges off linux = %v", err)
		}
		if err := InstallSeccomp(nil); !errors.Is(err, ErrConfineUnsupported) {
			t.Fatalf("InstallSeccomp off linux = %v", err)
		}
		if ConfinedProcFD(3) != "" {
			t.Fatal("ConfinedProcFD off linux")
		}
		t.Skip("privilege drops are Linux only")
	}
	if got := ConfinedProcFD(7); got != "/proc/self/fd/7" {
		t.Fatalf("ConfinedProcFD = %q", got)
	}
	for _, bad := range [][2]int{{0, 1}, {1, 0}, {-1, 5}} {
		if err := DropPrivileges(bad[0], bad[1]); err == nil {
			t.Fatalf("DropPrivileges(%d, %d) accepted", bad[0], bad[1])
		}
	}
	if err := InstallSeccomp(nil); err == nil {
		t.Fatal("empty program installed")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestConfineChild$")
	cmd.Env = append(os.Environ(), confineChildEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
	text := string(out)
	if os.Geteuid() != 0 {
		if !strings.Contains(text, "drop: drop privileges:") {
			t.Fatalf("non-root drop was not refused:\n%s", text)
		}
		return
	}
	if !strings.Contains(text, "getppid: operation not permitted") {
		t.Fatalf("filter did not answer getppid with EPERM:\n%s", text)
	}
	want := map[string]string{
		"Uid:":        fmt.Sprintf("Uid: %d %d %d %d", confineTestUID, confineTestUID, confineTestUID, confineTestUID),
		"Gid:":        fmt.Sprintf("Gid: %d %d %d %d", confineTestUID, confineTestUID, confineTestUID, confineTestUID),
		"Groups:":     "Groups:",
		"NoNewPrivs:": "NoNewPrivs: 1",
		"Seccomp:":    "Seccomp: 2",
	}
	seen := map[string]int{}
	for _, line := range strings.Split(text, "\n") {
		for key, w := range want {
			if strings.HasPrefix(line, key) {
				seen[key]++
				if line != w {
					t.Fatalf("thread %s, want %s\n%s", line, w, text)
				}
			}
		}
	}
	// Every thread printed every line, and there was more than one thread.
	for key := range want {
		if seen[key] < 2 || seen[key] != seen["Uid:"] {
			t.Fatalf("%s seen %d times (Uid %d)\n%s", key, seen[key], seen["Uid:"], text)
		}
	}
}
