//go:build linux

package rootd

// F10 on the real kernel, in both privilege modes (M1 PR 6): memory
// pressure kills one sandbox, whole, and never the machinery. As root, on
// a cgroup v2 mount the test can write: a privileged container with its
// own cgroup namespace, whose root's processes were first moved into a
// child so the root can hand the memory controller down:
//
//	mkdir /sys/fs/cgroup/init
//	for p in $(cat /sys/fs/cgroup/cgroup.procs); do echo $p > /sys/fs/cgroup/init/cgroup.procs; done
//	echo "+cpu +memory +pids" > /sys/fs/cgroup/cgroup.subtree_control
//	go test -run 'TestKernelF10' -v ./internal/rootd/
//
// The test lays out the worker pod's groups (internal/supervisor) under a
// group of its own, with stand-in processes:
//
//	aerol-f10-<pid>/                memory.oom.group 0
//	├── supervisor/                 "supervisor" and "sandboxd"
//	└── sandboxes/                  the parent: memory.max 512 MiB, oom.group 0
//	    ├── _runtime/               "containerd", holding 192 MiB; oom.group 0
//	    │   └── aerolvm-rootd/      "helper"
//	    ├── sb-a/                   a sandbox: a 96 MiB "sentry", a "hog"
//	    └── sb-b/                   a sandbox: a 16 MiB "sentry"
//
// Everything starts at the machinery's OOM score, -999: gVisor's processes
// inherit the shim's. The hog then fills a memfd until the parent's limit
// is hit: memory charged to sb-a that sits in no process's RSS, as a
// gVisor sandbox's memory file does, so killing the hog alone is not what
// the kernel picks. Three legs:
//
//   - unmarked: the kernel picks the biggest process, containerd, which is
//     what F10 found on EKS;
//   - single: the containerd driver marks both sandboxes in process;
//   - split: the same driver marks them through the helper's cgroup part,
//     over the helper's socket.
//
// Marked, one event kills sb-a whole (a process started after the marks
// included) and nothing else.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/aerol-ai/microvm/internal/rootclient"
	cntr "github.com/aerol-ai/microvm/internal/runtime/containerd"
)

const (
	f10RoleEnv = "AEROL_F10_ROLE"
	f10CapMiB  = 512
)

// TestKernelF10Child is re-executed as each stand-in process:
// "hold:<MiB>" touches that much memory and waits; "hog" waits for a line
// on stdin, then fills a memfd until it is killed.
func TestKernelF10Child(t *testing.T) {
	role := os.Getenv(f10RoleEnv)
	if role == "" {
		t.Skip("a stand-in process only")
	}
	in := bufio.NewReader(os.Stdin)
	if mib, ok := strings.CutPrefix(role, "hold:"); ok {
		n, _ := strconv.Atoi(mib)
		keep := make([]byte, n<<20)
		for i := 0; i < len(keep); i += 4096 {
			keep[i] = 1
		}
		fmt.Println("READY")
		_, _ = in.ReadString('\n')
		keep[0] = 2 // kept alive until here
		os.Exit(0)
	}
	fd, err := unix.MemfdCreate("aerol-f10-hog", 0)
	if err != nil {
		fmt.Println("memfd:", err)
		os.Exit(1)
	}
	fmt.Println("READY")
	if _, err := in.ReadString('\n'); err != nil {
		os.Exit(0)
	}
	chunk := make([]byte, 1<<20)
	for i := range chunk {
		chunk[i] = byte(i)
	}
	for off := int64(0); ; off += int64(len(chunk)) {
		if _, err := unix.Pwrite(fd, chunk, off); err != nil {
			fmt.Println("write:", err)
			os.Exit(1)
		}
	}
}

// f10Proc is one stand-in.
type f10Proc struct {
	name  string
	cmd   *exec.Cmd
	stdin io.WriteCloser
	done  chan struct{}
	err   error
}

func (p *f10Proc) dead() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

// f10Layout is the groups above, under the cgroup mount.
type f10Layout struct {
	t      *testing.T
	base   string // "/aerol-f10-<pid>", as the kernel names it
	procs  []*f10Proc
	groups []string // made, in order
}

func (l *f10Layout) dir(group string) string {
	return filepath.Join(defaultCgroupRoot, filepath.FromSlash(group))
}

func (l *f10Layout) parent() string { return l.base + "/sandboxes" }

func (l *f10Layout) mkdir(group string) {
	l.t.Helper()
	if err := os.Mkdir(l.dir(group), 0o755); err != nil {
		l.t.Fatalf("make %s (see the comment at the top): %v", group, err)
	}
	l.groups = append(l.groups, group)
}

func (l *f10Layout) write(group, file, value string) {
	l.t.Helper()
	if err := os.WriteFile(filepath.Join(l.dir(group), file), []byte(value), 0o644); err != nil {
		l.t.Fatalf("write %s/%s=%q (see the comment at the top): %v", group, file, value, err)
	}
}

func (l *f10Layout) read(group, file string) string {
	l.t.Helper()
	raw, err := os.ReadFile(filepath.Join(l.dir(group), file))
	if err != nil {
		l.t.Fatal(err)
	}
	return strings.TrimSpace(string(raw))
}

// event reads one counter of a group's memory.events; -1 when this
// kernel has no such counter (oom_group_kill came in Linux 5.17).
func (l *f10Layout) event(group, key string) int {
	l.t.Helper()
	for line := range strings.SplitSeq(l.read(group, "memory.events"), "\n") {
		if k, v, ok := strings.Cut(line, " "); ok && k == key {
			n, _ := strconv.Atoi(v)
			return n
		}
	}
	return -1
}

// killed: the stand-in died of SIGKILL, the out-of-memory killer's signal.
func (p *f10Proc) killed() bool {
	var ee *exec.ExitError
	if !p.dead() || !errors.As(p.err, &ee) {
		return false
	}
	ws, ok := ee.Sys().(syscall.WaitStatus)
	return ok && ws.Signaled() && ws.Signal() == syscall.SIGKILL
}

// newF10Layout makes the groups and settings above.
func newF10Layout(t *testing.T) *f10Layout {
	t.Helper()
	needRoot(t)
	if _, err := os.Stat(filepath.Join(defaultCgroupRoot, "cgroup.controllers")); err != nil {
		t.Skip("needs cgroup v2 at /sys/fs/cgroup")
	}
	l := &f10Layout{t: t, base: fmt.Sprintf("/aerol-f10-%d-%s", os.Getpid(), shortID(t))}
	t.Cleanup(l.cleanup)
	l.mkdir(l.base)
	l.write(l.base, "cgroup.subtree_control", "+memory +pids")
	l.mkdir(l.base + "/supervisor")
	l.mkdir(l.parent())
	l.write(l.parent(), "cgroup.subtree_control", "+memory +pids")
	l.write(l.parent(), "memory.max", strconv.Itoa(f10CapMiB<<20))
	if _, err := os.Stat(filepath.Join(l.dir(l.parent()), "memory.swap.max")); err == nil {
		l.write(l.parent(), "memory.swap.max", "0")
	}
	for _, g := range []string{"/_runtime", "/_runtime/aerolvm-rootd", "/sb-a", "/sb-b"} {
		l.mkdir(l.parent() + g)
	}
	// The supervisor keeps group kills off above the sandboxes' own.
	for _, g := range []string{l.base, l.parent(), l.parent() + "/_runtime"} {
		l.write(g, "memory.oom.group", "0")
	}
	return l
}

// start runs a stand-in in group at OOM score -999.
func (l *f10Layout) start(name, group, role string) *f10Proc {
	l.t.Helper()
	fd, err := os.Open(l.dir(group))
	if err != nil {
		l.t.Fatal(err)
	}
	defer fd.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestKernelF10Child$")
	cmd.Env = append(os.Environ(), f10RoleEnv+"="+role)
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(fd.Fd())}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		l.t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		l.t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		l.t.Fatalf("start %s: %v", name, err)
	}
	p := &f10Proc{name: name, cmd: cmd, stdin: stdin, done: make(chan struct{})}
	l.procs = append(l.procs, p)
	ready := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(out).ReadString('\n')
		ready <- strings.TrimSpace(line)
		_, _ = io.Copy(io.Discard, out)
	}()
	select {
	case line := <-ready:
		if line != "READY" {
			l.t.Fatalf("%s: %q", name, line)
		}
	case <-time.After(30 * time.Second):
		l.t.Fatalf("%s never got ready", name)
	}
	go func() { p.err = cmd.Wait(); close(p.done) }()
	if err := os.WriteFile(fmt.Sprintf("/proc/%d/oom_score_adj", cmd.Process.Pid), []byte("-999"), 0); err != nil {
		l.t.Fatal(err)
	}
	return p
}

func (l *f10Layout) cleanup() {
	for _, p := range l.procs {
		_ = p.cmd.Process.Kill()
		<-p.done
	}
	for i := len(l.groups) - 1; i >= 0; i-- {
		for range 50 {
			if err := os.Remove(l.dir(l.groups[i])); err == nil || errors.Is(err, os.ErrNotExist) {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
}

// f10Run is one leg: mark (nil for none), then the pressure. It answers
// the stand-ins by name, once the event is over.
func f10Run(t *testing.T, mark func(l *f10Layout, ctx context.Context) error) (*f10Layout, map[string]*f10Proc) {
	t.Helper()
	l := newF10Layout(t)
	byName := map[string]*f10Proc{}
	for _, s := range []struct{ name, group, role string }{
		{"supervisor", l.base + "/supervisor", "hold:1"},
		{"sandboxd", l.base + "/supervisor", "hold:8"},
		{"containerd", l.parent() + "/_runtime", "hold:192"},
		{"helper", l.parent() + "/_runtime/aerolvm-rootd", "hold:1"},
		{"sb-a sentry", l.parent() + "/sb-a", "hold:96"},
		{"sb-a hog", l.parent() + "/sb-a", "hog"},
		{"sb-b sentry", l.parent() + "/sb-b", "hold:16"},
	} {
		byName[s.name] = l.start(s.name, s.group, s.role)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if mark != nil {
		if err := mark(l, ctx); err != nil {
			t.Fatalf("mark: %v", err)
		}
	}
	// gVisor starts some processes after the marks: still -999.
	byName["sb-a late"] = l.start("sb-a late", l.parent()+"/sb-a", "hold:1")
	if _, err := io.WriteString(byName["sb-a hog"].stdin, "go\n"); err != nil {
		t.Fatal(err)
	}
	// The event is over once the hog is gone; unmarked, the kernel takes
	// containerd first, and the leg stops there.
	select {
	case <-byName["sb-a hog"].done:
	case <-byName["containerd"].done:
		if mark == nil {
			break
		}
		t.Fatal("the kernel killed containerd")
	case <-time.After(60 * time.Second):
		t.Fatal("no out-of-memory event within a minute")
	}
	time.Sleep(200 * time.Millisecond) // a group kill's last exits
	return l, byName
}

func TestKernelF10(t *testing.T) {
	marks := func(d *cntr.Driver) func(*f10Layout, context.Context) error {
		return func(l *f10Layout, ctx context.Context) error {
			for _, g := range []string{"/sb-a", "/sb-b"} {
				if err := d.MarkOOMVictim(ctx, l.parent()+g); err != nil {
					return err
				}
			}
			return nil
		}
	}
	t.Run("unmarked, the machinery dies", func(t *testing.T) {
		l, p := f10Run(t, nil)
		if !p["containerd"].killed() || l.event(l.parent()+"/_runtime", "oom_kill") < 1 {
			t.Fatalf("containerd lives (%v): this test would not see F10", p["containerd"].err)
		}
		t.Logf("unmarked: the kernel killed containerd first (%v), as F10 found", p["containerd"].err)
	})
	check := func(t *testing.T, l *f10Layout, p map[string]*f10Proc) {
		t.Helper()
		sbA := l.parent() + "/sb-a"
		// One event takes the whole sandbox: each of its processes is
		// killed, the late one too, while sb-b, the next in line if the
		// kernel killed one process at a time, lives.
		for _, name := range []string{"sb-a sentry", "sb-a hog", "sb-a late"} {
			if !p[name].killed() {
				t.Errorf("%s was not killed (%v): the sandbox was not killed whole", name, p[name].err)
			}
		}
		if n := l.event(sbA, "oom_kill"); n < 3 {
			t.Errorf("sb-a: %d out-of-memory kills, want one for each of its 3 processes", n)
		}
		for _, name := range []string{"supervisor", "sandboxd", "containerd", "helper", "sb-b sentry"} {
			if p[name].dead() {
				t.Errorf("%s died (%v)", name, p[name].err)
			}
		}
		if l.read(sbA, "cgroup.procs") != "" || l.event(sbA, "oom_group_kill") == 0 {
			t.Errorf("sb-a: procs %q, oom_group_kill %d", l.read(sbA, "cgroup.procs"), l.event(sbA, "oom_group_kill"))
		}
		if n := l.event(l.parent()+"/_runtime", "oom_kill"); n != 0 {
			t.Errorf("%d kills in the machinery's group", n)
		}
		if l.read(l.parent(), "memory.oom.group") != "0" || l.read(l.parent()+"/_runtime", "memory.oom.group") != "0" {
			t.Error("a group above the sandboxes was marked")
		}
		t.Logf("sb-a: oom_kill %d, oom_group_kill %d (-1: not on this kernel); its 3 processes killed, every other process lives",
			l.event(sbA, "oom_kill"), l.event(sbA, "oom_group_kill"))
	}
	t.Run("scores alone, a sandbox dies in part", func(t *testing.T) {
		// Half of the mark, by hand: the scores without memory.oom.group.
		// The kernel then kills one process at a time: sb-a's sentry
		// frees nothing of the hog's file, and sb-b goes next.
		_, p := f10Run(t, func(l *f10Layout, _ context.Context) error {
			for _, g := range []string{"/sb-a", "/sb-b"} {
				procs := strings.Fields(l.read(l.parent()+g, "cgroup.procs"))
				for _, pid := range procs {
					if err := os.WriteFile("/proc/"+pid+"/oom_score_adj", []byte("500"), 0); err != nil {
						return err
					}
				}
			}
			return nil
		})
		if !p["sb-b sentry"].killed() && p["sb-a late"].killed() {
			t.Fatal("without memory.oom.group the sandbox still died whole: this test would not see the group setting")
		}
		t.Logf("scores alone: sb-b killed %v, sb-a's late process killed %v", p["sb-b sentry"].killed(), p["sb-a late"].killed())
	})
	t.Run("single", func(t *testing.T) {
		var d *cntr.Driver
		l, p := f10Run(t, func(l *f10Layout, ctx context.Context) error {
			d = cntr.New(cntr.Config{CgroupParent: l.parent()}, nil, nil)
			return marks(d)(l, ctx)
		})
		check(t, l, p)
	})
	t.Run("split", func(t *testing.T) {
		l, p := f10Run(t, func(l *f10Layout, ctx context.Context) error {
			r := newRig(t, func(c *Config, _ *Options) { c.Policy.CgroupParent = l.parent() })
			c := rootclient.New(rootclient.Config{Socket: r.cfg.Socket, HelperUID: uint32(os.Geteuid())})
			t.Cleanup(func() { _ = c.Close() })
			d := cntr.New(cntr.Config{CgroupParent: l.parent()}, nil, nil)
			d.SetCgroupMarker(c)
			if err := marks(d)(l, ctx); err != nil {
				return err
			}
			// The broken agent, on the real kernel: the machinery's group
			// is refused, and stays as the supervisor set it.
			if err := c.MarkSandboxCgroup(ctx, "_runtime"); !errors.Is(err, rootclient.ErrRefused) {
				return fmt.Errorf("containerd's group: %v", err)
			}
			if got := l.read(l.parent()+"/_runtime", "memory.oom.group"); got != "0" {
				return fmt.Errorf("_runtime memory.oom.group = %s", got)
			}
			return nil
		})
		check(t, l, p)
	})
}

// f10Marked reads back a group's settings: memory.oom.group and every
// process's score in it and below.
func f10Marked(t testing.TB, group string) (string, []string) {
	t.Helper()
	dir := filepath.Join(defaultCgroupRoot, filepath.FromSlash(group))
	raw, err := os.ReadFile(filepath.Join(dir, "memory.oom.group"))
	if err != nil {
		t.Fatal(err)
	}
	var scores []string
	err = filepath.WalkDir(dir, func(p string, e os.DirEntry, err error) error {
		if err != nil || !e.IsDir() {
			return err
		}
		procs, err := os.ReadFile(path.Join(p, "cgroup.procs"))
		for _, pid := range strings.Fields(string(procs)) {
			s, _ := os.ReadFile("/proc/" + pid + "/oom_score_adj")
			scores = append(scores, strings.TrimSpace(string(s)))
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(raw)), scores
}
