//go:build linux

package containerd

// Regression tests for the review of the first unpacker (Q3): a neighbour
// running as the same uid grabbed the folder through /proc in the moment
// after exec, kept writing after the parent's check, and could outlive the
// child. Most need root to switch uids, so they run in the Docker run of
// this suite and skip elsewhere.

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/docker"
)

// runUnpackTestHelper is the helper half of this test binary, picked by
// unpackTestHelperEnv (see TestMain).
func runUnpackTestHelper(mode string) int {
	switch mode {
	case "attacker":
		runNeighbourAttacker()
		return 0
	case "holder":
		return runFolderHolder()
	case "deepchain":
		// A broken child: it ignores the tar and leaves a folder chain far
		// past the depth cap in the folder on fd 3.
		if err := makeChainAt(3, deepChainLevels); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	}
	fmt.Fprintf(os.Stderr, "unknown helper mode %q\n", mode)
	return 2
}

// runNeighbourAttacker is the reviewer's proof of concept, unchanged in what
// it does: watch /proc for an unpacker, try to open its folder (fd 3) and its
// tar (fd 0), and if it gets the folder, drop a pipe and a file into it once
// the parent's check has passed. It prints GOT or MISS, with the unpacker's
// uid, for each unpacker it sees. It runs until killed.
func runNeighbourAttacker() {
	seen := map[string]bool{}
	for {
		ents, _ := os.ReadDir("/proc")
		for _, e := range ents {
			pid := e.Name()
			if pid[0] < '0' || pid[0] > '9' || seen[pid] {
				continue
			}
			cmdline, err := os.ReadFile("/proc/" + pid + "/cmdline")
			if err != nil || !bytes.Contains(cmdline, []byte(ContextUnpackFlag)) {
				continue
			}
			seen[pid] = true
			uid := procUID(pid)
			for _, fd := range []string{"3", "0"} {
				f, err := os.Open("/proc/" + pid + "/fd/" + fd)
				if err != nil {
					fmt.Printf("MISS pid=%s fd=%s uid=%s err=%v\n", pid, fd, uid, err)
					continue
				}
				fmt.Printf("GOT pid=%s fd=%s uid=%s\n", pid, fd, uid)
				if fd == "3" {
					go func(f *os.File) {
						time.Sleep(400 * time.Millisecond)
						e1 := unix.Mkfifoat(int(f.Fd()), "evil-fifo", 0o644)
						e2 := os.WriteFile(fmt.Sprintf("/proc/self/fd/%d/injected.txt", f.Fd()), []byte("from a neighbour\n"), 0o644)
						fmt.Printf("WROTE fifo=%v file=%v\n", e1, e2)
					}(f)
				}
			}
		}
	}
}

// procUID is the real uid on a /proc/<pid>/status Uid line, or "" if the
// process is already gone.
func procUID(pid string) string {
	raw, err := os.ReadFile("/proc/" + pid + "/status")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if f := strings.Fields(line); len(f) > 1 && f[0] == "Uid:" {
			return f[1]
		}
	}
	return ""
}

// runFolderHolder holds the folders on fds 3 and 4 the way a descriptor that
// outlived the unpacker would. It writes a file through each, says "ready",
// waits for a line on stdin (the parent locks the tree down meanwhile), then
// tries to add a pipe and a file and to chmod each folder back open.
func runFolderHolder() int {
	for _, fd := range []int{3, 4} {
		f, err := unix.Openat(fd, fmt.Sprintf("before-%d", fd), unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY, 0o644)
		if err == nil {
			_ = unix.Close(f)
		}
		fmt.Printf("before fd%d file=%v\n", fd, err)
	}
	fmt.Println("ready")
	if _, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil {
		return 1
	}
	for _, fd := range []int{3, 4} {
		fmt.Printf("after fd%d fifo=%v\n", fd, unix.Mkfifoat(fd, "evil-fifo", 0o644))
		f, err := unix.Openat(fd, "injected.txt", unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY, 0o644)
		if err == nil {
			_ = unix.Close(f)
		}
		fmt.Printf("after fd%d file=%v\n", fd, err)
		fmt.Printf("after fd%d chmod=%v\n", fd, unix.Fchmod(fd, 0o777))
	}
	return 0
}

// The proof of concept, as a regression test: a neighbour running as
// nobody watches every build and never gets the folder or the tar, and
// nothing it writes reaches buildctl. Each unpacker it sees runs as an id
// from the reserved range.
func TestUnpackNeighbourCannotReachTheChild(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to run the unpacker and the neighbour as other uids")
	}
	ids := childUnpackFixture(t)
	listing := filepath.Join(t.TempDir(), "listing")
	buildctl := writeScript(t, t.TempDir(), "buildctl", `for a in "$@"; do case "$a" in context=*) ctx="${a#context=}";; esac; done
/usr/bin/sleep 0.3
/usr/bin/ls -la "$ctx" >> "`+listing+`"
echo --- >> "`+listing+`"
`)
	// Enough entries that each unpacker lives long enough to be seen.
	data := tarWith(t, func(tw *tar.Writer) {
		for i := range 2000 {
			_ = tw.WriteHeader(&tar.Header{Name: fmt.Sprintf("d%d/f%d", i%20, i), Mode: 0o644, Size: 1, Typeflag: tar.TypeReg})
			_, _ = tw.Write([]byte("x"))
		}
	})

	attacker := exec.Command(unpackTestExe)
	attacker.Env = []string{unpackTestHelperEnv + "=attacker"}
	var seen bytes.Buffer
	attacker.Stdout = &seen
	attacker.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
	if err := attacker.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	b := childBuilder(ids, buildctl)
	for i := range 10 {
		if err := b.BuildImage(context.Background(), docker.BuildImageRequest{
			Tag: "built:poc", DockerfileContent: "FROM scratch", ContextTar: data,
		}); err != nil {
			t.Fatalf("build %d: %v", i, err)
		}
	}
	time.Sleep(600 * time.Millisecond) // any write the neighbour got in would have landed
	_ = attacker.Process.Kill()
	_ = attacker.Wait()

	var misses int
	for _, line := range strings.Split(strings.TrimSpace(seen.String()), "\n") {
		switch {
		case strings.HasPrefix(line, "GOT") || strings.HasPrefix(line, "WROTE"):
			t.Fatalf("the neighbour reached an unpacker: %s", line)
		case strings.HasPrefix(line, "MISS"):
			misses++
			if !strings.Contains(line, "permission denied") && !strings.Contains(line, "no such file") {
				t.Fatalf("unexpected refusal: %s", line)
			}
			uid := strings.TrimPrefix(strings.Fields(line)[3], "uid=")
			if uid == "" {
				continue // gone before the neighbour read its status
			}
			n, err := strconv.Atoi(uid)
			if err != nil || n < ids.uidBase || n >= ids.uidBase+config.BuildContextIDCount {
				t.Fatalf("an unpacker ran as uid %q, outside the reserved range: %s", uid, line)
			}
		}
	}
	if misses == 0 {
		t.Fatalf("the neighbour never saw an unpacker, so this proved nothing; it printed %q", seen.String())
	}
	got, _ := os.ReadFile(listing)
	if bytes.Contains(got, []byte("evil-fifo")) || bytes.Contains(got, []byte("injected")) {
		t.Fatalf("buildctl saw what the neighbour wrote:\n%s", got)
	}
	t.Logf("the neighbour saw %d unpacker descriptors and opened none", misses)
}

// A descriptor that outlives the child (handed to another process, say) can
// write to the folder until the parent takes it back, and not after: once
// lockDownContext is done every folder is root's without group or other
// write, so nothing can be added and no mode put back.
func TestLockDownContextShutsOutAHeldDescriptor(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to hand the folder to another uid")
	}
	const id = config.DefaultBuildContextIDBase + config.BuildContextIDCount - 1
	dir := filepath.Join(t.TempDir(), "context")
	sub := filepath.Join(dir, "sub")
	for _, d := range []string{dir, sub} {
		if err := os.Mkdir(d, 0o777); err != nil {
			t.Fatal(err)
		}
		// Mkdir is subject to the umask; the child could chmod its own folders wide open.
		if err := os.Chmod(d, 0o777); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(d, id, id); err != nil {
			t.Fatal(err)
		}
	}
	var held []*os.File
	for _, d := range []string{dir, sub} {
		f, err := os.Open(d)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		held = append(held, f)
	}

	holder := exec.Command(unpackTestExe)
	holder.Env = []string{unpackTestHelperEnv + "=holder"}
	holder.ExtraFiles = held
	holder.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: id, Gid: id}}
	stdin, err := holder.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := holder.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := holder.Start(); err != nil {
		t.Fatal(err)
	}
	lines := bufio.NewScanner(stdout)
	var before, after []string
	for lines.Scan() && lines.Text() != "ready" {
		before = append(before, lines.Text())
	}
	if err := lockDownContext(context.Background(), dir); err != nil {
		t.Fatalf("lockDownContext: %v", err)
	}
	_, _ = stdin.Write([]byte("go\n"))
	for lines.Scan() {
		after = append(after, lines.Text())
	}
	if err := holder.Wait(); err != nil {
		t.Fatalf("holder: %v", err)
	}

	if len(before) != 2 || !strings.HasSuffix(before[0], "file=<nil>") || !strings.HasSuffix(before[1], "file=<nil>") {
		t.Fatalf("the holder could not write before the lockdown, so this proved nothing: %q", before)
	}
	if len(after) != 6 {
		t.Fatalf("holder said %q", after)
	}
	for _, line := range after {
		if strings.HasSuffix(line, "=<nil>") {
			t.Fatalf("after the lockdown the holder still could: %s", line)
		}
	}
	for path, want := range map[string]string{dir: "0:0 drwx------", sub: "0:0 drwxr-xr-x", filepath.Join(sub, "before-4"): "0:0 -rw-r--r--"} {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		st := info.Sys().(*syscall.Stat_t)
		if got := fmt.Sprintf("%d:%d %v", st.Uid, st.Gid, info.Mode()); got != want {
			t.Fatalf("%s = %s, want %s", path, got, want)
		}
	}
}

// The child runs as the ids it was given, with no other groups, as PID 1 of
// a PID namespace of its own (root only), which the stand-in shows by saying
// who it is.
func TestUnpackContextInChildIDsAndPIDNamespace(t *testing.T) {
	ids := childUnpackFixture(t)
	uid, gid := ids.uidBase, ids.gidBase
	whoami := writeScript(t, worldDir(t), "whoami", `echo "ids=$(/usr/bin/id -u):$(/usr/bin/id -g) groups=$(/usr/bin/id -G) pid=$$" >&2
exit 1
`)
	orig := contextUnpackExe
	t.Cleanup(func() { contextUnpackExe = orig })
	contextUnpackExe = func() (string, error) { return whoami, nil }
	err := unpackContextInChild(context.Background(), nil, filepath.Join(t.TempDir(), "context"), uid, gid)
	want := fmt.Sprintf("ids=%d:%d", uid, gid)
	if os.Geteuid() == 0 {
		want += fmt.Sprintf(" groups=%d pid=1", gid)
	}
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("child said %v, want %q", err, want)
	}
}

// Nothing the child starts outlives it. As root the child is PID 1 of its
// own namespace, so its exit kills the rest and the wait returns at once; a
// test that is not root has no namespace, and WaitDelay stops the wait on a
// leftover that holds stderr.
func TestUnpackContextInChildLeavesNothingRunning(t *testing.T) {
	ids := childUnpackFixture(t)
	marker := fmt.Sprintf("29.%d", os.Getpid())
	forker := writeScript(t, worldDir(t), "forker", "/usr/bin/sleep "+marker+" &\nexit 0\n")
	origExe, origDelay := contextUnpackExe, contextUnpackWaitDelay
	t.Cleanup(func() { contextUnpackExe, contextUnpackWaitDelay = origExe, origDelay })
	contextUnpackExe = func() (string, error) { return forker, nil }
	contextUnpackWaitDelay = time.Second
	t.Cleanup(func() {
		for _, pid := range pidsWithArg(marker) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	})

	start := time.Now()
	err := unpackContextInChild(context.Background(), nil, filepath.Join(t.TempDir(), "context"), ids.uidBase, ids.gidBase)
	took := time.Since(start)
	if os.Geteuid() == 0 {
		if err != nil || took > 900*time.Millisecond {
			t.Fatalf("unpack = %v after %v; want nil at once", err, took)
		}
		if pids := pidsWithArg(marker); len(pids) != 0 {
			t.Fatalf("the child's sleep outlived it: pids %v", pids)
		}
		return
	}
	if !errors.Is(err, exec.ErrWaitDelay) || took > 3*time.Second {
		t.Fatalf("unpack = %v after %v; want ErrWaitDelay after about a second", err, took)
	}
}

// pidsWithArg lists the live processes with arg on their command line.
func pidsWithArg(arg string) []int {
	var pids []int
	ents, _ := os.ReadDir("/proc")
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		raw, err := os.ReadFile("/proc/" + e.Name() + "/cmdline")
		if err == nil && bytes.Contains(raw, []byte(arg)) {
			pids = append(pids, pid)
		}
	}
	return pids
}

// A tar that carries one name twice, the first copy read-only (tar -r, a
// repo's .git/objects), unpacks in the child, which is not root: the later
// copy replaces the first.
func TestBuildImageChildReplacesReadOnlyDuplicate(t *testing.T) {
	ids := childUnpackFixture(t)
	out := filepath.Join(t.TempDir(), "seen")
	buildctl := writeScript(t, t.TempDir(), "buildctl", `for a in "$@"; do case "$a" in context=*) ctx="${a#context=}";; esac; done
/usr/bin/cat "$ctx/obj/f" > "`+out+`"
`)
	if err := childBuilder(ids, buildctl).BuildImage(context.Background(), docker.BuildImageRequest{
		Tag: "built:dup", DockerfileContent: "FROM scratch", ContextTar: readOnlyDuplicateTar(t),
	}); err != nil {
		t.Fatalf("BuildImage: %v", err)
	}
	if got, _ := os.ReadFile(out); string(got) != "two" {
		t.Fatalf("buildctl saw %q, want the later copy", got)
	}
}

// The second review's first proof of concept: a tar with one folder entry
// thousands of levels deep made the parent's lockdown take minutes (it
// re-walked the path per level) past the build's timeout, holding its id.
// Now the child refuses such names at once: past PATH_MAX by length, below
// it by depth.
func TestBuildImageChildRefusesDeepTree(t *testing.T) {
	ids := childUnpackFixture(t)
	for _, tc := range []struct {
		levels int
		want   string
	}{
		{8000, "longer than 4096 bytes"},
		{2000, "nested deeper than 256 folders"},
	} {
		data := tarWith(t, func(tw *tar.Writer) {
			_ = tw.WriteHeader(&tar.Header{Name: strings.Repeat("a/", tc.levels), Mode: 0o755, Typeflag: tar.TypeDir})
		})
		tmp := emptyTempDir(t)
		start := time.Now()
		err := childBuilder(ids, "/bin/true").BuildImage(context.Background(),
			docker.BuildImageRequest{Tag: "built:deep", DockerfileContent: "FROM scratch", ContextTar: data})
		if took := time.Since(start); err == nil || !strings.Contains(err.Error(), tc.want) || took > 5*time.Second {
			t.Fatalf("%d levels: %v after %v; want %q at once", tc.levels, err, took, tc.want)
		}
		assertEmptyDir(t, tmp)
	}
}

// The second review's other proof of concept: a broken child hard-links a
// host file into its folder. The parent refuses the link before it touches
// anything, so the host file keeps its owner and mode.
func TestBuildImageChildHardLinkLeavesHostFileAlone(t *testing.T) {
	ids := childUnpackFixture(t)
	world := worldDir(t)
	victim := victimFile(t, world)
	before := ownerMode(t, victim)
	evil := writeScript(t, world, "evil-child", "/bin/ln "+victim+" /proc/self/fd/3/victim-link || exit 9\nexit 0\n")
	orig := contextUnpackExe
	t.Cleanup(func() { contextUnpackExe = orig })
	contextUnpackExe = func() (string, error) { return evil, nil }
	tmp := emptyTempDir(t)
	err := childBuilder(ids, "/bin/true").BuildImage(context.Background(), docker.BuildImageRequest{
		Tag: "built:link", DockerfileContent: "FROM scratch", ContextTar: readOnlyDuplicateTar(t),
	})
	if err == nil || !strings.Contains(err.Error(), `"victim-link" is a hard link`) {
		t.Fatalf("BuildImage = %v; want the link refused", err)
	}
	if got := ownerMode(t, victim); got != before {
		t.Fatalf("the host file changed: %s, was %s", got, before)
	}
	assertEmptyDir(t, tmp)
}

// The daemon-start check finds a sandboxd the unpack ids cannot run, and the
// warning names what to change.
func TestCheckContextUnpacker(t *testing.T) {
	origIn, origNS := unpackInChild, pidNamespaceAllowed
	t.Cleanup(func() { unpackInChild, pidNamespaceAllowed = origIn, origNS })
	unpackInChild = func() bool { return true }
	pidNamespaceAllowed = func() bool { return true }
	world := worldDir(t)
	write := func(path string, mode os.FileMode) string {
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	ok := write(filepath.Join(world, "sandboxd"), 0o755)
	private := write(filepath.Join(world, "private"), 0o750)
	closedDir := filepath.Join(world, "closed")
	if err := os.Mkdir(closedDir, 0o700); err != nil {
		t.Fatal(err)
	}
	inClosed := write(filepath.Join(closedDir, "sandboxd"), 0o755)

	if err := checkRunnableByOthers(ok); err != nil {
		t.Fatalf("a 0755 binary under /tmp: %v", err)
	}
	if err := checkRunnableByOthers(private); err == nil || !strings.Contains(err.Error(), "other users cannot run it") {
		t.Fatalf("a 0750 binary: %v", err)
	}
	if err := checkRunnableByOthers(inClosed); err == nil || !strings.Contains(err.Error(), closedDir+" is mode drwx------: other users cannot enter it") {
		t.Fatalf("a binary in a 0700 folder: %v", err)
	}
	if err := checkRunnableByOthers(filepath.Join(world, "missing")); err == nil {
		t.Fatal("a missing binary must fail")
	}

	var logs bytes.Buffer
	b := NewBuildKitBuilder("", "", slog.New(slog.NewTextHandler(&logs, nil)))
	orig := contextUnpackExe
	t.Cleanup(func() { contextUnpackExe = orig })
	contextUnpackExe = func() (string, error) { return inClosed, nil }
	if err := b.CheckContextUnpacker(); err == nil || !strings.Contains(logs.String(), "--install-prefix") || !strings.Contains(logs.String(), closedDir) {
		t.Fatalf("CheckContextUnpacker = %v, logged %q", err, logs.String())
	}
	contextUnpackExe = func() (string, error) { return "", errors.New("no binary") }
	if err := b.CheckContextUnpacker(); err == nil || !strings.Contains(err.Error(), "find the sandboxd binary") {
		t.Fatalf("exe lookup failure: %v", err)
	}
	logs.Reset()
	contextUnpackExe = func() (string, error) { return ok, nil }
	if err := b.CheckContextUnpacker(); err != nil || logs.Len() != 0 {
		t.Fatalf("CheckContextUnpacker = %v, logged %q; want silence", err, logs.String())
	}

	// Without CAP_SYS_ADMIN no unpack can start, and the warning says so.
	pidNamespaceAllowed = func() bool { return false }
	if err := b.CheckContextUnpacker(); err == nil || !strings.Contains(logs.String(), "CAP_SYS_ADMIN") {
		t.Fatalf("CheckContextUnpacker = %v, logged %q", err, logs.String())
	}
}

// haveCapSysAdmin agrees with the kernel's own account in /proc/self/status.
func TestHaveCapSysAdmin(t *testing.T) {
	raw, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Skip(err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if f := strings.Fields(line); len(f) == 2 && f[0] == "CapEff:" {
			eff, err := strconv.ParseUint(f[1], 16, 64)
			if err != nil {
				t.Fatal(err)
			}
			if want := eff&(1<<unix.CAP_SYS_ADMIN) != 0; haveCapSysAdmin() != want {
				t.Fatalf("haveCapSysAdmin = %v, CapEff %s says %v", !want, f[1], want)
			}
			return
		}
	}
	t.Fatal("no CapEff line")
}
