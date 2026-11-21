//go:build linux

package containerd

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/docker"
)

// unpackTestExe is the binary helper processes run: this test binary, or as
// root a copy every uid can run (prepareUnpackChild).
var unpackTestExe = os.Args[0]

// prepareUnpackChild runs from TestMain. As root (the Docker run of this
// suite) every BuildImage with a context takes the child path as an id from
// the reserved range, which cannot run this test binary where go test built
// it, in a 0700 folder. Point the re-exec at a copy anyone can run.
func prepareUnpackChild() error {
	if os.Geteuid() != 0 {
		return nil
	}
	if rootWithoutPIDNamespace {
		unpackInChild = func() bool { return false }
		fmt.Fprintln(os.Stderr, "note: root without CAP_SYS_ADMIN: builds unpack in process and the child tests skip; run with --cap-add SYS_ADMIN to cover them")
	}
	dir, err := os.MkdirTemp("", "aerolvm-unpack-exe-")
	if err != nil {
		return err
	}
	afterTests = append(afterTests, func() { _ = os.RemoveAll(dir) })
	exe := filepath.Join(dir, "containerd.test")
	if err := copyFile(os.Args[0], exe, 0o755); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		return err
	}
	unpackTestExe = exe
	contextUnpackExe = func() (string, error) { return exe, nil }
	return nil
}

// rootWithoutPIDNamespace is a root run without CAP_SYS_ADMIN (a plain
// docker run). Root sandboxd on a host has it; without it the child cannot
// start, by design, so the child tests skip there.
var rootWithoutPIDNamespace = os.Geteuid() == 0 && !haveCapSysAdmin()

// testContextIDs are the ids a child runs as in tests. As root, the default
// reserved range. As anyone else (CI), the caller's own uid and gid, one
// unpack at a time, because only root may switch; the path under test (the
// re-exec, the folder handed over on fd 3, the tar on stdin, the child's
// guards, the lockdown and the walk after it) is the same.
func testContextIDs() *contextIDPool {
	if os.Geteuid() != 0 {
		return sharedContextIDPool(os.Getuid(), os.Getgid(), 1)
	}
	return sharedContextIDPool(config.DefaultBuildContextIDBase, config.DefaultBuildContextIDBase, config.BuildContextIDCount)
}

// childUnpackFixture forces the child path and returns the ids it runs as.
func childUnpackFixture(t *testing.T) *contextIDPool {
	t.Helper()
	if rootWithoutPIDNamespace {
		t.Skip("root without CAP_SYS_ADMIN cannot give the child its PID namespace; run with --cap-add SYS_ADMIN")
	}
	orig := unpackInChild
	t.Cleanup(func() { unpackInChild = orig })
	unpackInChild = func() bool { return true }
	return testContextIDs()
}

func childBuilder(ids *contextIDPool, buildctl string) *BuildKitBuilder {
	b := NewBuildKitBuilder("", buildctl, nil)
	b.contextIDs = ids
	return b
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// worldDir is a folder every uid can write to and reach, so a test proves
// the child did not write somewhere by what the child did, not by what its
// uid was allowed to do.
func worldDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "aerolvm-unpack-world-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	return dir
}

// writeScript writes a shell script. The unpacker's environment is empty, so
// scripts it runs name their commands by full path.
func writeScript(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// The context unpacks in a child, then comes back to the parent: the parent's
// temp folder and the context folder are 0700, everything is the parent's
// again, and modes are the tar's less group and other write. A symlink in the
// tar is not made, so a file named through it lands inside, not in the
// (writable) folder the link points at. The parent then writes the request's
// Dockerfile, runs buildctl, and removes everything.
func TestBuildImageUnpacksContextInUnprivilegedChild(t *testing.T) {
	ids := childUnpackFixture(t)
	outside := worldDir(t)
	out := filepath.Join(t.TempDir(), "seen")
	buildctl := writeScript(t, t.TempDir(), "buildctl", `for a in "$@"; do case "$a" in context=*) ctx="${a#context=}";; esac; done
{
  stat -c '%u:%g %a' "$(dirname "$ctx")" "$ctx" "$ctx/app" "$ctx/app/main.go" "$ctx/link" "$ctx/link/pwned"
  [ -L "$ctx/link" ] && echo link-is-a-symlink
  cat "$ctx/app/main.go"; echo
  cat "$ctx/Dockerfile"
} > "`+out+`"
`)
	tmp := emptyTempDir(t)
	data := tarWith(t, func(tw *tar.Writer) {
		_ = tw.WriteHeader(&tar.Header{Name: "app/", Mode: 0o777, Typeflag: tar.TypeDir})
		_ = tw.WriteHeader(&tar.Header{Name: "app/main.go", Mode: 0o666, Size: 5, Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte("hello"))
		_ = tw.WriteHeader(&tar.Header{Name: "Dockerfile", Mode: 0o644, Size: 11, Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte("FROM tenant"))
		_ = tw.WriteHeader(&tar.Header{Name: "link", Typeflag: tar.TypeSymlink, Linkname: outside})
		_ = tw.WriteHeader(&tar.Header{Name: "link/pwned", Mode: 0o644, Size: 1, Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte("x"))
	})
	if err := childBuilder(ids, buildctl).BuildImage(context.Background(), docker.BuildImageRequest{
		Tag: "built:child", DockerfileContent: "FROM request", ContextTar: data,
	}); err != nil {
		t.Fatalf("BuildImage: %v", err)
	}

	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	me := fmt.Sprintf("%d:%d", os.Geteuid(), os.Getegid())
	want := strings.Join([]string{
		me + " 700", // the parent's temp folder
		me + " 700", // the context folder
		me + " 755", // app/
		me + " 644", // app/main.go
		me + " 755", // link, made a folder
		me + " 644", // link/pwned, inside
		"hello",
		"FROM request",
	}, "\n") + "\n"
	if string(got) != want {
		t.Fatalf("buildctl saw:\n%s\nwant:\n%s", got, want)
	}
	assertEmptyDir(t, outside)
	assertEmptyDir(t, tmp)
}

// Every hostile tar the in-process unpacker refuses, the child refuses too,
// buildctl never runs, and nothing is left behind.
func TestBuildImageChildRefusesHostileContexts(t *testing.T) {
	file := func(name string, body []byte) func(*tar.Writer) {
		return func(tw *tar.Writer) {
			_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
			_, _ = tw.Write(body)
		}
	}
	for _, tc := range []struct {
		name    string
		data    func(t *testing.T) []byte
		entries int
		bytes   int64
		want    string
	}{
		{name: "absolute", data: func(t *testing.T) []byte { return tarWith(t, file("/etc/cron.d/pwn", []byte("x"))) }, want: "escapes context dir"},
		{name: "dotdot", data: func(t *testing.T) []byte { return tarWith(t, file("a/../../escape", []byte("x"))) }, want: "escapes context dir"},
		{name: "too many entries", entries: 3, want: "too many entries (max 3)", data: func(t *testing.T) []byte {
			return tarWith(t, func(tw *tar.Writer) {
				for i := range 5 {
					file(fmt.Sprintf("f%d", i), []byte("x"))(tw)
				}
			})
		}},
		{name: "too large", bytes: 16, want: "exceeds 16 bytes", data: func(t *testing.T) []byte {
			return tarWith(t, file("big.bin", bytes.Repeat([]byte("A"), 64)))
		}},
		{name: "corrupt", want: "invalid tar header", data: func(*testing.T) []byte {
			return bytes.Repeat([]byte{0x41}, 700)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ids := childUnpackFixture(t)
			if tc.entries > 0 {
				orig := maxContextEntries
				maxContextEntries = tc.entries
				t.Cleanup(func() { maxContextEntries = orig })
			}
			if tc.bytes > 0 {
				orig := maxContextTotalBytes
				maxContextTotalBytes = tc.bytes
				t.Cleanup(func() { maxContextTotalBytes = orig })
			}
			marker := filepath.Join(t.TempDir(), "ran")
			buildctl := writeScript(t, t.TempDir(), "buildctl", "touch "+marker+"\n")
			tmp := emptyTempDir(t)
			err := childBuilder(ids, buildctl).BuildImage(context.Background(),
				docker.BuildImageRequest{Tag: "built:bad", DockerfileContent: "FROM alpine", ContextTar: tc.data(t)})
			// "exit status 1": the refusal came from the child, not in process.
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "exit status 1") {
				t.Fatalf("BuildImage = %v, want the child's %q", err, tc.want)
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatal("buildctl ran after the unpack failed")
			}
			assertEmptyDir(t, tmp)
		})
	}
}

// The parent refuses a root owner before it makes anything or starts a child.
func TestUnpackContextInChildRefusesRootOwner(t *testing.T) {
	for _, ids := range [][2]int{{0, 1}, {1, 0}, {-1, 1}, {1, 1 << 32}} {
		dir := filepath.Join(t.TempDir(), "context")
		err := unpackContextInChild(context.Background(), nil, dir, ids[0], ids[1])
		if err == nil || !strings.Contains(err.Error(), "non-root") {
			t.Fatalf("uid %d gid %d: err = %v", ids[0], ids[1], err)
		}
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Fatalf("uid %d gid %d: the folder was made", ids[0], ids[1])
		}
	}
}

func TestUnpackContextInChildFailures(t *testing.T) {
	ids := childUnpackFixture(t)
	uid, gid := ids.uidBase, ids.gidBase
	scripts := worldDir(t)
	data := tarWith(t, func(tw *tar.Writer) {
		_ = tw.WriteHeader(&tar.Header{Name: "f", Mode: 0o644, Size: 1, Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte("x"))
	})
	origExe := contextUnpackExe
	t.Cleanup(func() { contextUnpackExe = origExe })
	run := func(ctx context.Context, exe string) error {
		if exe != "" {
			contextUnpackExe = func() (string, error) { return exe, nil }
		}
		return unpackContextInChild(ctx, data, filepath.Join(t.TempDir(), "context"), uid, gid)
	}

	contextUnpackExe = func() (string, error) { return "", errors.New("no binary") }
	if err := run(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "find the sandboxd binary") {
		t.Fatalf("exe lookup failure: %v", err)
	}
	contextUnpackExe = origExe

	if err := unpackContextInChild(context.Background(), data, t.TempDir(), uid, gid); !errors.Is(err, os.ErrExist) {
		t.Fatalf("existing folder: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := run(ctx, ""); err == nil || !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("cancelled: %v", err)
	}

	// A child that fails without a word still fails the unpack.
	if err := run(context.Background(), "/bin/false"); err == nil || !strings.Contains(err.Error(), "build context unpacker: exit status 1") {
		t.Fatalf("silent child: %v", err)
	}

	// A child that writes without end costs the daemon at most the cap.
	noisy := writeScript(t, scripts, "noisy", "/usr/bin/head -c 100000 /dev/zero | /usr/bin/tr '\\0' x >&2\nexit 3\n")
	err := run(context.Background(), noisy)
	if err == nil {
		t.Fatal("noisy child: want an error")
	}
	if msg := err.Error(); !strings.Contains(msg, "exit status 3") || len(msg) < contextUnpackStderrMax || len(msg) > contextUnpackStderrMax+64 {
		t.Fatalf("noisy child: %d bytes of error, %.80q", len(msg), msg)
	}

	// Only root can hand the folder to another uid.
	if os.Geteuid() != 0 {
		err := unpackContextInChild(context.Background(), data, filepath.Join(t.TempDir(), "context"), uid+1, gid)
		if err == nil || !strings.Contains(err.Error(), "hand the folder") {
			t.Fatalf("chown to another uid as non-root: %v", err)
		}
	}
}

// ownerMode is "uid:gid mode" of path, not following a link.
func ownerMode(t *testing.T, path string) string {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	st := info.Sys().(*syscall.Stat_t)
	return fmt.Sprintf("%d:%d %v", st.Uid, st.Gid, info.Mode())
}

// victimFile is a file outside the context, 0666 and (as root) owned by
// 1234, the way a host file a broken child links in would be.
func victimFile(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "victim")
	if err := os.WriteFile(path, []byte("host file\n"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(path, 1234, 1234); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

// What the child leaves is read by root, so the lockdown stops at anything
// extractTarStream does not make, and leaves that entry, and whatever it
// leads to, as it found it. A plain tree comes back as the parent's, with
// group and other write gone.
func TestLockDownContextRefusesWhatTheChildNeverMakes(t *testing.T) {
	me := fmt.Sprintf("%d:%d", os.Geteuid(), os.Getegid())
	mk := func(t *testing.T, extra func(dir string) error) string {
		dir := filepath.Join(t.TempDir(), "context")
		if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o777); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(dir, "sub"), 0o777); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "sub", "f"), []byte("x"), 0o666); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(dir, "sub", "f"), 0o666); err != nil {
			t.Fatal(err)
		}
		if extra != nil {
			if err := extra(dir); err != nil {
				t.Fatal(err)
			}
		}
		return dir
	}
	plain := mk(t, nil)
	if err := lockDownContext(context.Background(), plain); err != nil {
		t.Fatalf("plain tree: %v", err)
	}
	for path, want := range map[string]string{plain: me + " drwx------", plain + "/sub": me + " drwxr-xr-x", plain + "/sub/f": me + " -rw-r--r--"} {
		if got := ownerMode(t, path); got != want {
			t.Fatalf("%s = %s, want %s", path, got, want)
		}
	}

	victim := victimFile(t, t.TempDir())
	before := ownerMode(t, victim)
	for _, tc := range []struct {
		name  string
		extra func(dir string) error
		want  string
	}{
		{"symlink", func(dir string) error { return os.Symlink(victim, filepath.Join(dir, "sub", "l")) }, `"sub/l" is a symlink`},
		{"pipe", func(dir string) error { return unix.Mkfifo(filepath.Join(dir, "p"), 0o644) }, `"p" is a named pipe`},
		{"hard link out", func(dir string) error { return os.Link(victim, filepath.Join(dir, "sub", "h")) }, `"sub/h" is a hard link`},
		{"hard link in", func(dir string) error { return os.Link(filepath.Join(dir, "sub", "f"), filepath.Join(dir, "h")) }, "is a hard link"},
	} {
		if err := lockDownContext(context.Background(), mk(t, tc.extra)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: err = %v, want %q", tc.name, err, tc.want)
		}
		if got := ownerMode(t, victim); got != before {
			t.Fatalf("%s: the lockdown changed the host file: %s, was %s", tc.name, got, before)
		}
	}
	if err := lockDownContext(context.Background(), filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("a missing folder must fail")
	}
}

// One pass over descriptors: a tree at the depth cap takes back fast, and
// one past it (which only a broken child could make) is refused with the
// deep folder untouched.
func TestLockDownContextDepth(t *testing.T) {
	deep := func(t *testing.T, levels int) (string, string) {
		dir := filepath.Join(t.TempDir(), "context")
		last := filepath.Join(dir, strings.Repeat("a/", levels))
		if err := os.MkdirAll(last, 0o777); err != nil {
			t.Fatal(err)
		}
		return dir, last
	}
	dir, _ := deep(t, maxContextDepth)
	start := time.Now()
	if err := lockDownContext(context.Background(), dir); err != nil {
		t.Fatalf("at the cap: %v", err)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("a %d-level tree took %v", maxContextDepth, took)
	}

	orig := maxContextDepth
	t.Cleanup(func() { maxContextDepth = orig })
	maxContextDepth = 8
	dir, last := deep(t, 10)
	if err := os.Chmod(last, 0o777); err != nil {
		t.Fatal(err)
	}
	before := ownerMode(t, last)
	if err := lockDownContext(context.Background(), dir); err == nil || !strings.Contains(err.Error(), "nested deeper than 8 folders") {
		t.Fatalf("past the cap: %v", err)
	}
	if got := ownerMode(t, last); got != before {
		t.Fatalf("the folder past the cap was changed: %s, was %s", got, before)
	}
}

// cancelAfterChecks cancels itself on the n-th call to Err, which the
// lockdown makes once per entry, so a test can cancel in the middle of it.
type cancelAfterChecks struct {
	context.Context
	cancel context.CancelFunc
	left   atomic.Int32
}

func newCancelAfterChecks(n int32) *cancelAfterChecks {
	ctx, cancel := context.WithCancel(context.Background())
	c := &cancelAfterChecks{Context: ctx, cancel: cancel}
	c.left.Store(n)
	return c
}

func (c *cancelAfterChecks) Err() error {
	if c.left.Add(-1) == 0 {
		c.cancel()
	}
	return c.Context.Err()
}

// A lockdown stops when its build's context ends, the folder goes, and the
// id goes back to the pool.
func TestUnpackContextCancelDuringLockdownReleasesTheID(t *testing.T) {
	ids := childUnpackFixture(t)
	free := len(ids.free)
	data := tarWith(t, func(tw *tar.Writer) {
		for i := range 50 {
			_ = tw.WriteHeader(&tar.Header{Name: fmt.Sprintf("f%d", i), Mode: 0o644, Size: 1, Typeflag: tar.TypeReg})
			_, _ = tw.Write([]byte("x"))
		}
	})
	ctx := newCancelAfterChecks(10)
	defer ctx.cancel()
	dir := filepath.Join(t.TempDir(), "context")
	b := childBuilder(ids, "")
	err := b.unpackContext(ctx, data, dir)
	if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "take the folder back") {
		t.Fatalf("unpackContext = %v; want the lockdown cancelled", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("the folder is still there: %v", err)
	}
	if got := len(ids.free); got != free {
		t.Fatalf("%d ids free after, %d before", got, free)
	}
}

// runUnpackChild starts the unpacker the way unpackContextInChild does, with
// the given arguments and descriptors, and returns its stderr.
func runUnpackChild(t *testing.T, uid, gid int, args []string, extra []*os.File, stdin []byte) (string, error) {
	t.Helper()
	exe, err := contextUnpackExe()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, append([]string{ContextUnpackFlag}, args...)...)
	cmd.Stdin = bytes.NewReader(stdin)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Env = []string{}
	cmd.ExtraFiles = extra
	if uid >= 0 {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{
			Uid: uint32(uid), Gid: uint32(gid), NoSetGroups: os.Geteuid() != 0,
		}}
	}
	err = cmd.Run()
	return stderr.String(), err
}

// The child checks its own arguments and that it has its folder.
func TestContextUnpackChildArgsAndFolder(t *testing.T) {
	ids := testContextIDs()
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--max-entries", "0", "--max-bytes", "1"}, "must both be > 0"},
		{[]string{"--bogus"}, "flag provided but not defined"},
		// No folder on fd 3.
		{[]string{"--max-entries", "1", "--max-bytes", "1"}, "enter the context folder"},
	} {
		stderr, err := runUnpackChild(t, ids.uidBase, ids.gidBase, tc.args, nil, nil)
		if err == nil || !strings.Contains(stderr, tc.want) {
			t.Fatalf("%v: err %v, stderr %q, want %q", tc.args, err, stderr, tc.want)
		}
	}
}

// A child that finds itself root refuses to unpack: the uid drop not taking
// is the bug this mode exists to prevent.
func TestContextUnpackChildRefusesRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to start the child as root")
	}
	dir := t.TempDir()
	folder, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer folder.Close()
	data := tarWith(t, func(tw *tar.Writer) {
		_ = tw.WriteHeader(&tar.Header{Name: "f", Mode: 0o644, Size: 1, Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte("x"))
	})
	stderr, err := runUnpackChild(t, -1, -1, []string{"--max-entries", "10", "--max-bytes", "100"}, []*os.File{folder}, data)
	if err == nil || !strings.Contains(stderr, "refusing to run as root") {
		t.Fatalf("root child: err %v, stderr %q", err, stderr)
	}
	assertEmptyDir(t, dir)
}

func TestParseContextUnpackArgs(t *testing.T) {
	entries, size, err := parseContextUnpackArgs([]string{"--max-entries", "7", "--max-bytes", "99"})
	if err != nil || entries != 7 || size != 99 {
		t.Fatalf("= %d, %d, %v", entries, size, err)
	}
	for _, args := range [][]string{
		nil,
		{"--max-entries", "7"},
		{"--max-bytes", "99"},
		{"--max-entries", "-1", "--max-bytes", "99"},
		{"--max-entries", "x", "--max-bytes", "99"},
		{"--max-entries", "7", "--max-bytes", "99", "extra"},
		{"--nope"},
	} {
		if _, _, err := parseContextUnpackArgs(args); err == nil {
			t.Fatalf("%q must be refused", args)
		}
	}
}

func TestRefuseRootIDs(t *testing.T) {
	if err := refuseRootIDs(65534, 65534, 65534, 65534); err != nil {
		t.Fatalf("non-root ids refused: %v", err)
	}
	for _, ids := range [][4]int{{0, 1, 1, 1}, {1, 0, 1, 1}, {1, 1, 0, 1}, {1, 1, 1, 0}} {
		if err := refuseRootIDs(ids[0], ids[1], ids[2], ids[3]); err == nil {
			t.Fatalf("%v must be refused", ids)
		}
	}
}

func TestCappedBuffer(t *testing.T) {
	c := &cappedBuffer{max: 5}
	for _, p := range []string{"abc", "defg", "hij"} {
		if n, err := c.Write([]byte(p)); n != len(p) || err != nil {
			t.Fatalf("Write(%q) = %d, %v", p, n, err)
		}
	}
	if c.String() != "abcde" {
		t.Fatalf("kept %q, want abcde", c.String())
	}
}
