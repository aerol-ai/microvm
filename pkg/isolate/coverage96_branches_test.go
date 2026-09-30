package isolate

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Error arms of the chroot builder, cgroup layout, realized-jail teardown and
// the host's jail glue. Every path these tests create or break lives under a
// t.TempDir(); nothing is written relative to the working directory.

// writeFakeDynamicELF writes a minimal ELF64 with a single PT_INTERP program
// header naming interp, so resolveSharedLibs takes the dynamic (ldd) path.
func writeFakeDynamicELF(t *testing.T, path, interp string) {
	t.Helper()
	const phoff, phsize = 64, 56
	body := append([]byte(interp), 0)
	h := make([]byte, phoff+phsize+len(body))
	copy(h, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0})
	binary.LittleEndian.PutUint16(h[16:], 2)    // ET_EXEC
	binary.LittleEndian.PutUint16(h[18:], 0x3e) // x86-64
	binary.LittleEndian.PutUint32(h[20:], 1)
	binary.LittleEndian.PutUint64(h[32:], phoff)
	binary.LittleEndian.PutUint16(h[52:], 64)
	binary.LittleEndian.PutUint16(h[54:], phsize)
	binary.LittleEndian.PutUint16(h[56:], 1)
	binary.LittleEndian.PutUint16(h[58:], 64)
	ph := h[phoff:]
	binary.LittleEndian.PutUint32(ph[0:], 3) // PT_INTERP
	binary.LittleEndian.PutUint32(ph[4:], 4)
	binary.LittleEndian.PutUint64(ph[8:], phoff+phsize)
	binary.LittleEndian.PutUint64(ph[32:], uint64(len(body)))
	binary.LittleEndian.PutUint64(ph[40:], uint64(len(body)))
	binary.LittleEndian.PutUint64(ph[48:], 1)
	copy(h[phoff+phsize:], body)
	if err := os.WriteFile(path, h, 0o755); err != nil {
		t.Fatal(err)
	}
}

// stubLDD swaps lddCommand for the test's lifetime.
func stubLDD(t *testing.T, fn func(string) ([]byte, error)) {
	t.Helper()
	orig := lddCommand
	lddCommand = fn
	t.Cleanup(func() { lddCommand = orig })
}

// physTempDir is t.TempDir() with symlinks resolved (macOS's /var is a link
// to /private/var), so path depth arithmetic matches what the kernel walks.
func physTempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func mustWrite(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func skipIfRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root bypasses the permission check this case relies on")
	}
}

// rootAlias returns a host path that the kernel resolves to a real file under
// root but that filepath.Clean collapses to "/"+name. PrepareJailBase stages
// each library at filepath.Join(staging, lib), so such a library lands at
// staging/<name>. The ".." count is exactly root's depth plus the link, so
// the lexical path climbs back to staging and never above it.
func rootAlias(t *testing.T, root, name string) string {
	t.Helper()
	depth := strings.Count(root, "/") + 1 // root's components + "lnk"
	target := filepath.Join(root, "land")
	for i := 0; i < depth; i++ {
		target = filepath.Join(target, "d")
	}
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(root, "land", name))
	if err := os.Symlink(target, filepath.Join(root, "lnk")); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "lnk") + strings.Repeat("/..", depth) + "/" + name
	if filepath.Clean(alias) != "/"+name {
		t.Fatalf("alias %q cleans to %q", alias, filepath.Clean(alias))
	}
	if _, err := os.Stat(alias); err != nil {
		t.Fatalf("alias does not resolve: %v", err)
	}
	return alias
}

func lddFor(libs ...string) func(string) ([]byte, error) {
	var b strings.Builder
	b.WriteString("\n") // blank lines are skipped
	for i, l := range libs {
		b.WriteString("\tlib" + string(rune('a'+i)) + ".so => " + l + " (0x1)\n")
	}
	return func(string) ([]byte, error) { return []byte(b.String()), nil }
}

func TestResolveSharedLibsDynamic(t *testing.T) {
	root := physTempDir(t)
	// The real ldd only reads the binary (and is absent off Linux, which is
	// an error, not a hang); the result does not matter here.
	static := filepath.Join(root, "static")
	writeFakeStaticELF(t, static)
	_, _ = lddCommand(static)

	interp := filepath.Join(root, "ld.so")
	lib := filepath.Join(root, "libc.so")
	mustWrite(t, interp)
	mustWrite(t, lib)
	bin := filepath.Join(root, "workerd")
	writeFakeDynamicELF(t, bin, interp)

	t.Run("ldd fails", func(t *testing.T) {
		stubLDD(t, func(string) ([]byte, error) { return []byte("boom"), errors.New("exit 1") })
		if _, err := resolveSharedLibs(bin); err == nil || !strings.Contains(err.Error(), "ldd") {
			t.Fatalf("err = %v, want ldd failure", err)
		}
	})
	t.Run("missing library", func(t *testing.T) {
		stubLDD(t, func(string) ([]byte, error) { return []byte("\tlibx.so => not found\n"), nil })
		if _, err := resolveSharedLibs(bin); err == nil {
			t.Fatal("not-found library accepted")
		}
	})
	t.Run("library vanished", func(t *testing.T) {
		stubLDD(t, lddFor(filepath.Join(root, "gone.so")))
		if _, err := resolveSharedLibs(bin); err == nil || !strings.Contains(err.Error(), "shared library") {
			t.Fatalf("err = %v, want stat failure", err)
		}
	})
	t.Run("interp appended", func(t *testing.T) {
		stubLDD(t, lddFor(lib))
		libs, err := resolveSharedLibs(bin)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Join(libs, ",") != lib+","+interp {
			t.Fatalf("libs = %v, want [%s %s]", libs, lib, interp)
		}
	})
	t.Run("interp already listed", func(t *testing.T) {
		stubLDD(t, lddFor(interp, lib))
		libs, err := resolveSharedLibs(bin)
		if err != nil || len(libs) != 2 {
			t.Fatalf("libs = %v err=%v", libs, err)
		}
	})
}

func TestPrepareJailBaseDynamicStagesLibraries(t *testing.T) {
	root := physTempDir(t)
	interp := filepath.Join(root, "sys", "ld.so")
	lib := filepath.Join(root, "sys", "lib", "libc.so")
	mustWrite(t, interp)
	mustWrite(t, lib)
	bin := filepath.Join(root, "workerd")
	writeFakeDynamicELF(t, bin, interp)
	stubLDD(t, lddFor(lib))

	base := filepath.Join(root, "jail")
	if err := PrepareJailBase(base, bin); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{lib, interp} {
		if _, err := os.Stat(filepath.Join(base, jailBaseName, p)); err != nil {
			t.Fatalf("base lacks %s: %v", p, err)
		}
	}
}

func TestPrepareJailBaseErrorPaths(t *testing.T) {
	newBin := func(t *testing.T, root string) string {
		t.Helper()
		interp := filepath.Join(root, "ld.so")
		mustWrite(t, interp)
		bin := filepath.Join(root, "workerd")
		writeFakeDynamicELF(t, bin, interp)
		return bin
	}

	t.Run("resolve fails", func(t *testing.T) {
		root := physTempDir(t)
		bin := newBin(t, root)
		stubLDD(t, func(string) ([]byte, error) { return nil, errors.New("no ldd") })
		if err := PrepareJailBase(filepath.Join(root, "jail"), bin); err == nil {
			t.Fatal("ldd failure ignored")
		}
	})

	t.Run("staging mkdir", func(t *testing.T) {
		root := physTempDir(t)
		bin := newBin(t, root)
		stubLDD(t, lddFor())
		blocker := filepath.Join(root, "blocker")
		mustWrite(t, blocker)
		if err := PrepareJailBase(blocker, bin); err == nil || !strings.Contains(err.Error(), "mkdir base") {
			t.Fatalf("err = %v, want mkdir base", err)
		}
	})

	t.Run("stage workerd", func(t *testing.T) {
		root := physTempDir(t)
		bin := newBin(t, root)
		// ldd runs after the ELF parse and before the copy: pulling the binary
		// here is the window where the stat passed but the copy cannot.
		stubLDD(t, func(b string) ([]byte, error) {
			_ = os.Remove(b)
			return nil, nil
		})
		base := filepath.Join(root, "jail")
		if err := PrepareJailBase(base, bin); err == nil || !strings.Contains(err.Error(), "stage workerd") {
			t.Fatalf("err = %v, want stage workerd", err)
		}
		if _, err := os.Stat(filepath.Join(base, jailBaseName+".next")); !os.IsNotExist(err) {
			t.Fatalf("staging left behind: %v", err)
		}
	})

	t.Run("stage lib dir", func(t *testing.T) {
		root := physTempDir(t)
		bin := newBin(t, root)
		// First library is a plain file at root/g. The second resolves (via
		// lnk2 → deep/sub, then ..) to deep/g/x on the host, but lexically to
		// root/g/x, whose parent in staging is the file the first one made.
		first := filepath.Join(root, "g")
		mustWrite(t, first)
		mustWrite(t, filepath.Join(root, "deep", "g", "x"))
		if err := os.MkdirAll(filepath.Join(root, "deep", "sub"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(root, "deep", "sub"), filepath.Join(root, "lnk2")); err != nil {
			t.Fatal(err)
		}
		second := filepath.Join(root, "lnk2") + "/../g/x"
		stubLDD(t, lddFor(first, second))
		if err := PrepareJailBase(filepath.Join(root, "jail"), bin); err == nil || !strings.Contains(err.Error(), "stage lib dir") {
			t.Fatalf("err = %v, want stage lib dir", err)
		}
	})

	t.Run("stage lib copy", func(t *testing.T) {
		root := physTempDir(t)
		bin := newBin(t, root)
		dirLib := filepath.Join(root, "libdir.so")
		if err := os.MkdirAll(dirLib, 0o755); err != nil {
			t.Fatal(err)
		}
		stubLDD(t, lddFor(dirLib))
		if err := PrepareJailBase(filepath.Join(root, "jail"), bin); err == nil || !strings.Contains(err.Error(), "stage "+dirLib) {
			t.Fatalf("err = %v, want stage %s", err, dirLib)
		}
	})

	for _, name := range []string{"dev", "tmp"} {
		t.Run(name+" mkdir", func(t *testing.T) {
			root := physTempDir(t)
			bin := newBin(t, root)
			stubLDD(t, lddFor(rootAlias(t, root, name)))
			base := filepath.Join(root, "jail")
			if err := PrepareJailBase(base, bin); err == nil {
				t.Fatalf("staging/%s as a file accepted", name)
			}
			if JailBasePrepared(base) {
				t.Fatal("failed build installed a base")
			}
		})
	}

	t.Run("retire old base", func(t *testing.T) {
		skipIfRoot(t)
		root := physTempDir(t)
		static := filepath.Join(root, "static")
		writeFakeStaticELF(t, static)
		base := filepath.Join(root, "jail")
		if err := PrepareJailBase(base, static); err != nil {
			t.Fatal(err)
		}
		// A .old that RemoveAll cannot empty makes the retire rename fail.
		locked := filepath.Join(base, jailBaseName+".old", "locked")
		mustWrite(t, filepath.Join(locked, "f"))
		if err := os.Chmod(locked, 0o555); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
		if err := PrepareJailBase(base, static); err == nil || !strings.Contains(err.Error(), "retire old base") {
			t.Fatalf("err = %v, want retire old base", err)
		}
		if !JailBasePrepared(base) {
			t.Fatal("failed retire lost the serving base")
		}
	})

	t.Run("install base", func(t *testing.T) {
		root := physTempDir(t)
		static := filepath.Join(root, "static")
		writeFakeStaticELF(t, static)
		base := filepath.Join(root, "jail")
		if err := os.MkdirAll(base, 0o755); err != nil {
			t.Fatal(err)
		}
		// Dangling symlink: Stat says "absent", so no retire, but renaming a
		// directory onto a non-directory fails.
		if err := os.Symlink(filepath.Join(root, "nowhere"), filepath.Join(base, jailBaseName)); err != nil {
			t.Fatal(err)
		}
		if err := PrepareJailBase(base, static); err == nil || !strings.Contains(err.Error(), "install base") {
			t.Fatalf("err = %v, want install base", err)
		}
		if _, err := os.Stat(filepath.Join(base, jailBaseName+".next")); !os.IsNotExist(err) {
			t.Fatalf("staging left behind: %v", err)
		}
	})
}

func TestCopyFileModeErrors(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	mustWrite(t, src)
	if err := copyFileMode(filepath.Join(dir, "missing"), filepath.Join(dir, "dst"), 0o644); err == nil {
		t.Fatal("missing source accepted")
	}
	if err := copyFileMode(src, filepath.Join(dir, "no", "such", "dst"), 0o644); err == nil {
		t.Fatal("unwritable destination accepted")
	}
	srcDir := filepath.Join(dir, "srcdir")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "dst")
	if err := copyFileMode(srcDir, dst, 0o644); err == nil {
		t.Fatal("directory source copied")
	}
	if _, err := os.Stat(dst + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temp file left after failed copy: %v", err)
	}
	if err := copyFileMode(src, dst, 0o640); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(dst); err != nil || st.Mode().Perm() != 0o640 {
		t.Fatalf("dst = %v %v", st, err)
	}
}

func TestLinkGroupJailErrorPaths(t *testing.T) {
	prepared := func(t *testing.T) string {
		t.Helper()
		root := t.TempDir()
		static := filepath.Join(root, "w")
		writeFakeStaticELF(t, static)
		base := filepath.Join(root, "jail")
		if err := PrepareJailBase(base, static); err != nil {
			t.Fatal(err)
		}
		return base
	}
	uid, gid := os.Getuid(), os.Getgid()

	t.Run("group dir is a file", func(t *testing.T) {
		base := prepared(t)
		group := filepath.Join(base, "g")
		mustWrite(t, group)
		if err := linkGroupJail(base, group, uid, gid); err == nil {
			t.Fatal("file group dir accepted")
		}
	})

	t.Run("symlink in base is skipped", func(t *testing.T) {
		base := prepared(t)
		if err := os.Symlink("workerd", filepath.Join(base, jailBaseName, "alias")); err != nil {
			t.Fatal(err)
		}
		group := filepath.Join(base, "g")
		if err := linkGroupJail(base, group, uid, gid); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(filepath.Join(group, "alias")); !os.IsNotExist(err) {
			t.Fatalf("symlink copied into group: %v", err)
		}
	})

	t.Run("dir blocked by file", func(t *testing.T) {
		base := prepared(t)
		group := filepath.Join(base, "g")
		mustWrite(t, filepath.Join(group, "tmp"))
		if err := linkGroupJail(base, group, uid, gid); err == nil || !strings.Contains(err.Error(), "populate") {
			t.Fatalf("err = %v, want populate failure", err)
		}
	})

	t.Run("link and copy fallback blocked", func(t *testing.T) {
		base := prepared(t)
		group := filepath.Join(base, "g")
		// A non-empty directory where workerd goes: Remove, Link and the
		// copy's final rename all fail.
		mustWrite(t, filepath.Join(group, JailWorkerdPath, "keep"))
		if err := linkGroupJail(base, group, uid, gid); err == nil || !strings.Contains(err.Error(), "populate") {
			t.Fatalf("err = %v, want populate failure", err)
		}
	})

	t.Run("unreadable base dir", func(t *testing.T) {
		skipIfRoot(t)
		base := prepared(t)
		sealed := filepath.Join(base, jailBaseName, "sealed")
		if err := os.MkdirAll(sealed, 0o755); err != nil {
			t.Fatal(err)
		}
		group := filepath.Join(base, "g")
		t.Cleanup(func() {
			_ = os.Chmod(sealed, 0o755)
			_ = os.Chmod(filepath.Join(group, "sealed"), 0o755)
		})
		if err := os.Chmod(sealed, 0); err != nil {
			t.Fatal(err)
		}
		if err := linkGroupJail(base, group, uid, gid); err == nil || !strings.Contains(err.Error(), "populate") {
			t.Fatalf("err = %v, want populate failure", err)
		}
	})

	t.Run("run dir blocked", func(t *testing.T) {
		base := prepared(t)
		group := filepath.Join(base, "g")
		mustWrite(t, filepath.Join(group, JailRunDirName))
		if err := linkGroupJail(base, group, uid, gid); err == nil {
			t.Fatal("file run dir accepted")
		}
	})

	t.Run("run dir chown", func(t *testing.T) {
		skipIfRoot(t)
		base := prepared(t)
		if err := linkGroupJail(base, filepath.Join(base, "g"), 0, 0); err == nil || !strings.Contains(err.Error(), "chown run dir") {
			t.Fatalf("err = %v, want chown run dir", err)
		}
	})
}

func TestCgroupFSErrorPaths(t *testing.T) {
	t.Run("root mkdir", func(t *testing.T) {
		blocker := filepath.Join(t.TempDir(), "file")
		mustWrite(t, blocker)
		if _, err := (cgroupFS{root: filepath.Join(blocker, "cg")}).ensure("g", 0, 0, 0); err == nil {
			t.Fatal("root under a file accepted")
		}
	})
	t.Run("subtree_control unstatable", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "cg")
		if err := os.MkdirAll(root, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("cgroup.subtree_control", filepath.Join(root, "cgroup.subtree_control")); err != nil {
			t.Fatal(err)
		}
		if _, err := (cgroupFS{root: root}).ensure("g", 0, 0, 0); err == nil {
			t.Fatal("symlink loop on subtree_control accepted")
		}
	})
	t.Run("subtree_control unwritable", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "cg")
		if err := os.MkdirAll(filepath.Join(root, "cgroup.subtree_control"), 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := (cgroupFS{root: root}).ensure("g", 0, 0, 0); err == nil || !strings.Contains(err.Error(), "enable cgroup controllers") {
			t.Fatalf("err = %v, want enable controllers", err)
		}
	})
	t.Run("group mkdir", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "cg")
		mustWrite(t, filepath.Join(root, "g"))
		if _, err := (cgroupFS{root: root}).ensure("g", 0, 0, 0); err == nil {
			t.Fatal("file group accepted")
		}
	})
	t.Run("negative caps", func(t *testing.T) {
		if _, err := (cgroupFS{root: filepath.Join(t.TempDir(), "cg")}).ensure("g", -1, 0, 0); err == nil {
			t.Fatal("negative cpu accepted")
		}
	})
	for _, ctl := range []string{"cpu.max", "memory.max", "pids.max"} {
		t.Run(ctl+" unwritable", func(t *testing.T) {
			dir := t.TempDir()
			if err := os.MkdirAll(filepath.Join(dir, ctl), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := (cgroupFS{root: filepath.Dir(dir)}).applyCaps(dir, 1, 64, 8); err == nil || !strings.Contains(err.Error(), ctl) {
				t.Fatalf("err = %v, want %s", err, ctl)
			}
		})
	}
	t.Run("remove non-empty", func(t *testing.T) {
		root := t.TempDir()
		dir := filepath.Join(root, "g")
		mustWrite(t, filepath.Join(dir, "stray"))
		if err := (cgroupFS{root: root}).remove(dir); err == nil {
			t.Fatal("non-empty cgroup removed")
		}
	})
}

func TestJailRealizedCloseFDAndTeardownErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fd")
	mustWrite(t, path)
	fd, err := syscall.Open(path, syscall.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	r := &jailRealized{cgroupFD: fd}
	r.closeFD()
	if r.cgroupFD != 0 {
		t.Fatalf("cgroupFD = %d after close", r.cgroupFD)
	}
	if err := syscall.Close(fd); err == nil {
		t.Fatal("descriptor still open after closeFD")
	}

	root := t.TempDir()
	bad := &jailRealized{
		chrootBase: filepath.Join(root, "jail"),
		chrootDir:  filepath.Join(root, "elsewhere", "g"),
		cgroup:     cgroupFS{root: filepath.Join(root, "cg")},
		cgroupDir:  filepath.Join(root, "other", "g"),
	}
	err = bad.teardown()
	if err == nil || !strings.Contains(err.Error(), "refusing to remove cgroup") || strings.Count(err.Error(), "refusing to remove") != 2 {
		t.Fatalf("teardown err = %v, want both refusals", err)
	}
	unmountNoexecMounts(nil)
}

func TestHostNilObserverAndWaitReadyExit(t *testing.T) {
	var none *Host
	none.SetEgressObserver(func(string, string, string) {})
	none.observeEgress("sb", "tcp", "example.com:443")

	truePath, err := exec.LookPath("true")
	if err != nil {
		t.Skip("no `true` binary on PATH")
	}
	cmd := exec.Command(truePath)
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	h := &Host{cfg: HostConfig{StartTimeout: 5 * time.Second}}
	client := unixHTTPClient(filepath.Join(t.TempDir(), "absent.sock"))
	if err := h.waitReady(context.Background(), cmd, client); err == nil || !strings.Contains(err.Error(), "exited") {
		t.Fatalf("waitReady = %v, want exited", err)
	}
}

func TestHostStopLogsJailTeardownFailure(t *testing.T) {
	root := t.TempDir()
	var logged strings.Builder
	h := &Host{
		logger: slog.New(slog.NewTextHandler(&logged, nil)),
		jail:   &jailRealized{chrootBase: filepath.Join(root, "jail"), chrootDir: filepath.Join(root, "elsewhere")},
	}
	if err := h.Stop(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logged.String(), "teardown incomplete") {
		t.Fatalf("log = %q, want teardown warning", logged.String())
	}
	if h.jail != nil {
		t.Fatal("jail record kept after Stop")
	}
}

func TestGrantJailAccessErrors(t *testing.T) {
	dir := t.TempDir()
	notDir := filepath.Join(dir, "file")
	mustWrite(t, notDir)
	h := &Host{cfg: HostConfig{Jail: JailConfig{Require: true, UID: os.Getuid(), GID: os.Getgid()}}}
	if err := h.grantJailAccess(filepath.Join(notDir, "child")); err == nil || !strings.Contains(err.Error(), "jail access") {
		t.Fatalf("err = %v, want jail access stat failure", err)
	}
	if err := h.grantJailAccess("", filepath.Join(dir, "missing"), notDir); err != nil {
		t.Fatalf("own uid chown = %v", err)
	}
	skipIfRoot(t)
	h.cfg.Jail.UID, h.cfg.Jail.GID = 0, 0
	if err := h.grantJailAccess(notDir); err == nil || !strings.Contains(err.Error(), "chown") {
		t.Fatalf("err = %v, want chown failure", err)
	}
}

// Short top-level names: t.TempDir embeds the test name and these tests bind
// unix sockets, whose paths cap at 104 bytes on macOS.
func TestSlotChown(t *testing.T) {
	skipIfRoot(t)
	sock := filepath.Join(t.TempDir(), "e0.sock")
	if len(sock) > 100 {
		t.Skipf("socket path too long for this host: %d bytes", len(sock))
	}
	h := &Host{
		cfg:         HostConfig{Jail: JailConfig{Require: true, UID: 0, GID: 0}},
		egressSocks: []string{sock},
		slotSrv:     make([]*http.Server, 1),
	}
	h.mu.Lock()
	err := h.startSlotServerLocked(0)
	h.mu.Unlock()
	if err == nil || !strings.Contains(err.Error(), "chown") {
		t.Fatalf("err = %v, want chown failure", err)
	}
	if h.slotSrv[0] != nil {
		t.Fatal("slot server recorded after failed grant")
	}
}

func TestJailGateRm(t *testing.T) {
	if JailRealizable() && os.Geteuid() == 0 {
		t.Skip("root on linux can realize the jail")
	}
	chroot := filepath.Join(t.TempDir(), "g")
	run := filepath.Join(chroot, JailRunDirName)
	if len(filepath.Join(run, egressDenySocketName)) > 100 {
		t.Skip("socket path too long for this host")
	}
	h, err := NewHost(HostConfig{
		WorkerdPath: "/nonexistent-workerd", GroupKey: "g", RunDir: run, EgressPoolSize: 1,
		Jail:   JailConfig{Require: true, ChrootDir: chroot, UID: 1001, GID: 1001, ShimPath: "/nonexistent-sandboxd"},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	err = h.Start(context.Background())
	if err == nil {
		_ = h.Stop()
		t.Fatal("Start succeeded with an unrealizable required jail")
	}
	if !strings.Contains(err.Error(), "jail required but not realized") {
		t.Fatalf("err = %v, want jail gate refusal", err)
	}
	if _, err := os.Stat(chroot); !os.IsNotExist(err) {
		t.Fatalf("chroot left behind after refused spawn: %v", err)
	}
}
