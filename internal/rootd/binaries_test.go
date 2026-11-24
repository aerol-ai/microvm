package rootd

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// binTree is a folder of this test's user (root's stand-in, as in
// OpenFolder) that no one else can write, with no link on its path.
func binTree(t *testing.T) string {
	t.Helper()
	d := filepath.Join(shortDir(t), "bin")
	if err := os.Mkdir(d, 0o755); err != nil {
		t.Fatal(err)
	}
	return d
}

func writeBin(t *testing.T, path string, mode os.FileMode) string {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/bin/true\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	// After the write: the umask does not narrow a chmod.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestCheckRootBinaryFile: a program root runs is root's plain file that no
// one else can write, every folder on its path is root's and closed to
// others (or, above its own folder, sticky), and no folder on its path is
// a link. Its last name may be a link of root's to such a file, as
// distributions ship them (mkfs.ext4 -> mke2fs, Debian's ip -> ../bin/ip);
// the check answers that file.
func TestCheckRootBinaryFile(t *testing.T) {
	for _, tc := range []struct {
		name string
		make func(t *testing.T) (path, file string) // file "" is path
		want string                                 // "" passes
	}{
		{"root's own file in root's folder", func(t *testing.T) (string, string) {
			return writeBin(t, filepath.Join(binTree(t), "workerd"), 0o755), ""
		}, ""},
		{"read only, no one may run it but root", func(t *testing.T) (string, string) {
			return writeBin(t, filepath.Join(binTree(t), "workerd"), 0o500), ""
		}, ""},
		{"a sticky folder anyone writes, above the file's own", func(t *testing.T) (string, string) {
			sticky := filepath.Join(binTree(t), "tmp")
			mkdirMode(t, sticky, 0o1777)
			dir := filepath.Join(sticky, "opt")
			mkdirMode(t, dir, 0o755)
			return writeBin(t, filepath.Join(dir, "workerd"), 0o755), ""
		}, ""},
		{"a link beside its file (Ubuntu's mkfs.ext4 -> mke2fs)", func(t *testing.T) (string, string) {
			dir := binTree(t)
			file := writeBin(t, filepath.Join(dir, "mke2fs"), 0o755)
			return symlink(t, "mke2fs", filepath.Join(dir, "mkfs.ext4")), file
		}, ""},
		{"a link up and over (Debian's /usr/sbin/ip -> ../bin/ip)", func(t *testing.T) (string, string) {
			usr := binTree(t)
			mkdirMode(t, filepath.Join(usr, "bin"), 0o755)
			mkdirMode(t, filepath.Join(usr, "sbin"), 0o755)
			file := writeBin(t, filepath.Join(usr, "bin", "ip"), 0o755)
			return symlink(t, "../bin/ip", filepath.Join(usr, "sbin", "ip")), file
		}, ""},
		{"a link by absolute path to a checked file", func(t *testing.T) (string, string) {
			dir := binTree(t)
			file := writeBin(t, filepath.Join(dir, "workerd-1.2"), 0o755)
			return symlink(t, file, filepath.Join(dir, "workerd")), file
		}, ""},
		{"a relative path", func(*testing.T) (string, string) { return "bin/workerd", "" }, "clean absolute path"},
		{"an unclean path", func(t *testing.T) (string, string) { return binTree(t) + "/x/../workerd", "" }, "clean absolute path"},
		{"no such file", func(t *testing.T) (string, string) { return filepath.Join(binTree(t), "workerd"), "" }, "no such file"},
		{"no such folder", func(t *testing.T) (string, string) {
			return filepath.Join(binTree(t), "none", "workerd"), ""
		}, "without following a link"},
		{"a file its group can write", func(t *testing.T) (string, string) {
			return writeBin(t, filepath.Join(binTree(t), "workerd"), 0o775), ""
		}, "written by others"},
		{"a file anyone can write", func(t *testing.T) (string, string) {
			return writeBin(t, filepath.Join(binTree(t), "workerd"), 0o757), ""
		}, "written by others"},
		{"a folder its group can write", func(t *testing.T) (string, string) {
			dir := filepath.Join(binTree(t), "opt")
			mkdirMode(t, dir, 0o775)
			return writeBin(t, filepath.Join(dir, "workerd"), 0o755), ""
		}, "written by others"},
		{"a folder above it anyone can write", func(t *testing.T) (string, string) {
			open := filepath.Join(binTree(t), "shared")
			mkdirMode(t, open, 0o777)
			dir := filepath.Join(open, "opt")
			mkdirMode(t, dir, 0o755)
			return writeBin(t, filepath.Join(dir, "workerd"), 0o755), ""
		}, "written by others"},
		{"its own folder sticky and open to all (/tmp)", func(t *testing.T) (string, string) {
			dir := filepath.Join(binTree(t), "tmp")
			mkdirMode(t, dir, 0o1777)
			return writeBin(t, filepath.Join(dir, "workerd"), 0o755), ""
		}, "written by others"},
		{"a folder on the way is a link (merged /usr: /sbin)", func(t *testing.T) (string, string) {
			dir := binTree(t)
			usr := filepath.Join(dir, "usr")
			mkdirMode(t, usr, 0o755)
			writeBin(t, filepath.Join(usr, "mkfs.ext4"), 0o755)
			symlink(t, "usr", filepath.Join(dir, "sbin"))
			return filepath.Join(dir, "sbin", "mkfs.ext4"), ""
		}, "without following a link"},
		{"a link through a folder that is a link (Ubuntu's /usr/sbin/ip -> /bin/ip)", func(t *testing.T) (string, string) {
			dir := binTree(t)
			mkdirMode(t, filepath.Join(dir, "usr"), 0o755)
			mkdirMode(t, filepath.Join(dir, "usr", "bin"), 0o755)
			mkdirMode(t, filepath.Join(dir, "usr", "sbin"), 0o755)
			writeBin(t, filepath.Join(dir, "usr", "bin", "ip"), 0o755)
			symlink(t, "usr/bin", filepath.Join(dir, "bin"))
			return symlink(t, filepath.Join(dir, "bin", "ip"), filepath.Join(dir, "usr", "sbin", "ip")), ""
		}, "without following a link"},
		{"a link to a link", func(t *testing.T) (string, string) {
			dir := binTree(t)
			writeBin(t, filepath.Join(dir, "mke2fs"), 0o755)
			symlink(t, "mke2fs", filepath.Join(dir, "mkfs.ext4"))
			return symlink(t, "mkfs.ext4", filepath.Join(dir, "mkfs")), ""
		}, "itself a link"},
		{"a link to a file anyone can write", func(t *testing.T) (string, string) {
			dir := binTree(t)
			writeBin(t, filepath.Join(dir, "mke2fs"), 0o757)
			return symlink(t, "mke2fs", filepath.Join(dir, "mkfs.ext4")), ""
		}, "written by others"},
		{"a link into a folder anyone can write", func(t *testing.T) (string, string) {
			dir := binTree(t)
			open := filepath.Join(dir, "open")
			mkdirMode(t, open, 0o777)
			writeBin(t, filepath.Join(open, "mke2fs"), 0o755)
			return symlink(t, "open/mke2fs", filepath.Join(dir, "mkfs.ext4")), ""
		}, "written by others"},
		{"a link to nothing", func(t *testing.T) (string, string) {
			return symlink(t, "mke2fs", filepath.Join(binTree(t), "mkfs.ext4")), ""
		}, "no such file"},
		{"a link to a folder", func(t *testing.T) (string, string) {
			dir := binTree(t)
			mkdirMode(t, filepath.Join(dir, "d"), 0o755)
			return symlink(t, "d", filepath.Join(dir, "mkfs.ext4")), ""
		}, "not a plain file"},
		{"a folder", func(t *testing.T) (string, string) {
			dir := filepath.Join(binTree(t), "workerd")
			mkdirMode(t, dir, 0o755)
			return dir, ""
		}, "not a plain file"},
		{"a FIFO", func(t *testing.T) (string, string) {
			p := filepath.Join(binTree(t), "workerd")
			if err := unix.Mkfifo(p, 0o600); err != nil {
				t.Fatal(err)
			}
			return p, ""
		}, "not a plain file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, want := tc.make(t)
			if want == "" {
				want = path
			}
			file, err := checkRootBinaryFile(path)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				if file != want {
					t.Fatalf("names %s, want %s", file, want)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("%v, want an error naming %q", err, tc.want)
			}
		})
	}
	t.Run("someone else's file", func(t *testing.T) {
		if os.Geteuid() != 0 {
			t.Skip("only root gives a file away")
		}
		p := writeBin(t, filepath.Join(binTree(t), "workerd"), 0o755)
		if err := os.Chown(p, 4242, 4242); err != nil {
			t.Fatal(err)
		}
		if _, err := checkRootBinaryFile(p); err == nil || !strings.Contains(err.Error(), "belongs to uid 4242") {
			t.Fatalf("%v, want a refusal naming the owner", err)
		}
		// A link someone else made, to root's file.
		dir := binTree(t)
		writeBin(t, filepath.Join(dir, "mke2fs"), 0o755)
		link := symlink(t, "mke2fs", filepath.Join(dir, "mkfs.ext4"))
		if err := os.Lchown(link, 4242, 4242); err != nil {
			t.Fatal(err)
		}
		if _, err := checkRootBinaryFile(link); err == nil || !strings.Contains(err.Error(), "link of uid 4242") {
			t.Fatalf("%v, want a refusal naming the link's owner", err)
		}
	})
}

func symlink(t *testing.T, target, link string) string {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	return link
}

// mkdirMode makes dir with mode, sticky bit included (unix.Chmod: in an
// os.FileMode the sticky bit is os.ModeSticky, not 0o1000).
func mkdirMode(t *testing.T, dir string, mode uint32) {
	t.Helper()
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := unix.Chmod(dir, mode); err != nil {
		t.Fatal(err)
	}
}

// TestCheckRootBinaries: every program the helper's settings name for root
// to run is checked, under its setting's name, and only those the settings
// turn on.
func TestCheckRootBinaries(t *testing.T) {
	var none Config
	if got := rootBinaries(none); len(got) != 0 {
		t.Fatalf("a helper with no host kind and no moves names %v", got)
	}
	c := Config{Hosts: testHostsConfig(t)}
	c.Hosts.Firecracker = &FirecrackerHostsConfig{JailerBinary: "/j/jailer", FirecrackerBinary: "/j/firecracker", Mkfs4Bin: "/j/mkfs.ext4"}
	c.Moves = &MovesConfig{Runsc: "/j/runsc"}
	var seen []string
	if err := checkRootBinaries(c, func(p string) (string, error) { seen = append(seen, p); return p, nil }); err != nil {
		t.Fatal(err)
	}
	want := []string{"/usr/local/bin/workerd", "/j/jailer", "/j/firecracker", "/j/mkfs.ext4", "/j/runsc"}
	if !slices.Equal(seen, want) {
		t.Fatalf("checked %v, want %v (no ip: it is unset, so ip comes from PATH)", seen, want)
	}
	c.Hosts.Firecracker.IPBinary = "/j/ip"
	for _, tc := range []struct{ setting, path string }{
		{"SB_ISOLATE_WORKERD_PATH", "/usr/local/bin/workerd"},
		{"SB_JAILER_BINARY", "/j/jailer"},
		{"SB_FIRECRACKER_BINARY", "/j/firecracker"},
		{"SB_FIRECRACKER_MKFS_BIN", "/j/mkfs.ext4"},
		{"SB_FIRECRACKER_IP_BINARY", "/j/ip"},
		{"SB_ROOTD_RUNSC", "/j/runsc"},
	} {
		err := checkRootBinaries(c, func(p string) (string, error) {
			if p == tc.path {
				return "", errors.New("folder /j can be written by others")
			}
			return p, nil
		})
		if err == nil || !strings.Contains(err.Error(), tc.setting+"="+tc.path) || !strings.Contains(err.Error(), "written by others") {
			t.Errorf("%s refused: %v, want an error naming the setting, the path and why", tc.setting, err)
		}
	}
	// A program that is a link names a file outside the agent's folders
	// too: the start check proves the file root's, and this that the agent
	// does not own the folder it is in by its settings.
	c.AgentDirs = []string{"/var/lib/sandboxd"}
	for _, tc := range []struct{ file, want string }{
		{"/usr/sbin/mke2fs", ""},
		{"/var/lib/sandboxd/bin/mke2fs", "is a link to /var/lib/sandboxd/bin/mke2fs: /var/lib/sandboxd/bin/mke2fs is inside /var/lib/sandboxd"},
		{"/sbin/mke2fs", "under /sbin"},
	} {
		err := checkRootBinaries(c, func(p string) (string, error) {
			if p == "/j/mkfs.ext4" {
				return tc.file, nil
			}
			return p, nil
		})
		if tc.want == "" {
			if err != nil {
				t.Errorf("a link to %s: %v", tc.file, err)
			}
		} else if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "SB_FIRECRACKER_MKFS_BIN=/j/mkfs.ext4") {
			t.Errorf("a link to %s: %v, want an error naming the setting and %q", tc.file, err, tc.want)
		}
	}
}

// TestNewRefusesRootBinaries: the helper checks the programs it runs at
// start, before it makes its socket, with the real check when no stand-in
// is given.
func TestNewRefusesRootBinaries(t *testing.T) {
	start := func(t *testing.T, workerdMode os.FileMode) (Config, error) {
		cfg := testConfig(t)
		cfg.Hosts = testHostsConfig(t)
		cfg.Hosts.Workerd.Jail.WorkerdPath = writeBin(t, filepath.Join(binTree(t), "workerd"), workerdMode)
		srv, err := New(cfg, Options{Containerd: (&stubContainerd{}).handle, Peer: func(net.Conn) error { return nil }}, nil)
		if err == nil {
			srv.Shutdown(context.Background())
		}
		return cfg, err
	}
	if _, err := start(t, 0o755); err != nil {
		t.Fatalf("a workerd of root's: %v", err)
	}
	// A workerd that is a link to root's file, as a package ships it.
	cfg := testConfig(t)
	cfg.Hosts = testHostsConfig(t)
	dir := binTree(t)
	writeBin(t, filepath.Join(dir, "workerd-1.2"), 0o755)
	cfg.Hosts.Workerd.Jail.WorkerdPath = symlink(t, "workerd-1.2", filepath.Join(dir, "workerd"))
	srv, err := New(cfg, Options{Containerd: (&stubContainerd{}).handle, Peer: func(net.Conn) error { return nil }}, nil)
	if err != nil {
		t.Fatalf("a workerd that is a link to root's file: %v", err)
	}
	srv.Shutdown(context.Background())
	cfg, err = start(t, 0o777)
	if err == nil || !strings.Contains(err.Error(), "SB_ISOLATE_WORKERD_PATH="+cfg.Hosts.Workerd.Jail.WorkerdPath) {
		t.Fatalf("a workerd anyone can write: %v, want a refusal naming it", err)
	}
	if _, err := os.Lstat(cfg.Socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused helper made its socket: %v", err)
	}
}

// TestCheckRootProgramPath: the part of the rule a path alone shows, which
// the helper's config and every deploy tool's test apply: clean and
// absolute, outside the agent's folders, and under no folder a merged /usr
// makes a link.
func TestCheckRootProgramPath(t *testing.T) {
	agent := []string{"/var/lib/sandboxd", "/run/sandboxd"}
	for _, tc := range []struct {
		path, want string // want "" passes
	}{
		{"/usr/local/bin/workerd", ""},
		{"/usr/sbin/mkfs.ext4", ""},
		{"/opt/aerolvm-workerd/workerd", ""},
		{"/usr/local/lib/aerolvm-firecracker/vmlinux", ""},
		{"/var/lib/sandboxd-helper/runsc", ""}, // beside an agent folder, not in it
		{"/sbinx/mkfs.ext4", ""},               // a name that only starts like a link
		{"usr/sbin/mkfs.ext4", "clean absolute path"},
		{"/usr/sbin/../sbin/mkfs.ext4", "clean absolute path"},
		{"/usr//sbin/mkfs.ext4", "clean absolute path"},
		{"/", "clean absolute path"},
		{"", "clean absolute path"},
		{"/var/lib/sandboxd/bin/jailer", "inside /var/lib/sandboxd, which the agent writes"},
		{"/run/sandboxd", "inside /run/sandboxd, which the agent writes"},
		{"/sbin/mkfs.ext4", "under /sbin, which is a link into /usr"},
		{"/bin/ip", "under /bin, which is a link into /usr"},
		{"/lib/firecracker/jailer", "under /lib, which is a link into /usr"},
		{"/lib64/x", "under /lib64"},
	} {
		err := CheckRootProgramPath(tc.path, agent)
		if tc.want == "" {
			if err != nil {
				t.Errorf("%q refused: %v", tc.path, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: %v, want an error naming %q", tc.path, err, tc.want)
		}
		// It names no path to use: the right one differs by distribution,
		// and /usr/sbin/ip is a link to /bin/ip on Ubuntu.
		if err != nil && strings.Contains(err.Error(), "under /") && (strings.Contains(err.Error(), "/usr/sbin") || !strings.Contains(err.Error(), "readlink -f")) {
			t.Errorf("%q: %v suggests a path, or not readlink -f", tc.path, err)
		}
	}
	if l := MergedUsrLinks(); !slices.Equal(l, mergedUsrLinks) || &l[0] == &mergedUsrLinks[0] {
		t.Errorf("MergedUsrLinks = %v, want a copy of %v", l, mergedUsrLinks)
	}
	c := Config{Hosts: testHostsConfig(t)}
	c.Moves = &MovesConfig{Runsc: "/j/runsc"}
	if got := RootPrograms(c); len(got) != 2 || got["SB_ISOLATE_WORKERD_PATH"] != "/usr/local/bin/workerd" || got["SB_ROOTD_RUNSC"] != "/j/runsc" {
		t.Errorf("RootPrograms = %v", got)
	}
	if err := checkRootPrograms(agent, settingPath{"SB_X", "/sbin/x"}); err == nil || !strings.HasPrefix(err.Error(), "SB_X: ") {
		t.Errorf("checkRootPrograms names no setting: %v", err)
	}
}
