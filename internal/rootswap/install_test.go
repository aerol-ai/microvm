package rootswap

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// shortDir is a test folder with no link on the way to it (macOS: /var is
// one), closed to others, as root's own folders must be.
func shortDir(t testing.TB) string {
	t.Helper()
	d, err := os.MkdirTemp("", "rs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	if d, err = filepath.EvalSymlinks(d); err != nil {
		t.Fatal(err)
	}
	return d
}

// release is one signed helper, written to a folder the way a release
// lays it out: the binary and, beside it, its manifest and signature.
type release struct {
	dir  string
	body []byte
	m    Manifest
}

func makeRelease(t testing.TB, priv ed25519.PrivateKey, body []byte, version string) release {
	t.Helper()
	dir := shortDir(t)
	m := manifestFor(t, body, version)
	manifest, sig, err := Sign(priv, m)
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{BinaryName: body, ManifestName: manifest, SignatureName: sig} {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return release{dir: dir, body: body, m: m}
}

// layout is a staged folder the agent writes and root's own folder.
type layout struct {
	stage, bin string
	keys       []ed25519.PublicKey
	priv       ed25519.PrivateKey
}

func newLayout(t testing.TB) layout {
	t.Helper()
	dir := shortDir(t)
	l := layout{stage: filepath.Join(dir, "stage"), bin: filepath.Join(dir, "root", "rootd")}
	if err := os.Mkdir(l.stage, 0o777); err != nil {
		t.Fatal(err)
	}
	// The agent's folder: anyone in the pod may write it.
	if err := os.Chmod(l.stage, 0o777); err != nil {
		t.Fatal(err)
	}
	pub, priv := throwaway(t)
	l.keys, l.priv = []ed25519.PublicKey{pub}, priv
	return l
}

func (l layout) stageRelease(t testing.TB, body []byte, version string) release {
	t.Helper()
	r := makeRelease(t, l.priv, body, version)
	if err := Stage(r.dir, l.stage); err != nil {
		t.Fatal(err)
	}
	return r
}

// install is the supervisor's check, start to end.
func (l layout) install() (*Installed, error) {
	m, err := ReadStaged(l.stage, l.keys)
	if err != nil {
		return nil, err
	}
	return Install(l.stage, l.bin, m)
}

func binEntries(t *testing.T, bin string) []string {
	t.Helper()
	ents, err := os.ReadDir(bin)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

// TestInstall: a signed staged helper is copied into root's folder, which
// is made closed to others, as a 0500 file named for its version and hash,
// with exactly the signed bytes.
func TestInstall(t *testing.T) {
	l := newLayout(t)
	r := l.stageRelease(t, []byte("#!/bin/sh\necho signed\n"), "v0.7.8")
	inst, err := l.install()
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(inst.Path) != l.bin || !strings.HasPrefix(filepath.Base(inst.Path), "aerolvm-rootd-v0.7.8-"+r.m.SHA256[:16]) {
		t.Fatalf("copy at %s", inst.Path)
	}
	if inst.Manifest != r.m {
		t.Fatalf("manifest %+v", inst.Manifest)
	}
	got, err := os.ReadFile(inst.Path)
	if err != nil || !bytes.Equal(got, r.body) {
		t.Fatalf("copy = %q, %v", got, err)
	}
	fi, err := os.Stat(inst.Path)
	if err != nil || fi.Mode().Perm() != 0o500 {
		t.Fatalf("copy mode %v, %v", fi.Mode(), err)
	}
	for _, d := range []string{l.bin, filepath.Dir(l.bin)} {
		if fi, err := os.Stat(d); err != nil || fi.Mode().Perm()&0o022 != 0 {
			t.Fatalf("%s: %v %v, want closed to others", d, fi.Mode(), err)
		}
	}
	// The same release again replaces the copy with the same bytes.
	if again, err := l.install(); err != nil || again.Path != inst.Path {
		t.Fatalf("again = %v, %v", again, err)
	}
	if err := inst.Remove(); err != nil {
		t.Fatal(err)
	}
	if err := inst.Remove(); err != nil {
		t.Fatalf("removing a removed copy: %v", err)
	}
}

// TestInstallRefuses: an unsigned, wrongly signed, truncated or swapped
// staged helper never becomes a copy root runs, and nothing half made is
// left in root's folder.
func TestInstallRefuses(t *testing.T) {
	for _, tc := range []struct {
		name   string
		setup  func(t *testing.T, l layout)
		reason string
	}{
		{"unsigned", func(t *testing.T, l layout) {
			l.stageRelease(t, []byte("helper"), "v1.0.0")
			_ = os.Remove(filepath.Join(l.stage, SignatureName))
		}, ReasonUnsigned},
		{"no manifest", func(t *testing.T, l layout) {
			l.stageRelease(t, []byte("helper"), "v1.0.0")
			_ = os.Remove(filepath.Join(l.stage, ManifestName))
		}, ReasonBadManifest},
		{"signed by a key that is not a release key", func(t *testing.T, l layout) {
			_, priv := throwaway(t)
			if err := Stage(makeRelease(t, priv, []byte("helper"), "v1.0.0").dir, l.stage); err != nil {
				t.Fatal(err)
			}
		}, ReasonBadSignature},
		{"the signature of another release", func(t *testing.T, l layout) {
			old := makeRelease(t, l.priv, []byte("old helper"), "v1.0.0")
			l.stageRelease(t, []byte("helper"), "v1.0.1")
			copyTo(t, filepath.Join(old.dir, SignatureName), filepath.Join(l.stage, SignatureName))
		}, ReasonBadSignature},
		{"truncated", func(t *testing.T, l layout) {
			r := l.stageRelease(t, []byte("helper binary"), "v1.0.0")
			_ = os.WriteFile(filepath.Join(l.stage, BinaryName), r.body[:5], 0o755)
		}, ReasonTruncated},
		{"longer than signed", func(t *testing.T, l layout) {
			r := l.stageRelease(t, []byte("helper binary"), "v1.0.0")
			_ = os.WriteFile(filepath.Join(l.stage, BinaryName), append(r.body, "extra"...), 0o755)
		}, ReasonWrongSize},
		{"other bytes of the signed size", func(t *testing.T, l layout) {
			l.stageRelease(t, []byte("helper binary"), "v1.0.0")
			_ = os.WriteFile(filepath.Join(l.stage, BinaryName), []byte("HELPER BINARY"), 0o755)
		}, ReasonHash},
		{"no binary", func(t *testing.T, l layout) {
			l.stageRelease(t, []byte("helper"), "v1.0.0")
			_ = os.Remove(filepath.Join(l.stage, BinaryName))
		}, ReasonMissing},
		{"a link to a binary root trusts", func(t *testing.T, l layout) {
			r := l.stageRelease(t, []byte("helper"), "v1.0.0")
			other := filepath.Join(r.dir, "real")
			_ = os.WriteFile(other, r.body, 0o755)
			_ = os.Remove(filepath.Join(l.stage, BinaryName))
			_ = os.Symlink(other, filepath.Join(l.stage, BinaryName))
		}, ReasonNotFile},
		{"a FIFO, which must not hang root", func(t *testing.T, l layout) {
			l.stageRelease(t, []byte("helper"), "v1.0.0")
			_ = os.Remove(filepath.Join(l.stage, BinaryName))
			if err := unix.Mkfifo(filepath.Join(l.stage, BinaryName), 0o666); err != nil {
				t.Fatal(err)
			}
		}, ReasonNotFile},
		{"a folder", func(t *testing.T, l layout) {
			l.stageRelease(t, []byte("helper"), "v1.0.0")
			_ = os.Remove(filepath.Join(l.stage, BinaryName))
			_ = os.Mkdir(filepath.Join(l.stage, BinaryName), 0o755)
		}, ReasonNotFile},
		{"a manifest that is a link", func(t *testing.T, l layout) {
			r := l.stageRelease(t, []byte("helper"), "v1.0.0")
			_ = os.Remove(filepath.Join(l.stage, ManifestName))
			_ = os.Symlink(filepath.Join(r.dir, ManifestName), filepath.Join(l.stage, ManifestName))
		}, ReasonNotFile},
		{"a signature file too large", func(t *testing.T, l layout) {
			l.stageRelease(t, []byte("helper"), "v1.0.0")
			_ = os.WriteFile(filepath.Join(l.stage, SignatureName), bytes.Repeat([]byte("A"), maxSignatureSize+1), 0o644)
		}, ReasonNotFile},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := newLayout(t)
			tc.setup(t, l)
			done := make(chan struct{})
			var inst *Installed
			var err error
			go func() { inst, err = l.install(); close(done) }()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("the check hung")
			}
			if ReasonOf(err) != tc.reason {
				t.Fatalf("install = %v, %v; want reason %s", inst, err, tc.reason)
			}
			if left := binEntries(t, l.bin); len(left) != 0 {
				t.Fatalf("left in root's folder: %v", left)
			}
		})
	}
}

// TestReplacedAfterTheCheckChangesNothing is outside review O3: the agent
// can write the staged folder, so it may replace the binary at any moment.
// What root runs is its own copy, checked after it was made:
//
//   - a replace (a new file renamed in) after the binary was opened leaves
//     the opened file as it was, and the copy is the signed one;
//   - a write into the opened file before it is copied makes a copy that
//     does not match, and nothing is installed;
//   - any replace or write after Install leaves the copy as it is, and
//     running it runs the signed program.
func TestReplacedAfterTheCheckChangesNothing(t *testing.T) {
	signed := []byte("#!/bin/sh\necho signed\n")
	evil := []byte("#!/bin/sh\necho EVIL!!\n") // same size as signed
	t.Run("renamed over once open", func(t *testing.T) {
		l := newLayout(t)
		l.stageRelease(t, signed, "v1.0.0")
		afterOpen = func() { replaceByRename(t, filepath.Join(l.stage, BinaryName), evil) }
		t.Cleanup(func() { afterOpen = nil })
		inst, err := l.install()
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := os.ReadFile(inst.Path); !bytes.Equal(got, signed) {
			t.Fatalf("copy = %q", got)
		}
	})
	t.Run("written into once open", func(t *testing.T) {
		l := newLayout(t)
		l.stageRelease(t, signed, "v1.0.0")
		afterOpen = func() {
			if err := os.WriteFile(filepath.Join(l.stage, BinaryName), evil, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		t.Cleanup(func() { afterOpen = nil })
		if _, err := l.install(); ReasonOf(err) != ReasonHash {
			t.Fatalf("install = %v, want %s", err, ReasonHash)
		}
		if left := binEntries(t, l.bin); len(left) != 0 {
			t.Fatalf("left in root's folder: %v", left)
		}
	})
	t.Run("replaced after install", func(t *testing.T) {
		l := newLayout(t)
		l.stageRelease(t, signed, "v1.0.0")
		inst, err := l.install()
		if err != nil {
			t.Fatal(err)
		}
		staged := filepath.Join(l.stage, BinaryName)
		if err := os.WriteFile(staged, evil, 0o755); err != nil { // in place
			t.Fatal(err)
		}
		replaceByRename(t, staged, evil)
		_ = os.Remove(staged)
		_ = os.Symlink("/bin/sh", staged)
		out, err := exec.Command(inst.Path).CombinedOutput()
		if err != nil || string(out) != "signed\n" {
			t.Fatalf("the copy ran %q, %v; want the signed program", out, err)
		}
	})
}

func replaceByRename(t *testing.T, path string, body []byte) {
	t.Helper()
	tmp := path + ".new"
	if err := os.WriteFile(tmp, body, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

func copyTo(t *testing.T, from, to string) {
	t.Helper()
	b, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestInstallFolderRules: root's folder must be root's alone, and the
// staged folder is reached without following a link.
func TestInstallFolderRules(t *testing.T) {
	t.Run("a bin folder others can write", func(t *testing.T) {
		l := newLayout(t)
		l.stageRelease(t, []byte("helper"), "v1.0.0")
		if err := os.MkdirAll(l.bin, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(l.bin, 0o777); err != nil {
			t.Fatal(err)
		}
		if _, err := l.install(); err == nil || !strings.Contains(err.Error(), "can be written by others") {
			t.Fatalf("install = %v", err)
		}
	})
	t.Run("a staged folder behind a link", func(t *testing.T) {
		l := newLayout(t)
		r := makeRelease(t, l.priv, []byte("helper"), "v1.0.0")
		via := filepath.Join(filepath.Dir(l.stage), "via")
		if err := os.Symlink(r.dir, via); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadStaged(via, l.keys); err == nil || !strings.Contains(err.Error(), "without following a link") {
			t.Fatalf("ReadStaged = %v", err)
		}
		if _, err := Install(via, l.bin, r.m); err == nil {
			t.Fatal("Install followed the link")
		}
		if _, err := Fingerprint(via); err == nil {
			t.Fatal("Fingerprint followed the link")
		}
	})
	t.Run("a manifest Install was not given by ReadStaged", func(t *testing.T) {
		l := newLayout(t)
		if _, err := Install(l.stage, l.bin, Manifest{Kind: Kind}); ReasonOf(err) != ReasonBadManifest {
			t.Fatalf("Install = %v", err)
		}
	})
	t.Run("root's folder cannot be made", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root writes a read-only folder")
		}
		l := newLayout(t)
		r := l.stageRelease(t, []byte("helper"), "v1.0.0")
		parent := filepath.Dir(l.bin)
		if err := os.Mkdir(parent, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })
		if _, err := Install(l.stage, l.bin, r.m); err == nil {
			t.Fatal("Install made a folder in a read-only one")
		}
		if err := Sweep(l.bin); err == nil {
			t.Fatal("Sweep opened a folder it could not make")
		}
	})
}

// TestFingerprint: the name changes whenever a staged file is replaced or
// written, and stays while nothing is.
func TestFingerprint(t *testing.T) {
	l := newLayout(t)
	empty, err := Fingerprint(l.stage)
	if err != nil || empty != "-;-;-;" {
		t.Fatalf("an empty folder = %q, %v", empty, err)
	}
	l.stageRelease(t, []byte("helper"), "v1.0.0")
	a, _ := Fingerprint(l.stage)
	if b, _ := Fingerprint(l.stage); a != b || a == empty {
		t.Fatalf("unchanged files: %q then %q", a, b)
	}
	l.stageRelease(t, []byte("helper"), "v1.0.1")
	if b, _ := Fingerprint(l.stage); a == b {
		t.Fatal("a new release staged over the old kept the fingerprint")
	}
	if _, err := Fingerprint(filepath.Join(l.stage, "missing")); err == nil {
		t.Fatal("a missing folder has a fingerprint")
	}
}

// TestSweep removes the copies and half-made copies a stopped supervisor
// left, keeps what it is told to, and leaves anything else alone.
func TestSweep(t *testing.T) {
	l := newLayout(t)
	l.stageRelease(t, []byte("helper"), "v1.0.0")
	keep, err := l.install()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"aerolvm-rootd-v0.9.0-0123456789abcdef", ".aerolvm-rootd.0123456789abcdef", "notes.txt"} {
		if err := os.WriteFile(filepath.Join(l.bin, n), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := Sweep(l.bin, keep.Path); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(binEntries(t, l.bin), ",")
	if got != filepath.Base(keep.Path)+",notes.txt" {
		t.Fatalf("left %s", got)
	}
	if err := Sweep(l.bin); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(binEntries(t, l.bin), ","); got != "notes.txt" {
		t.Fatalf("left %s", got)
	}
}

// TestStage: the agent's side puts the three files in place under their
// fixed names and leaves no half-written file; a missing source is an
// error naming it.
func TestStage(t *testing.T) {
	l := newLayout(t)
	r := l.stageRelease(t, []byte("helper"), "v1.0.0")
	for _, n := range []string{BinaryName, ManifestName, SignatureName} {
		want, _ := os.ReadFile(filepath.Join(r.dir, n))
		if got, err := os.ReadFile(filepath.Join(l.stage, n)); err != nil || !bytes.Equal(got, want) {
			t.Fatalf("%s = %q, %v", n, got, err)
		}
	}
	if got := strings.Join(binEntries(t, l.stage), ","); got != "aerolvm-rootd,aerolvm-rootd.manifest,aerolvm-rootd.sig" {
		t.Fatalf("staged folder holds %s", got)
	}
	if err := Stage(filepath.Join(r.dir, "missing"), l.stage); err == nil || !strings.Contains(err.Error(), BinaryName) {
		t.Fatalf("Stage from nowhere = %v", err)
	}
	if err := Stage(r.dir, filepath.Join(l.stage, "missing")); err == nil {
		t.Fatal("Stage into nowhere succeeded")
	}
	// A folder where the manifest goes: the rename fails, and no
	// half-staged file is left under a temporary name.
	_ = os.Remove(filepath.Join(l.stage, ManifestName))
	if err := os.MkdirAll(filepath.Join(l.stage, ManifestName, "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Stage(r.dir, l.stage); err == nil || !strings.Contains(err.Error(), ManifestName) {
		t.Fatalf("Stage over a folder = %v", err)
	}
	for _, n := range binEntries(t, l.stage) {
		if strings.HasPrefix(n, ".") {
			t.Fatalf("left %s behind", n)
		}
	}
	if runtime.GOOS == "linux" && os.Geteuid() != 0 {
		ro := shortDir(t)
		_ = os.Chmod(ro, 0o500)
		if err := Stage(r.dir, ro); err == nil {
			t.Fatal("Stage into a read-only folder succeeded")
		}
	}
}
