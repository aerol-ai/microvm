package rootswap

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// signedFor is a release's signed manifest for body: its bytes, as the
// release signed them, and the signature.
func signedFor(t testing.TB, priv ed25519.PrivateKey, body []byte, version string) Signed {
	t.Helper()
	m := manifestFor(t, body, version)
	raw, sig, err := Sign(priv, m)
	if err != nil {
		t.Fatal(err)
	}
	return Signed{Manifest: m, Raw: raw, Signature: sig}
}

// TestFloor: a folder with no floor has none; the floor read back is the
// signed manifest written last, byte for byte, with its signature, in
// files only root can read, with nothing half-written left beside them. A
// floor written with no signature removes the one before it.
func TestFloor(t *testing.T) {
	_, priv := throwaway(t)
	bin := filepath.Join(shortDir(t), "root", "rootd")
	if f, err := ReadFloor(bin); err != nil || f != nil {
		t.Fatalf("no floor yet: %+v, %v", f, err)
	}
	for _, v := range []string{"v1.0.0", "v1.2.0", "v1.1.0"} {
		s := signedFor(t, priv, []byte("helper "+v), v)
		if err := WriteFloor(bin, s); err != nil {
			t.Fatal(err)
		}
		f, err := ReadFloor(bin)
		if err != nil || f == nil || f.Manifest != s.Manifest || !bytes.Equal(f.Raw, s.Raw) || !bytes.Equal(f.Signature, s.Signature) {
			t.Fatalf("after writing %s: %+v, %v", v, f, err)
		}
	}
	if got := strings.Join(binEntries(t, bin), ","); got != FloorName+","+FloorSigName {
		t.Fatalf("the folder holds %s", got)
	}
	for _, n := range []string{FloorName, FloorSigName} {
		fi, err := os.Stat(filepath.Join(bin, n))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v, %v; want mode 0600", n, fi, err)
		}
	}
	unsigned := signedFor(t, priv, []byte("helper v1.3.0"), "v1.3.0")
	unsigned.Signature = nil
	if err := WriteFloor(bin, unsigned); err != nil {
		t.Fatal(err)
	}
	if f, err := ReadFloor(bin); err != nil || f.Manifest != unsigned.Manifest || f.Signature != nil {
		t.Fatalf("unsigned floor: %+v, %v", f, err)
	}
	if got := strings.Join(binEntries(t, bin), ","); got != FloorName {
		t.Fatalf("an old signature was left beside an unsigned floor: %s", got)
	}
	// A floor #1465 wrote: the manifest as root marshalled it, no signature.
	if err := os.WriteFile(filepath.Join(bin, FloorName), []byte(`{"kind":"aerolvm-rootd","version":"v1.4.0","api":1,"os":"linux","arch":"amd64","size":1,"sha256":"`+
		strings.Repeat("a", 64)+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if f, err := ReadFloor(bin); err != nil || f.Manifest.Version != "v1.4.0" || f.Signature != nil {
		t.Fatalf("an older floor file: %+v, %v", f, err)
	}
	for name, bad := range map[string]Signed{
		"no release":                  {Manifest: Manifest{Kind: Kind, Version: "latest"}, Raw: []byte(`{"kind":"aerolvm-rootd","version":"latest"}`)},
		"bytes that are not the same": {Manifest: unsigned.Manifest, Raw: signedFor(t, priv, []byte("other"), "v1.3.0").Raw},
	} {
		if err := WriteFloor(bin, bad); err == nil {
			t.Fatalf("%s: wrote a floor", name)
		}
	}
}

// TestFloorRefuses: a floor or a floor signature that is there but is not
// a whole manifest, or a small regular file of root's, in root's own
// folder, is an error, never "no floor": the supervisor then runs nothing
// rather than anything.
func TestFloorRefuses(t *testing.T) {
	_, priv := throwaway(t)
	good := signedFor(t, priv, []byte("helper"), "v1.0.0")
	for _, tc := range []struct {
		name string
		make func(t *testing.T, bin string)
		want string
	}{
		{"not json", func(t *testing.T, bin string) { writeFloorBytes(t, bin, FloorName, "{not json") }, ReasonBadManifest},
		{"a field it does not know", func(t *testing.T, bin string) {
			writeFloorBytes(t, bin, FloorName, `{"kind":"aerolvm-rootd","version":"v1.0.0","api":1,"os":"linux","arch":"amd64","size":1,"sha256":"`+
				strings.Repeat("a", 64)+`","extra":1}`)
		}, ReasonBadManifest},
		{"data after it", func(t *testing.T, bin string) {
			writeFloorBytes(t, bin, FloorName, string(good.Raw)+"{}")
		}, ReasonBadManifest},
		{"no release version", func(t *testing.T, bin string) {
			writeFloorBytes(t, bin, FloorName, `{"kind":"aerolvm-rootd","version":"latest","api":1,"os":"linux","arch":"amd64","size":1,"sha256":"`+
				strings.Repeat("a", 64)+`"}`)
		}, ReasonNotRelease},
		{"too large", func(t *testing.T, bin string) {
			writeFloorBytes(t, bin, FloorName, strings.Repeat(" ", maxManifestSize+1))
		}, "at most"},
		{"a signature too large", func(t *testing.T, bin string) {
			writeFloorBytes(t, bin, FloorName, string(good.Raw))
			writeFloorBytes(t, bin, FloorSigName, strings.Repeat("A", maxSignatureSize+1))
		}, "at most"},
		{"a link", func(t *testing.T, bin string) {
			other := filepath.Join(shortDir(t), "floor")
			if err := WriteFloor(filepath.Dir(other), good); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(filepath.Dir(other), FloorName), filepath.Join(bin, FloorName)); err != nil {
				t.Fatal(err)
			}
		}, "root helper floor"},
		{"a signature that is a link", func(t *testing.T, bin string) {
			writeFloorBytes(t, bin, FloorName, string(good.Raw))
			if err := os.Symlink("/etc/hosts", filepath.Join(bin, FloorSigName)); err != nil {
				t.Fatal(err)
			}
		}, "root helper floor"},
		{"a folder", func(t *testing.T, bin string) {
			if err := os.Mkdir(filepath.Join(bin, FloorName), 0o700); err != nil {
				t.Fatal(err)
			}
		}, "not a regular file"},
		{"a FIFO", func(t *testing.T, bin string) {
			if err := unix.Mkfifo(filepath.Join(bin, FloorName), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "not a regular file"},
		{"a folder others can write", func(t *testing.T, bin string) {
			if err := WriteFloor(bin, good); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(bin, 0o777); err != nil {
				t.Fatal(err)
			}
		}, "written by others"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bin := filepath.Join(shortDir(t), "rootd")
			if err := os.Mkdir(bin, 0o700); err != nil {
				t.Fatal(err)
			}
			tc.make(t, bin)
			f, err := ReadFloor(bin)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ReadFloor = %+v, %v; want an error with %q", f, err, tc.want)
			}
		})
	}
}

// TestWriteFloorFails: a floor that cannot be written is an error, and
// leaves nothing half-written behind.
func TestWriteFloorFails(t *testing.T) {
	_, priv := throwaway(t)
	s := signedFor(t, priv, []byte("helper"), "v1.0.0")
	for _, blocked := range []string{FloorName, FloorSigName} {
		bin := filepath.Join(shortDir(t), "rootd")
		if err := os.MkdirAll(filepath.Join(bin, blocked), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := WriteFloor(bin, s); err == nil {
			t.Fatalf("wrote a floor with a folder at %s", blocked)
		}
		for _, n := range binEntries(t, bin) {
			if n != blocked && n != FloorSigName {
				t.Fatalf("%s blocked: the folder holds %s", blocked, n)
			}
		}
	}
	unsigned := s
	unsigned.Signature = nil
	bin := filepath.Join(shortDir(t), "rootd")
	if err := os.MkdirAll(filepath.Join(bin, FloorSigName, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := WriteFloor(bin, unsigned); err == nil {
		t.Fatal("wrote an unsigned floor beside a signature it could not remove")
	}
	open := filepath.Join(shortDir(t), "open")
	if err := os.Mkdir(open, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := WriteFloor(open, s); err == nil || !strings.Contains(err.Error(), "written by others") {
		t.Fatalf("WriteFloor in a folder others write = %v", err)
	}
}

// TestResume: after a restart, the floor's own copy runs again only when
// the floor's signature verifies against the keys of the image that runs
// now and the copy is still exactly that binary. Anything else is refused,
// and nothing runs from the folder.
func TestResume(t *testing.T) {
	l := newLayout(t)
	body := []byte("helper v1")
	r := l.stageRelease(t, body, "v1.0.0")
	inst, err := l.install()
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(r.dir, ManifestName))
	sig, _ := os.ReadFile(filepath.Join(r.dir, SignatureName))
	floor := Signed{Manifest: inst.Manifest, Raw: raw, Signature: sig}
	got, err := Resume(l.bin, l.keys, floor)
	if err != nil {
		t.Fatal(err)
	}
	if got.Path != inst.Path || got.Manifest != inst.Manifest || !bytes.Equal(got.Raw, raw) || !bytes.Equal(got.Signature, sig) {
		t.Fatalf("Resume = %+v, want %+v", got, inst)
	}

	newKey, newPriv := throwaway(t)
	_, otherPriv := throwaway(t)
	for _, tc := range []struct {
		name  string
		keys  []ed25519.PublicKey
		floor func() Signed
		bin   func(t *testing.T)
		want  string
	}{
		{"no signature kept", l.keys, func() Signed { f := floor; f.Signature = nil; return f }, nil, ReasonUnsigned},
		{"keys of this image changed", []ed25519.PublicKey{newKey}, func() Signed { return floor }, nil, ReasonBadSignature},
		{"signed by another key", l.keys, func() Signed {
			f := floor
			_, f.Signature, _ = Sign(otherPriv, floor.Manifest)
			return f
		}, nil, ReasonBadSignature},
		{"a manifest that is not the one signed", l.keys, func() Signed {
			f := floor
			f.Manifest.Version = "v9.9.9"
			return f
		}, nil, ReasonBadManifest},
		{"a manifest for another machine", []ed25519.PublicKey{newKey}, func() Signed {
			m := floor.Manifest
			m.OS = map[string]string{"linux": "darwin"}[m.OS]
			if m.OS == "" {
				m.OS = "linux"
			}
			raw, sig, _ := Sign(newPriv, m)
			return Signed{Manifest: m, Raw: raw, Signature: sig}
		}, nil, ReasonPlatform},
		{"the copy is gone", l.keys, func() Signed { return floor }, func(t *testing.T) {
			if err := os.Remove(inst.Path); err != nil {
				t.Fatal(err)
			}
		}, "root helper copy"},
		{"the copy changed", l.keys, func() Signed { return floor }, func(t *testing.T) {
			if err := os.WriteFile(inst.Path, []byte("helper v2"), 0o500); err != nil {
				t.Fatal(err)
			}
		}, ReasonHash},
		{"the copy is a link", l.keys, func() Signed { return floor }, func(t *testing.T) {
			other := filepath.Join(shortDir(t), "helper")
			if err := os.WriteFile(other, body, 0o500); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(inst.Path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(other, inst.Path); err != nil {
				t.Fatal(err)
			}
		}, "root helper copy"},
		{"the folder is open to others", l.keys, func() Signed { return floor }, func(t *testing.T) {
			if err := os.Chmod(l.bin, 0o777); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(l.bin, 0o700) })
		}, "written by others"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Each case starts from the copy as installed.
			_ = os.Remove(inst.Path)
			if _, err := l.install(); err != nil {
				t.Fatal(err)
			}
			if tc.bin != nil {
				_ = os.Chmod(inst.Path, 0o700)
				tc.bin(t)
			}
			if got, err := Resume(l.bin, tc.keys, tc.floor()); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Resume = %+v, %v; want an error with %q", got, err, tc.want)
			}
		})
	}
}

func writeFloorBytes(t *testing.T, bin, name, s string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(bin, name), []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestFloorOfAnotherUser: a floor or floor signature that is not root's own
// file is refused, even in root's folder. Only root can make one, so the
// test runs as root (a privileged Linux container); elsewhere it skips.
func TestFloorOfAnotherUser(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("only root can give a file to another user")
	}
	_, priv := throwaway(t)
	good := signedFor(t, priv, []byte("helper"), "v1.0.0")
	for _, name := range []string{FloorName, FloorSigName} {
		bin := filepath.Join(shortDir(t), "rootd")
		if err := WriteFloor(bin, good); err != nil {
			t.Fatal(err)
		}
		if err := os.Lchown(filepath.Join(bin, name), 1000, 1000); err != nil {
			t.Fatal(err)
		}
		if f, err := ReadFloor(bin); err == nil || !strings.Contains(err.Error(), "belongs to uid 1000") {
			t.Fatalf("%s of uid 1000: ReadFloor = %+v, %v", name, f, err)
		}
	}
}
