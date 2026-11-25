package rootswap

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// TestFloor: a folder with no floor has none; the floor read back is the
// manifest written last, in a file only root can read, with nothing
// half-written left beside it.
func TestFloor(t *testing.T) {
	bin := filepath.Join(shortDir(t), "root", "rootd")
	if f, err := ReadFloor(bin); err != nil || f != nil {
		t.Fatalf("no floor yet: %+v, %v", f, err)
	}
	for _, v := range []string{"v1.0.0", "v1.2.0", "v1.1.0"} {
		m := manifestFor(t, []byte("helper "+v), v)
		if err := WriteFloor(bin, m); err != nil {
			t.Fatal(err)
		}
		f, err := ReadFloor(bin)
		if err != nil || f == nil || *f != m {
			t.Fatalf("after writing %s: %+v, %v", v, f, err)
		}
	}
	if got := strings.Join(binEntries(t, bin), ","); got != FloorName {
		t.Fatalf("the folder holds %s", got)
	}
	fi, err := os.Stat(filepath.Join(bin, FloorName))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("floor file %v, %v; want mode 0600", fi, err)
	}
	if err := WriteFloor(bin, Manifest{Kind: Kind, Version: "latest"}); err == nil {
		t.Fatal("wrote a floor that is no release")
	}
}

// TestFloorRefuses: a floor that is there but is not a whole manifest in a
// regular file of root's, in root's own folder, is an error, never "no
// floor": the supervisor then runs nothing rather than anything.
func TestFloorRefuses(t *testing.T) {
	good := manifestFor(t, []byte("helper"), "v1.0.0")
	for _, tc := range []struct {
		name string
		make func(t *testing.T, bin string)
		want string
	}{
		{"not json", func(t *testing.T, bin string) { writeFloorBytes(t, bin, "{not json") }, ReasonBadManifest},
		{"a field it does not know", func(t *testing.T, bin string) {
			writeFloorBytes(t, bin, `{"kind":"aerolvm-rootd","version":"v1.0.0","api":1,"os":"linux","arch":"amd64","size":1,"sha256":"`+
				strings.Repeat("a", 64)+`","extra":1}`)
		}, ReasonBadManifest},
		{"data after it", func(t *testing.T, bin string) {
			if err := WriteFloor(bin, good); err != nil {
				t.Fatal(err)
			}
			f, err := os.OpenFile(filepath.Join(bin, FloorName), os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = f.WriteString("{}")
			_ = f.Close()
		}, ReasonBadManifest},
		{"no release version", func(t *testing.T, bin string) {
			writeFloorBytes(t, bin, `{"kind":"aerolvm-rootd","version":"latest","api":1,"os":"linux","arch":"amd64","size":1,"sha256":"`+
				strings.Repeat("a", 64)+`"}`)
		}, ReasonNotRelease},
		{"too large", func(t *testing.T, bin string) { writeFloorBytes(t, bin, strings.Repeat(" ", maxManifestSize+1)) }, "at most"},
		{"a link", func(t *testing.T, bin string) {
			other := filepath.Join(shortDir(t), "floor")
			if err := WriteFloor(filepath.Dir(other), good); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(filepath.Dir(other), FloorName), filepath.Join(bin, FloorName)); err != nil {
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
	m := manifestFor(t, []byte("helper"), "v1.0.0")
	bin := filepath.Join(shortDir(t), "rootd")
	if err := os.MkdirAll(filepath.Join(bin, FloorName), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := WriteFloor(bin, m); err == nil {
		t.Fatal("wrote a floor over a folder")
	}
	if got := strings.Join(binEntries(t, bin), ","); got != FloorName {
		t.Fatalf("the folder holds %s", got)
	}
	open := filepath.Join(shortDir(t), "open")
	if err := os.Mkdir(open, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := WriteFloor(open, m); err == nil || !strings.Contains(err.Error(), "written by others") {
		t.Fatalf("WriteFloor in a folder others write = %v", err)
	}
}

func writeFloorBytes(t *testing.T, bin, s string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(bin, FloorName), []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}
