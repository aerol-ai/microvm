package rootfstar

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func writeFile(t *testing.T, root, guestPath, content string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(guestPath))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// entries reads a tar into name -> header (and content for files).
func entries(t *testing.T, data []byte) (map[string]*tar.Header, map[string]string) {
	t.Helper()
	headers, contents := map[string]*tar.Header{}, map[string]string{}
	tr := tar.NewReader(bytes.NewReader(data))
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return headers, contents
		}
		if err != nil {
			t.Fatal(err)
		}
		headers[hdr.Name] = hdr
		if hdr.Typeflag == tar.TypeReg {
			b, _ := io.ReadAll(tr)
			contents[hdr.Name] = string(b)
		}
	}
}

func names(headers map[string]*tar.Header) []string {
	out := make([]string, 0, len(headers))
	for n := range headers {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func TestWriteKeepsWhatAnImageLayerNeeds(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "/etc/os-release", "ID=alpine\n")
	writeFile(t, root, "/root/app/main.py", "print('hi')\n")
	if err := os.Symlink("main.py", filepath.Join(root, "root/app/entry")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(root, "root/app/main.py"), filepath.Join(root, "root/app/main-copy.py")); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := Write(&buf, root); err != nil {
		t.Fatal(err)
	}
	headers, contents := entries(t, buf.Bytes())
	if contents["etc/os-release"] != "ID=alpine\n" || headers["root/app/"] == nil {
		t.Fatalf("entries %v", names(headers))
	}
	if h := headers["root/app/entry"]; h == nil || h.Typeflag != tar.TypeSymlink || h.Linkname != "main.py" {
		t.Fatalf("symlink = %+v", h)
	}
	// One of the two names is the file, the other a hard link to it.
	a, b := headers["root/app/main.py"], headers["root/app/main-copy.py"]
	if a == nil || b == nil || (a.Typeflag == tar.TypeLink) == (b.Typeflag == tar.TypeLink) {
		t.Fatalf("hard link pair = %+v / %+v", a, b)
	}
	if a.Uname != "" || a.Gname != "" {
		t.Fatal("owner names leaked into the image")
	}
}

func TestWriteKeepsExtendedAttributes(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "/usr/bin/ping", "elf")
	if err := unix.Lsetxattr(filepath.Join(root, "usr/bin/ping"), "user.aerolvm-test", []byte("cap"), 0); err != nil {
		t.Skipf("this filesystem keeps no user xattrs: %v", err)
	}
	var buf bytes.Buffer
	if err := Write(&buf, root); err != nil {
		t.Fatal(err)
	}
	headers, _ := entries(t, buf.Bytes())
	if got := headers["usr/bin/ping"].PAXRecords["SCHILY.xattr.user.aerolvm-test"]; got != "cap" {
		t.Fatalf("xattr in tar = %q, want cap", got)
	}
}

// A socket a guest program left on its disk does not stop the export.
func TestWriteLeavesOutSockets(t *testing.T) {
	// Short path: a unix socket name is capped near 100 bytes.
	root, err := os.MkdirTemp("", "fcs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	writeFile(t, root, "/etc/hostname", "box")
	ln, err := net.Listen("unix", filepath.Join(root, "agent.sock"))
	if err != nil {
		t.Skipf("no unix sockets here: %v", err)
	}
	defer ln.Close()
	var buf bytes.Buffer
	if err := Write(&buf, root); err != nil {
		t.Fatal(err)
	}
	headers, _ := entries(t, buf.Bytes())
	if _, ok := headers["agent.sock"]; ok {
		t.Fatal("the socket is in the image")
	}
	if _, ok := headers["etc/hostname"]; !ok {
		t.Fatal("the files next to the socket are missing")
	}
}

// File names on a Linux disk are bytes, not UTF-8; the export keeps them.
func TestWriteKeepsNamesThatAreNotUTF8(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "caf\xe9")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Skipf("this filesystem wants UTF-8 names: %v", err)
	}
	writeFile(t, dir, "/menu", "soup")
	var buf bytes.Buffer
	if err := Write(&buf, root); err != nil {
		t.Fatal(err)
	}
	headers, _ := entries(t, buf.Bytes())
	if _, ok := headers["caf\xe9/menu"]; !ok {
		t.Fatalf("entries %v, want caf\\xe9/menu", names(headers))
	}
}

// failAfter accepts limit bytes, then fails every write: the reading side
// going away mid-stream.
type failAfter struct{ limit, n int }

func (w *failAfter) Write(p []byte) (int, error) {
	if w.n+len(p) > w.limit {
		return 0, errors.New("reader gone")
	}
	w.n += len(p)
	return len(p), nil
}

func TestWriteFailures(t *testing.T) {
	t.Run("a missing root", func(t *testing.T) {
		if err := Write(io.Discard, filepath.Join(t.TempDir(), "missing")); err == nil {
			t.Fatal("no error")
		}
	})
	t.Run("an unreadable file", func(t *testing.T) {
		if os.Getuid() == 0 {
			t.Skip("root reads mode-000 files")
		}
		root := t.TempDir()
		writeFile(t, root, "/secret", "x")
		if err := os.Chmod(filepath.Join(root, "secret"), 0); err != nil {
			t.Fatal(err)
		}
		if err := Write(io.Discard, root); err == nil {
			t.Fatal("no error")
		}
	})
	root := t.TempDir()
	writeFile(t, root, "/data", strings.Repeat("x", 100))
	var whole bytes.Buffer
	if err := Write(&whole, root); err != nil {
		t.Fatal(err)
	}
	// The stream is header(s), one 512-byte content block, then the
	// 1024-byte trailer.
	headerBytes := whole.Len() - 512 - 1024
	for name, limit := range map[string]int{"the reader goes in a header": 0, "the reader goes in a file's content": headerBytes} {
		t.Run(name, func(t *testing.T) {
			if err := Write(&failAfter{limit: limit}, root); err == nil || !strings.Contains(err.Error(), "reader gone") {
				t.Fatalf("err = %v, want the write error", err)
			}
		})
	}
}

// tarOf builds a tar stream from entries in order.
type entry struct {
	name     string
	typeflag byte
	linkname string
	body     string
}

func tarOf(t *testing.T, list ...entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range list {
		hdr := &tar.Header{Name: e.name, Typeflag: e.typeflag, Linkname: e.linkname, Mode: 0o644, Size: int64(len(e.body))}
		if e.typeflag != tar.TypeReg {
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if hdr.Size > 0 {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

var agentFiles = map[string]bool{"/etc/toolboxd.env": true, "/lost+found": true}

func excluded(p string) bool { return agentFiles[p] }

func TestFilterDropsExcludedEntries(t *testing.T) {
	src := tarOf(t,
		entry{name: "etc/", typeflag: tar.TypeDir},
		entry{name: "etc/os-release", typeflag: tar.TypeReg, body: "ID=alpine"},
		entry{name: "etc/toolboxd.env", typeflag: tar.TypeReg, body: "SB_TOOLBOX_TOKEN=secret"},
		entry{name: "etc/token-link", typeflag: tar.TypeLink, linkname: "etc/toolboxd.env"},
		entry{name: "etc/token-symlink", typeflag: tar.TypeSymlink, linkname: "/etc/toolboxd.env"},
		entry{name: "lost+found/", typeflag: tar.TypeDir},
		entry{name: "lost+found/#12", typeflag: tar.TypeReg, body: "orphan"},
		entry{name: "./root/a", typeflag: tar.TypeReg, body: "a"},
		entry{name: "root/b", typeflag: tar.TypeLink, linkname: "root/a"},
	)
	var out bytes.Buffer
	if err := Filter(&out, bytes.NewReader(src), excluded, 1<<20); err != nil {
		t.Fatal(err)
	}
	headers, contents := entries(t, out.Bytes())
	want := []string{"./root/a", "etc/", "etc/os-release", "etc/token-symlink", "root/b"}
	if got := names(headers); !reflect.DeepEqual(got, want) {
		t.Fatalf("entries %v, want %v", got, want)
	}
	if contents["etc/os-release"] != "ID=alpine" || strings.Contains(out.String(), "secret") {
		t.Fatal("content lost, or the token kept")
	}
}

func TestFilterRefusesAnUnsafeOrBrokenStream(t *testing.T) {
	for name, src := range map[string][]byte{
		"an absolute name":       tarOf(t, entry{name: "/etc/passwd", typeflag: tar.TypeReg, body: "x"}),
		"a name that climbs out": tarOf(t, entry{name: "a/../../etc/passwd", typeflag: tar.TypeReg, body: "x"}),
		"an empty name":          tarOf(t, entry{name: "/", typeflag: tar.TypeDir}),
		"a hard link out":        tarOf(t, entry{name: "a", typeflag: tar.TypeLink, linkname: "../../etc/shadow"}),
		"garbage":                bytes.Repeat([]byte{0x7f}, 1024),
	} {
		t.Run(name, func(t *testing.T) {
			if err := Filter(io.Discard, bytes.NewReader(src), nil, 1<<20); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	t.Run("a stream cut short", func(t *testing.T) {
		whole := tarOf(t, entry{name: "data", typeflag: tar.TypeReg, body: strings.Repeat("x", 2000)})
		err := Filter(io.Discard, bytes.NewReader(whole[:900]), nil, 1<<20)
		if err == nil || !strings.Contains(err.Error(), "rootfs stream") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("a writer that fails", func(t *testing.T) {
		src := tarOf(t, entry{name: "data", typeflag: tar.TypeReg, body: strings.Repeat("x", 2000)})
		if err := Filter(&failAfter{limit: 0}, bytes.NewReader(src), nil, 1<<20); err == nil {
			t.Fatal("accepted")
		}
		if err := Filter(&failAfter{limit: 600}, bytes.NewReader(src), nil, 1<<20); err == nil {
			t.Fatal("accepted")
		}
	})
}

// A stream longer than the limit is refused, whether it runs over in a
// header or in a file's body; one exactly at it is not.
func TestFilterEnforcesTheSizeLimit(t *testing.T) {
	src := tarOf(t, entry{name: "data", typeflag: tar.TypeReg, body: strings.Repeat("x", 4096)})
	if err := Filter(io.Discard, bytes.NewReader(src), nil, int64(len(src))); err != nil {
		t.Fatalf("a stream exactly at the limit: %v", err)
	}
	for _, limit := range []int64{100, 2048} {
		if err := Filter(io.Discard, bytes.NewReader(src), nil, limit); !errors.Is(err, ErrTooLarge) {
			t.Fatalf("limit %d: err = %v, want ErrTooLarge", limit, err)
		}
	}
	c := &countingReader{r: bytes.NewReader(src), limit: 1, over: true}
	if _, err := c.Read(make([]byte, 8)); !errors.Is(err, ErrTooLarge) {
		t.Fatal("a reader already over its limit read on")
	}
}
