package containerd

import (
	"archive/tar"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/docker"
)

// writeInspectingBuildctl writes a stand-in buildctl that copies the build
// context's app/main.go and Dockerfile into out, so a test can see what the
// unpacker left after BuildImage has removed its temp folder.
func writeInspectingBuildctl(t *testing.T, out string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "buildctl")
	script := `#!/bin/sh
for a in "$@"; do case "$a" in context=*) ctx="${a#context=}";; esac; done
{ cat "$ctx/app/main.go"; echo; cat "$ctx/Dockerfile"; } > "` + out + `"
`
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// emptyTempDir points os.TempDir at a fresh folder, so a test can check that
// BuildImage left nothing behind.
func emptyTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	return dir
}

func assertEmptyDir(t *testing.T, dir string) {
	t.Helper()
	left, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Fatalf("BuildImage left %d entries in %s, first %q", len(left), dir, left[0].Name())
	}
}

func contextWithDockerfile(t *testing.T) []byte {
	t.Helper()
	return tarWith(t, func(tw *tar.Writer) {
		_ = tw.WriteHeader(&tar.Header{Name: "app/", Mode: 0o755, Typeflag: tar.TypeDir})
		_ = tw.WriteHeader(&tar.Header{Name: "app/main.go", Mode: 0o644, Size: 5, Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte("hello"))
		// The tenant's own Dockerfile, which the request's must replace.
		_ = tw.WriteHeader(&tar.Header{Name: "Dockerfile", Mode: 0o644, Size: 11, Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte("FROM tenant"))
	})
}

// With the child path off (any sandboxd that is not root on Linux, and every
// other OS), the context still unpacks, in process, and the request's
// Dockerfile replaces the one the tar carried.
func TestBuildImageUnpacksInProcessWhenNoChild(t *testing.T) {
	orig := unpackInChild
	t.Cleanup(func() { unpackInChild = orig })
	unpackInChild = func() bool { return false }

	out := filepath.Join(t.TempDir(), "seen")
	b := NewBuildKitBuilder("", writeInspectingBuildctl(t, out), nil)
	tmp := emptyTempDir(t)
	err := b.BuildImage(context.Background(), docker.BuildImageRequest{
		Tag:               "built:fallback",
		DockerfileContent: "FROM request",
		ContextTar:        contextWithDockerfile(t),
	})
	if err != nil {
		t.Fatalf("BuildImage: %v", err)
	}
	got, _ := os.ReadFile(out)
	if string(got) != "hello\nFROM request\n" {
		t.Fatalf("buildctl saw %q, want the context file and the request's Dockerfile", got)
	}
	assertEmptyDir(t, tmp)
}

// writeDockerfile is a root write into a folder the unpacker owns, so it
// must replace a link at the name, never write through it.
func TestWriteDockerfileReplacesALink(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(outside, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "Dockerfile")); err != nil {
		t.Fatal(err)
	}
	if err := writeDockerfile(dir, "FROM alpine\n"); err != nil {
		t.Fatalf("writeDockerfile: %v", err)
	}
	if got, _ := os.ReadFile(outside); string(got) != "keep" {
		t.Fatalf("the link's target was written: %q", got)
	}
	info, err := os.Lstat(filepath.Join(dir, "Dockerfile"))
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("Dockerfile = %v, %v; want a regular file", info, err)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "Dockerfile")); string(got) != "FROM alpine\n" {
		t.Fatalf("Dockerfile = %q", got)
	}

	if err := writeDockerfile(filepath.Join(dir, "missing"), "x"); err == nil {
		t.Fatal("writeDockerfile into a missing folder must fail")
	}
}

// The child unpacks into "." after it enters its folder; the bounds come in
// as arguments.
func TestExtractTarStreamIntoWorkingDir(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	data := tarWith(t, func(tw *tar.Writer) {
		_ = tw.WriteHeader(&tar.Header{Name: "top.txt", Mode: 0o600, Size: 2, Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte("hi"))
		_ = tw.WriteHeader(&tar.Header{Name: "a/b/c.txt", Mode: 0o644, Size: 1, Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte("c"))
	})
	if err := extractTarStream(bytes.NewReader(data), ".", 10, 100); err != nil {
		t.Fatalf("extractTarStream: %v", err)
	}
	for name, want := range map[string]string{"top.txt": "hi", "a/b/c.txt": "c"} {
		if got, err := os.ReadFile(filepath.Join(dir, name)); err != nil || string(got) != want {
			t.Fatalf("%s = %q, %v; want %q", name, got, err, want)
		}
	}
	if err := extractTarStream(bytes.NewReader(data), ".", 1, 100); err == nil || !strings.Contains(err.Error(), "max 1") {
		t.Fatalf("extractTarStream with max 1 entry = %v", err)
	}
	if err := extractTarStream(bytes.NewReader(data), ".", 10, 2); err == nil || !strings.Contains(err.Error(), "exceeds 2 bytes") {
		t.Fatalf("extractTarStream with max 2 bytes = %v", err)
	}
	if err := extractTarStream(bytes.NewReader(data), filepath.Join(dir, "missing"), 10, 100); err == nil {
		t.Fatal("extractTarStream into a missing folder must fail")
	}
}

// Links, devices and pipes in a context tar are skipped, never made, so no
// later entry can write through them. Both a link out of the folder and a
// file named through it end up as plain folders and files inside.
func TestExtractTarSkipsLinksAndSpecialFiles(t *testing.T) {
	outside := t.TempDir()
	data := tarWith(t, func(tw *tar.Writer) {
		_ = tw.WriteHeader(&tar.Header{Name: "link", Typeflag: tar.TypeSymlink, Linkname: outside})
		_ = tw.WriteHeader(&tar.Header{Name: "link/pwned", Mode: 0o644, Size: 1, Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte("x"))
		_ = tw.WriteHeader(&tar.Header{Name: "up", Typeflag: tar.TypeSymlink, Linkname: "../../.."})
		_ = tw.WriteHeader(&tar.Header{Name: "hard", Typeflag: tar.TypeLink, Linkname: "/etc/passwd"})
		_ = tw.WriteHeader(&tar.Header{Name: "pipe", Typeflag: tar.TypeFifo, Mode: 0o644})
		_ = tw.WriteHeader(&tar.Header{Name: "dev", Typeflag: tar.TypeChar, Mode: 0o644, Devmajor: 1, Devminor: 3})
	})
	dir := t.TempDir()
	if err := extractTar(data, dir); err != nil {
		t.Fatalf("extractTar: %v", err)
	}
	assertEmptyDir(t, outside)
	info, err := os.Lstat(filepath.Join(dir, "link"))
	if err != nil || !info.IsDir() {
		t.Fatalf("link = %v, %v; want a plain folder", info, err)
	}
	for _, name := range []string{"up", "hard", "pipe", "dev"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatalf("%s was made (err %v); links and special files must be skipped", name, err)
		}
	}
}

// readOnlyDuplicateTar carries obj/f twice, the first copy 0444, as tar -r
// and a repo's .git/objects make.
func readOnlyDuplicateTar(t *testing.T) []byte {
	t.Helper()
	return tarWith(t, func(tw *tar.Writer) {
		_ = tw.WriteHeader(&tar.Header{Name: "obj/f", Mode: 0o444, Size: 3, Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte("one"))
		_ = tw.WriteHeader(&tar.Header{Name: "obj/f", Mode: 0o644, Size: 3, Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte("two"))
	})
}

// An unpacker that is not root may not write a read-only file it made
// itself; the later copy replaces it instead, mode included.
func TestExtractTarReplacesReadOnlyDuplicate(t *testing.T) {
	dir := t.TempDir()
	if err := extractTar(readOnlyDuplicateTar(t), dir); err != nil {
		t.Fatalf("extractTar: %v", err)
	}
	path := filepath.Join(dir, "obj", "f")
	if got, _ := os.ReadFile(path); string(got) != "two" {
		t.Fatalf("obj/f = %q, want the later copy", got)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm()&0o200 == 0 {
		t.Fatalf("obj/f mode = %v, %v; want the later copy's, owner-writable", info.Mode(), err)
	}
}

// A name longer than PATH_MAX, or nested deeper than the cap, is refused
// before anything is made; one at both limits unpacks.
func TestExtractTarCapsNameLengthAndDepth(t *testing.T) {
	dirEntry := func(name string) []byte {
		return tarWith(t, func(tw *tar.Writer) {
			_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Typeflag: tar.TypeDir})
		})
	}
	for _, tc := range []struct {
		name string
		want string
	}{
		{strings.Repeat("a/", maxContextDepth+1), "nested deeper than 256 folders"},
		{strings.Repeat("b", 200) + "/" + strings.Repeat("c/", 2000), "longer than 4096 bytes"},
	} {
		dir := t.TempDir()
		if err := extractTar(dirEntry(tc.name), dir); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%.20q...: %v, want %q", tc.name, err, tc.want)
		}
		assertEmptyDir(t, dir)
	}
	dir := t.TempDir()
	atCap := strings.Repeat("a/", maxContextDepth)
	if err := extractTar(dirEntry(atCap), dir); err != nil {
		t.Fatalf("%d levels: %v", maxContextDepth, err)
	}
	if _, err := os.Stat(filepath.Join(dir, atCap)); err != nil {
		t.Fatalf("the deepest folder was not made: %v", err)
	}
	// 16 levels of 255-byte names (NAME_MAX): exactly 4096 bytes.
	exact := strings.Repeat(strings.Repeat("e", 255)+"/", 16)
	if len(exact) != maxContextNameBytes {
		t.Fatalf("test name is %d bytes", len(exact))
	}
	if err := extractTar(dirEntry(exact), t.TempDir()); err != nil {
		t.Fatalf("a name of exactly %d bytes: %v", maxContextNameBytes, err)
	}
}

// Every builder gets the default range; one set to another base shares the
// pool for that range with any other builder on it. A pool hands out each
// pair once until it comes back, and waiting for one gives up with ctx.
func TestContextIDPool(t *testing.T) {
	b := NewBuildKitBuilder("", "", nil)
	if p := b.contextIDs; p.uidBase != config.DefaultBuildContextIDBase || p.gidBase != config.DefaultBuildContextIDBase || cap(p.free) != config.BuildContextIDCount {
		t.Fatalf("default pool = %d/%d x%d", p.uidBase, p.gidBase, cap(p.free))
	}
	// A base past a 32-bit int goes through a variable: as a constant it
	// would not compile on a 32-bit build. There it wraps, and the pool
	// still keeps and shares the base it is given.
	var wide int64 = 3_000_000_000
	high := int(wide)
	if b.WithContextIDBase(high) != b || b.contextIDs.uidBase != high || b.contextIDs.gidBase != high {
		t.Fatalf("WithContextIDBase: %d/%d", b.contextIDs.uidBase, b.contextIDs.gidBase)
	}
	if NewBuildKitBuilder("", "", nil).WithContextIDBase(high).contextIDs != b.contextIDs {
		t.Fatal("two builders on one range must share its pool")
	}

	p := sharedContextIDPool(7_000_000, 8_000_000, 2)
	u1, g1, o1, err := p.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	u2, g2, _, err := p.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// The pool is shared state: refill it for the next run (-count).
	t.Cleanup(func() {
		for len(p.free) > 0 {
			<-p.free
		}
		for i := range cap(p.free) {
			p.release(i)
		}
	})
	if u1 == u2 || g1 == g2 || u1-7_000_000 != g1-8_000_000 || u2-7_000_000 != g2-8_000_000 {
		t.Fatalf("pairs %d:%d and %d:%d", u1, g1, u2, g2)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, _, err := p.acquire(cancelled); err == nil {
		t.Fatal("an empty pool must give up with ctx")
	}
	p.release(o1)
	if u, _, off, err := p.acquire(context.Background()); err != nil || u != u1 || off != o1 {
		t.Fatalf("after release: %d, %v; want %d", u, err, u1)
	}

	// unpackContext waits for an id the same way.
	orig := unpackInChild
	t.Cleanup(func() { unpackInChild = orig })
	unpackInChild = func() bool { return true }
	busy := NewBuildKitBuilder("", "", nil)
	busy.contextIDs = p // both ids taken above
	err = busy.unpackContext(cancelled, readOnlyDuplicateTar(t), filepath.Join(t.TempDir(), "context"))
	if err == nil || !strings.Contains(err.Error(), "wait for a free id") {
		t.Fatalf("unpackContext with no free id = %v", err)
	}
}

// The daemon-start check has nothing to say where the unpacker is not used.
func TestCheckContextUnpackerWithoutChild(t *testing.T) {
	orig := unpackInChild
	t.Cleanup(func() { unpackInChild = orig })
	unpackInChild = func() bool { return false }
	if err := NewBuildKitBuilder("", "", nil).CheckContextUnpacker(); err != nil {
		t.Fatalf("CheckContextUnpacker = %v", err)
	}
}
