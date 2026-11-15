package wasm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const fsProbeWasmName = "fsprobe.wasm"

// ensureFSProbeWasm returns the wasip1 file-system probe guest, compiling it
// from testdata/fsprobe on first use (the same pattern as the HTTP guest).
func ensureFSProbeWasm(t *testing.T) string {
	t.Helper()
	out, err := filepath.Abs(filepath.Join("testdata", fsProbeWasmName))
	if err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(out); err == nil && st.Size() > 0 {
		return out
	}
	if runtime.GOOS == "windows" {
		t.Skip("fsprobe.wasm compile skipped on windows")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain unavailable; cannot compile fsprobe.wasm")
	}
	src, err := filepath.Abs(filepath.Join("testdata", "fsprobe"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	// Build to a temp name and rename, so a parallel package run never loads a
	// half-written module.
	tmp := out + fmt.Sprintf(".%d.tmp", os.Getpid())
	cmd := exec.CommandContext(ctx, "go", "build", "-o", tmp, ".")
	cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm")
	cmd.Dir = src
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile fsprobe.wasm: %v\n%s", err, combined)
	}
	if err := os.Rename(tmp, out); err != nil {
		t.Fatal(err)
	}
	return out
}

const hostCanary = "HOST-CANARY-do-not-read"

// escapeFixture lays out a host tree with the guest's work dir four levels
// down and a canary file at every level above it, so a link that climbs any
// number of levels lands next to one:
//
//	base/canary.txt
//	base/a/canary.txt
//	base/a/b/canary.txt
//	base/a/b/c/canary.txt, victimdir/
//	base/a/b/c/work/           <- mounted at /work
//
// The work dir also holds escaping links the host planted before the guest
// started (a restored or bind-mounted directory can carry them).
type escapeFixture struct {
	base, work string
	before     map[string]string
}

func newEscapeFixture(t *testing.T) *escapeFixture {
	t.Helper()
	base := t.TempDir()
	work := filepath.Join(base, "a", "b", "c", "work")
	mustDo(t, os.MkdirAll(work, 0o755))
	for _, dir := range []string{base, filepath.Join(base, "a"), filepath.Join(base, "a", "b"), filepath.Join(base, "a", "b", "c")} {
		mustDo(t, os.WriteFile(filepath.Join(dir, "canary.txt"), []byte(hostCanary), 0o644))
	}
	mustDo(t, os.Mkdir(filepath.Join(base, "a", "b", "c", "victimdir"), 0o755))
	// An old time, so a write or a utimes through a link shows in the snapshot.
	old := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	mustDo(t, os.Chtimes(filepath.Join(base, "a", "b", "c", "canary.txt"), old, old))

	mustDo(t, os.Mkdir(filepath.Join(work, "inner"), 0o755))
	for link, target := range map[string]string{
		"pre":       "..",
		"prefile":   "../canary.txt",
		"preabs":    base,
		"dangle":    "../newfile",
		"inner/up":  "..",
		"chain":     "inner/up/..",
		"preabsdir": "/etc",
	} {
		mustDo(t, os.Symlink(target, filepath.Join(work, link)))
	}
	f := &escapeFixture{base: base, work: work}
	f.before = f.snapshotOutside(t)
	return f
}

func mustDo(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// snapshotOutside records everything under base except the work dir: type,
// mode, mtime, size, a content hash and any link target.
func (f *escapeFixture) snapshotOutside(t *testing.T) map[string]string {
	t.Helper()
	snap := map[string]string{}
	err := filepath.WalkDir(f.base, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == f.work {
			return filepath.SkipDir
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		entry := fmt.Sprintf("%v %d", fi.Mode(), fi.ModTime().UnixNano())
		switch {
		case fi.Mode().IsRegular():
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			entry += fmt.Sprintf(" %x", sha256.Sum256(data))
		case fi.Mode()&fs.ModeSymlink != 0:
			target, _ := os.Readlink(p)
			entry += " -> " + target
		}
		snap[p] = entry
		return nil
	})
	mustDo(t, err)
	return snap
}

// checkHostUntouched fails if anything outside the work dir changed, if the
// guest printed the canary, or if any name in the work dir is a hard link to
// a host canary.
func (f *escapeFixture) checkHostUntouched(t *testing.T, stdout string) {
	t.Helper()
	after := f.snapshotOutside(t)
	for p, was := range f.before {
		if now, ok := after[p]; !ok {
			t.Errorf("host file %s was removed", p)
		} else if now != was {
			t.Errorf("host file %s changed:\n was %s\n now %s", p, was, now)
		}
	}
	for p := range after {
		if _, ok := f.before[p]; !ok {
			t.Errorf("guest created %s outside its work dir", p)
		}
	}
	if strings.Contains(stdout, hostCanary) {
		t.Errorf("guest read a host canary:\n%s", stdout)
	}
	canary, err := os.Stat(filepath.Join(f.base, "a", "b", "c", "canary.txt"))
	mustDo(t, err)
	_ = filepath.WalkDir(f.work, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if fi, err := os.Lstat(p); err == nil && os.SameFile(fi, canary) {
			t.Errorf("%s is a hard link to a host file", p)
		}
		return nil
	})
}

// probeStep is one guest file operation and the outcome it must have: "ok",
// "ok=<output>", "err", "err <ERRNO>", or "any" (either, checked afterwards).
type probeStep struct {
	op   []string
	want string
}

func step(want string, op ...string) probeStep { return probeStep{op: op, want: want} }

// probeArgs turns steps into the guest's argv.
func probeArgs(steps []probeStep) []string {
	args := []string{"fsprobe"}
	for _, s := range steps {
		args = append(append(args, s.op...), ";")
	}
	return args
}

func checkProbeOutput(t *testing.T, steps []probeStep, stdout string) {
	t.Helper()
	lines := strings.Split(strings.TrimRight(stdout, "\n"), "\n")
	if len(lines) != len(steps) {
		t.Fatalf("guest printed %d lines for %d steps:\n%s", len(lines), len(steps), stdout)
	}
	for i, s := range steps {
		got := strings.TrimPrefix(lines[i], s.op[0]+" ")
		ok := false
		switch {
		case s.want == "any":
			ok = true
		case s.want == "ok":
			ok = strings.HasPrefix(got, "ok")
		case strings.HasPrefix(s.want, "ok="):
			ok = got == "ok "+strings.TrimPrefix(s.want, "ok=")
		default: // "err" or "err ERRNO"
			ok = strings.HasPrefix(got, s.want)
		}
		if !ok {
			t.Errorf("step %d %v = %q; want %s", i, s.op, got, s.want)
		}
	}
}

func climb(levels int) string {
	return strings.TrimSuffix(strings.Repeat("../", levels), "/")
}

// confinementCases are the guest-side escape attempts and the normal work
// that must keep working. Every escape must fail, and the fixture's host
// files must be left exactly as they were.
func confinementCases() []struct {
	name  string
	steps []probeStep
} {
	type tc = struct {
		name  string
		steps []probeStep
	}
	var cases []tc
	for _, levels := range []int{1, 2, 3, 4, 6, 40} {
		cases = append(cases, tc{
			name: fmt.Sprintf("new symlink climbing %d levels", levels),
			steps: []probeStep{
				step("err EPERM", "symlink", climb(levels), "/work/esc"),
				step("err", "read", "/work/esc/canary.txt"),
				step("err", "readdir", "/work/esc"),
				step("err", "write", "/work/esc/planted", "x"),
			},
		})
	}
	cases = append(cases,
		tc{name: "new symlink to the host /etc", steps: []probeStep{
			step("err EPERM", "symlink", climb(40)+"/etc", "/work/x"),
			step("err", "read", "/work/x/hosts"),
			step("err EPERM", "symlink", "/etc", "/work/abs"),
			step("err", "read", "/work/abs/hosts"),
		}},
		tc{name: "new symlink with dot-dot inside the target", steps: []probeStep{
			// Lexically outside.
			step("err EPERM", "symlink", "inner/../../canary.txt", "/work/mid"),
			step("err", "read", "/work/mid"),
			// Lexically inside today, but moving inner/ would change that.
			step("err EPERM", "symlink", "inner/..", "/work/self"),
		}},
		tc{name: "new symlink from a subdirectory", steps: []probeStep{
			step("ok", "mkdir", "/work/d"),
			step("err EPERM", "symlink", "../../canary.txt", "/work/d/l"),
			step("err", "read", "/work/d/l"),
		}},
		tc{name: "planted links are not followed out", steps: []probeStep{
			step("err", "read", "/work/pre/canary.txt"),
			step("err", "read", "/work/prefile"),
			step("err", "read", "/work/preabs/canary.txt"),
			step("err", "read", "/work/preabsdir/hosts"),
			step("err", "read", "/work/chain/canary.txt"),
			step("err", "stat", "/work/pre"),
			step("err", "stat", "/work/prefile"),
			step("err", "readdir", "/work/pre"),
			step("err", "readdir", "/work/preabs"),
			// The link itself is the guest's to see.
			step("ok", "lstat", "/work/pre"),
			step("ok=../canary.txt", "readlink", "/work/prefile"),
		}},
		tc{name: "planted links do not carry writes out", steps: []probeStep{
			step("err", "write", "/work/prefile", "x"),
			step("err", "append", "/work/prefile", "x"),
			step("err", "truncate", "/work/prefile"),
			step("err", "write", "/work/pre/planted", "x"),
			step("err", "write", "/work/dangle", "x"),
			step("err EEXIST", "openexcl", "/work/dangle"),
			step("err", "mkdir", "/work/pre/newdir"),
			step("err", "chtimes", "/work/prefile"),
			step("err", "futimes", "/work/prefile"),
			step("err", "write", "/work/chain/planted", "x"),
		}},
		tc{name: "hard links cannot reach a host file", steps: []probeStep{
			step("err", "link", "/work/pre/canary.txt", "/work/hl"),
			step("err", "link", "/work/preabs/canary.txt", "/work/hl"),
			step("err", "link", "/work/chain/canary.txt", "/work/hl"),
			// Linking the link itself is allowed on some hosts; what it
			// makes is another link, which still is not followed out.
			step("any", "link", "/work/prefile", "/work/hl2"),
			step("err", "read", "/work/hl2"),
		}},
		tc{name: "rename and unlink do not act through links", steps: []probeStep{
			step("err", "rename", "/work/pre/canary.txt", "/work/stolen"),
			step("ok", "write", "/work/mine", "guest"),
			step("err", "rename", "/work/mine", "/work/pre/moved"),
			step("err", "rename", "/work/mine", "/work/chain/moved"),
			step("err", "unlink", "/work/pre/canary.txt"),
			step("err", "unlink", "/work/chain/canary.txt"),
			step("err", "rmdir", "/work/pre/victimdir"),
			// The links themselves can be renamed and removed.
			step("ok", "rename", "/work/dangle", "/work/dangle2"),
			step("ok", "unlink", "/work/prefile"),
			step("ok", "unlink", "/work/pre"),
		}},
		tc{name: "normal work inside the mount", steps: []probeStep{
			step("ok", "write", "/work/f.txt", "hello"),
			step("ok=hello", "read", "/work/f.txt"),
			step("ok", "append", "/work/f.txt", "-world"),
			step("ok=hello-world", "read", "/work/f.txt"),
			step("ok", "mkdir", "/work/d"),
			step("err EEXIST", "mkdir", "/work/d"),
			step("ok", "write", "/work/d/g", "data"),
			step("ok", "rename", "/work/d/g", "/work/d/h"),
			step("ok=h", "readdir", "/work/d"),
			step("ok", "symlink", "d/h", "/work/lnk"),
			step("ok=data", "read", "/work/lnk"),
			step("ok=d/h", "readlink", "/work/lnk"),
			step("ok", "symlink", "up", "/work/inner/loop"),
			step("ok", "link", "/work/f.txt", "/work/f2"),
			step("ok=hello-world", "read", "/work/f2"),
			step("ok", "stat", "/work/lnk"),
			step("ok", "chtimes", "/work/f.txt"),
			step("ok", "futimes", "/work/f.txt"),
			step("ok", "truncate", "/work/f.txt"),
			step("ok=", "read", "/work/f.txt"),
			step("ok", "openexcl", "/work/new"),
			step("err EEXIST", "openexcl", "/work/new"),
			step("err ENOTEMPTY", "rmdir", "/work/d"),
			step("err EISDIR", "unlink", "/work/d"),
			step("err ENOTDIR", "rmdir", "/work/f2"),
			step("ok", "unlink", "/work/d/h"),
			step("ok", "mkdir", "/work/e"),
			step("ok", "rename", "/work/d", "/work/e"),
			step("ok", "rmdir", "/work/e"),
			step("ok", "unlink", "/work/f2"),
			step("ok", "unlink", "/work/lnk"),
			step("err ENOENT", "read", "/work/lnk"),
		}},
	)
	return cases
}

// runProbe runs the probe guest's steps against a fresh fixture and checks
// both the per-step outcomes and that the host was not touched.
func runProbe(t *testing.T, steps []probeStep, run func(Capabilities) (RunResult, error)) {
	t.Helper()
	fix := newEscapeFixture(t)
	caps := Capabilities{
		Args:           probeArgs(steps),
		Preopens:       []Preopen{{GuestPath: "/work", HostPath: fix.work}},
		WASIListenPort: WASIListenPortDisabled,
	}
	res, err := run(caps)
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("guest run: exit=%d err=%v\nstdout:\n%s\nstderr:\n%s", res.ExitCode, err, res.Stdout, res.Stderr)
	}
	checkProbeOutput(t, steps, res.Stdout)
	fix.checkHostUntouched(t, res.Stdout)
	if t.Failed() {
		t.Logf("guest output:\n%s", res.Stdout)
	}
}

func TestGuestPreopenConfinement(t *testing.T) {
	ctx := context.Background()
	mod := ensureFSProbeWasm(t)
	eng, err := newWazeroEngine(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = eng.Close(ctx) })
	if err := eng.LoadModule(ctx, mod, LoadOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range confinementCases() {
		t.Run(tc.name, func(t *testing.T) {
			runProbe(t, tc.steps, func(caps Capabilities) (RunResult, error) {
				return eng.Run(ctx, caps, "_start")
			})
		})
	}
}

// The resident host and the warm pool run guests on the MultiInstanceEngine;
// its mounts go through the same confinement.
func TestGuestPreopenConfinementMultiInstance(t *testing.T) {
	ctx := context.Background()
	mod := ensureFSProbeWasm(t)
	multi, err := NewMultiInstanceEngine(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = multi.Close(ctx) })
	if err := multi.LoadModule(ctx, mod); err != nil {
		t.Fatal(err)
	}
	for i, tc := range confinementCases() {
		t.Run(tc.name, func(t *testing.T) {
			runProbe(t, tc.steps, func(caps Capabilities) (RunResult, error) {
				return multi.Run(ctx, fmt.Sprintf("sb-%d", i), caps, "_start")
			})
		})
	}
}

// A read-only mount serves reads and refuses every change.
func TestGuestReadOnlyPreopen(t *testing.T) {
	ctx := context.Background()
	mod := ensureFSProbeWasm(t)
	eng, err := newWazeroEngine(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = eng.Close(ctx) })
	if err := eng.LoadModule(ctx, mod, LoadOptions{}); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	mustDo(t, os.WriteFile(filepath.Join(dir, "f.txt"), []byte("ro"), 0o644))
	mustDo(t, os.Mkdir(filepath.Join(dir, "sub"), 0o755))
	steps := []probeStep{
		step("ok=ro", "read", "/data/f.txt"),
		step("ok=f.txt,sub", "readdir", "/data"),
		step("err", "write", "/data/f.txt", "x"),
		step("err", "write", "/data/new", "x"),
		step("err", "append", "/data/f.txt", "x"),
		step("err", "truncate", "/data/f.txt"),
		step("err EROFS", "mkdir", "/data/d"),
		step("err EROFS", "rmdir", "/data/sub"),
		step("err EROFS", "unlink", "/data/f.txt"),
		step("err EROFS", "rename", "/data/f.txt", "/data/g"),
		step("err EROFS", "symlink", "f.txt", "/data/l"),
		step("err EROFS", "link", "/data/f.txt", "/data/l"),
		step("err EROFS", "chtimes", "/data/f.txt"),
		step("ok", "write", "/work/w", "rw"),
	}
	work := t.TempDir()
	res, err := eng.Run(ctx, Capabilities{
		Args:           probeArgs(steps),
		Preopens:       []Preopen{{GuestPath: "/work", HostPath: work}, {GuestPath: "/data", HostPath: dir, ReadOnly: true}},
		WASIListenPort: WASIListenPortDisabled,
	}, "_start")
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("guest run: exit=%d err=%v\n%s%s", res.ExitCode, err, res.Stdout, res.Stderr)
	}
	checkProbeOutput(t, steps, res.Stdout)
	if data, _ := os.ReadFile(filepath.Join(dir, "f.txt")); !bytes.Equal(data, []byte("ro")) {
		t.Fatalf("read-only file changed to %q", data)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 2 {
		t.Fatalf("read-only dir has %d entries, want 2", len(entries))
	}
}
