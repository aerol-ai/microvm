package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// The shared file core (plans/agent-sandbox-feature-parity.md, F1, ER1).
// One bug here reaches the AerolVM SDKs, Daytona and E2B at once, so each
// operation is tested on its own first, then through each API's routes.

func listedRels(entries []listedEntry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, filepath.ToSlash(e.rel))
	}
	return out
}

func TestListFolderDepthCapAndSymlinks(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "a", "x", "deep.txt"), "d")
	mustWrite(t, filepath.Join(root, "a", "y.txt"), "y")
	mustWrite(t, filepath.Join(root, "b.txt"), "b")
	outside := t.TempDir()
	mustWrite(t, filepath.Join(outside, "secret.txt"), "s")
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name      string
		opts      fileOptions
		want      []string
		truncated bool
	}{
		{name: "depth 0 counts as 1", opts: fileOptions{}, want: []string{"a", "b.txt", "link"}},
		{name: "depth 1", opts: fileOptions{Depth: 1}, want: []string{"a", "b.txt", "link"}},
		// Walk order: a folder's contents right after it. The symlinked
		// folder is listed but never entered.
		{name: "depth 2", opts: fileOptions{Depth: 2}, want: []string{"a", "a/x", "a/y.txt", "b.txt", "link"}},
		{name: "depth 3", opts: fileOptions{Depth: 3}, want: []string{"a", "a/x", "a/x/deep.txt", "a/y.txt", "b.txt", "link"}},
		{name: "cap equal to the count is not truncated", opts: fileOptions{Depth: 1, EntryCap: 3}, want: []string{"a", "b.txt", "link"}},
		{name: "cap below the count truncates", opts: fileOptions{Depth: 3, EntryCap: 2}, want: []string{"a", "a/x"}, truncated: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entries, truncated, err := listFolder(root, tc.opts)
			if err != nil {
				t.Fatal(err)
			}
			if got := listedRels(entries); strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("entries = %v, want %v", got, tc.want)
			}
			if truncated != tc.truncated {
				t.Fatalf("truncated = %v, want %v", truncated, tc.truncated)
			}
		})
	}

	entries, _, err := listFolder(root, fileOptions{Depth: 1})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.rel == "link" && (e.info.Mode()&fs.ModeSymlink == 0 || e.info.IsDir()) {
			t.Fatalf("link entry = %v, want the link itself", e.info.Mode())
		}
		if e.path != filepath.Join(root, e.rel) {
			t.Fatalf("path = %q, want it under the folder as named", e.path)
		}
	}

	// The folder named may itself be a symlink, as with ls.
	viaLink, _, err := listFolder(filepath.Join(root, "link"), fileOptions{Depth: 1})
	if err != nil || len(viaLink) != 1 || viaLink[0].path != filepath.Join(root, "link", "secret.txt") {
		t.Fatalf("listing through a symlinked folder = %+v, %v", viaLink, err)
	}

	if _, _, err := listFolder(filepath.Join(root, "b.txt"), fileOptions{}); !isKindErr(err) {
		t.Fatalf("listing a file = %v, want a wrong-kind error", err)
	}
	if _, _, err := listFolder(filepath.Join(root, "missing"), fileOptions{}); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("listing a missing folder = %v, want not exist", err)
	}
}

func TestListFolderSkipsUnreadableSubfolders(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a mode-000 folder")
	}
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "locked", "hidden.txt"), "h")
	mustWrite(t, filepath.Join(root, "open", "seen.txt"), "s")
	if err := os.Chmod(filepath.Join(root, "locked"), 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(root, "locked"), 0o755) })
	entries, _, err := listFolder(root, fileOptions{Depth: 2})
	if err != nil {
		t.Fatalf("an unreadable subfolder failed the listing: %v", err)
	}
	if got := strings.Join(listedRels(entries), ","); got != "locked,open,open/seen.txt" {
		t.Fatalf("entries = %s", got)
	}
}

func isKindErr(err error) bool {
	var kind *fileKindError
	return errors.As(err, &kind)
}

func isRequestErr(err error) bool {
	var req *fileRequestError
	return errors.As(err, &req)
}

func TestMakeDirOptions(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "plain.txt")
	mustWrite(t, file, "x")
	existing := filepath.Join(root, "existing")
	if err := os.Mkdir(existing, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(existing, 0o777|fs.ModeSticky); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name     string
		path     string
		opts     fileOptions
		check    func(error) bool
		wantMode os.FileMode
	}{
		{name: "parents, new, default mode is exact", path: filepath.Join(root, "p", "q"), opts: fileOptions{CreateParents: true}, wantMode: 0o755},
		{name: "parents, existing keeps its mode", path: existing, opts: fileOptions{CreateParents: true}, wantMode: 0o777 | fs.ModeSticky},
		{name: "parents, existing with a mode", path: filepath.Join(root, "p"), opts: fileOptions{CreateParents: true, Mode: 0o700}, wantMode: 0o700},
		{name: "parents, a file in the way", path: file, opts: fileOptions{CreateParents: true}, check: isKindErr},
		{name: "plain, new with a mode", path: filepath.Join(root, "m"), opts: fileOptions{Mode: 0o750}, wantMode: 0o750},
		{name: "plain, existing", path: existing, opts: fileOptions{}, check: func(err error) bool { return errors.Is(err, fs.ErrExist) }},
		{name: "plain, missing parent", path: filepath.Join(root, "no", "such"), opts: fileOptions{}, check: func(err error) bool { return errors.Is(err, fs.ErrNotExist) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := makeDir(tc.path, tc.opts)
			if tc.check != nil {
				if !tc.check(err) {
					t.Fatalf("err = %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(tc.path)
			if err != nil || !info.IsDir() {
				t.Fatalf("folder missing: %v", err)
			}
			if got := info.Mode() & (fs.ModePerm | fs.ModeSticky); got != tc.wantMode {
				t.Fatalf("mode = %v, want %v", got, tc.wantMode)
			}
		})
	}
}

func TestRemovePathOptions(t *testing.T) {
	root := t.TempDir()
	target := t.TempDir()
	mustWrite(t, filepath.Join(target, "keep.txt"), "k")
	mustWrite(t, filepath.Join(root, "tree", "inner", "f.txt"), "f")
	mustWrite(t, filepath.Join(root, "file.txt"), "f")
	if err := os.Symlink(target, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}

	if err := removePath("/", fileOptions{Recursive: true}); !isRequestErr(err) {
		t.Fatalf("delete / = %v, want a refusal", err)
	}
	if err := removePath(filepath.Join(root, "missing"), fileOptions{}); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing = %v", err)
	}
	if err := removePath(filepath.Join(root, "tree"), fileOptions{}); !isKindErr(err) {
		t.Fatalf("folder without recursive = %v", err)
	}
	// A symlink to a folder is a file to delete, even without recursive, and
	// what it points to stays.
	if err := removePath(filepath.Join(root, "link"), fileOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(target, "keep.txt")); err != nil {
		t.Fatalf("deleting a symlink reached its target: %v", err)
	}
	for _, path := range []string{filepath.Join(root, "file.txt"), filepath.Join(root, "tree")} {
		if err := removePath(path, fileOptions{Recursive: true}); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("%s still there: %v", path, err)
		}
	}
}

func TestMovePathOverwriteParentsAndNesting(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "src.txt")
	dst := filepath.Join(root, "dst.txt")
	mustWrite(t, src, "new")
	mustWrite(t, dst, "old")

	if err := movePath(src, dst, fileOptions{}); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("move onto an existing file without overwrite = %v, want exist", err)
	}
	if mustRead(t, src) != "new" || mustRead(t, dst) != "old" {
		t.Fatal("a refused move changed a file")
	}
	if err := movePath(src, dst, fileOptions{Overwrite: true}); err != nil {
		t.Fatal(err)
	}
	if mustRead(t, dst) != "new" {
		t.Fatal("overwrite did not replace")
	}
	if err := movePath(filepath.Join(root, "missing"), dst, fileOptions{}); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing source = %v", err)
	}
	if err := movePath(dst, filepath.Join(root, "no", "parent.txt"), fileOptions{}); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing parent without CreateParents = %v", err)
	}
	moved := filepath.Join(root, "made", "for", "it.txt")
	if err := movePath(dst, moved, fileOptions{CreateParents: true}); err != nil || mustRead(t, moved) != "new" {
		t.Fatalf("move with CreateParents = %v", err)
	}

	tree := filepath.Join(root, "tree")
	mustWrite(t, filepath.Join(tree, "sub", "f"), "f")
	if err := movePath(tree, filepath.Join(tree, "sub", "inside"), fileOptions{}); !isRequestErr(err) {
		t.Fatalf("folder into itself = %v, want a refusal", err)
	}
	// A folder onto itself is not "into itself"; Go's rename refuses any
	// existing folder as the destination, as Daytona's move always has.
	if err := movePath(tree, tree, fileOptions{Overwrite: true}); !errors.Is(err, fs.ErrExist) || isRequestErr(err) {
		t.Fatalf("folder onto itself = %v, want exist", err)
	}
}

// Two movers racing for one name without overwrite: the kernel picks one
// winner, and the loser's file is still where it was.
func TestMovePathNoOverwriteRace(t *testing.T) {
	for round := 0; round < 20; round++ {
		root := t.TempDir()
		dst := filepath.Join(root, "dst")
		srcs := []string{filepath.Join(root, "a"), filepath.Join(root, "b")}
		for _, src := range srcs {
			mustWrite(t, src, filepath.Base(src))
		}
		var wg sync.WaitGroup
		errs := make([]error, len(srcs))
		for i, src := range srcs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				errs[i] = movePath(src, dst, fileOptions{})
			}()
		}
		wg.Wait()
		wins := 0
		for i, err := range errs {
			switch {
			case err == nil:
				wins++
			case errors.Is(err, fs.ErrExist):
				if _, statErr := os.Stat(srcs[i]); statErr != nil {
					t.Fatalf("the loser's source is gone: %v", statErr)
				}
			default:
				t.Fatalf("unexpected error: %v", err)
			}
		}
		if wins != 1 {
			t.Fatalf("round %d: %d movers won, want exactly 1", round, wins)
		}
	}
}

// simulateCrossDevice makes every rename of src fail with EXDEV, as a move
// from a tmpfs /tmp to the root filesystem does.
func simulateCrossDevice(t *testing.T, src string) {
	t.Helper()
	realRename, realNoReplace := renameFn, renameNoReplaceFn
	t.Cleanup(func() { renameFn, renameNoReplaceFn = realRename, realNoReplace })
	exdev := func(old, new string) error {
		return &os.LinkError{Op: "rename", Old: old, New: new, Err: syscall.EXDEV}
	}
	renameFn = func(old, new string) error {
		if old == src {
			return exdev(old, new)
		}
		return realRename(old, new)
	}
	renameNoReplaceFn = func(old, new string) error {
		if old == src {
			return exdev(old, new)
		}
		return realNoReplace(old, new)
	}
}

func TestMovePathAcrossFilesystems(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "src")
	mustWrite(t, filepath.Join(src, "inner", "f.sh"), "#!/bin/sh")
	if err := os.Chmod(filepath.Join(src, "inner", "f.sh"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("inner/f.sh", filepath.Join(src, "link")); err != nil {
		t.Fatal(err)
	}
	simulateCrossDevice(t, src)

	dst := filepath.Join(root, "dst")
	if err := movePath(src, dst, fileOptions{}); err != nil {
		t.Fatalf("move across filesystems: %v", err)
	}
	if _, err := os.Lstat(src); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("source still there after the move: %v", err)
	}
	info, err := os.Stat(filepath.Join(dst, "inner", "f.sh"))
	if err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("moved file = %v, %v; want mode 0755", info, err)
	}
	if target, err := os.Readlink(filepath.Join(dst, "link")); err != nil || target != "inner/f.sh" {
		t.Fatalf("moved symlink = %q, %v", target, err)
	}
	assertNoTempLeft(t, root)

	// Without overwrite an existing destination stops the move before any
	// copying, and the source stays whole.
	src2 := filepath.Join(root, "src2")
	mustWrite(t, filepath.Join(src2, "f"), "x")
	simulateCrossDevice(t, src2)
	if err := movePath(src2, dst, fileOptions{}); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("cross-device move onto an existing folder = %v", err)
	}
	if mustRead(t, filepath.Join(src2, "f")) != "x" {
		t.Fatal("the refused move changed its source")
	}
	// With overwrite, a non-empty folder still cannot be replaced (rename's
	// own rule); the source is kept and no temp copy is left.
	if err := movePath(src2, dst, fileOptions{Overwrite: true}); !errors.Is(err, syscall.ENOTEMPTY) && !errors.Is(err, fs.ErrExist) {
		t.Fatalf("cross-device move over a non-empty folder = %v", err)
	}
	if mustRead(t, filepath.Join(src2, "f")) != "x" {
		t.Fatal("a failed move lost its source")
	}
	assertNoTempLeft(t, root)
}

func TestMovePathAcrossFilesystemsCopyFailureKeepsSource(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "src")
	mustWrite(t, filepath.Join(src, "f"), "x")
	if err := syscall.Mkfifo(filepath.Join(src, "pipe"), 0o644); err != nil {
		t.Skip("mkfifo:", err)
	}
	simulateCrossDevice(t, src)
	if err := movePath(src, filepath.Join(root, "dst"), fileOptions{}); !isKindErr(err) {
		t.Fatalf("moving a pipe across filesystems = %v, want a wrong-kind error", err)
	}
	if mustRead(t, filepath.Join(src, "f")) != "x" {
		t.Fatal("source damaged")
	}
	if _, err := os.Lstat(filepath.Join(root, "dst")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("a failed move left a destination")
	}
	assertNoTempLeft(t, root)
}

func assertNoTempLeft(t *testing.T, dir string) {
	t.Helper()
	left, _ := filepath.Glob(filepath.Join(dir, ".*.aerolvm-*"))
	if len(left) != 0 {
		t.Fatalf("temporary copies left behind: %v", left)
	}
}

func TestCopyPath(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	mustWrite(t, filepath.Join(outside, "secret"), "s")
	src := filepath.Join(root, "src")
	mustWrite(t, filepath.Join(src, "bin", "run.sh"), "#!/bin/sh")
	if err := os.Chmod(filepath.Join(src, "bin", "run.sh"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(src, "bin"), 0o711); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(src, "out")); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "one.txt")
	mustWrite(t, file, "one")

	if err := copyPath(src, filepath.Join(root, "dst"), fileOptions{}); !isKindErr(err) {
		t.Fatalf("folder without recursive = %v", err)
	}
	dst := filepath.Join(root, "dst")
	if err := copyPath(src, dst, fileOptions{Recursive: true}); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(filepath.Join(dst, "bin", "run.sh")); err != nil || info.Mode().Perm() != 0o750 {
		t.Fatalf("copied file = %v, %v; want mode 0750", info, err)
	}
	if info, err := os.Stat(filepath.Join(dst, "bin")); err != nil || info.Mode().Perm() != 0o711 {
		t.Fatalf("copied folder = %v, %v; want mode 0711", info, err)
	}
	// The symlink is copied as a link, never followed into what it names.
	if target, err := os.Readlink(filepath.Join(dst, "out")); err != nil || target != outside {
		t.Fatalf("copied symlink = %q, %v", target, err)
	}
	if mustRead(t, filepath.Join(src, "bin", "run.sh")) != "#!/bin/sh" {
		t.Fatal("copy changed its source")
	}

	if err := copyPath(file, dst, fileOptions{}); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("copy onto an existing path = %v", err)
	}
	other := filepath.Join(root, "other.txt")
	mustWrite(t, other, "other")
	if err := copyPath(file, other, fileOptions{Overwrite: true}); err != nil || mustRead(t, other) != "one" {
		t.Fatalf("copy with overwrite = %v", err)
	}
	if err := copyPath(src, filepath.Join(src, "bin", "again"), fileOptions{Recursive: true}); !isRequestErr(err) {
		t.Fatalf("copy into itself = %v", err)
	}
	if err := copyPath(filepath.Join(root, "missing"), filepath.Join(root, "x"), fileOptions{}); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing source = %v", err)
	}
	if err := copyPath(file, filepath.Join(root, "no", "parent"), fileOptions{}); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing destination folder = %v", err)
	}
	assertNoTempLeft(t, root)
}

func TestRenameNoReplaceFallback(t *testing.T) {
	root := t.TempDir()
	a, b := filepath.Join(root, "a"), filepath.Join(root, "b")
	mustWrite(t, a, "a")
	mustWrite(t, b, "b")
	if err := renameNoReplaceFallback(a, b); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("fallback onto an existing file = %v", err)
	}
	c := filepath.Join(root, "c")
	if err := renameNoReplaceFallback(a, c); err != nil || mustRead(t, c) != "a" {
		t.Fatalf("fallback to a free name = %v", err)
	}
	if err := renameNoReplaceFallback(c, filepath.Join(b, "under-a-file")); err == nil {
		t.Fatal("fallback through a file succeeded")
	}
}

// The error writers map the same failures to the same statuses on the REST
// routes and on E2B's envd routes, each in its own body shape.
func TestFilesystemErrorStatuses(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
		code string
	}{
		{"request", &fileRequestError{msg: "no"}, http.StatusBadRequest, ""},
		{"kind", &fileKindError{msg: "folder"}, http.StatusConflict, ""},
		{"not found", &fs.PathError{Op: "open", Path: "/x", Err: syscall.ENOENT}, http.StatusNotFound, errCodeFileNotFound},
		{"permission", &fs.PathError{Op: "open", Path: "/x", Err: syscall.EACCES}, http.StatusForbidden, ""},
		{"eperm", &fs.PathError{Op: "open", Path: "/x", Err: syscall.EPERM}, http.StatusForbidden, ""},
		{"not empty", &os.LinkError{Op: "rename", Old: "a", New: "b", Err: syscall.ENOTEMPTY}, http.StatusConflict, ""},
		{"exists", &fs.PathError{Op: "mkdir", Path: "/x", Err: syscall.EEXIST}, http.StatusConflict, ""},
		{"not a folder", &fs.PathError{Op: "mkdir", Path: "/x", Err: syscall.ENOTDIR}, http.StatusConflict, ""},
		{"is a folder", &fs.PathError{Op: "open", Path: "/x", Err: syscall.EISDIR}, http.StatusConflict, ""},
		{"disk full", &fs.PathError{Op: "write", Path: "/x", Err: syscall.ENOSPC}, http.StatusInsufficientStorage, ""},
		{"quota", &fs.PathError{Op: "write", Path: "/x", Err: syscall.EDQUOT}, http.StatusInsufficientStorage, ""},
		{"other", errors.New("boom"), http.StatusInternalServerError, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rest := httptest.NewRecorder()
			writeFilesystemError(rest, tc.err)
			var body models.ErrorResponse
			if err := json.Unmarshal(rest.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if rest.Code != tc.want || body.Code != tc.code {
				t.Fatalf("REST = %d %+v, want %d code %q", rest.Code, body, tc.want, tc.code)
			}
			if tc.want == http.StatusInsufficientStorage && !strings.Contains(body.Error, "sandbox disk is full") {
				t.Fatalf("507 body = %q", body.Error)
			}
			envd := httptest.NewRecorder()
			writeEnvdFilesystemError(envd, tc.err)
			var envdBody envdErrorResponse
			if err := json.Unmarshal(envd.Body.Bytes(), &envdBody); err != nil {
				t.Fatal(err)
			}
			if envd.Code != tc.want || envdBody.Code != tc.want {
				t.Fatalf("envd = %d %+v, want %d", envd.Code, envdBody, tc.want)
			}
		})
	}
}

// daytonaStrictFileInfo mirrors Daytona's Go toolbox client, which decodes a
// FileInfo with DisallowUnknownFields: one extra field fails every Daytona Go
// SDK call that reads file details.
type daytonaStrictFileInfo struct {
	Group       string `json:"group"`
	IsDir       bool   `json:"isDir"`
	ModTime     string `json:"modTime"`
	Mode        string `json:"mode"`
	Name        string `json:"name"`
	Owner       string `json:"owner"`
	Permissions string `json:"permissions"`
	Size        int32  `json:"size"`
}

func decodeStrict(t *testing.T, data []byte, out any) {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		t.Fatalf("Daytona's client would reject %s: %v", data, err)
	}
}

func TestFileInfoRouteShapes(t *testing.T) {
	h := authedRoutes(newDaytonaTestServer(t))
	root := t.TempDir()
	file := filepath.Join(root, "f.txt")
	mustWrite(t, file, "hello")

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/files/info?path="+url.QueryEscape(file), nil))
	var daytona daytonaStrictFileInfo
	decodeStrict(t, rr.Body.Bytes(), &daytona)
	if rr.Code != http.StatusOK || daytona.Size != 5 || daytona.Name != "f.txt" {
		t.Fatalf("Daytona info = %d %+v", rr.Code, daytona)
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/files/info?extended=true&path="+url.QueryEscape(file), nil))
	var extended extendedFileInfo
	if err := json.Unmarshal(rr.Body.Bytes(), &extended); err != nil || rr.Code != http.StatusOK {
		t.Fatalf("extended info = %d %s", rr.Code, rr.Body.String())
	}
	if extended.Path != file || extended.SizeBytes != 5 || extended.Size != 5 || extended.SymlinkTarget != nil {
		t.Fatalf("extended info = %+v", extended)
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/files/info?extended=maybe&path="+url.QueryEscape(file), nil))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad extended = %d", rr.Code)
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/files/info?path="+url.QueryEscape(filepath.Join(root, "nope")), nil))
	var missing models.ErrorResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &missing)
	if rr.Code != http.StatusNotFound || missing.Code != errCodeFileNotFound {
		t.Fatalf("missing file = %d %+v", rr.Code, missing)
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/files/info", nil))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("no path = %d", rr.Code)
	}
}

// A file over 2 GiB: Daytona's 32-bit size stops at its limit, size_bytes
// does not. The file is sparse, so the test writes almost nothing.
func TestFileInfoSizeBytesPast32Bits(t *testing.T) {
	file := filepath.Join(t.TempDir(), "big")
	f, err := os.Create(file)
	if err != nil {
		t.Fatal(err)
	}
	const size = int64(5) << 30
	if err := f.Truncate(size); err != nil {
		_ = f.Close()
		t.Skip("sparse file:", err)
	}
	_ = f.Close()
	info, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	body := fileInfoBody(file, info, true).(extendedFileInfo)
	if body.SizeBytes != size || int64(body.Size) != int64(^uint32(0)>>1) {
		t.Fatalf("size_bytes = %d, size = %d", body.SizeBytes, body.Size)
	}
}

func TestListFilesRoute(t *testing.T) {
	h := authedRoutes(newDaytonaTestServer(t))
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "a", "inner.txt"), "i")
	mustWrite(t, filepath.Join(root, "b.txt"), "b")
	if err := os.Symlink("b.txt", filepath.Join(root, "c-link")); err != nil {
		t.Fatal(err)
	}

	get := func(query string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/files?path="+url.QueryEscape(root)+query, nil))
		return rr
	}

	// Daytona's call: one level, no cap, its own shape only.
	rr := get("")
	var plain []daytonaStrictFileInfo
	decodeStrict(t, rr.Body.Bytes(), &plain)
	if rr.Code != http.StatusOK || len(plain) != 3 || rr.Header().Get(listTruncatedHeader) != "" {
		t.Fatalf("Daytona list = %d %s", rr.Code, rr.Body.String())
	}

	// The SDK's call.
	rr = get("&depth=2&limit=10&extended=true")
	var items []extendedFileInfo
	if err := json.Unmarshal(rr.Body.Bytes(), &items); err != nil || rr.Code != http.StatusOK {
		t.Fatalf("SDK list = %d %s", rr.Code, rr.Body.String())
	}
	var paths []string
	for _, item := range items {
		paths = append(paths, strings.TrimPrefix(item.Path, root))
		if strings.HasSuffix(item.Path, "c-link") && (item.SymlinkTarget == nil || *item.SymlinkTarget != "b.txt") {
			t.Fatalf("symlink entry = %+v", item)
		}
	}
	if strings.Join(paths, ",") != "/a,/a/inner.txt,/b.txt,/c-link" {
		t.Fatalf("paths = %v", paths)
	}
	if rr.Header().Get(listTruncatedHeader) != "" {
		t.Fatal("an uncut listing says truncated")
	}

	rr = get("&depth=2&limit=2&extended=true")
	if err := json.Unmarshal(rr.Body.Bytes(), &items); err != nil || len(items) != 2 || rr.Header().Get(listTruncatedHeader) != "true" {
		t.Fatalf("capped list = %d %s header %q", len(items), rr.Body.String(), rr.Header().Get(listTruncatedHeader))
	}

	for _, bad := range []string{"&depth=0", "&depth=x", "&limit=0", "&limit=-3", "&extended=maybe"} {
		if rr := get(bad); rr.Code != http.StatusBadRequest {
			t.Fatalf("%s = %d, want 400", bad, rr.Code)
		}
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/files?path="+url.QueryEscape(filepath.Join(root, "b.txt")), nil))
	if rr.Code != http.StatusConflict {
		t.Fatalf("listing a file = %d, want 409", rr.Code)
	}
}

func TestMoveAndCopyRoutes(t *testing.T) {
	h := authedRoutes(newDaytonaTestServer(t))
	root := t.TempDir()
	call := func(route string, values url.Values) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, route+"?"+values.Encode(), nil))
		return rr
	}
	a, b := filepath.Join(root, "a.txt"), filepath.Join(root, "b.txt")
	mustWrite(t, a, "a")
	mustWrite(t, b, "b")

	// The SDKs' overwrite guard.
	if rr := call("/files/move", url.Values{"source": {a}, "destination": {b}, "overwrite": {"false"}}); rr.Code != http.StatusConflict {
		t.Fatalf("move without overwrite = %d %s", rr.Code, rr.Body.String())
	}
	if mustRead(t, a) != "a" || mustRead(t, b) != "b" {
		t.Fatal("a refused move changed a file")
	}
	// Daytona's moveFiles never sends overwrite and has always replaced.
	if rr := call("/files/move", url.Values{"source": {a}, "destination": {b}}); rr.Code != http.StatusNoContent || mustRead(t, b) != "a" {
		t.Fatalf("Daytona move = %d", rr.Code)
	}
	if rr := call("/files/move", url.Values{"source": {b}, "destination": {a}, "overwrite": {"perhaps"}}); rr.Code != http.StatusBadRequest {
		t.Fatalf("bad overwrite = %d", rr.Code)
	}
	if rr := call("/files/move", url.Values{"destination": {a}}); rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "source") {
		t.Fatalf("no source = %d %s", rr.Code, rr.Body.String())
	}

	tree := filepath.Join(root, "tree")
	mustWrite(t, filepath.Join(tree, "x"), "x")
	cases := []struct {
		name   string
		values url.Values
		want   int
	}{
		{"file", url.Values{"source": {b}, "destination": {filepath.Join(root, "c.txt")}}, http.StatusNoContent},
		{"onto existing, default no overwrite", url.Values{"source": {b}, "destination": {filepath.Join(root, "c.txt")}}, http.StatusConflict},
		{"onto existing with overwrite", url.Values{"source": {b}, "destination": {filepath.Join(root, "c.txt")}, "overwrite": {"true"}}, http.StatusNoContent},
		{"folder without recursive", url.Values{"source": {tree}, "destination": {filepath.Join(root, "tree2")}}, http.StatusConflict},
		{"folder recursive", url.Values{"source": {tree}, "destination": {filepath.Join(root, "tree2")}, "recursive": {"true"}}, http.StatusNoContent},
		{"into itself", url.Values{"source": {tree}, "destination": {filepath.Join(tree, "again")}, "recursive": {"true"}}, http.StatusBadRequest},
		{"missing source", url.Values{"source": {filepath.Join(root, "nope")}, "destination": {filepath.Join(root, "d")}}, http.StatusNotFound},
		{"bad overwrite", url.Values{"source": {b}, "destination": {filepath.Join(root, "d")}, "overwrite": {"2x"}}, http.StatusBadRequest},
		{"bad recursive", url.Values{"source": {b}, "destination": {filepath.Join(root, "d")}, "recursive": {"2x"}}, http.StatusBadRequest},
		{"no destination", url.Values{"source": {b}}, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if rr := call("/files/copy", tc.values); rr.Code != tc.want {
				t.Fatalf("copy = %d %s, want %d", rr.Code, rr.Body.String(), tc.want)
			}
		})
	}
	if mustRead(t, filepath.Join(root, "tree2", "x")) != "x" {
		t.Fatal("recursive copy missing its file")
	}
}

func TestCreateFolderParentsAndRetryCode(t *testing.T) {
	h := authedRoutes(newDaytonaTestServer(t))
	root := t.TempDir()
	file := filepath.Join(root, "f")
	mustWrite(t, file, "x")
	post := func(values url.Values) (*httptest.ResponseRecorder, models.ErrorResponse) {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/files/folder?"+values.Encode(), nil))
		var body models.ErrorResponse
		_ = json.Unmarshal(rr.Body.Bytes(), &body)
		return rr, body
	}
	dir := filepath.Join(root, "d")
	if rr, _ := post(url.Values{"path": {dir}, "parents": {"false"}}); rr.Code != http.StatusCreated {
		t.Fatalf("mkdir = %d", rr.Code)
	}
	// What a retried mkdir sees after its first attempt made the folder.
	if rr, body := post(url.Values{"path": {dir}, "parents": {"false"}}); rr.Code != http.StatusConflict || body.Code != errCodeFolderExists {
		t.Fatalf("mkdir again = %d %+v, want 409 folder_exists", rr.Code, body)
	}
	// A file there is a conflict the SDK must not take as done.
	if rr, body := post(url.Values{"path": {file}, "parents": {"false"}}); rr.Code != http.StatusConflict || body.Code != "" {
		t.Fatalf("mkdir over a file = %d %+v", rr.Code, body)
	}
	if rr, _ := post(url.Values{"path": {filepath.Join(root, "x", "y")}, "parents": {"false"}}); rr.Code != http.StatusNotFound {
		t.Fatalf("mkdir without parents under a missing folder = %d", rr.Code)
	}
	if rr, _ := post(url.Values{"path": {dir}, "parents": {"nah"}}); rr.Code != http.StatusBadRequest {
		t.Fatalf("bad parents = %d", rr.Code)
	}
}

func TestDeleteRouteNotFoundCode(t *testing.T) {
	h := authedRoutes(newDaytonaTestServer(t))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodDelete, "/files?path="+url.QueryEscape(filepath.Join(t.TempDir(), "gone")), nil))
	var body models.ErrorResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if rr.Code != http.StatusNotFound || body.Code != errCodeFileNotFound {
		t.Fatalf("delete of a missing path = %d %+v", rr.Code, body)
	}
}

// E2B's envd calls go through the same core and keep their own behaviour:
// Move makes the destination folder and replaces, Remove is recursive.
func TestEnvdFilesystemUsesSharedCore(t *testing.T) {
	h := authedRoutes(newEnvdTestServer(t))
	root := t.TempDir()
	rpc := func(method string, body any) *httptest.ResponseRecorder {
		data, _ := json.Marshal(body)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, envdPrefix+"/filesystem.Filesystem/"+method, bytes.NewReader(data)))
		return rr
	}
	src := filepath.Join(root, "src.txt")
	dst := filepath.Join(root, "dst.txt")
	mustWrite(t, src, "new")
	mustWrite(t, dst, "old")
	if rr := rpc("Move", envdMoveRequest{Source: src, Destination: dst}); rr.Code != http.StatusOK || mustRead(t, dst) != "new" {
		t.Fatalf("envd Move over a file = %d %s", rr.Code, rr.Body.String())
	}
	nested := filepath.Join(root, "made", "here.txt")
	if rr := rpc("Move", envdMoveRequest{Source: dst, Destination: nested}); rr.Code != http.StatusOK || mustRead(t, nested) != "new" {
		t.Fatalf("envd Move into a new folder = %d %s", rr.Code, rr.Body.String())
	}
	// The cross-filesystem fallback reaches E2B too.
	crossSrc := filepath.Join(root, "cross.txt")
	mustWrite(t, crossSrc, "c")
	simulateCrossDevice(t, crossSrc)
	if rr := rpc("Move", envdMoveRequest{Source: crossSrc, Destination: filepath.Join(root, "crossed.txt")}); rr.Code != http.StatusOK {
		t.Fatalf("envd Move across filesystems = %d %s", rr.Code, rr.Body.String())
	}
	if rr := rpc("Remove", envdRemoveRequest{Path: filepath.Join(root, "made")}); rr.Code != http.StatusOK {
		t.Fatalf("envd Remove of a folder = %d", rr.Code)
	}
	if rr := rpc("Remove", envdRemoveRequest{Path: "/"}); rr.Code != http.StatusBadRequest {
		t.Fatalf("envd Remove / = %d, want 400", rr.Code)
	}
	if rr := rpc("ListDir", envdListDirRequest{Path: filepath.Join(root, "crossed.txt")}); rr.Code != http.StatusConflict {
		t.Fatalf("envd ListDir of a file = %d, want 409", rr.Code)
	}
	if rr := rpc("MakeDir", envdMakeDirRequest{Path: filepath.Join(root, "m", "n")}); rr.Code != http.StatusOK {
		t.Fatalf("envd MakeDir = %d", rr.Code)
	}
	if info, err := os.Stat(filepath.Join(root, "m", "n")); err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("envd MakeDir mode = %v, %v", info, err)
	}
}

// A copy that fails part way (an unreadable file or folder in the tree)
// returns the error and removes its half-built copy.
func TestCopyPathFailuresCleanUp(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads mode-000 files")
	}
	root := t.TempDir()
	locked := filepath.Join(root, "locked.txt")
	mustWrite(t, locked, "x")
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	if err := copyPath(locked, filepath.Join(root, "copy.txt"), fileOptions{}); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("copying an unreadable file = %v, want permission", err)
	}
	tree := filepath.Join(root, "tree")
	mustWrite(t, filepath.Join(tree, "closed", "f"), "f")
	if err := os.Chmod(filepath.Join(tree, "closed"), 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(tree, "closed"), 0o755) })
	if err := copyPath(tree, filepath.Join(root, "tree2"), fileOptions{Recursive: true}); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("copying a tree with an unreadable folder = %v, want permission", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "tree2")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("a failed copy left a destination")
	}
	assertNoTempLeft(t, root)
}

// TestCopyPathKeepsSetuidAndSetgid: copyTree sets the mode, then gives the
// copy its owner. On Linux that chown clears setuid and setgid, so they
// must be put back after it.
func TestCopyPathKeepsSetuidAndSetgid(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "tool")
	mustWrite(t, src, "#!/bin/sh")
	if err := os.Chmod(src, 0o755|os.ModeSetuid|os.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(src)
	if err != nil {
		t.Fatal(err)
	}
	if before.Mode()&(os.ModeSetuid|os.ModeSetgid) != os.ModeSetuid|os.ModeSetgid {
		t.Skipf("this filesystem did not keep the bits on the source: %v", before.Mode())
	}
	dst := filepath.Join(root, "copy")
	if err := copyPath(src, dst, fileOptions{}); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	want := os.FileMode(0o755) | os.ModeSetuid | os.ModeSetgid
	if got := after.Mode() & (os.ModePerm | os.ModeSetuid | os.ModeSetgid); got != want {
		t.Fatalf("copy mode = %v, want %v", got, want)
	}
}
