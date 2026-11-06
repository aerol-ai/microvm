package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// These go through the real route switch, so on main before B1 every one of
// them got the default 404 (plans/agent-sandbox-feature-parity.md, B1).

func TestDaytonaDeleteFileRoute(t *testing.T) {
	h := authedRoutes(newDaytonaTestServer(t))
	root := t.TempDir()
	file := filepath.Join(root, "a.txt")
	dir := filepath.Join(root, "tree")
	mustWrite(t, file, "x")
	mustWrite(t, filepath.Join(dir, "inner", "b.txt"), "y")

	cases := []struct {
		name  string
		query string
		want  int
		gone  string
		stays string
	}{
		{name: "missing path", query: "", want: http.StatusBadRequest},
		{name: "bad recursive", query: "path=" + url.QueryEscape(file) + "&recursive=maybe", want: http.StatusBadRequest},
		{name: "refuse root", query: "path=/&recursive=true", want: http.StatusBadRequest},
		{name: "missing file", query: "path=" + url.QueryEscape(filepath.Join(root, "nope")), want: http.StatusNotFound},
		{name: "folder needs recursive", query: "path=" + url.QueryEscape(dir), want: http.StatusConflict, stays: dir},
		{name: "file", query: "path=" + url.QueryEscape(file), want: http.StatusNoContent, gone: file},
		{name: "folder recursive", query: "path=" + url.QueryEscape(dir) + "&recursive=true", want: http.StatusNoContent, gone: dir},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, httptest.NewRequest(http.MethodDelete, "/files?"+tc.query, nil))
			if rr.Code != tc.want {
				t.Fatalf("status = %d, want %d; body=%s", rr.Code, tc.want, rr.Body.String())
			}
			if tc.gone != "" {
				if _, err := os.Lstat(tc.gone); !os.IsNotExist(err) {
					t.Fatalf("%s still exists (err=%v)", tc.gone, err)
				}
			}
			if tc.stays != "" {
				if _, err := os.Lstat(tc.stays); err != nil {
					t.Fatalf("%s was removed: %v", tc.stays, err)
				}
			}
		})
	}
}

func TestDaytonaCreateFolderRoute(t *testing.T) {
	h := authedRoutes(newDaytonaTestServer(t))
	root := t.TempDir()
	file := filepath.Join(root, "plain.txt")
	mustWrite(t, file, "x")

	cases := []struct {
		name     string
		query    string
		want     int
		check    string
		wantMode os.FileMode
	}{
		{name: "nested with default mode", query: "path=" + url.QueryEscape(filepath.Join(root, "a", "b")), want: http.StatusCreated, check: filepath.Join(root, "a", "b"), wantMode: 0o755},
		{name: "explicit mode beats umask", query: "path=" + url.QueryEscape(filepath.Join(root, "open")) + "&mode=777", want: http.StatusCreated, check: filepath.Join(root, "open"), wantMode: 0o777},
		{name: "existing folder is fine", query: "path=" + url.QueryEscape(root) + "&mode=700", want: http.StatusCreated, check: root, wantMode: 0o700},
		{name: "file in the way", query: "path=" + url.QueryEscape(file), want: http.StatusConflict},
		{name: "bad mode", query: "path=" + url.QueryEscape(filepath.Join(root, "z")) + "&mode=9z", want: http.StatusBadRequest},
		{name: "mode too large", query: "path=" + url.QueryEscape(filepath.Join(root, "z")) + "&mode=17777", want: http.StatusBadRequest},
		{name: "missing path", query: "", want: http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/files/folder?"+tc.query, nil))
			if rr.Code != tc.want {
				t.Fatalf("status = %d, want %d; body=%s", rr.Code, tc.want, rr.Body.String())
			}
			if tc.check != "" {
				info, err := os.Stat(tc.check)
				if err != nil || !info.IsDir() {
					t.Fatalf("folder %s missing: %v", tc.check, err)
				}
				if got := info.Mode().Perm(); got != tc.wantMode {
					t.Fatalf("mode = %o, want %o", got, tc.wantMode)
				}
			}
		})
	}
}

func TestDaytonaReplaceInFilesRoute(t *testing.T) {
	h := authedRoutes(newDaytonaTestServer(t))
	root := t.TempDir()
	one := filepath.Join(root, "one.txt")
	two := filepath.Join(root, "two.sh")
	untouched := filepath.Join(root, "untouched.txt")
	mustWrite(t, one, "a.b.c a.b.c")
	mustWrite(t, two, "echo a.b.c")
	if err := os.Chmod(two, 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, untouched, "nothing here")

	body, _ := json.Marshal(daytonaReplaceRequest{
		Files:    []string{one, two, untouched, filepath.Join(root, "missing.txt"), root},
		Pattern:  "a.b.c",
		NewValue: "X",
	})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/files/replace", bytes.NewReader(body)))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", rr.Code, rr.Body.String())
	}
	var results []daytonaReplaceResult
	if err := json.Unmarshal(rr.Body.Bytes(), &results); err != nil {
		t.Fatalf("decode: %v", err)
	}
	wantSuccess := []bool{true, true, true, false, false}
	if len(results) != len(wantSuccess) {
		t.Fatalf("results = %+v", results)
	}
	for i, ok := range wantSuccess {
		if results[i].Success != ok || (ok && results[i].Error != "") || (!ok && results[i].Error == "") {
			t.Fatalf("result %d = %+v, want success=%v", i, results[i], ok)
		}
	}
	// The pattern is a plain string: "." must not match any character.
	if got := mustRead(t, one); got != "X X" {
		t.Fatalf("one.txt = %q", got)
	}
	if got := mustRead(t, two); got != "echo X" {
		t.Fatalf("two.sh = %q", got)
	}
	if info, _ := os.Stat(two); info.Mode().Perm() != 0o755 {
		t.Fatalf("two.sh mode = %o, want 755 kept", info.Mode().Perm())
	}
	leftovers, _ := filepath.Glob(filepath.Join(root, ".*replace-*"))
	if len(leftovers) != 0 {
		t.Fatalf("temp files left behind: %v", leftovers)
	}

	for name, raw := range map[string]string{
		"bad json":      "{",
		"empty pattern": `{"files":["` + one + `"],"pattern":"","newValue":"y"}`,
	} {
		t.Run(name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/files/replace", strings.NewReader(raw)))
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rr.Code)
			}
		})
	}
}

func TestDaytonaSetPermissionsRoute(t *testing.T) {
	h := authedRoutes(newDaytonaTestServer(t))
	root := t.TempDir()
	file := filepath.Join(root, "p.txt")
	mustWrite(t, file, "x")
	uid := strconv.Itoa(os.Getuid())
	gid := strconv.Itoa(os.Getgid())

	cases := []struct {
		name     string
		query    string
		want     int
		wantMode os.FileMode
	}{
		{name: "mode only", query: "mode=600", want: http.StatusOK, wantMode: 0o600},
		{name: "owner and group by id", query: "mode=640&owner=" + uid + "&group=" + gid, want: http.StatusOK, wantMode: 0o640},
		{name: "unknown owner", query: "owner=no-such-user-zz9", want: http.StatusBadRequest},
		{name: "unknown group", query: "group=no-such-group-zz9", want: http.StatusBadRequest},
		{name: "bad mode", query: "mode=abc", want: http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/files/permissions?path="+url.QueryEscape(file)+"&"+tc.query, nil))
			if rr.Code != tc.want {
				t.Fatalf("status = %d, want %d; body=%s", rr.Code, tc.want, rr.Body.String())
			}
			if tc.wantMode != 0 {
				info, _ := os.Stat(file)
				if info.Mode().Perm() != tc.wantMode {
					t.Fatalf("mode = %o, want %o", info.Mode().Perm(), tc.wantMode)
				}
			}
		})
	}
	t.Run("missing file", func(t *testing.T) {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/files/permissions?path="+url.QueryEscape(filepath.Join(root, "gone"))+"&mode=600", nil))
		if rr.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rr.Code)
		}
	})
}

// Language servers answer a clear 501. Daytona terminals used to as well,
// until plan E8 built them (daytona_pty_test.go).
func TestDaytonaUnsupportedRoutesAnswer501(t *testing.T) {
	h := authedRoutes(newDaytonaTestServer(t))
	for _, tc := range []struct{ method, path, want string }{
		{http.MethodPost, "/lsp/start", "language servers"},
		{http.MethodPost, "/lsp/completions", "language servers"},
	} {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(tc.method, tc.path, nil))
		if rr.Code != http.StatusNotImplemented || !strings.Contains(rr.Body.String(), tc.want) {
			t.Fatalf("%s %s = %d %s, want 501 mentioning %q", tc.method, tc.path, rr.Code, rr.Body.String(), tc.want)
		}
	}
}

func TestWriteFilesystemErrorMapsWrongKindAndFullDisk(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "f")
	mustWrite(t, file, "x")
	_, notDir := os.ReadDir(file)
	errNotEmpty := os.Remove(root)
	for name, tc := range map[string]struct {
		err  error
		want int
	}{
		"not a dir": {notDir, http.StatusConflict},
		"not empty": {errNotEmpty, http.StatusConflict},
		"exists":    {&os.PathError{Op: "mkdir", Path: file, Err: os.ErrExist}, http.StatusConflict},
		"full disk": {&os.PathError{Op: "write", Path: file, Err: errENOSPC()}, http.StatusInsufficientStorage},
	} {
		t.Run(name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			writeFilesystemError(rr, tc.err)
			if rr.Code != tc.want {
				t.Fatalf("status = %d, want %d (err=%v)", rr.Code, tc.want, tc.err)
			}
		})
	}
}

func TestParseFileModeSpecialBits(t *testing.T) {
	mode, err := parseFileMode("4755", 0)
	if err != nil || mode&os.ModeSetuid == 0 || mode.Perm() != 0o755 {
		t.Fatalf("4755 -> %v, %v", mode, err)
	}
	mode, err = parseFileMode("3700", 0)
	if err != nil || mode&os.ModeSetgid == 0 || mode&os.ModeSticky == 0 {
		t.Fatalf("3700 -> %v, %v", mode, err)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func errENOSPC() error { return syscall.ENOSPC }

func TestUnknownRouteIsMarkedMissing(t *testing.T) {
	h := authedRoutes(newDaytonaTestServer(t))
	for _, path := range []string{"/no-such-route", "/process/session/s1/bogus", "/envd/nope.Service/Call"} {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}")))
		if rr.Code != http.StatusNotFound || rr.Header().Get(routeMissingHeader) != "none" {
			t.Fatalf("POST %s = %d header %q, want 404 marked missing", path, rr.Code, rr.Header().Get(routeMissingHeader))
		}
	}
	// A real route answering 404 for a missing file is not marked.
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/files/info?path=/definitely/not/here", nil))
	if rr.Code != http.StatusNotFound || rr.Header().Get(routeMissingHeader) != "" {
		t.Fatalf("missing file = %d header %q, want an unmarked 404", rr.Code, rr.Header().Get(routeMissingHeader))
	}
}

func TestWriteFileAtomicFailuresLeaveNoTempFile(t *testing.T) {
	root := t.TempDir()
	if err := writeFileAtomic(filepath.Join(root, "missing-dir", "f"), []byte("x"), 0o644); err == nil {
		t.Fatal("write into a missing folder succeeded")
	}
	// Renaming over a folder fails after the temp file is written; the temp
	// file must be removed.
	target := filepath.Join(root, "dir")
	mustWrite(t, filepath.Join(target, "inner"), "x")
	if err := writeFileAtomic(target, []byte("x"), 0o644); err == nil {
		t.Fatal("rename over a non-empty folder succeeded")
	}
	leftovers, _ := filepath.Glob(filepath.Join(root, ".*replace-*"))
	if len(leftovers) != 0 {
		t.Fatalf("temp files left behind: %v", leftovers)
	}
}

func TestLookupOwnerAndGroupByName(t *testing.T) {
	if uid, err := lookupOwnerID("root"); err != nil || uid != 0 {
		t.Fatalf("lookupOwnerID(root) = %d, %v", uid, err)
	}
	if _, err := lookupGroupID("0"); err != nil {
		t.Fatalf("lookupGroupID(0): %v", err)
	}
}
