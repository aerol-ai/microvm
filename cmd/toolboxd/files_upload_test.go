package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"io/fs"
	"mime/multipart"
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

// Upload write options (plans/agent-sandbox-feature-parity.md, F2).

func uploadRequest(t *testing.T, target, content string, query url.Values) *http.Request {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	if err := mw.WriteField("path", target); err != nil {
		t.Fatal(err)
	}
	part, err := mw.CreateFormFile("file", filepath.Base(target))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write([]byte(content))
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/files/upload?"+query.Encode(), &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	return req
}

func inode(t *testing.T, path string) uint64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Sys().(*syscall.Stat_t).Ino
}

func TestUploadWriteOptions(t *testing.T) {
	h := authedRoutes(newDaytonaTestServer(t))
	root := t.TempDir()
	write := func(name, content string, mode os.FileMode) string {
		path := filepath.Join(root, name)
		mustWrite(t, path, content)
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	exec := write("run.sh", "old", 0o755)
	appendTo := write("log.txt", "a", 0o644)
	taken := write("taken.txt", "keep", 0o644)
	atomicTarget := write("atomic.txt", "old", 0o750)
	// A hard link to the atomic target from outside: an atomic replace must
	// give the target a new file, not write through the shared one.
	outsideLink := filepath.Join(t.TempDir(), "outside-link")
	if err := os.Link(atomicTarget, outsideLink); err != nil {
		t.Fatal(err)
	}
	atomicTaken := write("atomic-taken.txt", "keep", 0o644)
	folder := filepath.Join(root, "folder")
	mustWrite(t, filepath.Join(folder, "inner"), "x")

	cases := []struct {
		name     string
		target   string
		content  string
		query    url.Values
		want     int
		wantBody string
		wantMode os.FileMode
		code     string
	}{
		{name: "plain new file", target: filepath.Join(root, "new.txt"), content: "n", want: http.StatusCreated, wantBody: "n", wantMode: 0o644},
		{name: "plain overwrite keeps the mode", target: exec, content: "new", want: http.StatusCreated, wantBody: "new", wantMode: 0o755},
		{name: "append", target: appendTo, content: "b", query: url.Values{"append": {"true"}}, want: http.StatusCreated, wantBody: "ab", wantMode: 0o644},
		{name: "append makes a missing file", target: filepath.Join(root, "fresh.log"), content: "x", query: url.Values{"append": {"true"}}, want: http.StatusCreated, wantBody: "x", wantMode: 0o644},
		{name: "create_only new", target: filepath.Join(root, "once.txt"), content: "1", query: url.Values{"create_only": {"true"}}, want: http.StatusCreated, wantBody: "1", wantMode: 0o644},
		{name: "create_only existing", target: taken, content: "2", query: url.Values{"create_only": {"true"}}, want: http.StatusPreconditionFailed, wantBody: "keep", wantMode: 0o644, code: errCodeFileExists},
		{name: "mode on a new file", target: filepath.Join(root, "secret"), content: "s", query: url.Values{"mode": {"600"}}, want: http.StatusCreated, wantBody: "s", wantMode: 0o600},
		{name: "mode on an existing file", target: exec, content: "m", query: url.Values{"mode": {"700"}}, want: http.StatusCreated, wantBody: "m", wantMode: 0o700},
		{name: "atomic replace keeps the mode", target: atomicTarget, content: "new", query: url.Values{"atomic": {"true"}}, want: http.StatusCreated, wantBody: "new", wantMode: 0o750},
		{name: "atomic new with a mode", target: filepath.Join(root, "atomic-new"), content: "a", query: url.Values{"atomic": {"true"}, "mode": {"640"}}, want: http.StatusCreated, wantBody: "a", wantMode: 0o640},
		{name: "atomic create_only existing", target: atomicTaken, content: "z", query: url.Values{"atomic": {"true"}, "create_only": {"true"}}, want: http.StatusPreconditionFailed, wantBody: "keep", wantMode: 0o644, code: errCodeFileExists},
		{name: "atomic create_only new", target: filepath.Join(root, "atomic-once"), content: "o", query: url.Values{"atomic": {"true"}, "create_only": {"true"}}, want: http.StatusCreated, wantBody: "o", wantMode: 0o644},
		{name: "append with create_only", target: filepath.Join(root, "c1"), content: "c", query: url.Values{"append": {"true"}, "create_only": {"true"}}, want: http.StatusBadRequest},
		{name: "append with atomic", target: filepath.Join(root, "c2"), content: "c", query: url.Values{"append": {"true"}, "atomic": {"true"}}, want: http.StatusBadRequest},
		{name: "bad append", target: filepath.Join(root, "c3"), content: "c", query: url.Values{"append": {"yes please"}}, want: http.StatusBadRequest},
		{name: "bad create_only", target: filepath.Join(root, "c3"), content: "c", query: url.Values{"create_only": {"2"}}, want: http.StatusBadRequest},
		{name: "bad atomic", target: filepath.Join(root, "c3"), content: "c", query: url.Values{"atomic": {"x"}}, want: http.StatusBadRequest},
		{name: "bad mode", target: filepath.Join(root, "c3"), content: "c", query: url.Values{"mode": {"999"}}, want: http.StatusBadRequest},
		{name: "onto a folder", target: folder, content: "c", want: http.StatusConflict},
		{name: "atomic onto a folder", target: folder, content: "c", query: url.Values{"atomic": {"true"}}, want: http.StatusConflict},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, uploadRequest(t, tc.target, tc.content, tc.query))
			if rr.Code != tc.want {
				t.Fatalf("status = %d, want %d; body=%s", rr.Code, tc.want, rr.Body.String())
			}
			if rr.Code == http.StatusBadRequest {
				if strings.Contains(tc.name, " with ") {
					for _, option := range []string{"append", "create_only", "atomic"} {
						if tc.query.Has(option) && !strings.Contains(rr.Body.String(), option) {
							t.Fatalf("conflict message %s does not name %s", rr.Body.String(), option)
						}
					}
				}
				return
			}
			if tc.code != "" {
				var body models.ErrorResponse
				if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil || body.Code != tc.code {
					t.Fatalf("error = %s, want code %s", rr.Body.String(), tc.code)
				}
			}
			if tc.wantBody == "" {
				return
			}
			if got := mustRead(t, tc.target); got != tc.wantBody {
				t.Fatalf("content = %q, want %q", got, tc.wantBody)
			}
			info, err := os.Stat(tc.target)
			if err != nil || info.Mode().Perm() != tc.wantMode {
				t.Fatalf("mode = %v (%v), want %v", info.Mode().Perm(), err, tc.wantMode)
			}
		})
	}
	if mustRead(t, outsideLink) != "old" {
		t.Fatal("an atomic replace wrote through a hard link to a file outside")
	}
	if inode(t, atomicTarget) == inode(t, outsideLink) {
		t.Fatal("the atomic replace kept the shared inode")
	}
	left, _ := filepath.Glob(filepath.Join(root, ".*.upload-*"))
	if len(left) != 0 {
		t.Fatalf("temp files left behind: %v", left)
	}
}

// Two create_only uploads to one path at the same moment: exactly one 2xx
// and one 412, plain and atomic (plan F2, CEO review Sections 2 and 4).
func TestUploadCreateOnlyRace(t *testing.T) {
	srv := httptest.NewServer(authedRoutes(newDaytonaTestServer(t)))
	t.Cleanup(srv.Close)
	for _, atomic := range []bool{false, true} {
		for round := 0; round < 25; round++ {
			target := filepath.Join(t.TempDir(), "once.txt")
			query := url.Values{"create_only": {"true"}}
			if atomic {
				query.Set("atomic", "true")
			}
			statuses := make([]int, 2)
			var wg sync.WaitGroup
			start := make(chan struct{})
			for i := range statuses {
				body, contentType := multipartBody(t, target, strings.Repeat(string(rune('a'+i)), 4096))
				wg.Add(1)
				go func() {
					defer wg.Done()
					req, _ := http.NewRequest(http.MethodPost, srv.URL+"/files/upload?"+query.Encode(), body)
					req.Header.Set("Content-Type", contentType)
					<-start
					resp, err := srv.Client().Do(req)
					if err != nil {
						t.Error(err)
						return
					}
					resp.Body.Close()
					statuses[i] = resp.StatusCode
				}()
			}
			close(start)
			wg.Wait()
			created, refused := 0, 0
			for _, status := range statuses {
				switch status {
				case http.StatusCreated:
					created++
				case http.StatusPreconditionFailed:
					refused++
				}
			}
			if created != 1 || refused != 1 {
				t.Fatalf("atomic=%v round %d: statuses %v, want one 201 and one 412", atomic, round, statuses)
			}
			// The file is one writer's whole content, never a mix.
			content := mustRead(t, target)
			if content != strings.Repeat("a", 4096) && content != strings.Repeat("b", 4096) {
				t.Fatalf("atomic=%v: the file mixes both writers", atomic)
			}
		}
	}
}

func multipartBody(t *testing.T, target, content string) (*bytes.Buffer, string) {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	_ = mw.WriteField("path", target)
	part, err := mw.CreateFormFile("file", filepath.Base(target))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write([]byte(content))
	_ = mw.Close()
	return &body, mw.FormDataContentType()
}

// /dev/full answers every write with ENOSPC: the same error a full sandbox
// disk gives, so the upload must say so (507), not a bare 500.
func TestUploadDiskFullIs507(t *testing.T) {
	if _, err := os.Stat("/dev/full"); err != nil {
		t.Skip("no /dev/full here")
	}
	rr := httptest.NewRecorder()
	authedRoutes(newDaytonaTestServer(t)).ServeHTTP(rr, uploadRequest(t, "/dev/full", "data", nil))
	if rr.Code != http.StatusInsufficientStorage || !strings.Contains(rr.Body.String(), "sandbox disk is full") {
		t.Fatalf("upload to /dev/full = %d %s", rr.Code, rr.Body.String())
	}
}

// A write that fails part way (here: the folder is read-only, so the temp
// file cannot be made) reports the error and changes nothing.
func TestUploadAtomicFailureLeavesTargetAlone(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes into a read-only folder")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "f.txt")
	mustWrite(t, target, "keep")
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	for _, tc := range []struct {
		path  string
		query url.Values
	}{
		{target, url.Values{"atomic": {"true"}}},
		// A new name: on the existing file create_only would stop at 412
		// before it tried to write, and never reach the failure.
		{filepath.Join(dir, "new.txt"), url.Values{"mode": {"600"}, "create_only": {"true"}}},
	} {
		rr := httptest.NewRecorder()
		authedRoutes(newDaytonaTestServer(t)).ServeHTTP(rr, uploadRequest(t, tc.path, "new", tc.query))
		if rr.Code/100 == 2 || rr.Code == http.StatusPreconditionFailed {
			t.Fatalf("%v into a read-only folder = %d, want the write to fail", tc.query, rr.Code)
		}
	}
	if mustRead(t, target) != "keep" {
		t.Fatal("a failed upload changed the file")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("a failed upload left files: %v", entries)
	}
	if info, err := os.Stat(target); err != nil || info.Mode()&fs.ModePerm != 0o644 {
		t.Fatalf("mode changed: %v", err)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, syscall.EIO }

// A body that breaks part way (the client hung up) fails the write. The
// atomic write leaves the old file whole and no temp file behind.
func TestWriteUploadBodyFailure(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "f.txt")
	mustWrite(t, target, "keep")
	for _, opts := range []uploadOptions{{Atomic: true}, {Append: true}, {CreateOnly: true, Mode: 0o600, modeSet: true}} {
		if err := writeUpload(filepath.Join(dir, map[bool]string{true: "f.txt", false: "other"}[opts.Atomic]), failingReader{}, opts); err == nil {
			t.Fatalf("%+v: a failing body wrote successfully", opts)
		}
	}
	if mustRead(t, target) != "keep" {
		t.Fatal("a failed atomic write changed the file")
	}
	left, _ := filepath.Glob(filepath.Join(dir, ".*.upload-*"))
	if len(left) != 0 {
		t.Fatalf("temp files left: %v", left)
	}
}

// tarOf builds a tar (gzipped when zip is set) of name/body pairs; a body
// starting with "->" makes a symlink to the rest.
func tarOf(t *testing.T, zip bool, pairs ...string) string {
	t.Helper()
	var buf bytes.Buffer
	var out io.Writer = &buf
	var gz *gzip.Writer
	if zip {
		gz = gzip.NewWriter(&buf)
		out = gz
	}
	tw := tar.NewWriter(out)
	for i := 0; i+1 < len(pairs); i += 2 {
		name, body := pairs[i], pairs[i+1]
		hdr := &tar.Header{Name: name, Mode: 0o644, Typeflag: tar.TypeReg, Size: int64(len(body))}
		if strings.HasPrefix(body, "->") {
			hdr = &tar.Header{Name: name, Typeflag: tar.TypeSymlink, Linkname: strings.TrimPrefix(body, "->")}
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if hdr.Typeflag == tar.TypeReg {
			_, _ = tw.Write([]byte(body))
		}
	}
	_ = tw.Close()
	if gz != nil {
		_ = gz.Close()
	}
	return buf.String()
}

// Plan F3: upload a tar with extract=true and it is unpacked into the
// folder, through the same safe extraction the CLI uses.
func TestUploadExtract(t *testing.T) {
	h := authedRoutes(newDaytonaTestServer(t))
	base := t.TempDir()
	outside := filepath.Join(base, "outside.txt")
	mustWrite(t, outside, "untouched")
	extract := url.Values{"extract": {"true"}}
	post := func(target, archive string, query url.Values) (*httptest.ResponseRecorder, map[string]any) {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, uploadRequest(t, target, archive, query))
		var body map[string]any
		_ = json.Unmarshal(rr.Body.Bytes(), &body)
		return rr, body
	}

	dest := filepath.Join(base, "made", "here")
	rr, body := post(dest, tarOf(t, true, "a.txt", "one", "sub/b.txt", "two", "link", "->a.txt"), extract)
	if rr.Code != http.StatusCreated || body["entries"] != float64(3) || body["bytes"] != float64(6) {
		t.Fatalf("extract = %d %s", rr.Code, rr.Body.String())
	}
	if mustRead(t, filepath.Join(dest, "sub", "b.txt")) != "two" || mustRead(t, filepath.Join(dest, "link")) != "one" {
		t.Fatal("archive not unpacked")
	}

	cases := []struct {
		name    string
		target  string
		archive string
		query   url.Values
		env     map[string]string
		want    int
		mention string
	}{
		{name: "dot-dot", target: dest, archive: tarOf(t, false, "ok.txt", "1", "../outside.txt", "pwned"), query: extract, want: http.StatusBadRequest, mention: `entry \"../outside.txt\"`},
		{name: "escaping symlink", target: dest, archive: tarOf(t, false, "up", "->../../outside.txt"), query: extract, want: http.StatusBadRequest, mention: `entry \"up\"`},
		{name: "too many entries", target: dest, archive: tarOf(t, false, "x1", "1", "x2", "2"), query: extract, env: map[string]string{"SB_EXTRACT_MAX_ENTRIES": "1"}, want: http.StatusRequestEntityTooLarge, mention: "1 entries written"},
		{name: "too many bytes", target: dest, archive: tarOf(t, true, "big", strings.Repeat("z", 100)), query: extract, env: map[string]string{"SB_EXTRACT_MAX_BYTES": "10"}, want: http.StatusRequestEntityTooLarge},
		{name: "not an archive", target: dest, archive: strings.Repeat("garbage ", 200), query: extract, want: http.StatusBadRequest},
		{name: "into a file", target: outside, archive: tarOf(t, false, "a", "1"), query: extract, want: http.StatusConflict},
		{name: "extract with append", target: dest, archive: tarOf(t, false, "a", "1"), query: url.Values{"extract": {"true"}, "append": {"true"}}, want: http.StatusBadRequest, mention: "append"},
		{name: "extract with mode", target: dest, archive: tarOf(t, false, "a", "1"), query: url.Values{"extract": {"true"}, "mode": {"600"}}, want: http.StatusBadRequest, mention: "mode"},
		{name: "bad extract", target: dest, archive: "x", query: url.Values{"extract": {"perhaps"}}, want: http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			rr, _ := post(tc.target, tc.archive, tc.query)
			if rr.Code != tc.want || !strings.Contains(rr.Body.String(), tc.mention) {
				t.Fatalf("status = %d %s, want %d mentioning %q", rr.Code, rr.Body.String(), tc.want, tc.mention)
			}
		})
	}
	if mustRead(t, outside) != "untouched" {
		t.Fatal("a hostile archive wrote outside its folder")
	}
	// The failure part way kept the entry before it (owner decision P1).
	if mustRead(t, filepath.Join(dest, "ok.txt")) != "1" {
		t.Fatal("the entry before the failing one was not kept")
	}
}
