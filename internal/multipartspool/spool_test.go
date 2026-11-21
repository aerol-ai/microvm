package multipartspool

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// formPart is one part of a test form: a value when filename is "".
type formPart struct {
	name, filename, content string
}

func buildForm(t *testing.T, parts ...formPart) (*bytes.Buffer, string) {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for _, p := range parts {
		var w io.Writer
		var err error
		if p.filename == "" {
			w, err = mw.CreateFormField(p.name)
		} else {
			w, err = mw.CreateFormFile(p.name, p.filename)
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(w, p.content); err != nil {
			t.Fatal(err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	return &body, mw.FormDataContentType()
}

func newFormRequest(t *testing.T, target string, parts ...formPart) *http.Request {
	t.Helper()
	body, contentType := buildForm(t, parts...)
	r := httptest.NewRequest(http.MethodPost, target, body)
	r.Header.Set("Content-Type", contentType)
	return r
}

// watchTempDir points TMPDIR (os.TempDir) at a fresh folder and returns it,
// so a test can prove nothing was written to the shared temp folder.
func watchTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	if os.TempDir() != dir {
		t.Fatalf("os.TempDir() = %q, want %q", os.TempDir(), dir)
	}
	return dir
}

func assertEmptyDir(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%s): %v", dir, err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("%s holds %v, want nothing", dir, names)
	}
}

func readAllFile(t *testing.T, fh *FileHeader) string {
	t.Helper()
	f, err := fh.Open()
	if err != nil {
		t.Fatalf("Open(%s): %v", fh.Filename, err)
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("read %s: %v", fh.Filename, err)
	}
	return string(b)
}

// TestReadFormMatchesParseMultipartForm parses the same request with the
// standard library and with a Spool and compares what a handler sees: the
// form's values and files, r.Form and r.PostForm (query values first).
func TestReadFormMatchesParseMultipartForm(t *testing.T) {
	big := strings.Repeat("x", 4096)
	cases := []struct {
		name      string
		target    string
		maxMemory int64
		parts     []formPart
	}{
		{name: "value then file", target: "/up", maxMemory: 1 << 20, parts: []formPart{{name: "path", content: "/a"}, {name: "file", filename: "a.txt", content: "hello"}}},
		{name: "file before path", target: "/up", maxMemory: 1 << 20, parts: []formPart{{name: "file", filename: "a.txt", content: "hello"}, {name: "path", content: "/a"}}},
		{name: "query value comes first", target: "/up?path=/q&mode=1", maxMemory: 1 << 20, parts: []formPart{{name: "path", content: "/form"}, {name: "file", filename: "a.txt", content: "x"}}},
		{name: "empty file", target: "/up", maxMemory: 1 << 20, parts: []formPart{{name: "file", filename: "empty.txt"}}},
		{name: "repeated keys", target: "/up", maxMemory: 1 << 20, parts: []formPart{{name: "file", filename: "1", content: "one"}, {name: "file", filename: "2", content: "two"}, {name: "v", content: "a"}, {name: "v", content: "b"}}},
		{name: "parts spill past memory", target: "/up", maxMemory: 100, parts: []formPart{{name: "small", filename: "s", content: "tiny"}, {name: "big", filename: "b", content: big}, {name: "big2", filename: "b2", content: big}}},
		{name: "unnamed part skipped", target: "/up", maxMemory: 1 << 20, parts: []formPart{{name: "", content: "dropped"}, {name: "k", content: "v"}}},
		{name: "zero memory", target: "/up", maxMemory: 0, parts: []formPart{{name: "file", filename: "f", content: "z"}}},
		{name: "negative memory", target: "/up", maxMemory: -1, parts: []formPart{{name: "file", filename: "f", content: "z"}}},
		{name: "unbounded memory", target: "/up", maxMemory: math.MaxInt64, parts: []formPart{{name: "file", filename: "f", content: big}, {name: "k", content: "v"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			std := newFormRequest(t, tc.target, tc.parts...)
			if err := std.ParseMultipartForm(tc.maxMemory); err != nil {
				t.Fatalf("ParseMultipartForm: %v", err)
			}
			defer std.MultipartForm.RemoveAll()

			r := newFormRequest(t, tc.target, tc.parts...)
			form, err := New(t.TempDir()).ReadForm(r, tc.maxMemory)
			if err != nil {
				t.Fatalf("ReadForm: %v", err)
			}
			defer form.RemoveAll()

			if !reflect.DeepEqual(form.Value, std.MultipartForm.Value) {
				t.Fatalf("Value = %v, want %v", form.Value, std.MultipartForm.Value)
			}
			if !reflect.DeepEqual(r.Form, std.Form) || !reflect.DeepEqual(r.PostForm, std.PostForm) {
				t.Fatalf("Form = %v / %v, want %v / %v", r.Form, r.PostForm, std.Form, std.PostForm)
			}
			if r.FormValue("path") != std.FormValue("path") {
				t.Fatalf("FormValue(path) = %q, want %q", r.FormValue("path"), std.FormValue("path"))
			}
			if len(form.File) != len(std.MultipartForm.File) {
				t.Fatalf("File keys = %d, want %d", len(form.File), len(std.MultipartForm.File))
			}
			for key, want := range std.MultipartForm.File {
				got := form.File[key]
				if len(got) != len(want) {
					t.Fatalf("File[%s] = %d parts, want %d", key, len(got), len(want))
				}
				for i := range want {
					f, err := want[i].Open()
					if err != nil {
						t.Fatal(err)
					}
					wantBody, _ := io.ReadAll(f)
					_ = f.Close()
					if got[i].Filename != want[i].Filename || got[i].Size != want[i].Size || readAllFile(t, got[i]) != string(wantBody) {
						t.Fatalf("File[%s][%d] = %q/%d, want %q/%d", key, i, got[i].Filename, got[i].Size, want[i].Filename, want[i].Size)
					}
					if !reflect.DeepEqual(got[i].Header, want[i].Header) {
						t.Fatalf("File[%s][%d].Header = %v, want %v", key, i, got[i].Header, want[i].Header)
					}
				}
			}
		})
	}
}

// TestReadFormSpillsIntoPrivateRequestFolder is the Q4 guarantee: a part
// too big for memory lands in a 0700 folder for this request inside the
// spool, never in os.TempDir(), and RemoveAll takes the folder away.
func TestReadFormSpillsIntoPrivateRequestFolder(t *testing.T) {
	spoolDir := filepath.Join(t.TempDir(), "upload-spool")
	shared := watchTempDir(t)
	spool := New(spoolDir)
	if spool.Dir() != spoolDir {
		t.Fatalf("Dir() = %q, want %q", spool.Dir(), spoolDir)
	}

	content := strings.Repeat("a", 2048)
	r := newFormRequest(t, "/up", formPart{name: "path", content: "/dst"}, formPart{name: "file", filename: "big.bin", content: content})
	form, err := spool.ReadForm(r, 16)
	if err != nil {
		t.Fatalf("ReadForm: %v", err)
	}
	assertEmptyDir(t, shared)

	info, err := os.Stat(spoolDir)
	if err != nil || info.Mode().Perm() != dirPerm {
		t.Fatalf("spool folder = %v, %v; want mode %o", info, err, dirPerm)
	}
	entries, err := os.ReadDir(spoolDir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("spool holds %v (%v), want one request folder", entries, err)
	}
	reqDir := filepath.Join(spoolDir, entries[0].Name())
	if !strings.HasPrefix(entries[0].Name(), requestDirPrefix+processToken+"-") {
		t.Fatalf("request folder %q lacks this process's prefix", entries[0].Name())
	}
	if info, err := os.Stat(reqDir); err != nil || info.Mode().Perm() != dirPerm {
		t.Fatalf("request folder = %v, %v; want mode %o", info, err, dirPerm)
	}

	file, header, err := form.FormFile("file")
	if err != nil {
		t.Fatalf("FormFile: %v", err)
	}
	osFile, ok := file.(*os.File)
	if !ok || filepath.Dir(osFile.Name()) != reqDir {
		t.Fatalf("spilled part = %T, want an *os.File in %s", file, reqDir)
	}
	body, _ := io.ReadAll(file)
	_ = file.Close()
	if string(body) != content || header.Size != int64(len(content)) || header.Filename != "big.bin" {
		t.Fatalf("spilled part = %d bytes (Size %d, %q)", len(body), header.Size, header.Filename)
	}
	if r.FormValue("path") != "/dst" {
		t.Fatalf("FormValue(path) = %q", r.FormValue("path"))
	}

	if err := form.RemoveAll(); err != nil {
		t.Fatalf("RemoveAll: %v", err)
	}
	if err := form.RemoveAll(); err != nil {
		t.Fatalf("second RemoveAll: %v", err)
	}
	assertEmptyDir(t, spoolDir)
	assertEmptyDir(t, shared)
}

// failingReader yields data, then err: a client that goes away mid-body.
type failingReader struct {
	data io.Reader
	err  error
}

func (f *failingReader) Read(p []byte) (int, error) {
	n, err := f.data.Read(p)
	if err == io.EOF {
		return n, f.err
	}
	return n, err
}

// TestReadFormErrorsLeaveNothingBehind: every way a read can fail, including
// after a part has already spilled, returns no form and leaves neither the
// spool nor the shared temp folder holding anything.
func TestReadFormErrorsLeaveNothingBehind(t *testing.T) {
	spoolDir := filepath.Join(t.TempDir(), "upload-spool")
	shared := watchTempDir(t)
	spool := New(spoolDir)

	spilled := formPart{name: "file", filename: "big.bin", content: strings.Repeat("b", 4096)}
	full, contentType := buildForm(t, spilled, formPart{name: "path", content: "/dst"})
	fullBytes := full.Bytes()

	var manyParts []formPart
	manyParts = append(manyParts, spilled)
	for i := 0; i < maxParts; i++ {
		manyParts = append(manyParts, formPart{name: "v", content: "x"})
	}
	tooMany, tooManyType := buildForm(t, manyParts...)

	cases := []struct {
		name    string
		request func(t *testing.T) *http.Request
		want    error
	}{
		{
			name: "body cut after the spill",
			request: func(t *testing.T) *http.Request {
				r := httptest.NewRequest(http.MethodPost, "/up", bytes.NewReader(fullBytes[:len(fullBytes)-20]))
				r.Header.Set("Content-Type", contentType)
				return r
			},
		},
		{
			name: "client disconnects after the spill",
			request: func(t *testing.T) *http.Request {
				r := httptest.NewRequest(http.MethodPost, "/up", &failingReader{data: bytes.NewReader(fullBytes[:len(fullBytes)-20]), err: io.ErrUnexpectedEOF})
				r.Header.Set("Content-Type", contentType)
				return r
			},
			want: io.ErrUnexpectedEOF,
		},
		{
			name: "body over the request limit",
			request: func(t *testing.T) *http.Request {
				rr := httptest.NewRecorder()
				r := httptest.NewRequest(http.MethodPost, "/up", bytes.NewReader(fullBytes))
				r.Header.Set("Content-Type", contentType)
				r.Body = http.MaxBytesReader(rr, r.Body, int64(len(fullBytes)-100))
				return r
			},
		},
		{
			name: "too many parts",
			request: func(t *testing.T) *http.Request {
				r := httptest.NewRequest(http.MethodPost, "/up", bytes.NewReader(tooMany.Bytes()))
				r.Header.Set("Content-Type", tooManyType)
				return r
			},
			want: ErrMessageTooLarge,
		},
		{
			name: "not multipart",
			request: func(t *testing.T) *http.Request {
				r := httptest.NewRequest(http.MethodPost, "/up", strings.NewReader(`{}`))
				r.Header.Set("Content-Type", "application/json")
				return r
			},
			want: http.ErrNotMultipart,
		},
		{
			name: "no content type",
			request: func(t *testing.T) *http.Request {
				return httptest.NewRequest(http.MethodPost, "/up", strings.NewReader(`{}`))
			},
			want: http.ErrNotMultipart,
		},
		{
			name: "no boundary",
			request: func(t *testing.T) *http.Request {
				r := httptest.NewRequest(http.MethodPost, "/up", strings.NewReader(`x`))
				r.Header.Set("Content-Type", "multipart/form-data")
				return r
			},
			want: http.ErrMissingBoundary,
		},
		{
			name: "malformed content type",
			request: func(t *testing.T) *http.Request {
				r := httptest.NewRequest(http.MethodPost, "/up", strings.NewReader(`x`))
				r.Header.Set("Content-Type", "multipart/form-data; boundary")
				return r
			},
		},
		{
			name: "malformed query",
			request: func(t *testing.T) *http.Request {
				r := httptest.NewRequest(http.MethodPost, "/up", bytes.NewReader(fullBytes))
				r.Header.Set("Content-Type", contentType)
				r.URL.RawQuery = "bad=%zz"
				return r
			},
		},
		{
			name: "missing body",
			request: func(t *testing.T) *http.Request {
				r := httptest.NewRequest(http.MethodPost, "/up", nil)
				r.Header.Set("Content-Type", contentType)
				r.Body = nil
				r.Form = map[string][]string{}
				return r
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			form, err := spool.ReadForm(tc.request(t), 64)
			if err == nil {
				_ = form.RemoveAll()
				t.Fatal("ReadForm succeeded, want an error")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("ReadForm error = %v, want %v", err, tc.want)
			}
			if form != nil {
				t.Fatalf("ReadForm returned a form with error %v", err)
			}
			if _, statErr := os.Stat(spoolDir); statErr == nil {
				assertEmptyDir(t, spoolDir)
			}
			assertEmptyDir(t, shared)
		})
	}
}

// TestReadFormMemoryLimits: values past maxMemory+10 MiB are refused, as
// ParseMultipartForm refuses them; file parts past maxMemory spill instead.
func TestReadFormMemoryLimits(t *testing.T) {
	shared := watchTempDir(t)
	tooBig := strings.Repeat("v", valueMemoryExtra+1)
	r := newFormRequest(t, "/up", formPart{name: "v", content: tooBig})
	if _, err := New("").ReadForm(r, 0); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("oversized value: error = %v, want ErrMessageTooLarge", err)
	}
	std := newFormRequest(t, "/up", formPart{name: "v", content: tooBig})
	if err := std.ParseMultipartForm(0); !errors.Is(err, multipart.ErrMessageTooLarge) {
		t.Fatalf("stdlib oversized value: error = %v", err)
	}
	assertEmptyDir(t, shared)

	// A name that eats what a first value left of the budget.
	r = newFormRequest(t, "/up",
		formPart{name: "v", content: strings.Repeat("v", valueMemoryExtra-1000)},
		formPart{name: strings.Repeat("n", 700), content: "x"})
	if _, err := New("").ReadForm(r, 0); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("oversized name: error = %v, want ErrMessageTooLarge", err)
	}
	// A file part whose headers alone eat the budget.
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	header := make(map[string][]string)
	header["Content-Disposition"] = []string{`form-data; name="f"; filename="f"`}
	header["X-Pad"] = []string{strings.Repeat("h", valueMemoryExtra-1000)}
	w, err := mw.CreatePart(header)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(w, "x")
	_ = mw.Close()
	r = httptest.NewRequest(http.MethodPost, "/up", &body)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	if _, err := New("").ReadForm(r, 0); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("oversized file header: error = %v, want ErrMessageTooLarge", err)
	}
}

// TestReadFormHeaderValueBudget: the header values every file part keeps
// share one budget, as in ReadForm.
func TestReadFormHeaderValueBudget(t *testing.T) {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	values := make([]string, maxHeaderValues/2)
	for i := range values {
		values[i] = "v"
	}
	for i := 0; i < 3; i++ {
		w, err := mw.CreatePart(map[string][]string{
			"Content-Disposition": {fmt.Sprintf(`form-data; name="f%d"; filename="f"`, i)},
			"X-Many":              values,
		})
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(w, "x")
	}
	_ = mw.Close()
	r := httptest.NewRequest(http.MethodPost, "/up", &body)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	if _, err := New("").ReadForm(r, 1<<20); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("error = %v, want ErrMessageTooLarge", err)
	}
}

// TestReadFormWithoutSpool: a nil Spool or one with no folder keeps small
// forms working in memory and refuses a part that would need the disk,
// rather than falling back to the shared temp folder.
func TestReadFormWithoutSpool(t *testing.T) {
	shared := watchTempDir(t)
	for _, spool := range []*Spool{nil, New(""), New("   ")} {
		if spool.Dir() != "" {
			t.Fatalf("Dir() = %q, want empty", spool.Dir())
		}
		r := newFormRequest(t, "/up", formPart{name: "file", filename: "f", content: "small"})
		form, err := spool.ReadForm(r, 1<<20)
		if err != nil {
			t.Fatalf("small form: %v", err)
		}
		_, fh, err := form.FormFile("file")
		if err != nil || readAllFile(t, fh) != "small" {
			t.Fatalf("FormFile = %v", err)
		}
		if err := form.RemoveAll(); err != nil {
			t.Fatalf("RemoveAll: %v", err)
		}

		r = newFormRequest(t, "/up", formPart{name: "file", filename: "f", content: strings.Repeat("x", 100)})
		if _, err := spool.ReadForm(r, 10); !errors.Is(err, ErrNoSpool) {
			t.Fatalf("large form: error = %v, want ErrNoSpool", err)
		}
	}
	assertEmptyDir(t, shared)
}

func TestFormFileMissing(t *testing.T) {
	var nilForm *Form
	if _, _, err := nilForm.FormFile("file"); !errors.Is(err, http.ErrMissingFile) {
		t.Fatalf("nil form: %v", err)
	}
	if err := nilForm.RemoveAll(); err != nil {
		t.Fatalf("nil RemoveAll: %v", err)
	}
	form := &Form{File: map[string][]*FileHeader{}}
	if _, _, err := form.FormFile("file"); !errors.Is(err, http.ErrMissingFile) {
		t.Fatalf("empty form: %v", err)
	}
	// A spilled part whose file is gone reports the open error.
	form.File["file"] = []*FileHeader{{Filename: "gone", path: filepath.Join(t.TempDir(), "gone")}}
	if _, _, err := form.FormFile("file"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing spill: %v", err)
	}
}

// TestEnsureSweepsFoldersFromEarlierProcesses: the first spill removes
// request folders a process that died mid-request left, keeps this
// process's own and anything not named like a request folder, and tightens
// a spool folder made with looser modes.
func TestEnsureSweepsFoldersFromEarlierProcesses(t *testing.T) {
	spoolDir := filepath.Join(t.TempDir(), "upload-spool")
	if err := os.MkdirAll(spoolDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(spoolDir, 0o755); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(spoolDir, requestDirPrefix+"0123456789abcdef-1")
	own := filepath.Join(spoolDir, requestDirPrefix+processToken+"-1")
	other := filepath.Join(spoolDir, "operator-notes")
	for _, dir := range []string{stale, own} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "part-1"), []byte("left"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(other, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}

	spool := New(spoolDir)
	r := newFormRequest(t, "/up", formPart{name: "file", filename: "f", content: strings.Repeat("x", 100)})
	form, err := spool.ReadForm(r, 10)
	if err != nil {
		t.Fatalf("ReadForm: %v", err)
	}
	if err := form.RemoveAll(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale folder still there: %v", err)
	}
	for _, keep := range []string{own, other} {
		if _, err := os.Stat(keep); err != nil {
			t.Fatalf("%s was removed: %v", keep, err)
		}
	}
	if info, err := os.Stat(spoolDir); err != nil || info.Mode().Perm() != dirPerm {
		t.Fatalf("spool folder mode = %v, %v; want %o", info, err, dirPerm)
	}

	// The sweep runs once: a stale folder that shows up later stays until
	// the next process.
	if err := os.MkdirAll(stale, 0o700); err != nil {
		t.Fatal(err)
	}
	r = newFormRequest(t, "/up", formPart{name: "file", filename: "f", content: strings.Repeat("x", 100)})
	form, err = spool.ReadForm(r, 10)
	if err != nil {
		t.Fatal(err)
	}
	_ = form.RemoveAll()
	if _, err := os.Stat(stale); err != nil {
		t.Fatalf("second spill swept again: %v", err)
	}
}

// TestEnsureRefusesABadSpoolFolder: a symlink or a file where the spool
// should be is refused, and the failure is not latched.
func TestEnsureRefusesABadSpoolFolder(t *testing.T) {
	shared := watchTempDir(t)
	base := t.TempDir()
	target := filepath.Join(base, "elsewhere")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(base, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{link, file, filepath.Join(file, "under")} {
		spool := New(dir)
		r := newFormRequest(t, "/up", formPart{name: "file", filename: "f", content: strings.Repeat("x", 100)})
		if _, err := spool.ReadForm(r, 10); err == nil {
			t.Fatalf("%s: ReadForm succeeded", dir)
		}
		if spool.ready.Load() {
			t.Fatalf("%s: a failed ensure latched", dir)
		}
	}
	assertEmptyDir(t, target)
	assertEmptyDir(t, shared)

	// Once the path is fixed the same Spool works.
	fixed := filepath.Join(base, "fixed")
	spool := New(fixed)
	if err := os.WriteFile(fixed, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	r := newFormRequest(t, "/up", formPart{name: "file", filename: "f", content: strings.Repeat("x", 100)})
	if _, err := spool.ReadForm(r, 10); err == nil {
		t.Fatal("ReadForm over a file succeeded")
	}
	if err := os.Remove(fixed); err != nil {
		t.Fatal(err)
	}
	r = newFormRequest(t, "/up", formPart{name: "file", filename: "f", content: strings.Repeat("x", 100)})
	form, err := spool.ReadForm(r, 10)
	if err != nil {
		t.Fatalf("ReadForm after fix: %v", err)
	}
	_ = form.RemoveAll()
}

// TestSpillErrorsLeaveNothingBehind: a spool whose request folder cannot
// take a file fails the read and cleans what it made.
func TestSpillErrorsLeaveNothingBehind(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores folder modes")
	}
	spoolDir := filepath.Join(t.TempDir(), "upload-spool")
	spool := New(spoolDir)
	if _, err := spool.ensure(); err != nil {
		t.Fatal(err)
	}
	// No write or search permission on the spool: MkdirTemp fails.
	if err := os.Chmod(spoolDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(spoolDir, dirPerm) })
	r := newFormRequest(t, "/up", formPart{name: "file", filename: "f", content: strings.Repeat("x", 100)})
	if _, err := spool.ReadForm(r, 10); err == nil {
		t.Fatal("ReadForm succeeded without a writable spool")
	}
	_ = os.Chmod(spoolDir, dirPerm)

	// A request folder that will not take a file: CreateTemp fails.
	form := &Form{dir: filepath.Join(spoolDir, "missing")}
	if err := spool.spill(form, &FileHeader{}, []byte("head"), strings.NewReader("rest")); err == nil {
		t.Fatal("spill into a missing folder succeeded")
	}
	// A body that fails mid-copy still closes the part file; the caller's
	// RemoveAll takes the folder.
	form = &Form{}
	fh := &FileHeader{}
	if err := spool.spill(form, fh, []byte("head"), &failingReader{data: strings.NewReader("rest"), err: io.ErrUnexpectedEOF}); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("spill error = %v", err)
	}
	if fh.path == "" || form.dir == "" {
		t.Fatalf("spill did not record its file (%q) or folder (%q)", fh.path, form.dir)
	}
	if err := form.RemoveAll(); err != nil {
		t.Fatal(err)
	}
	assertEmptyDir(t, spoolDir)
}

// TestConcurrentSpillsGetTheirOwnFolders: requests that spill at once each
// get a folder, the first-use latch runs once, and every folder goes.
func TestConcurrentSpillsGetTheirOwnFolders(t *testing.T) {
	spoolDir := filepath.Join(t.TempDir(), "upload-spool")
	spool := New(spoolDir)
	const n = 16
	forms := make([]*Form, n)
	errs := make([]error, n)
	requests := make([]*http.Request, n)
	for i := range requests {
		content := strings.Repeat(string(rune('a'+i)), 256)
		requests[i] = newFormRequest(t, "/up", formPart{name: "file", filename: "f", content: content})
	}
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			forms[i], errs[i] = spool.ReadForm(requests[i], 8)
		}(i)
	}
	wg.Wait()
	seen := map[string]bool{}
	for i, form := range forms {
		if errs[i] != nil {
			t.Fatalf("request %d: %v", i, errs[i])
		}
		if seen[form.dir] {
			t.Fatalf("request %d shares folder %s", i, form.dir)
		}
		seen[form.dir] = true
		_, fh, err := form.FormFile("file")
		if err != nil || readAllFile(t, fh) != strings.Repeat(string(rune('a'+i)), 256) {
			t.Fatalf("request %d read back wrong content (%v)", i, err)
		}
	}
	for _, form := range forms {
		if err := form.RemoveAll(); err != nil {
			t.Fatal(err)
		}
	}
	assertEmptyDir(t, spoolDir)
}

func TestNewProcessToken(t *testing.T) {
	a, b := newProcessToken(), newProcessToken()
	if len(a) != 16 || a == b {
		t.Fatalf("tokens %q and %q", a, b)
	}
}

// TestSpoolFolderDeletedAfterLatch: an operator deleting the spool folder
// to free disk after the first spill must not turn every later spill into
// a 400 until restart. The next spill makes the folder again, 0700.
func TestSpoolFolderDeletedAfterLatch(t *testing.T) {
	spoolDir := filepath.Join(t.TempDir(), "upload-spool")
	shared := watchTempDir(t)
	spool := New(spoolDir)
	spillOnce := func() {
		t.Helper()
		r := newFormRequest(t, "/up", formPart{name: "file", filename: "f", content: strings.Repeat("x", 100)})
		form, err := spool.ReadForm(r, 10)
		if err != nil {
			t.Fatalf("ReadForm: %v", err)
		}
		_, fh, err := form.FormFile("file")
		if err != nil || readAllFile(t, fh) != strings.Repeat("x", 100) {
			t.Fatalf("FormFile: %v", err)
		}
		if err := form.RemoveAll(); err != nil {
			t.Fatal(err)
		}
	}

	spillOnce()
	if !spool.ready.Load() {
		t.Fatal("first spill did not latch")
	}
	if err := os.RemoveAll(spoolDir); err != nil {
		t.Fatal(err)
	}
	spillOnce()
	if info, err := os.Stat(spoolDir); err != nil || info.Mode().Perm() != dirPerm {
		t.Fatalf("spool folder after recreate = %v, %v; want mode %o", info, err, dirPerm)
	}
	if !spool.ready.Load() {
		t.Fatal("recreate did not latch again")
	}
	assertEmptyDir(t, spoolDir)
	assertEmptyDir(t, shared)

	// Swapped for a dangling symlink: the spill's folder is not there
	// (ENOENT), and remaking the spool is refused (not a real folder). The
	// spill fails, the latch stays clear, and once the link is gone the
	// next spill works.
	if err := os.RemoveAll(spoolDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(filepath.Dir(spoolDir), "nowhere"), spoolDir); err != nil {
		t.Fatal(err)
	}
	r := newFormRequest(t, "/up", formPart{name: "file", filename: "f", content: strings.Repeat("x", 100)})
	if _, err := spool.ReadForm(r, 10); err == nil {
		t.Fatal("ReadForm succeeded with no way to make the spool")
	}
	if spool.ready.Load() {
		t.Fatal("a failed recreate latched")
	}
	if err := os.Remove(spoolDir); err != nil {
		t.Fatal(err)
	}
	spillOnce()
	assertEmptyDir(t, shared)
}

// panicReader yields data, then panics: a body reader that blows up.
type panicReader struct{ data io.Reader }

func (p *panicReader) Read(b []byte) (int, error) {
	n, err := p.data.Read(b)
	if err == io.EOF {
		panic("body reader exploded")
	}
	return n, err
}

// TestReadFormPanicLeavesNothingBehind: a panic after a part has spilled
// still removes the request's folder, and the panic reaches the caller.
func TestReadFormPanicLeavesNothingBehind(t *testing.T) {
	spoolDir := filepath.Join(t.TempDir(), "upload-spool")
	shared := watchTempDir(t)
	body, contentType := buildForm(t, formPart{name: "file", filename: "big.bin", content: strings.Repeat("p", 4096)}, formPart{name: "path", content: "/dst"})
	cut := body.Bytes()[:body.Len()-20]
	r := httptest.NewRequest(http.MethodPost, "/up", &panicReader{data: bytes.NewReader(cut)})
	r.Header.Set("Content-Type", contentType)

	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("ReadForm swallowed the panic")
			}
		}()
		_, _ = New(spoolDir).ReadForm(r, 64)
	}()
	if folders, err := os.ReadDir(spoolDir); err != nil || len(folders) != 0 {
		t.Fatalf("spool holds %v (%v) after a panic, want an empty folder", folders, err)
	}
	assertEmptyDir(t, shared)
}
