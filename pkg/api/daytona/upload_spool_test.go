package daytona

import (
	"bytes"
	"context"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/internal/multipartspool"
)

// spoolBigFile is past bulkUpload's 64 MiB in-memory budget by more than
// the multipart reader's 4 KiB buffer, so the part has spilled to the
// spool by the time all its bytes are written.
const spoolBigFile = 64<<20 + 64<<10

// zeroes is an endless stream of filler bytes, a chunk per read (a byte
// loop is slow under -race).
type zeroes struct{}

var zeroChunk = make([]byte, 64<<10)

func (zeroes) Read(p []byte) (int, error) { return copy(p, zeroChunk), nil }

// formField is one part streamBulkUpload writes after the big file: a
// file part when filename is set, a value otherwise.
type formField struct {
	name, filename, content string
}

// streamBulkUpload streams a bulk-upload form without holding it in
// memory: files[0].file of size bytes first, then after in order. With cut
// set, the body fails with cut right after the file's bytes, once
// beforeCut has run: a client that goes away mid-upload.
func streamBulkUpload(size int64, after []formField, beforeCut func(), cut error) (io.Reader, string) {
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	go func() {
		part, err := mw.CreateFormFile("files[0].file", "big.bin")
		if err == nil {
			_, err = io.Copy(part, io.LimitReader(zeroes{}, size))
		}
		if err == nil && cut != nil {
			if beforeCut != nil {
				beforeCut()
			}
			_ = pw.CloseWithError(cut)
			return
		}
		for _, f := range after {
			if err != nil {
				break
			}
			var w io.Writer
			if f.filename != "" {
				w, err = mw.CreateFormFile(f.name, f.filename)
			} else {
				w, err = mw.CreateFormField(f.name)
			}
			if err == nil {
				_, err = io.WriteString(w, f.content)
			}
		}
		if err == nil {
			err = mw.Close()
		}
		_ = pw.CloseWithError(err)
	}()
	return pr, mw.FormDataContentType()
}

func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		t.Errorf("ReadDir(%s): %v", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names
}

// spoolParts counts the request folders in the spool and the part files
// in them.
func spoolParts(t *testing.T, spoolDir string) [2]int {
	t.Helper()
	var n [2]int
	for _, name := range dirNames(t, spoolDir) {
		n[0]++
		n[1] += len(dirNames(t, filepath.Join(spoolDir, name)))
	}
	return n
}

func assertNothingIn(t *testing.T, dir string) {
	t.Helper()
	if names := dirNames(t, dir); len(names) != 0 {
		t.Fatalf("%s holds %v, want nothing", dir, names)
	}
}

func postBulkUpload(t *testing.T, facadeURL, id string, body io.Reader, contentType string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, facadeURL+ToolboxPrefix+"/"+id+"/files/bulk-upload", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("bulk-upload: %v", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(respBody)
}

type toolboxUpload struct {
	path   string
	size   int64
	shared []string
	spool  [2]int
}

// TestBulkUploadSpillsOutsideSharedTemp is Q4 for the Daytona facade: a
// file past the 64 MiB in-memory budget spills to a private folder in the
// spool while the facade forwards it, the shared temp folder (TMPDIR) stays
// empty throughout, and the spool is empty once the request ends.
func TestBulkUploadSpillsOutsideSharedTemp(t *testing.T) {
	spoolDir := filepath.Join(t.TempDir(), "upload-spool")
	shared := t.TempDir()

	var mu sync.Mutex
	var uploads []toolboxUpload
	toolbox := http.NewServeMux()
	toolbox.HandleFunc("/files/upload", func(w http.ResponseWriter, r *http.Request) {
		// The facade holds the parsed form while it forwards each file,
		// so this is when a spilled part exists.
		seen := toolboxUpload{path: r.URL.Query().Get("path"), shared: dirNames(t, shared), spool: spoolParts(t, spoolDir)}
		mr, err := r.MultipartReader()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		for {
			part, err := mr.NextPart()
			if err != nil {
				break
			}
			n, _ := io.Copy(io.Discard, part)
			seen.size += n
		}
		mu.Lock()
		uploads = append(uploads, seen)
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	facadeURL, id := serveToolboxFacade(t, toolbox, nil, multipartspool.New(spoolDir))
	t.Setenv("TMPDIR", shared)

	// The big file's path comes after it; a small second file stays in
	// memory, and a file under an unrelated field is ignored.
	body, contentType := streamBulkUpload(spoolBigFile, []formField{
		{name: "files[0].path", content: "/dst/big.bin"},
		{name: "files[1].path", content: "/dst/small.txt"},
		{name: "files[1].file", filename: "small.txt", content: "small"},
		{name: "attachment", filename: "other.txt", content: "ignored"},
	}, nil, nil)
	if status, msg := postBulkUpload(t, facadeURL, id, body, contentType); status != http.StatusNoContent {
		t.Fatalf("status = %d (%s), want 204", status, msg)
	}

	mu.Lock()
	defer mu.Unlock()
	sort.Slice(uploads, func(i, j int) bool { return uploads[i].path < uploads[j].path })
	if len(uploads) != 2 || uploads[0].path != "/dst/big.bin" || uploads[1].path != "/dst/small.txt" {
		t.Fatalf("toolbox got %+v, want big.bin and small.txt", uploads)
	}
	if uploads[0].size != spoolBigFile || uploads[1].size != int64(len("small")) {
		t.Fatalf("toolbox got %d and %d bytes, want %d and 5", uploads[0].size, uploads[1].size, spoolBigFile)
	}
	for _, u := range uploads {
		if len(u.shared) != 0 {
			t.Fatalf("shared temp folder held %v while %s uploaded", u.shared, u.path)
		}
		// One request folder holding the big part only: the small one is
		// in memory.
		if u.spool != [2]int{1, 1} {
			t.Fatalf("spool held %v (folders, parts) while %s uploaded, want [1 1]", u.spool, u.path)
		}
	}
	assertNothingIn(t, spoolDir)
	assertNothingIn(t, shared)
}

// TestBulkUploadSpoolCleanupOnFailure: the spilled part goes on every way
// out, and the wire answer is the facade's usual one.
func TestBulkUploadSpoolCleanupOnFailure(t *testing.T) {
	t.Run("toolbox refuses the file", func(t *testing.T) {
		spoolDir := filepath.Join(t.TempDir(), "upload-spool")
		shared := t.TempDir()
		during := make(chan [2]int, 1)
		toolbox := http.NewServeMux()
		toolbox.HandleFunc("/files/upload", func(w http.ResponseWriter, r *http.Request) {
			during <- spoolParts(t, spoolDir)
			_, _ = io.Copy(io.Discard, r.Body)
			http.Error(w, `{"error":"disk full"}`, http.StatusInsufficientStorage)
		})
		facadeURL, id := serveToolboxFacade(t, toolbox, nil, multipartspool.New(spoolDir))
		t.Setenv("TMPDIR", shared)

		body, contentType := streamBulkUpload(spoolBigFile, []formField{{name: "files[0].path", content: "/dst/big.bin"}}, nil, nil)
		status, msg := postBulkUpload(t, facadeURL, id, body, contentType)
		if status != http.StatusInsufficientStorage || msg != "{\"error\":\"disk full\"}\n" {
			t.Fatalf("status = %d (%q), want the toolbox's 507", status, msg)
		}
		if got := <-during; got != [2]int{1, 1} {
			t.Fatalf("spool held %v during the upload, want one folder with one part", got)
		}
		assertNothingIn(t, spoolDir)
		assertNothingIn(t, shared)
	})

	// The rest fail before any toolbox call, so they need no sandbox.
	inProcess := func(t *testing.T, spool *multipartspool.Spool, body io.Reader, contentType string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, ToolboxPrefix+"/sb/files/bulk-upload", body)
		req.Header.Set("Content-Type", contentType)
		rr := httptest.NewRecorder()
		newHandlers(Deps{UploadSpool: spool}).bulkUpload(rr, req, "sb")
		return rr
	}

	t.Run("file without its path", func(t *testing.T) {
		spoolDir := filepath.Join(t.TempDir(), "upload-spool")
		shared := t.TempDir()
		t.Setenv("TMPDIR", shared)
		body, contentType := streamBulkUpload(spoolBigFile, nil, nil, nil)
		rr := inProcess(t, multipartspool.New(spoolDir), body, contentType)
		if rr.Code != http.StatusBadRequest || rr.Body.String() != "{\"error\":\"each uploaded file must include files[n].path and files[n].file\"}\n" {
			t.Fatalf("status = %d (%q), want the facade's 400", rr.Code, rr.Body.String())
		}
		assertNothingIn(t, spoolDir)
		assertNothingIn(t, shared)
	})

	t.Run("client goes away mid-body", func(t *testing.T) {
		spoolDir := filepath.Join(t.TempDir(), "upload-spool")
		shared := t.TempDir()
		t.Setenv("TMPDIR", shared)
		var atCut [2]int
		body, contentType := streamBulkUpload(spoolBigFile, nil, func() { atCut = spoolParts(t, spoolDir) }, io.ErrUnexpectedEOF)
		rr := inProcess(t, multipartspool.New(spoolDir), body, contentType)
		if rr.Code != http.StatusBadRequest || rr.Body.String() != "{\"error\":\"invalid multipart form (or too large)\"}\n" {
			t.Fatalf("status = %d (%q), want the facade's 400", rr.Code, rr.Body.String())
		}
		if atCut != [2]int{1, 1} {
			t.Fatalf("spool held %v when the client left, want one folder with one part", atCut)
		}
		assertNothingIn(t, spoolDir)
		assertNothingIn(t, shared)
	})

	t.Run("upload over the 256 MiB cap", func(t *testing.T) {
		spoolDir := filepath.Join(t.TempDir(), "upload-spool")
		shared := t.TempDir()
		t.Setenv("TMPDIR", shared)
		body, contentType := streamBulkUpload(maxBulkUploadBytes+1, []formField{{name: "files[0].path", content: "/dst/big.bin"}}, nil, nil)
		rr := inProcess(t, multipartspool.New(spoolDir), body, contentType)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d (%q), want 400", rr.Code, rr.Body.String())
		}
		// Let the abandoned writer finish.
		_, _ = io.Copy(io.Discard, body)
		assertNothingIn(t, spoolDir)
		assertNothingIn(t, shared)
	})

	t.Run("no spool refuses a part past memory", func(t *testing.T) {
		shared := t.TempDir()
		t.Setenv("TMPDIR", shared)
		body, contentType := streamBulkUpload(spoolBigFile, []formField{{name: "files[0].path", content: "/dst/big.bin"}}, nil, nil)
		rr := inProcess(t, nil, body, contentType)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d (%q), want 400", rr.Code, rr.Body.String())
		}
		_, _ = io.Copy(io.Discard, body)
		assertNothingIn(t, shared)
	})
}

// TestUploadSingleFileErrors: a sandbox the toolbox call cannot reach, and
// a spilled part that is gone by the time it is forwarded, both come back
// as errors.
func TestUploadSingleFileErrors(t *testing.T) {
	spool := multipartspool.New(filepath.Join(t.TempDir(), "upload-spool"))
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, _ := mw.CreateFormFile("files[0].file", "f.bin")
	_, _ = part.Write(bytes.Repeat([]byte("x"), 100))
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	form, err := spool.ReadForm(req, 10)
	if err != nil {
		t.Fatal(err)
	}
	fh := form.File["files[0].file"][0]
	svc, _, _, _ := newHandlerExtraTestEnv(t)
	h := newHandlers(Deps{Service: svc})

	if err := h.uploadSingleFile(context.Background(), "sb-missing", "/x", fh); err == nil {
		t.Fatal("upload to a missing sandbox succeeded")
	}
	if err := form.RemoveAll(); err != nil {
		t.Fatal(err)
	}
	if err := h.uploadSingleFile(context.Background(), "sb-missing", "/x", fh); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("spilled part gone: error = %v, want not-exist", err)
	}
}
