package toolhost

import (
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/internal/multipartspool"
)

// spoolBigFile is past handleUpload's 64 MiB in-memory budget by more than
// the multipart reader's 4 KiB buffer, so the part has spilled to the
// spool by the time all its bytes are written.
const spoolBigFile = 64<<20 + 64<<10

// zeroes is an endless stream of filler bytes, a chunk per read.
type zeroes struct{}

var zeroChunk = make([]byte, 64<<10)

func (zeroes) Read(p []byte) (int, error) { return copy(p, zeroChunk), nil }

// streamUpload streams a /files/upload form without holding it in memory:
// `file` of size bytes first, then `path`. probe runs once the file's bytes
// are consumed, while the handler holds the spilled part; with cut set the
// body then fails with cut instead of going on (a client that goes away).
func streamUpload(size int64, path string, probe func(), cut error) (io.Reader, string) {
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	go func() {
		part, err := mw.CreateFormFile("file", "big.bin")
		if err == nil {
			_, err = io.Copy(part, io.LimitReader(zeroes{}, size))
		}
		if err == nil && probe != nil {
			probe()
		}
		if err == nil && cut != nil {
			_ = pw.CloseWithError(cut)
			return
		}
		if err == nil {
			err = mw.WriteField("path", path)
		}
		if err == nil {
			err = mw.Close()
		}
		_ = pw.CloseWithError(err)
	}()
	return pr, mw.FormDataContentType()
}

// folderState is the number of entries in shared, and the request folders
// and part files in spoolDir.
func folderState(shared, spoolDir string) [3]int {
	var n [3]int
	entries, _ := os.ReadDir(shared)
	n[0] = len(entries)
	folders, _ := os.ReadDir(spoolDir)
	for _, f := range folders {
		n[1]++
		parts, _ := os.ReadDir(filepath.Join(spoolDir, f.Name()))
		n[2] += len(parts)
	}
	return n
}

// TestHandleUploadSpillsOutsideSharedTemp is Q4 for the WASM toolbox host,
// which runs inside sandboxd: a file past the 64 MiB in-memory budget
// spills to a private folder in the spool, never to the shared temp folder
// (TMPDIR), lands whole in the sandbox, and nothing is left once the
// request ends, on success or failure.
func TestHandleUploadSpillsOutsideSharedTemp(t *testing.T) {
	cases := []struct {
		name     string
		path     string
		cut      error
		wantCode int
		wantFile bool
	}{
		{name: "written", path: "/big.bin", wantCode: http.StatusCreated, wantFile: true},
		{name: "path escapes the sandbox", path: "../outside.bin", wantCode: http.StatusBadRequest},
		{name: "client goes away mid-body", cut: io.ErrUnexpectedEOF, wantCode: http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			workDir := t.TempDir()
			spoolDir := filepath.Join(t.TempDir(), "upload-spool")
			shared := t.TempDir()
			t.Setenv("TMPDIR", shared)
			h := New(Config{SandboxID: "sb", WorkDir: workDir, UploadSpool: multipartspool.New(spoolDir)})

			var during [3]int
			body, contentType := streamUpload(spoolBigFile, tc.path, func() { during = folderState(shared, spoolDir) }, tc.cut)
			req := httptest.NewRequest(http.MethodPost, "/files/upload", body)
			req.Header.Set("Content-Type", contentType)
			rec := httptest.NewRecorder()
			h.Handler().ServeHTTP(rec, req)
			if rec.Code != tc.wantCode {
				t.Fatalf("status = %d (%s), want %d", rec.Code, rec.Body.String(), tc.wantCode)
			}
			if during != [3]int{0, 1, 1} {
				t.Fatalf("mid-upload: %d shared temp entries, %d spool folders, %d parts; want 0, 1, 1", during[0], during[1], during[2])
			}
			if after := folderState(shared, spoolDir); after != [3]int{} {
				t.Fatalf("after the request: %v (shared, folders, parts), want nothing", after)
			}
			info, err := os.Stat(filepath.Join(workDir, "big.bin"))
			if tc.wantFile {
				if err != nil || info.Size() != spoolBigFile {
					t.Fatalf("uploaded file = %v, %v; want %d bytes", info, err, spoolBigFile)
				}
			} else if err == nil {
				t.Fatal("a refused upload wrote the file")
			}
		})
	}
}

// TestHandleUploadWithoutSpool: a host built with no spool keeps small
// uploads working and refuses one past memory with the usual 400.
func TestHandleUploadWithoutSpool(t *testing.T) {
	shared := t.TempDir()
	t.Setenv("TMPDIR", shared)
	h := New(Config{SandboxID: "sb", WorkDir: t.TempDir()})
	body, contentType := streamUpload(spoolBigFile, "/big.bin", nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/files/upload", body)
	req.Header.Set("Content-Type", contentType)
	rec := httptest.NewRecorder()
	h.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d (%s), want 400", rec.Code, rec.Body.String())
	}
	_, _ = io.Copy(io.Discard, body)
	if entries, _ := os.ReadDir(shared); len(entries) != 0 {
		t.Fatalf("shared temp folder holds %d entries", len(entries))
	}
}
