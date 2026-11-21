package runloop

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

// spoolBigFile is past uploadFile's 32 MiB in-memory budget by more than
// the multipart reader's 4 KiB buffer, so the part has spilled to the
// spool by the time all its bytes are written.
const spoolBigFile = 32<<20 + 64<<10

// zeroes is an endless stream of filler bytes, a chunk per read.
type zeroes struct{}

var zeroChunk = make([]byte, 64<<10)

func (zeroes) Read(p []byte) (int, error) { return copy(p, zeroChunk), nil }

// streamUpload streams an upload_file form without holding it in memory:
// `file` of size bytes first, then a `path` field unless path is "" (the
// order no SDK pins). With cut set, the body fails with cut right after the
// file's bytes, once beforeCut has run: a client that goes away mid-upload.
func streamUpload(size int64, path string, beforeCut func(), cut error) (io.Reader, string) {
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	go func() {
		part, err := mw.CreateFormFile("file", "big.bin")
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
		if err == nil && path != "" {
			err = mw.WriteField("path", path)
		}
		if err == nil {
			err = mw.Close()
		}
		_ = pw.CloseWithError(err)
	}()
	return pr, mw.FormDataContentType()
}

// spoolState counts the request folders in the spool and the part files
// in them.
func spoolState(t *testing.T, spoolDir string) [2]int {
	t.Helper()
	var n [2]int
	entries, _ := os.ReadDir(spoolDir)
	for _, e := range entries {
		n[0]++
		parts, _ := os.ReadDir(filepath.Join(spoolDir, e.Name()))
		n[1] += len(parts)
	}
	return n
}

func assertEmptyFolder(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
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

// spoolEnv is a devbox behind the facade with an upload spool, and TMPDIR
// pointed at a folder the test watches.
func spoolEnv(t *testing.T) (env *testEnv, devboxID, spoolDir, shared string) {
	t.Helper()
	env = newTestEnv(t)
	devboxID = env.mustCreate(t, "").ID
	spoolDir = filepath.Join(t.TempDir(), "upload-spool")
	env.h.deps.UploadSpool = multipartspool.New(spoolDir)
	shared = t.TempDir()
	t.Setenv("TMPDIR", shared)
	return env, devboxID, spoolDir, shared
}

func serveUpload(env *testEnv, devboxID string, body io.Reader, contentType string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, devboxesPath+"/"+devboxID+"/upload_file", body)
	req.Header.Set("Content-Type", contentType)
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, req)
	return rr
}

// TestUploadFileSpillsOutsideSharedTemp is Q4 for the Runloop facade: a
// file past the 32 MiB in-memory budget spills to a private folder in the
// spool while the facade forwards it, the shared temp folder (TMPDIR) stays
// empty throughout, and the spool is empty once the request ends.
func TestUploadFileSpillsOutsideSharedTemp(t *testing.T) {
	env, devboxID, spoolDir, shared := spoolEnv(t)
	during := make(chan [3]int, 1)
	env.toolbox.setBeforeServe(func(r *http.Request) {
		if r.URL.Path != "/files/upload" {
			return
		}
		// The facade holds the parsed form while it forwards the file.
		sharedEntries, _ := os.ReadDir(shared)
		s := spoolState(t, spoolDir)
		during <- [3]int{len(sharedEntries), s[0], s[1]}
	})

	body, contentType := streamUpload(spoolBigFile, "/tmp/big.bin", nil, nil)
	rr := serveUpload(env, devboxID, body, contentType)
	expectStatus(t, rr, http.StatusOK)
	if rr.Body.String() != "{}\n" {
		t.Fatalf("body = %q, want {}", rr.Body.String())
	}
	if got := <-during; got != [3]int{0, 1, 1} {
		t.Fatalf("during the upload: %d shared temp entries, %d spool folders, %d parts; want 0, 1, 1", got[0], got[1], got[2])
	}
	env.toolbox.mu.Lock()
	got := len(env.toolbox.files["/tmp/big.bin"])
	env.toolbox.mu.Unlock()
	if got != spoolBigFile {
		t.Fatalf("toolbox got %d bytes, want %d", got, spoolBigFile)
	}
	assertEmptyFolder(t, spoolDir)
	assertEmptyFolder(t, shared)
}

// TestUploadFileSpoolCleanupOnFailure: the spilled part goes on every way
// out, and the wire answer is the facade's usual one.
func TestUploadFileSpoolCleanupOnFailure(t *testing.T) {
	t.Run("toolbox refuses the file", func(t *testing.T) {
		env, devboxID, spoolDir, shared := spoolEnv(t)
		during := make(chan [2]int, 1)
		env.toolbox.setBeforeServe(func(r *http.Request) {
			if r.URL.Path == "/files/upload" {
				during <- spoolState(t, spoolDir)
			}
		})
		env.toolbox.failAlways("/files/upload", http.StatusInternalServerError)
		body, contentType := streamUpload(spoolBigFile, "/tmp/big.bin", nil, nil)
		expectStatus(t, serveUpload(env, devboxID, body, contentType), http.StatusBadGateway)
		if got := <-during; got != [2]int{1, 1} {
			t.Fatalf("spool held %v during the upload, want one folder with one part", got)
		}
		assertEmptyFolder(t, spoolDir)
		assertEmptyFolder(t, shared)
	})

	t.Run("file without a path", func(t *testing.T) {
		env, devboxID, spoolDir, shared := spoolEnv(t)
		body, contentType := streamUpload(spoolBigFile, "", nil, nil)
		rr := serveUpload(env, devboxID, body, contentType)
		expectStatus(t, rr, http.StatusBadRequest)
		assertEmptyFolder(t, spoolDir)
		assertEmptyFolder(t, shared)
	})

	t.Run("client goes away mid-body", func(t *testing.T) {
		env, devboxID, spoolDir, shared := spoolEnv(t)
		var atCut [2]int
		body, contentType := streamUpload(spoolBigFile, "", func() { atCut = spoolState(t, spoolDir) }, io.ErrUnexpectedEOF)
		rr := serveUpload(env, devboxID, body, contentType)
		expectStatus(t, rr, http.StatusBadRequest)
		if rr.Body.String() != "{\"message\":\"invalid multipart form (or too large)\"}\n" {
			t.Fatalf("body = %q", rr.Body.String())
		}
		if atCut != [2]int{1, 1} {
			t.Fatalf("spool held %v when the client left, want one folder with one part", atCut)
		}
		assertEmptyFolder(t, spoolDir)
		assertEmptyFolder(t, shared)
	})
}
