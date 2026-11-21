package api

import (
	"context"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// spoolFiller is an endless stream of filler bytes, a chunk per read.
type spoolFiller struct{}

var spoolFillerChunk = make([]byte, 64<<10)

func (spoolFiller) Read(p []byte) (int, error) { return copy(p, spoolFillerChunk), nil }

// TestFacadeUploadsSpoolThroughTheServer is Q4 end to end: through
// NewServer's own route registration (auth, routing, the facades' Deps),
// a Daytona bulk upload past 64 MiB and a Runloop upload_file past 32 MiB
// spill into <dir of DBPath>/upload-spool, never the shared temp folder
// (TMPDIR), and leave nothing behind.
func TestFacadeUploadsSpoolThroughTheServer(t *testing.T) {
	dataDir := t.TempDir()
	spoolDir := filepath.Join(dataDir, "upload-spool")
	shared := t.TempDir()

	type seen struct {
		size           int64
		shared, spools int
	}
	seenCh := make(chan seen, 1)
	toolbox := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/files/upload" {
			http.NotFound(w, r)
			return
		}
		// The facade holds the parsed form while it forwards the file.
		sharedEntries, _ := os.ReadDir(shared)
		spoolEntries, _ := os.ReadDir(spoolDir)
		got := seen{shared: len(sharedEntries), spools: len(spoolEntries)}
		if mr, err := r.MultipartReader(); err == nil {
			for {
				part, err := mr.NextPart()
				if err != nil {
					break
				}
				n, _ := io.Copy(io.Discard, part)
				got.size += n
			}
		}
		seenCh <- got
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(toolbox.Close)
	u, _ := url.Parse(toolbox.URL)
	host, portStr, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(portStr)

	cipher, err := secrets.NewCipher("", filepath.Join(t.TempDir(), "key"))
	if err != nil {
		t.Fatal(err)
	}
	st := storeWith(t, "uploads")
	svc := service.New(config.Config{ToolboxPort: port}, discardLogger(), st, nil, nil, nil, cipher, nil, nil)
	sb := ownedSandbox("sb-up", "payments")
	sb.ContainerIP = host
	sb.ToolboxToken = "toolbox-secret"
	if err := st.Create(context.Background(), sb); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(discardLogger(), svc, nil, nil, config.Config{DBPath: filepath.Join(dataDir, "state.db")}, "pat-token", nil)
	t.Setenv("TMPDIR", shared)

	cases := []struct {
		name, target, fileField, pathField string
		size                               int64
		want                               int
	}{
		{name: "daytona bulk upload", target: "/daytona/toolbox/sb-up/files/bulk-upload", fileField: "files[0].file", pathField: "files[0].path", size: 64<<20 + 64<<10, want: http.StatusNoContent},
		{name: "runloop upload_file", target: "/runloop/v1/devboxes/sb-up/upload_file", fileField: "file", pathField: "path", size: 32<<20 + 64<<10, want: http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The file comes before its path, streamed, past the
			// facade's in-memory budget.
			pr, pw := io.Pipe()
			mw := multipart.NewWriter(pw)
			go func() {
				part, err := mw.CreateFormFile(tc.fileField, "big.bin")
				if err == nil {
					_, err = io.Copy(part, io.LimitReader(spoolFiller{}, tc.size))
				}
				if err == nil {
					err = mw.WriteField(tc.pathField, "/tmp/big.bin")
				}
				if err == nil {
					err = mw.Close()
				}
				_ = pw.CloseWithError(err)
			}()
			req := httptest.NewRequest(http.MethodPost, tc.target, pr)
			req.Header.Set("Content-Type", mw.FormDataContentType())
			req.Header.Set("Authorization", "Bearer pat-token")
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d (%s), want %d", rec.Code, rec.Body.String(), tc.want)
			}
			got := <-seenCh
			if got.size != tc.size || got.shared != 0 || got.spools != 1 {
				t.Fatalf("toolbox saw %d bytes with %d shared temp entries and %d spool folders; want %d, 0, 1", got.size, got.shared, got.spools, tc.size)
			}
			for _, dir := range []string{spoolDir, shared} {
				if entries, _ := os.ReadDir(dir); len(entries) != 0 {
					t.Fatalf("%s holds %d entries after the request", dir, len(entries))
				}
			}
		})
	}
}
