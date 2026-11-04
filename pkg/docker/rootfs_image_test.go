package docker

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
)

// fakeImageDaemon answers the three calls a Firecracker snapshot makes:
// import (POST /images/create), inspect (GET /images/<ref>/json) and save
// (GET /images/<ref>/get). Unknown images answer 404 like Docker.
type fakeImageDaemon struct {
	images    map[string]string // ref -> image ID
	saved     string            // body of /get
	imported  bytes.Buffer
	importErr int
	saveErr   int
	readErr   bool
}

func (f *fakeImageDaemon) client() *Client {
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		reply := func(code int, body string) (*http.Response, error) {
			return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
		}
		path := r.URL.Path
		switch {
		case r.Method == http.MethodPost && path == "/images/create":
			if f.importErr != 0 {
				return reply(f.importErr, "no space left on device")
			}
			_, _ = io.Copy(&f.imported, r.Body)
			return reply(http.StatusOK, `{"status":"sha256:new"}`+"\n")
		case strings.HasSuffix(path, "/json"):
			ref := strings.TrimSuffix(strings.TrimPrefix(path, "/images/"), "/json")
			if id, ok := f.images[ref]; ok {
				return reply(http.StatusOK, `{"Id":"`+id+`"}`)
			}
			return reply(http.StatusNotFound, `{"message":"No such image: `+ref+`"}`)
		case strings.HasSuffix(path, "/get"):
			if f.saveErr != 0 {
				return reply(f.saveErr, "save failed")
			}
			if f.readErr {
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(&brokenReader{}), Header: make(http.Header)}, nil
			}
			return reply(http.StatusOK, f.saved)
		}
		return reply(http.StatusNotFound, "unexpected "+r.Method+" "+path)
	})
	return &Client{logger: slog.Default(), streamClient: &http.Client{Transport: transport}, httpClient: &http.Client{Transport: transport}}
}

type brokenReader struct{}

func (brokenReader) Read([]byte) (int, error) { return 0, errors.New("connection reset") }

func TestImportRootfsImage(t *testing.T) {
	f := &fakeImageDaemon{images: map[string]string{"aerolvm-snapshot/abc:latest": "sha256:feed"}}
	id, err := f.client().ImportRootfsImage(context.Background(), "aerolvm-snapshot/abc:latest", strings.NewReader("the VM's files"))
	if err != nil || id != "sha256:feed" || f.imported.String() != "the VM's files" {
		t.Fatalf("id %q err %v imported %q", id, err, f.imported.String())
	}
	f.importErr = http.StatusInternalServerError
	if _, err := f.client().ImportRootfsImage(context.Background(), "aerolvm-snapshot/abc:latest", strings.NewReader("x")); err == nil {
		t.Fatal("a failed import returned no error")
	}
	f.importErr, f.images = 0, nil
	if _, err := f.client().ImportRootfsImage(context.Background(), "aerolvm-snapshot/abc:latest", strings.NewReader("x")); err == nil || !strings.Contains(err.Error(), "inspect imported image") {
		t.Fatalf("an import whose image is missing after: %v", err)
	}
}

func TestExportImageArchive(t *testing.T) {
	f := &fakeImageDaemon{images: map[string]string{"aerolvm-snapshot/abc:latest": "sha256:feed"}, saved: "docker-save-tar"}
	var buf bytes.Buffer
	ok, err := f.client().ExportImageArchive(context.Background(), "aerolvm-snapshot/abc:latest", &buf)
	if !ok || err != nil || buf.String() != "docker-save-tar" {
		t.Fatalf("ok %v err %v wrote %q", ok, err, buf.String())
	}
	if ok, err := f.client().ExportImageArchive(context.Background(), "aerolvm-snapshot/missing:latest", io.Discard); ok || err != nil {
		t.Fatalf("missing image: ok %v err %v, want false, nil", ok, err)
	}
	f.saveErr = http.StatusInternalServerError
	if _, err := f.client().ExportImageArchive(context.Background(), "aerolvm-snapshot/abc:latest", io.Discard); err == nil {
		t.Fatal("a failed save returned no error")
	}
	f.saveErr, f.readErr = 0, true
	if _, err := f.client().ExportImageArchive(context.Background(), "aerolvm-snapshot/abc:latest", io.Discard); err == nil || !strings.Contains(err.Error(), "export image") {
		t.Fatalf("a broken save stream: %v", err)
	}
}
