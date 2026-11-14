package apiclient

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
)

// readTarUpload returns the path field and the archive's entries
// (name -> content, or "->target" for a symlink, "dir" for a folder).
func readTarUpload(t *testing.T, r *http.Request) (string, map[string]string) {
	t.Helper()
	_, params, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	reader := multipart.NewReader(r.Body, params["boundary"])
	path := ""
	entries := map[string]string{}
	for {
		part, err := reader.NextPart()
		if err != nil {
			break
		}
		if part.FormName() == "path" {
			data, _ := io.ReadAll(part)
			path = string(data)
			continue
		}
		gz, err := gzip.NewReader(part)
		if err != nil {
			t.Fatalf("archive is not gzip: %v", err)
		}
		tr := tar.NewReader(gz)
		for {
			hdr, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("bad tar: %v", err)
			}
			switch hdr.Typeflag {
			case tar.TypeDir:
				entries[hdr.Name] = "dir"
			case tar.TypeSymlink:
				entries[hdr.Name] = "->" + hdr.Linkname
			case tar.TypeReg:
				data, _ := io.ReadAll(tr)
				entries[hdr.Name] = string(data)
				if hdr.Name == "bin/run.sh" && hdr.Mode&0o777 != 0o750 {
					t.Errorf("mode = %o", hdr.Mode)
				}
			default:
				t.Errorf("unexpected entry %q type %q", hdr.Name, hdr.Typeflag)
			}
		}
	}
	return path, entries
}

func TestUploadDirSendsTheFolderAsATarOnce(t *testing.T) {
	ctx := context.Background()
	local := t.TempDir()
	for name, body := range map[string]string{"a.txt": "one", "bin/run.sh": "#!/bin/sh", "deep/x/y.txt": "deep"} {
		path := filepath.Join(local, name)
		_ = os.MkdirAll(filepath.Dir(path), 0o755)
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.Chmod(filepath.Join(local, "bin", "run.sh"), 0o750)
	_ = os.Symlink("a.txt", filepath.Join(local, "link"))
	_ = os.Link(filepath.Join(local, "a.txt"), filepath.Join(local, "hard.txt"))
	if err := syscall.Mkfifo(filepath.Join(local, "pipe"), 0o644); err != nil {
		t.Logf("no fifo: %v", err)
	}

	var gotPath string
	var got map[string]string
	fake := &fakeToolbox{features: []string{FeatureExtract}}
	fake.reply = func(r *http.Request, n int) (int, any, http.Header) {
		gotPath, got = readTarUpload(t, r)
		return http.StatusServiceUnavailable, nil, nil
	}
	client, _ := fake.serve(t)
	err := client.UploadDir(ctx, "sb-1", local, "/work/app")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("UploadDir = %v, want the 503 (a streamed body is not re-sent)", err)
	}
	calls := fake.recorded()
	if len(calls) != 1 || calls[0].URL.Query().Get("extract") != "true" || gotPath != "/work/app" {
		t.Fatalf("calls = %d, query %v, path %q", len(calls), calls[0].URL.Query(), gotPath)
	}
	names := make([]string, 0, len(got))
	for name := range got {
		names = append(names, name)
	}
	sort.Strings(names)
	want := "a.txt,bin/,bin/run.sh,deep/,deep/x/,deep/x/y.txt,hard.txt,link"
	if strings.Join(names, ",") != want {
		t.Fatalf("entries = %v, want %s", names, want)
	}
	if got["hard.txt"] != "one" || got["link"] != "->a.txt" || got["deep/x/y.txt"] != "deep" {
		t.Fatalf("entries = %v", got)
	}
}

func TestUploadDirRefusals(t *testing.T) {
	ctx := context.Background()
	fake := &fakeToolbox{features: []string{}}
	client, _ := fake.serve(t)
	if err := client.UploadDir(ctx, "sb-1", t.TempDir(), "/w"); !errors.Is(err, ErrUnsupportedFeature) {
		t.Fatalf("older agent = %v", err)
	}
	file := filepath.Join(t.TempDir(), "f")
	_ = os.WriteFile(file, nil, 0o644)
	if err := client.UploadDir(ctx, "sb-1", file, "/w"); err == nil || !strings.Contains(err.Error(), "not a folder") {
		t.Fatalf("a file = %v", err)
	}
	if err := client.UploadDir(ctx, "sb-1", filepath.Join(t.TempDir(), "missing"), "/w"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing folder = %v", err)
	}
	if len(fake.recorded()) != 0 {
		t.Fatal("a refused UploadDir sent an upload")
	}
	if err := WriteDirTar(io.Discard, filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("WriteDirTar of a missing folder succeeded")
	}
}
