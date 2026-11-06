package microvm

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// Each Sandbox file method reaches its toolbox route; the request details
// and retry rules are tested in internal/apiclient.
func TestSandboxFileMethods(t *testing.T) {
	ctx := context.Background()
	seen := map[string]bool{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen[r.Method+" "+r.URL.Path] = true
		switch r.Method + " " + r.URL.Path {
		case "GET /v1/sandboxes/sb1":
			_ = json.NewEncoder(w).Encode(models.Sandbox{ID: "sb1"})
		case "GET /v1/sandboxes/sb1/toolbox/version":
			_ = json.NewEncoder(w).Encode(map[string]any{"version": "v", "features": []string{"files.verbs"}})
		case "GET /v1/sandboxes/sb1/toolbox/files":
			_ = json.NewEncoder(w).Encode([]map[string]any{{"name": "a", "path": "/w/a", "size_bytes": 3}})
		case "GET /v1/sandboxes/sb1/toolbox/files/info":
			if r.URL.Query().Get("path") == "/missing" {
				w.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(w).Encode(models.ErrorResponse{Error: "stat /missing: no such file or directory", Code: "file_not_found"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"name": "a", "path": "/w/a", "size_bytes": 3})
		case "GET /v1/sandboxes/sb1/toolbox/files/search":
			_ = json.NewEncoder(w).Encode(map[string]any{"files": []string{"/w/a"}})
		case "GET /v1/sandboxes/sb1/toolbox/files/find":
			_ = json.NewEncoder(w).Encode([]sdktypes.FileMatch{{File: "/w/a", Line: 1, Content: "x"}})
		case "POST /v1/sandboxes/sb1/toolbox/files/move":
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(models.ErrorResponse{Error: "rename: file exists"})
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()
	client, err := NewClientWithConfig(&sdktypes.MicroVMConfig{PATToken: "pat", APIUrl: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	sb, err := client.Get(ctx, "sb1")
	if err != nil {
		t.Fatal(err)
	}

	if list, err := sb.ListFiles(ctx, "/w", sdktypes.ListFilesOptions{}); err != nil || len(list.Entries) != 1 || list.Entries[0].Size != 3 {
		t.Fatalf("ListFiles = %+v, %v", list, err)
	}
	if info, err := sb.GetFileInfo(ctx, "/w/a"); err != nil || info.Path != "/w/a" {
		t.Fatalf("GetFileInfo = %+v, %v", info, err)
	}
	if ok, err := sb.FileExists(ctx, "/w/a"); err != nil || !ok {
		t.Fatalf("FileExists = %v, %v", ok, err)
	}
	if ok, err := sb.FileExists(ctx, "/missing"); err != nil || ok {
		t.Fatalf("FileExists(missing) = %v, %v", ok, err)
	}
	if err := sb.DeleteFile(ctx, "/w/a", sdktypes.DeleteFileOptions{Recursive: true}); err != nil {
		t.Fatalf("DeleteFile: %v", err)
	}
	if err := sb.MakeDir(ctx, "/w/d", sdktypes.MakeDirOptions{Parents: true, Mode: 0o700}); err != nil {
		t.Fatalf("MakeDir: %v", err)
	}
	if err := sb.MoveFile(ctx, "/w/a", "/w/b", sdktypes.MoveFileOptions{}); !errors.Is(err, ErrConflict) {
		t.Fatalf("MoveFile onto an existing file = %v, want ErrConflict", err)
	}
	if err := sb.CopyFile(ctx, "/w/a", "/w/c", sdktypes.CopyFileOptions{Recursive: true}); err != nil {
		t.Fatalf("CopyFile: %v", err)
	}
	if files, err := sb.SearchFiles(ctx, "/w", "*"); err != nil || len(files) != 1 {
		t.Fatalf("SearchFiles = %v, %v", files, err)
	}
	if matches, err := sb.FindInFiles(ctx, "/w", "x"); err != nil || len(matches) != 1 {
		t.Fatalf("FindInFiles = %v, %v", matches, err)
	}
	for _, route := range []string{
		"DELETE /v1/sandboxes/sb1/toolbox/files",
		"POST /v1/sandboxes/sb1/toolbox/files/folder",
		"POST /v1/sandboxes/sb1/toolbox/files/copy",
	} {
		if !seen[route] {
			t.Fatalf("%s was not called", route)
		}
	}
}
