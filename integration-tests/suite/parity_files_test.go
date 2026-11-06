//go:build integration

package suite

// Live checks for the file items of plans/agent-sandbox-feature-parity.md
// (section 5.1, F1-F4). The SDK calls go through the Go SDK and the v1
// toolbox pass-through, as a customer's would.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// UC-373 — the F1 file verbs through the SDK, live: list with a depth and a
// cap, info and exists, mkdir with and without parents, move with the
// overwrite guard (and across filesystems), recursive copy keeping modes and
// symlinks, recursive delete, search and find.
func TestParityFileVerbsLive(t *testing.T) {
	harness.Require(t, sc, "UC-373")
	sb := paritySandbox(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	root := "/tmp/uc373"
	if err := sb.MakeDir(ctx, root+"/a/b", sdktypes.MakeDirOptions{Parents: true}); err != nil {
		t.Fatalf("MakeDir with parents: %v", err)
	}
	if err := sb.MakeDir(ctx, root+"/a", sdktypes.MakeDirOptions{}); !errors.Is(err, microvm.ErrConflict) {
		t.Fatalf("MakeDir without parents on an existing folder = %v, want a 409", err)
	}
	for path, body := range map[string]string{root + "/a/one.txt": "one", root + "/a/b/two.txt": "two", root + "/top.txt": "top TODO"} {
		if err := sb.UploadFile(ctx, path, []byte(body)); err != nil {
			t.Fatalf("upload %s: %v", path, err)
		}
	}
	_ = parityExec(t, ctx, sb, "chmod 750 "+root+"/a/one.txt && ln -s one.txt "+root+"/a/link && echo ok")

	list, err := sb.ListFiles(ctx, root, sdktypes.ListFilesOptions{Depth: 3})
	if err != nil {
		t.Fatalf("ListFiles: %v", err)
	}
	var paths []string
	for _, e := range list.Entries {
		paths = append(paths, strings.TrimPrefix(e.Path, root))
	}
	if got := strings.Join(paths, ","); got != "/a,/a/b,/a/b/two.txt,/a/link,/a/one.txt,/top.txt" || list.Truncated {
		t.Fatalf("listing = %s (truncated %v)", got, list.Truncated)
	}
	capped, err := sb.ListFiles(ctx, root, sdktypes.ListFilesOptions{Depth: 3, Limit: 2})
	if err != nil || len(capped.Entries) != 2 || !capped.Truncated {
		t.Fatalf("capped listing = %+v, %v", capped, err)
	}

	info, err := sb.GetFileInfo(ctx, root+"/a/one.txt")
	if err != nil || info.Size != 3 || info.Permissions != "0750" || info.Path != root+"/a/one.txt" {
		t.Fatalf("GetFileInfo = %+v, %v", info, err)
	}
	if ok, err := sb.FileExists(ctx, root+"/nope"); err != nil || ok {
		t.Fatalf("FileExists(missing) = %v, %v", ok, err)
	}

	// The overwrite guard: refused, and both files untouched.
	if err := sb.MoveFile(ctx, root+"/top.txt", root+"/a/one.txt", sdktypes.MoveFileOptions{}); !errors.Is(err, microvm.ErrConflict) {
		t.Fatalf("MoveFile onto an existing file = %v, want a 409", err)
	}
	if got := parityExec(t, ctx, sb, "cat "+root+"/top.txt "+root+"/a/one.txt"); got != "top TODOone" {
		t.Fatalf("after a refused move: %q", got)
	}
	if err := sb.MoveFile(ctx, root+"/top.txt", root+"/moved.txt", sdktypes.MoveFileOptions{}); err != nil {
		t.Fatalf("MoveFile: %v", err)
	}
	// /dev/shm is its own filesystem (tmpfs), so this move takes the
	// copy-then-remove path (EXDEV).
	_ = parityExec(t, ctx, sb, "mkdir -p /dev/shm/uc373 && echo shm > /dev/shm/uc373/f && echo ok")
	if err := sb.MoveFile(ctx, "/dev/shm/uc373", root+"/from-shm", sdktypes.MoveFileOptions{}); err != nil {
		t.Fatalf("MoveFile across filesystems: %v", err)
	}
	if got := parityExec(t, ctx, sb, "cat "+root+"/from-shm/f; test -e /dev/shm/uc373 && echo left || echo gone"); got != "shm\ngone" {
		t.Fatalf("after a cross-filesystem move: %q", got)
	}

	if err := sb.CopyFile(ctx, root+"/a", root+"/a-copy", sdktypes.CopyFileOptions{}); !errors.Is(err, microvm.ErrConflict) {
		t.Fatalf("CopyFile of a folder without recursive = %v, want a 409", err)
	}
	if err := sb.CopyFile(ctx, root+"/a", root+"/a-copy", sdktypes.CopyFileOptions{Recursive: true}); err != nil {
		t.Fatalf("CopyFile recursive: %v", err)
	}
	if got := parityExec(t, ctx, sb, "stat -c %a "+root+"/a-copy/one.txt; readlink "+root+"/a-copy/link; cat "+root+"/a-copy/b/two.txt"); got != "750\none.txt\ntwo" {
		t.Fatalf("copied tree: %q", got)
	}

	if files, err := sb.SearchFiles(ctx, root, "two.txt"); err != nil || len(files) != 2 {
		t.Fatalf("SearchFiles = %v, %v", files, err)
	}
	if matches, err := sb.FindInFiles(ctx, root, "TODO"); err != nil || len(matches) != 1 || matches[0].File != root+"/moved.txt" {
		t.Fatalf("FindInFiles = %+v, %v", matches, err)
	}

	if err := sb.DeleteFile(ctx, root+"/a-copy", sdktypes.DeleteFileOptions{}); !errors.Is(err, microvm.ErrConflict) {
		t.Fatalf("DeleteFile of a folder without recursive = %v, want a 409", err)
	}
	if err := sb.DeleteFile(ctx, root+"/a-copy", sdktypes.DeleteFileOptions{Recursive: true}); err != nil {
		t.Fatalf("DeleteFile recursive: %v", err)
	}
	if ok, err := sb.FileExists(ctx, root+"/a-copy"); err != nil || ok {
		t.Fatalf("after a recursive delete: exists=%v err=%v", ok, err)
	}
}

// UC-374 — the shared file core still answers Daytona's SDK in Daytona's own
// shape: listFiles and getFileDetails carry exactly Daytona's fields (its Go
// client rejects any other), moveFiles still replaces the destination, and
// createFolder still accepts an existing folder.
func TestParityDaytonaFilesKeepTheirShape(t *testing.T) {
	harness.Require(t, sc, "UC-374")
	sb := paritySandbox(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	root := "/tmp/uc374"
	for _, path := range []string{root + "/src.txt", root + "/dst.txt"} {
		if err := sb.UploadFile(ctx, path, []byte(path)); err != nil {
			t.Fatalf("upload: %v", err)
		}
	}
	type daytonaFileInfo struct {
		Group       string `json:"group"`
		IsDir       bool   `json:"isDir"`
		ModTime     string `json:"modTime"`
		Mode        string `json:"mode"`
		Name        string `json:"name"`
		Owner       string `json:"owner"`
		Permissions string `json:"permissions"`
		Size        int32  `json:"size"`
	}
	strict := func(body []byte, out any) {
		t.Helper()
		dec := json.NewDecoder(strings.NewReader(string(body)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(out); err != nil {
			t.Fatalf("Daytona's Go client would reject %s: %v", body, err)
		}
	}
	st, body := daytonaToolbox(t, ctx, http.MethodGet, sb.ID, "/files", url.Values{"path": {root}}, nil)
	var entries []daytonaFileInfo
	if st != http.StatusOK {
		t.Fatalf("listFiles = %d %s", st, body)
	}
	strict(body, &entries)
	if len(entries) != 2 {
		t.Fatalf("listFiles entries = %+v", entries)
	}
	st, body = daytonaToolbox(t, ctx, http.MethodGet, sb.ID, "/files/info", url.Values{"path": {root + "/src.txt"}}, nil)
	var info daytonaFileInfo
	if st != http.StatusOK {
		t.Fatalf("getFileDetails = %d %s", st, body)
	}
	strict(body, &info)
	if info.Size != int32(len(root+"/src.txt")) {
		t.Fatalf("getFileDetails = %+v", info)
	}
	if st, body := daytonaToolbox(t, ctx, http.MethodPost, sb.ID, "/files/move", url.Values{"source": {root + "/src.txt"}, "destination": {root + "/dst.txt"}}, nil); st/100 != 2 {
		t.Fatalf("Daytona moveFiles onto an existing file = %d %s, want it replaced", st, body)
	}
	if got := parityExec(t, ctx, sb, "cat "+root+"/dst.txt"); got != root+"/src.txt" {
		t.Fatalf("after Daytona's move: %q", got)
	}
	if st, body := daytonaToolbox(t, ctx, http.MethodPost, sb.ID, "/files/folder", url.Values{"path": {root}, "mode": {"755"}}, nil); st/100 != 2 {
		t.Fatalf("Daytona createFolder on an existing folder = %d %s", st, body)
	}
}

// UC-379 — a WASM sandbox answers the F1 file verbs with a clear 501 (it
// serves only upload, download and a plain list), and the SDK refuses the
// verbs whose options it would ignore before sending them.
func TestParityWasmFileVerbs501(t *testing.T) {
	harness.Require(t, sc, "UC-379")
	ref := stagedWasmModuleRefOrDefault(t)
	sb := client(t).NewSandbox(t, sdktypes.CreateSandboxOptions{
		Name: harness.UniqueName(sc, t), Runtime: "wasm", Image: ref, ModuleRef: ref,
	})
	waitRunning(t, sb)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	for _, probe := range []struct {
		method, path string
		query        url.Values
	}{
		{http.MethodGet, "/files/info", url.Values{"path": {"/x"}}},
		{http.MethodPost, "/files/move", url.Values{"source": {"/a"}, "destination": {"/b"}}},
		{http.MethodPost, "/files/copy", url.Values{"source": {"/a"}, "destination": {"/b"}}},
		{http.MethodPost, "/files/folder", url.Values{"path": {"/d"}}},
		{http.MethodDelete, "/files", url.Values{"path": {"/x"}}},
		{http.MethodGet, "/files/search", url.Values{"path": {"/"}, "pattern": {"*"}}},
		{http.MethodGet, "/files/find", url.Values{"path": {"/"}, "pattern": {"x"}}},
		{http.MethodGet, "/files", url.Values{"path": {"/"}, "depth": {"2"}}},
	} {
		resp, err := sb.ToolboxRequest(ctx, probe.method, probe.path, probe.query, nil, "")
		var apiErr *microvm.APIError
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			t.Fatalf("%s %s on WASM = %d, want 501", probe.method, probe.path, resp.StatusCode)
		}
		if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusNotImplemented {
			t.Fatalf("%s %s on WASM = %v, want a 501", probe.method, probe.path, err)
		}
	}
	if _, err := sb.ListFiles(ctx, "/", sdktypes.ListFilesOptions{}); !errors.Is(err, microvm.ErrUnsupportedFeature) {
		t.Fatalf("SDK ListFiles on WASM = %v, want ErrUnsupportedFeature", err)
	}
	if err := sb.MoveFile(ctx, "/a", "/b", sdktypes.MoveFileOptions{}); !errors.Is(err, microvm.ErrUnsupportedFeature) {
		t.Fatalf("SDK MoveFile on WASM = %v, want ErrUnsupportedFeature", err)
	}
}
