//go:build integration

package suite

// Live checks for the file items of plans/agent-sandbox-feature-parity.md
// (section 5.1, F1-F4). The SDK calls go through the Go SDK and the v1
// toolbox pass-through, as a customer's would.

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	"github.com/aerol-ai/microvm/internal/safetar"
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

// UC-375 — upload write options live (F2): append, create_only refused with
// 412 and the file untouched, a mode, an atomic replace that leaves a hard
// link to the old file alone, a clash refused with 400, and two create_only
// uploads at once giving exactly one success and one 412.
func TestParityUploadWriteOptionsLive(t *testing.T) {
	harness.Require(t, sc, "UC-375")
	sb := paritySandbox(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	root := "/tmp/uc375"
	logPath := root + "/log.txt"
	if err := sb.UploadFile(ctx, logPath, []byte("a")); err != nil {
		t.Fatalf("upload: %v", err)
	}
	if err := sb.UploadFileWithOptions(ctx, logPath, []byte("b"), sdktypes.UploadFileOptions{Append: true}); err != nil {
		t.Fatalf("append: %v", err)
	}
	var apiErr *microvm.APIError
	err := sb.UploadFileWithOptions(ctx, logPath, []byte("x"), sdktypes.UploadFileOptions{CreateOnly: true})
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusPreconditionFailed || apiErr.Code != "file_exists" {
		t.Fatalf("create_only on an existing file = %v, want 412 file_exists", err)
	}
	if got := parityExec(t, ctx, sb, "cat "+logPath); got != "ab" {
		t.Fatalf("log after append and a refused create_only = %q, want ab", got)
	}
	if err := sb.UploadFileWithOptions(ctx, root+"/secret", []byte("s"), sdktypes.UploadFileOptions{Mode: 0o600}); err != nil {
		t.Fatalf("upload with a mode: %v", err)
	}
	if got := parityExec(t, ctx, sb, "stat -c %a "+root+"/secret"); got != "600" {
		t.Fatalf("mode = %s, want 600", got)
	}
	_ = parityExec(t, ctx, sb, "printf old > "+root+"/conf && chmod 640 "+root+"/conf && ln "+root+"/conf /tmp/uc375-outside-link && echo ok")
	if err := sb.UploadFileWithOptions(ctx, root+"/conf", []byte("new"), sdktypes.UploadFileOptions{Atomic: true}); err != nil {
		t.Fatalf("atomic upload: %v", err)
	}
	if got := parityExec(t, ctx, sb, "cat "+root+"/conf; echo; cat /tmp/uc375-outside-link; echo; stat -c %a "+root+"/conf"); got != "new\nold\n640" {
		t.Fatalf("after an atomic replace: %q, want the new file, the hard link's old content and the mode kept", got)
	}
	err = sb.UploadFileWithOptions(ctx, root+"/clash", []byte("x"), sdktypes.UploadFileOptions{Append: true, Atomic: true})
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusBadRequest || !strings.Contains(apiErr.Message, "append") || !strings.Contains(apiErr.Message, "atomic") {
		t.Fatalf("append with atomic = %v, want a 400 naming both", err)
	}

	for round, atomic := range []bool{false, true, false, true} {
		target := root + "/race-" + string(rune('a'+round))
		results := make(chan error, 2)
		start := make(chan struct{})
		for i := 0; i < 2; i++ {
			go func() {
				<-start
				results <- sb.UploadFileWithOptions(ctx, target, []byte(strings.Repeat("x", 1<<16)), sdktypes.UploadFileOptions{CreateOnly: true, Atomic: atomic})
			}()
		}
		close(start)
		created, refused := 0, 0
		for i := 0; i < 2; i++ {
			err := <-results
			switch {
			case err == nil:
				created++
			case errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusPreconditionFailed:
				refused++
			default:
				t.Fatalf("racing create_only (atomic=%v): %v", atomic, err)
			}
		}
		if created != 1 || refused != 1 {
			t.Fatalf("racing create_only (atomic=%v): %d created, %d refused; want exactly one of each", atomic, created, refused)
		}
	}
}

// UC-378 — a write that hits a full disk says "sandbox disk is full" with a
// 507, not a bare 500. /dev/full answers every write with ENOSPC, the error
// a full disk gives, without filling a real disk on the test host.
func TestParityDiskFullIs507(t *testing.T) {
	harness.Require(t, sc, "UC-378")
	sb := paritySandbox(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	err := sb.UploadFile(ctx, "/dev/full", []byte("data"))
	var apiErr *microvm.APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusInsufficientStorage || !strings.Contains(apiErr.Message, "sandbox disk is full") {
		t.Fatalf("upload to /dev/full = %v, want 507 sandbox disk is full", err)
	}
}

// UC-376 — folders as tar archives (F3, X4): UploadDir lands a local folder
// with its modes and symlink; a hostile archive sent with extract=true is
// refused with a 400 naming the entry and the count written, keeps the
// entry before it, and writes nothing outside the folder; and tar streamed
// out over exec unpacks here through internal/safetar, the code path
// `aerolvm cp -r` uses to copy a folder out.
func TestParityUploadDirLive(t *testing.T) {
	harness.Require(t, sc, "UC-376")
	sb := paritySandbox(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	local := t.TempDir()
	for name, body := range map[string]string{"a.txt": "alpha", "pkg/b.sh": "#!/bin/sh"} {
		path := filepath.Join(local, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(filepath.Join(local, "pkg", "b.sh"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("a.txt", filepath.Join(local, "link")); err != nil {
		t.Fatal(err)
	}
	remote := "/tmp/uc376/app"
	if err := sb.UploadDir(ctx, local, remote); err != nil {
		t.Fatalf("UploadDir: %v", err)
	}
	if got := parityExec(t, ctx, sb, "cat "+remote+"/a.txt; echo; readlink "+remote+"/link; stat -c %a "+remote+"/pkg/b.sh"); got != "alpha\na.txt\n750" {
		t.Fatalf("uploaded folder: %q", got)
	}

	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	for _, e := range []struct{ name, body string }{{"ok.txt", "kept"}, {"../../escape-uc376", "pwned"}} {
		_ = tw.WriteHeader(&tar.Header{Name: e.name, Mode: 0o644, Typeflag: tar.TypeReg, Size: int64(len(e.body))})
		_, _ = tw.Write([]byte(e.body))
	}
	_ = tw.Close()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	_ = mw.WriteField("path", "/tmp/uc376/hostile")
	part, _ := mw.CreateFormFile("file", "evil.tar")
	_, _ = part.Write(archive.Bytes())
	_ = mw.Close()
	resp, err := sb.ToolboxRequest(ctx, http.MethodPost, "/files/upload", url.Values{"extract": {"true"}}, body.Bytes(), mw.FormDataContentType())
	if err == nil {
		resp.Body.Close()
		t.Fatalf("a hostile archive was accepted: %d", resp.StatusCode)
	}
	var apiErr *microvm.APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusBadRequest ||
		!strings.Contains(apiErr.Message, "../../escape-uc376") || !strings.Contains(apiErr.Message, "1 entries written") {
		t.Fatalf("hostile archive = %v, want a 400 naming the entry and the count", err)
	}
	if got := parityExec(t, ctx, sb, "cat /tmp/uc376/hostile/ok.txt; echo; test -e /tmp/escape-uc376 && echo escaped || echo contained"); got != "kept\ncontained" {
		t.Fatalf("after the hostile archive: %q", got)
	}

	// Copy the folder back out over exec, unpacked here safely.
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	dest := t.TempDir()
	go func() {
		_, err := safetar.Extract(pr, dest, safetar.Limits{MaxEntries: 1000, MaxBytes: 1 << 20})
		_, _ = io.Copy(io.Discard, pr)
		done <- err
	}()
	handle, err := sb.ExecStream(ctx, sdktypes.ExecStreamOptions{
		Command:  "tar -C " + remote + " -cf - .",
		OnStdout: func(b []byte) { _, _ = pw.Write(b) },
	})
	if err != nil {
		t.Fatalf("exec stream: %v", err)
	}
	exit, err := handle.Wait()
	_ = pw.Close()
	if err != nil || exit.Code != 0 {
		t.Fatalf("tar over exec = %+v, %v", exit, err)
	}
	if err := <-done; err != nil {
		t.Fatalf("unpacking the folder: %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(dest, "pkg", "b.sh")); err != nil || string(data) != "#!/bin/sh" {
		t.Fatalf("copied out: %q, %v", data, err)
	}
	if target, err := os.Readlink(filepath.Join(dest, "link")); err != nil || target != "a.txt" {
		t.Fatalf("copied-out symlink = %q, %v", target, err)
	}
}

// UC-377 — downloads through the v1 toolbox pass-through answer Range (206,
// 416 past the end) and HEAD (no body), and the SDK's MaxBytes refuses a
// file larger than asked for (F4).
func TestParityDownloadRangeAndMaxBytes(t *testing.T) {
	harness.Require(t, sc, "UC-377")
	sb := paritySandbox(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	file := "/tmp/uc377/data.txt"
	if err := sb.UploadFile(ctx, file, []byte("0123456789")); err != nil {
		t.Fatalf("upload: %v", err)
	}
	path := "/v1/sandboxes/" + sb.ID + "/toolbox/files/download?path=" + url.QueryEscape(file)
	if st, body := fcDo(t, ctx, http.MethodGet, "", path, nil, map[string]string{"Range": "bytes=2-5"}); st != http.StatusPartialContent || string(body) != "2345" {
		t.Fatalf("Range bytes=2-5 = %d %q, want 206 \"2345\"", st, body)
	}
	if st, body := fcDo(t, ctx, http.MethodGet, "", path, nil, map[string]string{"Range": "bytes=-3"}); st != http.StatusPartialContent || string(body) != "789" {
		t.Fatalf("Range bytes=-3 = %d %q", st, body)
	}
	if st, _ := fcDo(t, ctx, http.MethodGet, "", path, nil, map[string]string{"Range": "bytes=100-200"}); st != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("Range past the end = %d, want 416", st)
	}
	if st, body := fcDo(t, ctx, http.MethodHead, "", path, nil, nil); st != http.StatusOK || len(body) != 0 {
		t.Fatalf("HEAD = %d with %d body bytes", st, len(body))
	}

	if _, err := sb.DownloadFileWithOptions(ctx, file, sdktypes.DownloadFileOptions{MaxBytes: 5}); !errors.Is(err, microvm.ErrFileTooLarge) {
		t.Fatalf("MaxBytes 5 on a 10-byte file = %v, want ErrFileTooLarge", err)
	}
	if data, err := sb.DownloadFileWithOptions(ctx, file, sdktypes.DownloadFileOptions{MaxBytes: 10}); err != nil || string(data) != "0123456789" {
		t.Fatalf("MaxBytes 10 = %q, %v", data, err)
	}
	// A file whose size reads as 0 but has content (/proc): it streams with
	// no length, and the cap still holds as it arrives.
	body, err := sb.DownloadFileStreamWithOptions(ctx, "/proc/self/status", sdktypes.DownloadFileOptions{MaxBytes: 16})
	if err != nil {
		t.Fatalf("open /proc/self/status: %v", err)
	}
	_, err = io.ReadAll(body)
	body.Close()
	if !errors.Is(err, microvm.ErrFileTooLarge) {
		t.Fatalf("reading /proc/self/status capped at 16 bytes = %v, want ErrFileTooLarge", err)
	}
}
