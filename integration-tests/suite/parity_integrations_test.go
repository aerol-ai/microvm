//go:build integration

package suite

// Live checks for the agent-framework integrations of
// plans/agent-sandbox-feature-parity.md (section 5.11: G1, G2, G4, G5).
// The packages under integrations/ are Python and their own tests run
// offline against a fake. These cases send the same server calls, in the
// same order, through the Go SDK, so a server change that would break one
// of the packages fails here.

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// UC-457 — OpenAI Agents provider (G1). The provider's default
// workspace_persistence="snapshot": start() makes the workspace root with
// make_dir(parents), commands run as argv in it, the end of a run saves an
// AerolVM snapshot, and resume() boots a new sandbox with the snapshot's
// name as its image. The new sandbox must hold the workspace exactly, and
// list it with the structured listing the provider's ls() uses.
func TestParityOpenAIAgentsSnapshotRoundTrip(t *testing.T) {
	harness.Require(t, sc, "UC-457")
	c := client(t)
	sb := paritySandbox(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if err := sb.MakeDir(ctx, "/workspace", sdktypes.MakeDirOptions{Parents: true}); err != nil {
		t.Fatalf("make workspace root: %v", err)
	}
	if err := sb.UploadFile(ctx, "/workspace/notes/a.txt", []byte("saved")); err != nil {
		t.Fatalf("upload: %v", err)
	}
	// A word with a space and a quote must reach the program unchanged.
	res, err := sb.Exec(ctx, sdktypes.ExecRequest{
		Argv:           []string{"sh", "-c", `printf %s "$1" > b.txt`, "sh", "it's a b"},
		WorkDir:        "/workspace",
		TimeoutSeconds: 30,
	})
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("argv exec in the workspace: err=%v exit=%d stderr=%q", err, res.ExitCode, res.Stderr)
	}

	name := fcSnapshotName(t, "uc457")
	if _, err := sb.CreateSnapshot(ctx, name); err != nil {
		t.Fatalf("create snapshot: %v", err)
	}
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), time.Minute)
		defer ccancel()
		if derr := c.SDK().DeleteSnapshot(cctx, name); derr != nil {
			t.Logf("cleanup: delete snapshot %s: %v", name, derr)
		}
	})

	// In a cluster the snapshot reaches the registry by a background push,
	// so a create from it that lands on another node can fail until the push
	// is done. Retry as UC-260 does; a single node succeeds at once.
	var restored *microvm.Sandbox
	for deadline := time.Now().Add(4 * time.Minute); ; time.Sleep(5 * time.Second) {
		var err error
		restored, err = c.SDK().Create(ctx, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t), Image: name})
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("create from snapshot %s never worked: %v", name, err)
		}
	}
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), time.Minute)
		defer ccancel()
		_ = c.SDK().Destroy(cctx, restored.ID)
	})
	waitRunning(t, restored)
	for path, want := range map[string]string{"/workspace/notes/a.txt": "saved", "/workspace/b.txt": "it's a b"} {
		got, err := restored.DownloadFile(ctx, path)
		if err != nil || string(got) != want {
			t.Fatalf("restored %s = %q, %v; want %q", path, got, err, want)
		}
	}
	list, err := restored.ListFiles(ctx, "/workspace", sdktypes.ListFilesOptions{Depth: 1})
	if err != nil {
		t.Fatalf("list restored workspace: %v", err)
	}
	kinds := map[string]bool{}
	for _, e := range list.Entries {
		kinds[e.Name] = e.IsDir
	}
	if isDir, ok := kinds["notes"]; !ok || !isDir {
		t.Fatalf("restored listing has no notes folder: %+v", list.Entries)
	}
	if isDir, ok := kinds["b.txt"]; !ok || isDir {
		t.Fatalf("restored listing has no b.txt file: %+v", list.Entries)
	}
	if !strings.HasPrefix(list.Entries[0].Path, "/workspace/") {
		t.Fatalf("listing paths are not absolute: %+v", list.Entries[0])
	}
}

// apiStatusMessage is the HTTP status and message of an SDK error, or 0 when err is
// not an API error.
func apiStatusMessage(err error) (int, string) {
	var apiErr *microvm.APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode, apiErr.Message
	}
	return 0, ""
}

// UC-458 — LangChain DeepAgents backend (G2). The backend turns server
// answers into DeepAgents' per-file error codes, so this pins exactly those
// answers: a missing file is 404 (file_not_found), a folder downloaded is
// "is a directory" (is_directory) and a file uploaded onto a folder is 409
// (is_directory). It also runs a shell command the way execute() does (in
// the root, with a timeout and an output cap) and the ls and delete calls.
func TestParityDeepAgentsBackendCalls(t *testing.T) {
	harness.Require(t, sc, "UC-458")
	sb := paritySandbox(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	if err := sb.MakeDir(ctx, "/workspace", sdktypes.MakeDirOptions{Parents: true}); err != nil {
		t.Fatalf("make root: %v", err)
	}
	res, err := sb.Exec(ctx, sdktypes.ExecRequest{
		Command:        "echo out; echo bad >&2; printf 0123456789; exit 3",
		WorkDir:        "/workspace",
		TimeoutSeconds: 30,
		MaxStdoutBytes: 6,
	})
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if res.ExitCode != 3 || res.Stdout != "out\n01" || !res.StdoutTruncated || strings.TrimSpace(res.Stderr) != "bad" {
		t.Fatalf("exec = exit %d stdout %q truncated %v stderr %q", res.ExitCode, res.Stdout, res.StdoutTruncated, res.Stderr)
	}
	res, err = sb.Exec(ctx, sdktypes.ExecRequest{Command: "sleep 30", WorkDir: "/workspace", TimeoutSeconds: 1})
	if err != nil || !res.TimedOut {
		t.Fatalf("timed-out exec = %+v, %v; want TimedOut", res, err)
	}

	// Upload makes the missing folders (the backend skips the write
	// preflight script because of it).
	if err := sb.UploadFile(ctx, "/workspace/deep/a/b.txt", []byte("x")); err != nil {
		t.Fatalf("upload into missing folders: %v", err)
	}
	if _, err := sb.DownloadFile(ctx, "/workspace/missing.txt"); func() bool {
		st, _ := apiStatusMessage(err)
		return st != http.StatusNotFound
	}() {
		t.Fatalf("download of a missing file: %v; want 404", err)
	}
	if _, err := sb.DownloadFile(ctx, "/workspace/deep"); func() bool {
		_, msg := apiStatusMessage(err)
		return !strings.HasSuffix(strings.ToLower(msg), "is a directory")
	}() {
		t.Fatalf("download of a folder: %v; want an error ending \"is a directory\"", err)
	}
	if err := sb.UploadFile(ctx, "/workspace/deep", []byte("x")); func() bool {
		st, msg := apiStatusMessage(err)
		return st != http.StatusConflict || !strings.HasSuffix(strings.ToLower(msg), "is a directory")
	}() {
		t.Fatalf("upload onto a folder: %v; want 409 ending \"is a directory\"", err)
	}

	list, err := sb.ListFiles(ctx, "/workspace", sdktypes.ListFilesOptions{Depth: 1})
	if err != nil || len(list.Entries) != 1 || list.Entries[0].Path != "/workspace/deep" || !list.Entries[0].IsDir {
		t.Fatalf("ls /workspace = %+v, %v", list.Entries, err)
	}
	if err := sb.DeleteFile(ctx, "/workspace/deep", sdktypes.DeleteFileOptions{Recursive: true}); err != nil {
		t.Fatalf("recursive delete: %v", err)
	}
	if err := sb.DeleteFile(ctx, "/workspace/deep", sdktypes.DeleteFileOptions{Recursive: true}); func() bool {
		st, _ := apiStatusMessage(err)
		return st != http.StatusNotFound
	}() {
		t.Fatalf("delete of a missing path: %v; want 404", err)
	}
}

// UC-459 — Gymnasium environment (G4). make_snapshot builds the start state
// once: a sandbox gets the task folder through upload_dir and runs a setup
// command, and is saved as a snapshot. Every episode then boots from it.
// The case runs two episodes: each sees the task and setup files, a check
// command's exit code reports whether the work is done (CommandReward), and
// the second episode does not see what the first one wrote.
func TestParityGymnasiumEpisodes(t *testing.T) {
	harness.Require(t, sc, "UC-459")
	c := client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	task := t.TempDir()
	if err := os.WriteFile(filepath.Join(task, "README.txt"), []byte("create done.txt"), 0o644); err != nil {
		t.Fatal(err)
	}
	build := paritySandbox(t)
	if err := build.MakeDir(ctx, "/workspace", sdktypes.MakeDirOptions{Parents: true}); err != nil {
		t.Fatalf("make work folder: %v", err)
	}
	if err := build.UploadDir(ctx, task, "/workspace"); err != nil {
		t.Fatalf("upload task folder: %v", err)
	}
	if res, err := build.Exec(ctx, sdktypes.ExecRequest{Command: "echo built > setup.txt", WorkDir: "/workspace", TimeoutSeconds: 60}); err != nil || res.ExitCode != 0 {
		t.Fatalf("setup command: %+v, %v", res, err)
	}
	start := fcSnapshotName(t, "uc459")
	if _, err := build.CreateSnapshot(ctx, start); err != nil {
		t.Fatalf("create start snapshot: %v", err)
	}
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), time.Minute)
		defer ccancel()
		if derr := c.SDK().DeleteSnapshot(cctx, start); derr != nil {
			t.Logf("cleanup: delete snapshot %s: %v", start, derr)
		}
	})
	if err := c.SDK().Destroy(ctx, build.ID); err != nil {
		t.Fatalf("destroy the build sandbox: %v", err)
	}

	run := func(sb *microvm.Sandbox, command string) sdktypes.ExecResult {
		t.Helper()
		res, err := sb.Exec(ctx, sdktypes.ExecRequest{Command: command, WorkDir: "/workspace", TimeoutSeconds: 60})
		if err != nil {
			t.Fatalf("exec %q in %s: %v", command, sb.ID, err)
		}
		return res
	}
	for episode := 1; episode <= 2; episode++ {
		sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t), Image: start})
		waitRunning(t, sb)
		if got := run(sb, "cat README.txt setup.txt").Stdout; got != "create done.txtbuilt\n" {
			t.Fatalf("episode %d start state = %q", episode, got)
		}
		// Nothing from an earlier episode, and the task is not done yet.
		if res := run(sb, "test -f done.txt"); res.ExitCode == 0 {
			t.Fatalf("episode %d starts with done.txt from an earlier episode", episode)
		}
		run(sb, "touch done.txt")
		if res := run(sb, "test -f done.txt"); res.ExitCode != 0 {
			t.Fatalf("episode %d: the check does not see the agent's work", episode)
		}
		if err := c.SDK().Destroy(ctx, sb.ID); err != nil {
			t.Fatalf("destroy episode %d: %v", episode, err)
		}
	}
}
