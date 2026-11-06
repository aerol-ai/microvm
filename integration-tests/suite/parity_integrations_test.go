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
