package volumes

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type recordedCmd struct {
	name string
	args []string
	env  []string
}

func recordingRunner(cmds *[]recordedCmd, fail map[string]error) Runner {
	return func(_ context.Context, env []string, name string, args ...string) error {
		*cmds = append(*cmds, recordedCmd{name: name, args: args, env: env})
		if fail != nil {
			if err, ok := fail[name]; ok {
				return err
			}
		}
		return nil
	}
}

func TestReclaimS3BuildsRecursiveDelete(t *testing.T) {
	var cmds []recordedCmd
	r := NewReclaimer(Backend{Kind: BackendS3, S3Region: "us-east-1", S3Endpoint: "https://s3.example.com"}, "", recordingRunner(&cmds, nil))

	if err := r.Reclaim(context.Background(), BackendS3, "bucket/prefix/t-a/data"); err != nil {
		t.Fatalf("Reclaim: %v", err)
	}
	if len(cmds) != 1 || cmds[0].name != "aws" {
		t.Fatalf("commands = %+v, want one aws call", cmds)
	}
	got := strings.Join(cmds[0].args, " ")
	for _, want := range []string{"s3 rm s3://bucket/prefix/t-a/data --recursive", "--endpoint-url https://s3.example.com", "--region us-east-1"} {
		if !strings.Contains(got, want) {
			t.Fatalf("args %q missing %q", got, want)
		}
	}
}

func TestReclaimS3PassesStaticCredentials(t *testing.T) {
	var cmds []recordedCmd
	r := NewReclaimer(Backend{Kind: BackendS3, S3AccessKeyID: "AKIA", S3SecretAccessKey: "shh"}, "", recordingRunner(&cmds, nil))
	if err := r.Reclaim(context.Background(), BackendS3, "bucket/data"); err != nil {
		t.Fatalf("Reclaim: %v", err)
	}
	env := strings.Join(cmds[0].env, " ")
	if !strings.Contains(env, "AWS_ACCESS_KEY_ID=AKIA") || !strings.Contains(env, "AWS_SECRET_ACCESS_KEY=shh") {
		t.Fatalf("static creds not passed to aws CLI: %v", cmds[0].env)
	}
}

func TestReclaimS3InstanceRoleSendsNoCredEnv(t *testing.T) {
	var cmds []recordedCmd
	r := NewReclaimer(Backend{Kind: BackendS3}, "", recordingRunner(&cmds, nil))
	if err := r.Reclaim(context.Background(), BackendS3, "bucket/data"); err != nil {
		t.Fatalf("Reclaim: %v", err)
	}
	if len(cmds[0].env) != 0 {
		t.Fatalf("expected no cred env for instance-role, got %v", cmds[0].env)
	}
}

func TestReclaimS3PropagatesError(t *testing.T) {
	var cmds []recordedCmd
	r := NewReclaimer(Backend{Kind: BackendS3}, "", recordingRunner(&cmds, map[string]error{"aws": errors.New("boom")}))
	if err := r.Reclaim(context.Background(), BackendS3, "bucket/data"); err == nil {
		t.Fatal("expected error")
	}
}

func TestReclaimNFSMountsEmptiesUnmounts(t *testing.T) {
	root := t.TempDir()
	var cmds []recordedCmd
	r := NewReclaimer(Backend{Kind: BackendNFS, NFSOptions: "vers=4"}, root, recordingRunner(&cmds, nil))

	if err := r.Reclaim(context.Background(), BackendNFS, "nfs.example.com:/export/t-a/data"); err != nil {
		t.Fatalf("Reclaim: %v", err)
	}
	if len(cmds) != 2 {
		t.Fatalf("commands = %+v, want mount + umount", cmds)
	}
	if cmds[0].name != "mount" || cmds[1].name != "umount" {
		t.Fatalf("commands order = %+v", cmds)
	}
	mountArgs := strings.Join(cmds[0].args, " ")
	if !strings.Contains(mountArgs, "-t nfs") || !strings.Contains(mountArgs, "-o vers=4") || !strings.Contains(mountArgs, "nfs.example.com:/export/t-a/data") {
		t.Fatalf("mount args unexpected: %q", mountArgs)
	}
	// The transient mountpoint must be cleaned up.
	entries, _ := os.ReadDir(root)
	if len(entries) != 0 {
		t.Fatalf("scratch dir not cleaned: %v", entries)
	}
}

func TestReclaimNFSEmptiesMountedTree(t *testing.T) {
	root := t.TempDir()
	var mountedAt string
	runner := func(_ context.Context, _ []string, name string, args ...string) error {
		switch name {
		case "mount":
			// Simulate the kernel mount by populating the mountpoint so we can
			// assert emptyDir wiped it before umount.
			mountedAt = args[len(args)-1]
			if err := os.WriteFile(filepath.Join(mountedAt, "old.txt"), []byte("x"), 0o644); err != nil {
				return err
			}
		case "umount":
			// Before umount, the tree must already be empty.
			entries, _ := os.ReadDir(mountedAt)
			if len(entries) != 0 {
				t.Fatalf("tree not emptied before umount: %v", entries)
			}
		}
		return nil
	}
	r := NewReclaimer(Backend{Kind: BackendNFS}, root, runner)
	if err := r.Reclaim(context.Background(), BackendNFS, "srv:/export/data"); err != nil {
		t.Fatalf("Reclaim: %v", err)
	}
}

func TestReclaimNFSNoMountRoot(t *testing.T) {
	r := NewReclaimer(Backend{Kind: BackendNFS}, "", recordingRunner(&[]recordedCmd{}, nil))
	if err := r.Reclaim(context.Background(), BackendNFS, "srv:/export/data"); err == nil {
		t.Fatal("expected error without mount root")
	}
}

func TestReclaimRejectsUnknownAndEmpty(t *testing.T) {
	r := NewReclaimer(Backend{}, "", recordingRunner(&[]recordedCmd{}, nil))
	if err := r.Reclaim(context.Background(), "gcs", "x"); err == nil {
		t.Fatal("expected unknown-backend error")
	}
	if err := r.Reclaim(context.Background(), BackendS3, "  "); err == nil {
		t.Fatal("expected empty-source error")
	}
}

// A failed unmount leaves the scratch folder as the export: the folder is
// removed only when empty, never walked, so nothing on the export goes.
// Before, a RemoveAll deleted what the export held there.
func TestReclaimNFSFailedUnmountWalksNothing(t *testing.T) {
	root := t.TempDir()
	var mountedAt string
	runner := func(_ context.Context, _ []string, name string, args ...string) error {
		if name == "mount" {
			mountedAt = args[len(args)-1]
			return nil
		}
		// What lands on the export after the emptying, while the unmount
		// fails: it must survive.
		if err := os.WriteFile(filepath.Join(mountedAt, "late.txt"), []byte("x"), 0o644); err != nil {
			return err
		}
		return errors.New("umount: target is busy")
	}
	r := NewReclaimer(Backend{Kind: BackendNFS}, root, runner)
	if err := r.Reclaim(context.Background(), BackendNFS, "h:/export/t-a/data"); err == nil || !strings.Contains(err.Error(), "umount") {
		t.Fatalf("Reclaim = %v", err)
	}
	if _, err := os.Stat(filepath.Join(mountedAt, "late.txt")); err != nil {
		t.Fatalf("the export's file went with the scratch folder: %v", err)
	}
}

// WithEmpty: the root helper's reclaimer empties with its own function.
func TestReclaimNFSWithEmpty(t *testing.T) {
	var emptied string
	r := NewReclaimer(Backend{Kind: BackendNFS}, t.TempDir(), recordingRunner(&[]recordedCmd{}, nil)).
		WithEmpty(func(dir string) error { emptied = dir; return nil })
	if err := r.Reclaim(context.Background(), BackendNFS, "h:/e/t/v"); err != nil || emptied == "" {
		t.Fatalf("Reclaim = %v, emptied %q", err, emptied)
	}
	bare := &Reclaimer{backend: Backend{Kind: BackendNFS}, mountRoot: t.TempDir(), run: recordingRunner(&[]recordedCmd{}, nil)}
	if err := bare.Reclaim(context.Background(), BackendNFS, "h:/e/t/v"); err != nil {
		t.Fatalf("a reclaimer with no emptier: %v", err)
	}
}
