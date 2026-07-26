package volumes

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestExecRunner(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "cmd.sh")
	const body = `#!/bin/sh
set -eu
case "$1" in
ok) exit 0 ;;
fail) echo boom >&2; exit 1 ;;
fail-quiet) exit 2 ;;
*) echo "unknown" >&2; exit 3 ;;
esac
`
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatalf("WriteFile(script): %v", err)
	}

	ctx := context.Background()
	if err := ExecRunner(ctx, []string{"EXTRA=1"}, script, "ok"); err != nil {
		t.Fatalf("ExecRunner(ok): %v", err)
	}
	if err := ExecRunner(ctx, nil, script, "fail"); err == nil {
		t.Fatal("ExecRunner(fail): want error")
	} else if !strings.Contains(err.Error(), "boom") {
		t.Fatalf("ExecRunner(fail) = %v, want stderr in error", err)
	}
	if err := ExecRunner(ctx, nil, script, "fail-quiet"); err == nil {
		t.Fatal("ExecRunner(fail-quiet): want error")
	}
}

func TestBuildMountSpecForSource(t *testing.T) {
	s3 := Backend{Kind: BackendS3, S3Region: "us-west-2"}
	spec, err := BuildMountSpecForSource(s3, "bucket/key", "/data", true)
	if err != nil {
		t.Fatalf("S3: %v", err)
	}
	if spec.Type != models.MountTypeS3 || spec.Options["region"] != "us-west-2" {
		t.Fatalf("S3 spec = %+v", spec)
	}

	nfs := Backend{Kind: BackendNFS}
	spec, err = BuildMountSpecForSource(nfs, "host:/export/t/n", "/mnt", false)
	if err != nil {
		t.Fatalf("NFS: %v", err)
	}
	if spec.Type != models.MountTypeNFS || spec.Options != nil {
		t.Fatalf("NFS without opts = %+v", spec)
	}

	nfsOpts := Backend{Kind: BackendNFS, NFSOptions: "vers=4"}
	spec, err = BuildMountSpecForSource(nfsOpts, "host:/export/t/n", "/mnt", false)
	if err != nil {
		t.Fatalf("NFS opts: %v", err)
	}
	if spec.Options["opts"] != "vers=4" {
		t.Fatalf("opts = %v", spec.Options)
	}

	for _, tc := range []struct {
		name string
		b    Backend
		src  string
		tgt  string
	}{
		{"empty-source", Backend{Kind: BackendS3}, "", "/x"},
		{"empty-target", Backend{Kind: BackendS3}, "bucket/k", ""},
		{"unknown-backend", Backend{Kind: "ftp"}, "x", "/y"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := BuildMountSpecForSource(tc.b, tc.src, tc.tgt, false); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestEmptyDir(t *testing.T) {
	if err := emptyDir(filepath.Join(t.TempDir(), "missing")); err != nil {
		t.Fatalf("missing dir should be no-op: %v", err)
	}

	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := emptyDir(file); err == nil {
		t.Fatal("expected ReadDir error on file path")
	}

	dir := t.TempDir()
	locked := filepath.Join(dir, "locked")
	if err := os.Mkdir(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	if err := emptyDir(dir); err != nil {
		// Some platforms let the owner delete 000 entries; the not-a-dir case
		// above still exercises the ReadDir error path.
		t.Logf("emptyDir on 000 entry: %v", err)
	}
}

func TestReclaimNFSErrorPaths(t *testing.T) {
	root := t.TempDir()

	t.Run("mount-fails", func(t *testing.T) {
		r := NewReclaimer(Backend{Kind: BackendNFS}, root, func(context.Context, []string, string, ...string) error {
			return errors.New("mount boom")
		})
		if err := r.Reclaim(context.Background(), BackendNFS, "srv:/export/data"); err == nil {
			t.Fatal("expected mount error")
		}
	})

	t.Run("umount-fails", func(t *testing.T) {
		r := NewReclaimer(Backend{Kind: BackendNFS}, root, func(_ context.Context, _ []string, name string, _ ...string) error {
			if name == "umount" {
				return errors.New("umount boom")
			}
			return nil
		})
		if err := r.Reclaim(context.Background(), BackendNFS, "srv:/export/data"); err == nil {
			t.Fatal("expected umount error")
		}
	})
}
