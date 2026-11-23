package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/oci"
)

// fakeTemplateDisk is the driver's split-mode template disk build
// (fcruntime.Driver.SplitTemplateDisk): build runs at a stage path, then
// the disk moves to out.
type fakeTemplateDisk struct {
	stage string
	ids   []string
	err   error
}

func (f *fakeTemplateDisk) SplitTemplateDisk(_ context.Context, id, out string, build func(string) error) error {
	f.ids = append(f.ids, id)
	if f.err != nil {
		return f.err
	}
	p := filepath.Join(f.stage, "rootfs.ext4")
	if err := build(p); err != nil {
		return err
	}
	return os.Rename(p, out)
}

// TestTemplateBuilderAdapterSplit (M1 PR 14b): in privilege mode split a
// template's disk is built in the template's own jail and lands at the
// template's path; a failure in the jail is the build's.
func TestTemplateBuilderAdapterSplit(t *testing.T) {
	cfg, work := ociHappyConfig(t)
	builder, err := oci.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	disk := &fakeTemplateDisk{stage: t.TempDir()}
	a := &templateBuilderAdapter{inner: builder, split: disk}
	out := filepath.Join(work, "tpl-1", "rootfs.ext4")
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		t.Fatal(err)
	}
	res, err := a.Build(context.Background(), service.TemplateBuildRequest{ImageRef: "docker://alpine:3.20", OutPath: out})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if res.RootfsPath != out || !slices.Equal(disk.ids, []string{"tpl-1"}) {
		t.Fatalf("result %+v, jails %v", res, disk.ids)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("the disk is not at the template's path: %v", err)
	}
	disk.err = errors.New("helper away")
	if _, err := a.Build(context.Background(), service.TemplateBuildRequest{ImageRef: "docker://alpine:3.20", OutPath: out}); err == nil {
		t.Fatal("a build whose jail failed")
	}
}
