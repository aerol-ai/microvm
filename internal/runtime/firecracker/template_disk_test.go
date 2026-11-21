package firecracker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// templateOnDisk writes a template's rootfs (and snapshot files) in a
// folder of its own and returns a resolver for it.
func templateOnDisk(t *testing.T, hasSnapshot bool) (*fakeTemplateResolver, string) {
	t.Helper()
	dir := t.TempDir()
	rootfs := filepath.Join(dir, "rootfs.ext4")
	for name, body := range map[string]string{"rootfs.ext4": "TEMPLATE-ROOTFS", "snapshot.memory": "MEM", "snapshot.state": "STATE"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return &fakeTemplateResolver{
		rootfsPath: rootfs, hasSnapshot: hasSnapshot, hasOverlay: true,
		snapshotMemoryPath: filepath.Join(dir, "snapshot.memory"), snapshotStatePath: filepath.Join(dir, "snapshot.state"),
		snapshotVsockCID: 200,
	}, rootfs
}

func sameFile(t *testing.T, a, b string) bool {
	t.Helper()
	ai, err := os.Stat(a)
	if err != nil {
		t.Fatal(err)
	}
	bi, err := os.Stat(b)
	if err != nil {
		t.Fatal(err)
	}
	return os.SameFile(ai, bi)
}

// A cold boot from a template attaches its root disk read-write, so it gets
// a copy of its own: a write in the guest must never reach the template
// every later sandbox starts from.
func TestTemplateColdBootGetsItsOwnRootfs(t *testing.T) {
	f := newDriverFixture(t)
	resolver, templateRootfs := templateOnDisk(t, false)
	f.driver.SetTemplateResolver(resolver)
	if _, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128, DiskGB: 1, TemplateID: "tpl-cold",
	}, "sb-cold", "tok", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	staged := filepath.Join(f.vmm.runDir, rootfsFileName)
	if sameFile(t, staged, templateRootfs) {
		t.Fatal("the cold boot's writable root disk is the template's own file")
	}
	if got, _ := os.ReadFile(staged); string(got) != "TEMPLATE-ROOTFS" {
		t.Fatalf("staged copy holds %q", got)
	}
	if err := os.WriteFile(staged, []byte("GUEST-WROTE-THIS"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(templateRootfs); string(got) != "TEMPLATE-ROOTFS" {
		t.Fatalf("a write to the sandbox's disk changed the template: %q", got)
	}
	if f.client.snapshotLoad != nil {
		t.Fatal("a template with no snapshot was loaded")
	}
}

// A snapshot load still shares the template's rootfs: the snapshot holds the
// drive read-only, so a link is safe and keeps clones fast.
func TestTemplateSnapshotLoadSharesTheRootfs(t *testing.T) {
	f := newDriverFixture(t)
	resolver, templateRootfs := templateOnDisk(t, true)
	f.driver.SetTemplateResolver(resolver)
	if _, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128, DiskGB: 1, TemplateID: "tpl-snap",
	}, "sb-snap", "tok", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !sameFile(t, filepath.Join(f.vmm.runDir, rootfsFileName), templateRootfs) {
		t.Fatal("a snapshot load copied the template's rootfs instead of linking it")
	}
}

// chownRecorder replaces chownStaged and records who each staged file was
// given to, by file name.
type chownRecorder struct {
	mu    sync.Mutex
	owner map[string][2]int
}

func recordChowns(t *testing.T) *chownRecorder {
	t.Helper()
	r := &chownRecorder{owner: map[string][2]int{}}
	orig := chownStaged
	chownStaged = func(path string, uid, gid int) error {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.owner[filepath.Base(path)] = [2]int{uid, gid}
		return nil
	}
	origRoot := stagerIsRoot
	stagerIsRoot = func() bool { return true }
	t.Cleanup(func() { chownStaged, stagerIsRoot = orig, origRoot })
	return r
}

func (r *chownRecorder) get(name string) ([2]int, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	o, ok := r.owner[name]
	return o, ok
}

// jailerFixture is newDriverFixture under the jailer, dropping to 990:990.
func jailerFixture(t *testing.T) *driverFixture {
	t.Helper()
	f := newDriverFixture(t)
	f.driver.cfg.UseJailer = true
	f.driver.cfg.JailerUID, f.driver.cfg.JailerGID = 990, 990
	return f
}

// Under the jailer, a file several VMs share and only read (kernel, template
// rootfs, snapshot memory and state) stays root's, with the jailer's group
// and mode 0640: no VM's firecracker can write it. A VM's own files (a
// cold boot's rootfs copy, its overlay) belong to the jailer, which opens
// them read-write.
func TestJailerStagingOwnership(t *testing.T) {
	jailer := [2]int{990, 990}
	shared := [2]int{0, 990}
	for _, tc := range []struct {
		name        string
		hasSnapshot bool
		want        map[string][2]int
	}{
		{"cold boot from a template", false, map[string][2]int{
			kernelFileName: shared, rootfsFileName: jailer, overlayFileName: jailer,
		}},
		{"snapshot load", true, map[string][2]int{
			rootfsFileName: shared, sandboxSnapshotMemoryFileName: shared, sandboxSnapshotStateFileName: shared, overlayFileName: jailer,
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			owners := recordChowns(t)
			f := jailerFixture(t)
			resolver, _ := templateOnDisk(t, tc.hasSnapshot)
			f.driver.SetTemplateResolver(resolver)
			if _, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
				Image: "alpine:3.20", CPU: 1, MemoryMB: 128, DiskGB: 1, OverlaySizeGB: 1, TemplateID: "tpl-own",
			}, "sb-own", "tok", nil); err != nil {
				t.Fatalf("Create: %v", err)
			}
			for name, want := range tc.want {
				got, ok := owners.get(name)
				if !ok || got != want {
					t.Errorf("%s given to %v (staged %v), want %v", name, got, ok, want)
				}
				if want == shared {
					info, err := os.Stat(filepath.Join(f.vmm.runDir, name))
					if err != nil {
						t.Fatal(err)
					}
					if info.Mode().Perm() != 0o640 {
						t.Errorf("%s mode %v, want 0640", name, info.Mode().Perm())
					}
				}
			}
		})
	}
}

func TestChrootSharedFile(t *testing.T) {
	src := filepath.Join(t.TempDir(), "vmlinux-host")
	if err := os.WriteFile(src, []byte("kernel"), 0o644); err != nil {
		t.Fatal(err)
	}

	direct := &Driver{cfg: Config{}}
	if got, err := direct.chrootSharedFile(t.TempDir(), src, kernelFileName); err != nil || got != src {
		t.Fatalf("direct mode = %q, %v; want the host path", got, err)
	}

	owners := recordChowns(t)
	noDrop := &Driver{cfg: Config{UseJailer: true}}
	runDir := t.TempDir()
	if got, err := noDrop.chrootSharedFile(runDir, src, kernelFileName); err != nil || got != kernelFileName {
		t.Fatalf("jailer without a uid = %q, %v", got, err)
	}
	if _, chowned := owners.get(kernelFileName); chowned {
		t.Fatal("a jailer with no privilege drop chowned the shared file")
	}
	if info, _ := os.Stat(filepath.Join(runDir, kernelFileName)); info.Mode().Perm() != 0o644 {
		t.Fatalf("a jailer with no privilege drop changed the mode to %v", info.Mode().Perm())
	}

	drop := &Driver{cfg: Config{UseJailer: true, JailerUID: 990, JailerGID: 991}}
	runDir = t.TempDir()
	if _, err := drop.chrootSharedFile(runDir, src, kernelFileName); err != nil {
		t.Fatal(err)
	}
	if got, _ := owners.get(kernelFileName); got != [2]int{0, 991} {
		t.Fatalf("shared file given to %v, want root and the jailer's group", got)
	}
	if !sameFile(t, filepath.Join(runDir, kernelFileName), src) {
		t.Fatal("a shared file was copied, not linked")
	}

	stagerIsRoot = func() bool { return false }
	runDir = t.TempDir()
	if _, err := drop.chrootSharedFile(runDir, src, kernelFileName); err != nil {
		t.Fatal(err)
	}
	if got, _ := owners.get(kernelFileName); got != [2]int{-1, 991} {
		t.Fatalf("a sandboxd that is not root gave the file to %v, want only the group changed (-1, 991)", got)
	}
	chownStaged = func(string, int, int) error { return errors.New("operation not permitted") }
	if _, err := drop.chrootSharedFile(t.TempDir(), src, kernelFileName); err == nil {
		t.Fatal("a failed chown returned no error")
	}
	if _, err := drop.chrootSharedFile(t.TempDir(), filepath.Join(t.TempDir(), "missing"), kernelFileName); err == nil {
		t.Fatal("a missing source returned no error")
	}
}

func TestCopyRootfsPrivate(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "rootfs.ext4")
	if err := os.WriteFile(src, []byte("data"), 0o640); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "copy.ext4")
	if err := copyRootfsPrivate(src, dst); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(dst); string(got) != "data" || sameFile(t, src, dst) {
		t.Fatalf("copy = %q (same inode %v)", got, sameFile(t, src, dst))
	}
	if info, _ := os.Stat(dst); info.Mode().Perm() != 0o600 {
		t.Fatalf("copy mode %v, want 0600", info.Mode().Perm())
	}
	for name, tc := range map[string][2]string{
		"missing source":      {filepath.Join(dir, "missing"), filepath.Join(dir, "a")},
		"source is a folder":  {dir, filepath.Join(dir, "b")},
		"destination missing": {src, filepath.Join(dir, "no", "such", "dir", "c")},
	} {
		if err := copyRootfsPrivate(tc[0], tc[1]); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}
