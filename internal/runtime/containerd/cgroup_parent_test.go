package containerd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/containerd/containerd/v2/core/containers"
	specs "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/aerol-ai/microvm/internal/pool/containerdpool"
	dockerpkg "github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

const testPodCgroup = "/kubepods.slice/kubepods-pod1.slice/cri-containerd-a.scope/sandboxes"

func TestCgroupSpecOpts(t *testing.T) {
	for _, tc := range []struct {
		name, parent, want string
		wantOpts           int
	}{
		{"no parent leaves containerd's default", "", "", 0},
		{"parent puts the sandbox under it", testPodCgroup, testPodCgroup + "/sb-1", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := &Driver{cfg: Config{CgroupParent: tc.parent}}
			opts := d.cgroupSpecOpts("sb-1")
			if len(opts) != tc.wantOpts {
				t.Fatalf("got %d spec options, want %d", len(opts), tc.wantOpts)
			}
			spec := &specs.Spec{Linux: &specs.Linux{}}
			for _, o := range opts {
				if err := o(context.Background(), nil, &containers.Container{}, spec); err != nil {
					t.Fatal(err)
				}
			}
			if spec.Linux.CgroupsPath != tc.want {
				t.Fatalf("CgroupsPath = %q, want %q", spec.Linux.CgroupsPath, tc.want)
			}
		})
	}
}

// Every way a sandbox's spec is built takes the parent: a create, and a
// parked warm container that is later adopted as a sandbox.
func TestCreateSpecUsesCgroupParent(t *testing.T) {
	for _, rt := range []string{models.RuntimeDocker, models.RuntimeGvisor} {
		t.Run(rt, func(t *testing.T) {
			stubToolboxProbe(t)
			hostIPv6(t, true)
			cap := &specCapture{}
			cap.install(t)
			d := newTestDriver(t)
			d.cfg.CgroupParent = testPodCgroup
			id := "sb-cg-" + rt
			if _, err := d.Create(context.Background(), models.CreateSandboxRequest{
				Image: "alpine:3.20", ContainerCommand: []string{"sleep", "inf"}, Runtime: rt,
			}, id, "tok", nil); err != nil {
				t.Fatal(err)
			}
			if got := cap.last(t).Linux.CgroupsPath; got != testPodCgroup+"/"+id {
				t.Fatalf("CgroupsPath = %q, want %q", got, testPodCgroup+"/"+id)
			}
		})
	}
}

func TestParkSpecUsesCgroupParent(t *testing.T) {
	stubToolboxProbe(t)
	hostIPv6(t, true)
	origWait := parkReadyWaitFn
	parkReadyWaitFn = func(context.Context, *dockerpkg.ParkedListener) error { return nil }
	t.Cleanup(func() { parkReadyWaitFn = origWait })
	cap := &specCapture{}
	cap.install(t)

	provider, img := newTestImageProvider(t)
	tr := newFakeTransport()
	tr.provider = provider
	tr.image = img
	tmp := t.TempDir()
	toolbox := filepath.Join(tmp, "toolboxd")
	if err := os.WriteFile(toolbox, []byte{0}, 0o755); err != nil {
		t.Fatal(err)
	}
	d := New(Config{
		ToolboxBinaryPath:  toolbox,
		ToolboxMountPath:   "/.aerol/toolboxd",
		ToolboxPort:        2280,
		ToolboxWaitTimeout: 2 * time.Second,
		LogDir:             filepath.Join(tmp, "logs"),
		RunDir:             filepath.Join(tmp, "run"),
		ReadyEnabled:       true,
		ReadyDir:           shortReadyDir(t),
		NativeNetnsPool:    true,
		CgroupParent:       testPodCgroup,
	}, nil, nil)
	d.SetClient(NewTestClient("aerolvm", tr))
	d.SetNetnsHandoff(&harnessNetns{path: "/run/netns/park-cg", ip: "10.88.0.80"})
	if _, err := d.parkContainer(context.Background(), "park-cg", containerdpool.Key{Image: "cfg:test", Runtime: models.RuntimeGvisor}); err != nil {
		t.Fatal(err)
	}
	if got := cap.last(t).Linux.CgroupsPath; got != testPodCgroup+"/park-cg" {
		t.Fatalf("CgroupsPath = %q, want %q", got, testPodCgroup+"/park-cg")
	}
}

func TestCheckCgroupParent(t *testing.T) {
	const parent = "/pod/sandboxes"
	for _, tc := range []struct {
		name    string
		setup   func(t *testing.T, root string)
		wantErr string
	}{
		{"not cgroup v2", func(t *testing.T, root string) {}, "not a cgroup v2 tree"},
		{"parent missing", func(t *testing.T, root string) { cgV2(t, root) }, "no such file"},
		{"parent is a file", func(t *testing.T, root string) {
			cgV2(t, root)
			cgWrite(t, filepath.Join(root, "pod", "sandboxes"), "")
		}, "not a directory"},
		{"no subtree_control", func(t *testing.T, root string) {
			cgV2(t, root)
			cgMkdir(t, filepath.Join(root, "pod", "sandboxes"))
		}, "cgroup.subtree_control"},
		{"pids not handed down", func(t *testing.T, root string) {
			cgV2(t, root)
			cgWrite(t, filepath.Join(root, "pod", "sandboxes", "cgroup.subtree_control"), "cpu memory\n")
		}, "does not hand pids down"},
		{"nothing handed down", func(t *testing.T, root string) {
			cgV2(t, root)
			cgWrite(t, filepath.Join(root, "pod", "sandboxes", "cgroup.subtree_control"), "\n")
		}, "cpu, memory, pids"},
		{"ready", func(t *testing.T, root string) {
			cgV2(t, root)
			cgWrite(t, filepath.Join(root, "pod", "sandboxes", "cgroup.subtree_control"), "cpuset cpu io memory pids\n")
		}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			tc.setup(t, root)
			err := CheckCgroupParent(root, parent)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("CheckCgroupParent: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

func cgV2(t *testing.T, root string) {
	t.Helper()
	cgWrite(t, filepath.Join(root, "cgroup.controllers"), "cpuset cpu io memory pids\n")
}

func cgMkdir(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
}

func cgWrite(t *testing.T, file, body string) {
	t.Helper()
	cgMkdir(t, filepath.Dir(file))
	if err := os.WriteFile(file, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
