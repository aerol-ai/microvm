package containerd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	cntr "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/containerd/v2/pkg/oci"
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
		wantAdj            *int
	}{
		{"no parent leaves containerd's default", "", "", 0, nil},
		{"parent puts the sandbox under it, first in line for the OOM killer", testPodCgroup, testPodCgroup + "/sb-1", 2, intPtr(sandboxOOMScoreAdj)},
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
			switch {
			case tc.wantAdj == nil && spec.Process != nil && spec.Process.OOMScoreAdj != nil:
				t.Fatalf("OOMScoreAdj = %d, want unset", *spec.Process.OOMScoreAdj)
			case tc.wantAdj != nil && (spec.Process == nil || spec.Process.OOMScoreAdj == nil || *spec.Process.OOMScoreAdj != *tc.wantAdj):
				t.Fatalf("OOMScoreAdj = %v, want %d", spec.Process, *tc.wantAdj)
			}
		})
	}
}

func intPtr(v int) *int { return &v }

// The score lands on an existing process section without touching the rest.
func TestWithOOMScoreAdjKeepsProcess(t *testing.T) {
	spec := &specs.Spec{Process: &specs.Process{Args: []string{"toolboxd"}}}
	if err := withOOMScoreAdj(500)(context.Background(), nil, &containers.Container{}, spec); err != nil {
		t.Fatal(err)
	}
	if spec.Process.OOMScoreAdj == nil || *spec.Process.OOMScoreAdj != 500 || len(spec.Process.Args) != 1 {
		t.Fatalf("process = %+v", spec.Process)
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
			cg, proc := fakeOOMTree(t, map[string][]int{testPodCgroup + "/" + id: {4100}}, []int{4100})
			if _, err := d.Create(context.Background(), models.CreateSandboxRequest{
				Image: "alpine:3.20", ContainerCommand: []string{"sleep", "inf"}, Runtime: rt,
			}, id, "tok", nil); err != nil {
				t.Fatal(err)
			}
			if got := cap.last(t).Linux.CgroupsPath; got != testPodCgroup+"/"+id {
				t.Fatalf("CgroupsPath = %q, want %q", got, testPodCgroup+"/"+id)
			}
			assertWholeOOMVictim(t, cg, proc, testPodCgroup+"/"+id, 4100)
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
	cg, proc := fakeOOMTree(t, map[string][]int{testPodCgroup + "/park-cg": {4300}}, []int{4300})
	if _, err := d.parkContainer(context.Background(), "park-cg", containerdpool.Key{Image: "cfg:test", Runtime: models.RuntimeGvisor}); err != nil {
		t.Fatal(err)
	}
	if got := cap.last(t).Linux.CgroupsPath; got != testPodCgroup+"/park-cg" {
		t.Fatalf("CgroupsPath = %q, want %q", got, testPodCgroup+"/park-cg")
	}
	// A parked slot is a sandbox in waiting: adoption keeps its group.
	assertWholeOOMVictim(t, cg, proc, testPodCgroup+"/park-cg", 4300)
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

// fakeOOMTree points CgroupRoot and ProcRoot at temporary trees: each group
// with memory.oom.group 0 and the listed PIDs in cgroup.procs, and each PID
// in pids with OOM score -999 (inherited from the shim, as in Phase 0 S3).
func fakeOOMTree(t *testing.T, groups map[string][]int, pids []int) (cgRoot, procRoot string) {
	t.Helper()
	cgRoot, procRoot = t.TempDir(), t.TempDir()
	for g, members := range groups {
		dir := filepath.Join(cgRoot, filepath.FromSlash(g))
		cgWrite(t, filepath.Join(dir, "memory.oom.group"), "0\n")
		var b strings.Builder
		for _, pid := range members {
			fmt.Fprintf(&b, "%d\n", pid)
		}
		cgWrite(t, filepath.Join(dir, "cgroup.procs"), b.String())
	}
	for _, pid := range pids {
		cgWrite(t, filepath.Join(procRoot, strconv.Itoa(pid), "oom_score_adj"), "-999\n")
	}
	oldCg, oldProc := CgroupRoot, ProcRoot
	CgroupRoot, ProcRoot = cgRoot, procRoot
	t.Cleanup(func() { CgroupRoot, ProcRoot = oldCg, oldProc })
	return cgRoot, procRoot
}

func readTrim(t *testing.T, file string) string {
	t.Helper()
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

func assertWholeOOMVictim(t *testing.T, cgRoot, procRoot, group string, pids ...int) {
	t.Helper()
	if got := readTrim(t, filepath.Join(cgRoot, filepath.FromSlash(group), "memory.oom.group")); got != "1" {
		t.Fatalf("%s memory.oom.group = %q, want 1", group, got)
	}
	for _, pid := range pids {
		if got := readTrim(t, filepath.Join(procRoot, strconv.Itoa(pid), "oom_score_adj")); got != "500" {
			t.Fatalf("pid %d oom_score_adj = %q, want 500", pid, got)
		}
	}
}

// Regression (Kubernetes Phase 0, finding F10): a sandbox the kernel kills
// in part frees nothing, and one with the shim's -999 score is never picked.
func TestMarkWholeOOMVictim(t *testing.T) {
	group := testPodCgroup + "/sb-1"
	t.Run("marks the group and every process in it and below", func(t *testing.T) {
		// 104 is listed but has exited: skipped, not an error.
		cg, proc := fakeOOMTree(t, map[string][]int{group: {101, 102, 104}, group + "/inner": {103}}, []int{101, 102, 103})
		d := &Driver{cfg: Config{CgroupParent: testPodCgroup}}
		if err := d.markWholeOOMVictim(group); err != nil {
			t.Fatal(err)
		}
		assertWholeOOMVictim(t, cg, proc, group, 101, 102, 103)
	})
	for _, tc := range []struct {
		name, parent, group string
	}{
		{"no cgroup parent", "", group},
		{"a group outside the parent", testPodCgroup, "/aerolvm/sb-1"},
		{"the parent itself", testPodCgroup, testPodCgroup},
		{"no group", testPodCgroup, ""},
	} {
		t.Run("leaves alone: "+tc.name, func(t *testing.T) {
			cg, proc := fakeOOMTree(t, map[string][]int{group: {101}, "/aerolvm/sb-1": {101}}, []int{101})
			d := &Driver{cfg: Config{CgroupParent: tc.parent}}
			if err := d.markWholeOOMVictim(tc.group); err != nil {
				t.Fatal(err)
			}
			for _, g := range []string{group, "/aerolvm/sb-1"} {
				if got := readTrim(t, filepath.Join(cg, filepath.FromSlash(g), "memory.oom.group")); got != "0" {
					t.Fatalf("%s memory.oom.group = %q, want it untouched", g, got)
				}
			}
			if got := readTrim(t, filepath.Join(proc, "101", "oom_score_adj")); got != "-999" {
				t.Fatalf("oom_score_adj = %q, want it untouched", got)
			}
		})
	}
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, cg, proc string)
		want  string
	}{
		{"the group is missing", func(t *testing.T, cg, _ string) {
			if err := os.RemoveAll(filepath.Join(cg, filepath.FromSlash(group))); err != nil {
				t.Fatal(err)
			}
		}, "set memory.oom.group"},
		{"cgroup.procs is unreadable", func(t *testing.T, cg, _ string) {
			if err := os.Remove(filepath.Join(cg, filepath.FromSlash(group), "cgroup.procs")); err != nil {
				t.Fatal(err)
			}
		}, "read cgroup.procs"},
		{"a score cannot be written", func(t *testing.T, _, proc string) {
			f := filepath.Join(proc, "101", "oom_score_adj")
			if err := os.Remove(f); err != nil {
				t.Fatal(err)
			}
			cgMkdir(t, f)
		}, "set OOM score of pid 101"},
	} {
		t.Run("fails when "+tc.name, func(t *testing.T) {
			cg, proc := fakeOOMTree(t, map[string][]int{group: {101}}, []int{101})
			tc.setup(t, cg, proc)
			err := (&Driver{cfg: Config{CgroupParent: testPodCgroup}}).markWholeOOMVictim(group)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want one containing %q", err, tc.want)
			}
		})
	}
}

// A restart makes the task's cgroup anew, so Start marks it again; a mark
// that fails stops the restart and leaves no task running.
func TestStartMarksRestartedSandbox(t *testing.T) {
	group := testPodCgroup + "/sb-stopped"
	newDriver := func(t *testing.T) (*Driver, *fakeTask) {
		stubToolboxProbe(t)
		task := &fakeTask{status: cntr.Stopped}
		tr := newFakeTransport()
		tr.containers["sb-stopped"] = &fakeContainer{
			id: "sb-stopped", task: task,
			specOverride: &oci.Spec{Linux: &specs.Linux{CgroupsPath: group}},
		}
		d := newTestDriver(t)
		d.cfg.CgroupParent = testPodCgroup
		d.SetClient(NewTestClient("aerolvm", tr))
		return d, task
	}
	t.Run("marked", func(t *testing.T) {
		cg, proc := fakeOOMTree(t, map[string][]int{group: {4200}}, []int{4200})
		d, _ := newDriver(t)
		if _, err := d.Start(context.Background(), "sb-stopped"); err != nil {
			t.Fatal(err)
		}
		assertWholeOOMVictim(t, cg, proc, group, 4200)
	})
	t.Run("a failed mark stops the restart", func(t *testing.T) {
		fakeOOMTree(t, map[string][]int{}, nil)
		d, task := newDriver(t)
		_, err := d.Start(context.Background(), "sb-stopped")
		if err == nil || !strings.Contains(err.Error(), "set memory.oom.group") {
			t.Fatalf("Start = %v, want the marking error", err)
		}
		if task.killed == 0 {
			t.Fatal("the restarted task was left running after the mark failed")
		}
	})
}

// gVisor starts some of its processes after task.Start returns (4 of 7,021
// gvisor_sentry processes were missed in a 1,000-sandbox live run), so the
// create marks the group again once the sandbox answers.
func TestCreateMarksProcessesStartedAfterTaskStart(t *testing.T) {
	stubToolboxProbe(t)
	hostIPv6(t, true)
	(&specCapture{}).install(t)
	d := newTestDriver(t)
	d.cfg.CgroupParent = testPodCgroup
	const id = "sb-late"
	group := testPodCgroup + "/" + id
	cg, proc := fakeOOMTree(t, map[string][]int{group: {4100}}, []int{4100})
	// The readiness wait is where the late process appears.
	pollToolboxHealthFn = func(context.Context, string, int) error {
		procs := filepath.Join(cg, filepath.FromSlash(group), "cgroup.procs")
		f, err := os.OpenFile(procs, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		defer f.Close()
		if _, err := f.WriteString("4199\n"); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(proc, "4199", "oom_score_adj"), []byte("-999\n"), 0o644)
	}
	cgMkdir(t, filepath.Join(proc, "4199"))
	if _, err := d.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", ContainerCommand: []string{"sleep", "inf"}, Runtime: models.RuntimeGvisor,
	}, id, "tok", nil); err != nil {
		t.Fatal(err)
	}
	assertWholeOOMVictim(t, cg, proc, group, 4100, 4199)
}

// A group that disappears between the two passes (the sandbox died while it
// came up) fails the start, on every path.
func TestSecondOOMMarkFailureFailsTheStart(t *testing.T) {
	removeGroup := func(t *testing.T, cg, group string) {
		t.Helper()
		if err := os.RemoveAll(filepath.Join(cg, filepath.FromSlash(group))); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("create", func(t *testing.T) {
		stubToolboxProbe(t)
		hostIPv6(t, true)
		(&specCapture{}).install(t)
		d := newTestDriver(t)
		d.cfg.CgroupParent = testPodCgroup
		group := testPodCgroup + "/sb-gone"
		cg, _ := fakeOOMTree(t, map[string][]int{group: {4100}}, []int{4100})
		pollToolboxHealthFn = func(context.Context, string, int) error { removeGroup(t, cg, group); return nil }
		_, err := d.Create(context.Background(), models.CreateSandboxRequest{
			Image: "alpine:3.20", ContainerCommand: []string{"sleep", "inf"}, Runtime: models.RuntimeGvisor,
		}, "sb-gone", "tok", nil)
		if err == nil || !strings.Contains(err.Error(), "set memory.oom.group") {
			t.Fatalf("Create = %v, want the second marking error", err)
		}
	})
	t.Run("restart", func(t *testing.T) {
		stubToolboxProbe(t)
		group := testPodCgroup + "/sb-stopped"
		cg, _ := fakeOOMTree(t, map[string][]int{group: {4200}}, []int{4200})
		task := &fakeTask{status: cntr.Stopped}
		tr := newFakeTransport()
		tr.containers["sb-stopped"] = &fakeContainer{
			id: "sb-stopped", task: task,
			specOverride: &oci.Spec{Linux: &specs.Linux{CgroupsPath: group}},
		}
		d := newTestDriver(t)
		d.cfg.CgroupParent = testPodCgroup
		d.SetClient(NewTestClient("aerolvm", tr))
		// The address read-back runs between the two passes.
		containerIPv4FromTaskFn = func(context.Context, cntr.Task) (string, error) {
			removeGroup(t, cg, group)
			return "10.88.0.9", nil
		}
		_, err := d.Start(context.Background(), "sb-stopped")
		if err == nil || !strings.Contains(err.Error(), "set memory.oom.group") {
			t.Fatalf("Start = %v, want the second marking error", err)
		}
		if task.killed == 0 {
			t.Fatal("the restarted task was left running after the second mark failed")
		}
	})
	t.Run("park", func(t *testing.T) {
		stubToolboxProbe(t)
		hostIPv6(t, true)
		(&specCapture{}).install(t)
		provider, img := newTestImageProvider(t)
		tr := newFakeTransport()
		tr.provider, tr.image = provider, img
		tmp := t.TempDir()
		toolbox := filepath.Join(tmp, "toolboxd")
		if err := os.WriteFile(toolbox, []byte{0}, 0o755); err != nil {
			t.Fatal(err)
		}
		d := New(Config{
			ToolboxBinaryPath: toolbox, ToolboxMountPath: "/.aerol/toolboxd", ToolboxPort: 2280,
			ToolboxWaitTimeout: 2 * time.Second, LogDir: filepath.Join(tmp, "logs"), RunDir: filepath.Join(tmp, "run"),
			ReadyEnabled: true, ReadyDir: shortReadyDir(t), NativeNetnsPool: true, CgroupParent: testPodCgroup,
		}, nil, nil)
		d.SetClient(NewTestClient("aerolvm", tr))
		d.SetNetnsHandoff(&harnessNetns{path: "/run/netns/park-gone", ip: "10.88.0.81"})
		group := testPodCgroup + "/park-gone"
		cg, _ := fakeOOMTree(t, map[string][]int{group: {4300}}, []int{4300})
		origWait := parkReadyWaitFn
		parkReadyWaitFn = func(context.Context, *dockerpkg.ParkedListener) error { removeGroup(t, cg, group); return nil }
		t.Cleanup(func() { parkReadyWaitFn = origWait })
		_, err := d.parkContainer(context.Background(), "park-gone", containerdpool.Key{Image: "cfg:test", Runtime: models.RuntimeGvisor})
		if err == nil || !strings.Contains(err.Error(), "set memory.oom.group") {
			t.Fatalf("park = %v, want the second marking error", err)
		}
	})
}
