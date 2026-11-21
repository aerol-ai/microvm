package containerd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	cntr "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/oci"
	specs "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/aerol-ai/microvm/internal/pool/containerdpool"
	dockerpkg "github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// recordingMarker is split mode's CgroupMarker (the root helper's cgroup
// part): it records each container it is asked to mark, and fails the
// call numbered failAt (1-based) when set.
type recordingMarker struct {
	mu     sync.Mutex
	ids    []string
	failAt int
}

func (m *recordingMarker) MarkSandboxCgroup(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ids = append(m.ids, id)
	if len(m.ids) == m.failAt {
		return errors.New("root helper: sandbox cgroup is gone")
	}
	return nil
}

func (m *recordingMarker) marked() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.ids)
}

// TestMarkOOMVictimInSplitMode (M1 PR 6): with a marker, the driver asks
// the helper for exactly the groups single mode marks, by container, and
// never writes a group's files itself; single mode is unchanged.
func TestMarkOOMVictimInSplitMode(t *testing.T) {
	ctx := context.Background()
	group := testPodCgroup + "/sb-1"
	for _, tc := range []struct {
		name, parent, group string
		want                []string
		err                 string
	}{
		{"a sandbox's group", testPodCgroup, group, []string{"sb-1"}, ""},
		{"a sandbox's group, unclean", testPodCgroup + "/", group + "/", []string{"sb-1"}, ""},
		{"no cgroup parent", "", group, nil, ""},
		{"no group", testPodCgroup, "", nil, ""},
		{"a group outside the parent (made before the setting)", testPodCgroup, "/aerolvm/sb-1", nil, ""},
		{"the parent itself", testPodCgroup, testPodCgroup, nil, ""},
		{"a group below a sandbox's", testPodCgroup, group + "/inner", nil, "directly under"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cg, proc := fakeOOMTree(t, map[string][]int{group: {101}}, []int{101})
			m := &recordingMarker{}
			d := &Driver{cfg: Config{CgroupParent: tc.parent}}
			d.SetCgroupMarker(m)
			err := d.MarkOOMVictim(ctx, tc.group)
			if (tc.err == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tc.err)) {
				t.Fatalf("err = %v, want %q", err, tc.err)
			}
			if !slices.Equal(m.marked(), tc.want) {
				t.Fatalf("asked the helper for %v, want %v", m.marked(), tc.want)
			}
			if readTrim(t, filepath.Join(cg, filepath.FromSlash(group), "memory.oom.group")) != "0" ||
				readTrim(t, filepath.Join(proc, "101", "oom_score_adj")) != "-999" {
				t.Fatal("split mode wrote a group's files itself")
			}
		})
	}
	t.Run("the helper's error is the mark's", func(t *testing.T) {
		d := &Driver{cfg: Config{CgroupParent: testPodCgroup}}
		d.SetCgroupMarker(&recordingMarker{failAt: 1})
		if err := d.MarkOOMVictim(ctx, group); err == nil || !strings.Contains(err.Error(), "is gone") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("single mode writes the files, as before", func(t *testing.T) {
		cg, proc := fakeOOMTree(t, map[string][]int{group: {101}}, []int{101})
		d := &Driver{cfg: Config{CgroupParent: testPodCgroup}}
		if err := d.MarkOOMVictim(ctx, group); err != nil {
			t.Fatal(err)
		}
		assertWholeOOMVictim(t, cg, proc, group, 101)
	})
}

// TestSplitMarksEveryStartThroughTheHelper: every path that starts a task
// (create, restart, warm-pool park) asks the helper to mark the sandbox's
// group twice, right after the start and once the sandbox answers, the
// two points single mode marks it; and a failed mark fails the start, the
// restart's task killed, as in single mode.
func TestSplitMarksEveryStartThroughTheHelper(t *testing.T) {
	create := func(t *testing.T, m *recordingMarker) error {
		stubToolboxProbe(t)
		hostIPv6(t, true)
		(&specCapture{}).install(t)
		d := newTestDriver(t)
		d.cfg.CgroupParent = testPodCgroup
		d.SetCgroupMarker(m)
		_, err := d.Create(context.Background(), models.CreateSandboxRequest{
			Image: "alpine:3.20", ContainerCommand: []string{"sleep", "inf"}, Runtime: models.RuntimeGvisor,
		}, "sb-new", "tok", nil)
		return err
	}
	var restarted *fakeTask
	restart := func(t *testing.T, m *recordingMarker) error {
		stubToolboxProbe(t)
		restarted = &fakeTask{status: cntr.Stopped}
		tr := newFakeTransport()
		tr.containers["sb-stopped"] = &fakeContainer{
			id: "sb-stopped", task: restarted,
			specOverride: &oci.Spec{Linux: &specs.Linux{CgroupsPath: testPodCgroup + "/sb-stopped"}},
		}
		d := newTestDriver(t)
		d.cfg.CgroupParent = testPodCgroup
		d.SetClient(NewTestClient("aerolvm", tr))
		d.SetCgroupMarker(m)
		_, err := d.Start(context.Background(), "sb-stopped")
		return err
	}
	park := func(t *testing.T, m *recordingMarker) error {
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
		d.SetNetnsHandoff(&harnessNetns{path: "/run/netns/park-1", ip: "10.88.0.81"})
		d.SetCgroupMarker(m)
		origWait := parkReadyWaitFn
		parkReadyWaitFn = func(context.Context, *dockerpkg.ParkedListener) error { return nil }
		t.Cleanup(func() { parkReadyWaitFn = origWait })
		_, err := d.parkContainer(context.Background(), "park-1", containerdpool.Key{Image: "cfg:test", Runtime: models.RuntimeGvisor})
		return err
	}
	for _, tc := range []struct {
		name string
		run  func(*testing.T, *recordingMarker) error
		id   string
	}{
		{"create", create, "sb-new"},
		{"restart", restart, "sb-stopped"},
		{"park", park, "park-1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// No group on disk: a mark written in process would fail.
			fakeOOMTree(t, map[string][]int{}, nil)
			m := &recordingMarker{}
			if err := tc.run(t, m); err != nil {
				t.Fatal(err)
			}
			if want := []string{tc.id, tc.id}; !slices.Equal(m.marked(), want) {
				t.Fatalf("asked the helper for %v, want %v", m.marked(), want)
			}
		})
		for _, failAt := range []int{1, 2} {
			t.Run(tc.name+": a failed mark fails it", func(t *testing.T) {
				fakeOOMTree(t, map[string][]int{}, nil)
				if err := tc.run(t, &recordingMarker{failAt: failAt}); err == nil || !strings.Contains(err.Error(), "is gone") {
					t.Fatalf("mark %d failed: err = %v", failAt, err)
				}
				if tc.name == "restart" && restarted.killed == 0 {
					t.Fatal("the restarted task was left running after the mark failed")
				}
			})
		}
	}
}
