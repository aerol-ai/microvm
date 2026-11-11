package containerd

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	cntr "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/errdefs"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/pool/containerdpool"
	"github.com/aerol-ai/microvm/pkg/createtiming"
	"github.com/aerol-ai/microvm/pkg/models"
)

const snapRoot = "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots"

func overlayMounts(n int) []mount.Mount {
	return []mount.Mount{{
		Type:   "overlay",
		Source: "overlay",
		Options: []string{
			"index=off",
			fmt.Sprintf("workdir=%s/%d/work", snapRoot, n),
			fmt.Sprintf("upperdir=%s/%d/fs", snapRoot, n),
			"lowerdir=" + snapRoot + "/3/fs:" + snapRoot + "/2/fs",
		},
	}}
}

func TestWritableLayerDir(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mounts  []mount.Mount
		wantDir string
		wantID  uint32
		wantErr string
	}{
		{name: "overlay upperdir", mounts: overlayMounts(42), wantDir: snapRoot + "/42/fs", wantID: 42},
		{name: "a snapshot with no layers below is a bind", mounts: []mount.Mount{{Type: "bind", Source: snapRoot + "/7/fs", Options: []string{"rw", "rbind"}}}, wantDir: snapRoot + "/7/fs", wantID: 7},
		{name: "the largest project ID", mounts: overlayMounts(4294967295), wantDir: snapRoot + "/4294967295/fs", wantID: 4294967295},
		{name: "no mounts", wantErr: "needs the overlayfs snapshotter"},
		{name: "a read-only view has no upper dir", mounts: []mount.Mount{{Type: "overlay", Options: []string{"lowerdir=" + snapRoot + "/2/fs"}}}, wantErr: "needs the overlayfs snapshotter"},
		{name: "another snapshotter's layout", mounts: []mount.Mount{{Type: "bind", Source: "/var/lib/containerd/io.containerd.snapshotter.v1.native/snapshots/5"}}, wantErr: "is not an overlayfs snapshot's directory"},
		{name: "project 0 means no project", mounts: overlayMounts(0), wantErr: "not a usable project ID"},
		{name: "past 32 bits", mounts: overlayMounts(4294967296), wantErr: "not a usable project ID"},
		{name: "not a number", mounts: []mount.Mount{{Type: "bind", Source: snapRoot + "/abc/fs"}}, wantErr: "not a usable project ID"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, id, err := writableLayerDir(tc.mounts)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || dir != tc.wantDir || id != tc.wantID {
				t.Fatalf("= %q %d %v, want %q %d", dir, id, err, tc.wantDir, tc.wantID)
			}
		})
	}
}

// fakeSnapshots names a snapshot number for each key.
type fakeSnapshots struct {
	numbers map[string]int
	err     error
}

func (f fakeSnapshots) Mounts(_ context.Context, key string) ([]mount.Mount, error) {
	if f.err != nil {
		return nil, f.err
	}
	n, ok := f.numbers[key]
	if !ok {
		return nil, fmt.Errorf("snapshot %s: not found", key)
	}
	return overlayMounts(n), nil
}

// fakeQuota records what the driver asked the filesystem for.
type fakeQuota struct {
	mu                               sync.Mutex
	enforcedCalls                    int
	enforcedErr, assignErr, limitErr error
	assigned                         map[string]uint32
	limits                           map[uint32]uint64
	onLimit                          func()
}

func (f *fakeQuota) Enforced(string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enforcedCalls++
	return f.enforcedErr
}

func (f *fakeQuota) Assign(dir string, id uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.assignErr != nil {
		return f.assignErr
	}
	if f.assigned == nil {
		f.assigned = map[string]uint32{}
	}
	f.assigned[dir] = id
	return nil
}

func (f *fakeQuota) Limit(_ string, id uint32, bytes uint64) error {
	if f.onLimit != nil {
		f.onLimit()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.limitErr != nil {
		return f.limitErr
	}
	if f.limits == nil {
		f.limits = map[uint32]uint64{}
	}
	f.limits[id] = bytes
	return nil
}

func withDiskQuotaFakes(t *testing.T, snaps snapshotMounter) *fakeQuota {
	t.Helper()
	q := &fakeQuota{}
	origOps, origSnaps := diskQuotaOps, snapshotMountsFn
	diskQuotaOps = q
	snapshotMountsFn = func(*Client) snapshotMounter { return snaps }
	t.Cleanup(func() { diskQuotaOps, snapshotMountsFn = origOps, origSnaps })
	return q
}

func TestLimitWritableLayer(t *testing.T) {
	client := NewTestClient("aerolvm", newFakeTransport())
	snaps := fakeSnapshots{numbers: map[string]int{"sb-1": 42, "sb-2": 43}}

	t.Run("off: nothing is asked", func(t *testing.T) {
		q := withDiskQuotaFakes(t, snaps)
		d := New(Config{}, nil, nil)
		if err := d.limitWritableLayer(context.Background(), client, "sb-1", 10); err != nil || q.enforcedCalls != 0 || len(q.limits) != 0 {
			t.Fatalf("err %v, calls %d, limits %v", err, q.enforcedCalls, q.limits)
		}
	})
	t.Run("no DiskGB: no limit", func(t *testing.T) {
		q := withDiskQuotaFakes(t, snaps)
		d := New(Config{DiskQuota: true}, nil, nil)
		if err := d.limitWritableLayer(context.Background(), client, "sb-1", 0); err != nil || len(q.limits) != 0 {
			t.Fatalf("err %v, limits %v", err, q.limits)
		}
	})
	t.Run("the layer gets its project and limit; the check runs once", func(t *testing.T) {
		q := withDiskQuotaFakes(t, snaps)
		d := New(Config{DiskQuota: true}, nil, nil)
		for _, key := range []string{"sb-1", "sb-2", "sb-1"} {
			if err := d.limitWritableLayer(context.Background(), client, key, 10); err != nil {
				t.Fatal(err)
			}
		}
		if q.enforcedCalls != 1 {
			t.Fatalf("filesystem checked %d times, want once", q.enforcedCalls)
		}
		// The snapshot's directory, so fs and work share the project.
		if q.assigned[snapRoot+"/42"] != 42 || q.assigned[snapRoot+"/43"] != 43 || len(q.assigned) != 2 {
			t.Fatalf("assigned %v", q.assigned)
		}
		if q.limits[42] != 10<<30 || q.limits[43] != 10<<30 {
			t.Fatalf("limits %v, want 10 GiB each", q.limits)
		}
	})
	t.Run("a failed check is not latched", func(t *testing.T) {
		q := withDiskQuotaFakes(t, snaps)
		q.enforcedErr = errors.New("project quotas are not enforced on this filesystem")
		d := New(Config{DiskQuota: true}, nil, nil)
		err := d.limitWritableLayer(context.Background(), client, "sb-1", 10)
		if err == nil || !strings.Contains(err.Error(), "SB_CONTAINERD_DISK_QUOTA is on") || len(q.limits) != 0 {
			t.Fatalf("err %v, limits %v", err, q.limits)
		}
		q.enforcedErr = nil
		if err := d.limitWritableLayer(context.Background(), client, "sb-1", 10); err != nil || q.enforcedCalls != 2 {
			t.Fatalf("after the mount was fixed: err %v, calls %d", err, q.enforcedCalls)
		}
	})
	t.Run("concurrent first creates share one check", func(t *testing.T) {
		q := withDiskQuotaFakes(t, snaps)
		d := New(Config{DiskQuota: true}, nil, nil)
		var wg sync.WaitGroup
		for range 20 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = d.limitWritableLayer(context.Background(), client, "sb-1", 5)
			}()
		}
		wg.Wait()
		if q.enforcedCalls != 1 {
			t.Fatalf("%d checks, want 1", q.enforcedCalls)
		}
	})
	for _, tc := range []struct {
		name  string
		snaps snapshotMounter
		setup func(*fakeQuota)
		want  string
	}{
		{name: "no snapshotter", snaps: nil, want: "containerd has no snapshotter"},
		{name: "snapshot lookup fails", snaps: fakeSnapshots{err: errors.New("boom")}, want: `snapshot "sb-1": boom`},
		{name: "assign fails", snaps: snaps, setup: func(q *fakeQuota) { q.assignErr = errors.New("EPERM") }, want: "project 42 on"},
		{name: "limit fails", snaps: snaps, setup: func(q *fakeQuota) { q.limitErr = errors.New("ESRCH") }, want: "10 GB on project 42"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := withDiskQuotaFakes(t, tc.snaps)
			if tc.setup != nil {
				tc.setup(q)
			}
			d := New(Config{DiskQuota: true}, nil, nil)
			if err := d.limitWritableLayer(context.Background(), client, "sb-1", 10); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

// quotaTestDriver is newTestDriver with the disk limit on, on tr.
func quotaTestDriver(t *testing.T, tr *fakeTransport) *Driver {
	t.Helper()
	d := newTestDriver(t)
	d.cfg.DiskQuota = true
	d.SetClient(NewTestClient("aerolvm", tr))
	return d
}

// A cold create puts the limit on the sandbox's snapshot before its task
// exists, records the step, and a failure removes the container.
func TestCreateLimitsTheWritableLayer(t *testing.T) {
	stubToolboxProbe(t)
	req := models.CreateSandboxRequest{Image: "alpine:3.20", ContainerCommand: []string{"sleep"}, DiskGB: 8, Runtime: models.RuntimeGvisor}

	t.Run("limited before the task", func(t *testing.T) {
		q := withDiskQuotaFakes(t, fakeSnapshots{numbers: map[string]int{"sb-q": 77}})
		tr := newFakeTransport()
		taskAtLimit := true
		q.onLimit = func() {
			tr.mu.Lock()
			defer tr.mu.Unlock()
			c := tr.containers["sb-q"]
			taskAtLimit = c == nil || c.task != nil
		}
		d := quotaTestDriver(t, tr)
		ctx, timing := createtiming.With(context.Background())
		if _, err := d.Create(ctx, req, "sb-q", "tok", nil); err != nil {
			t.Fatal(err)
		}
		if taskAtLimit || q.limits[77] != 8<<30 {
			t.Fatalf("limit set with a task already made (%v), limits %v", taskAtLimit, q.limits)
		}
		found := false
		for _, st := range timing.Stages() {
			found = found || st.Name == "containerd_disk_quota"
		}
		if !found {
			t.Fatal("no containerd_disk_quota stage")
		}
	})
	t.Run("a failure fails the create and removes the container", func(t *testing.T) {
		q := withDiskQuotaFakes(t, fakeSnapshots{numbers: map[string]int{"sb-q": 77}})
		q.enforcedErr = errors.New("project quotas are not enforced on this filesystem")
		tr := newFakeTransport()
		deleted := false
		tr.newContainerFn = func(_ context.Context, id string, _ ...cntr.NewContainerOpts) (cntr.Container, error) {
			c := &fakeContainer{id: id, onDelete: func() { deleted = true }}
			tr.mu.Lock()
			tr.containers[id] = c
			tr.mu.Unlock()
			return c, nil
		}
		d := quotaTestDriver(t, tr)
		if _, err := d.Create(context.Background(), req, "sb-q", "tok", nil); err == nil || !strings.Contains(err.Error(), "does not enforce project quotas") {
			t.Fatalf("Create = %v, want the quota error", err)
		}
		if !deleted {
			t.Fatal("the container was left behind")
		}
	})
}

// A resize changes the limit whether the sandbox runs or not.
func TestResizeChangesTheDiskLimit(t *testing.T) {
	q := withDiskQuotaFakes(t, fakeSnapshots{numbers: map[string]int{"sb-r-snap": 91}})
	tr := newFakeTransport()
	tr.containers["sb-r"] = &fakeContainer{id: "sb-r", taskErr: errdefs.ErrNotFound}
	d := quotaTestDriver(t, tr)
	if err := d.Resize(context.Background(), "sb-r", models.ResizeSandboxRequest{DiskGB: 20}); err != nil {
		t.Fatal(err)
	}
	if q.limits[91] != 20<<30 {
		t.Fatalf("limits %v, want 20 GiB on project 91", q.limits)
	}
	tr.containers["sb-r"].infoErr = errors.New("info boom")
	if err := d.Resize(context.Background(), "sb-r", models.ResizeSandboxRequest{DiskGB: 30}); err == nil || !strings.Contains(err.Error(), "resize disk") {
		t.Fatalf("Resize = %v, want the info error", err)
	}
	q.limitErr = errors.New("ESRCH")
	tr.containers["sb-r"].infoErr = nil
	if err := d.Resize(context.Background(), "sb-r", models.ResizeSandboxRequest{DiskGB: 30}); err == nil {
		t.Fatal("a failed limit was not reported")
	}
}

// adoptOrderHandle records whether the slot's layer was limited by the time
// the toolbox was handed the sandbox's identity.
type adoptOrderHandle struct {
	q             *fakeQuota
	id            uint32
	adopted       bool
	limitedBefore bool
}

func (h *adoptOrderHandle) Alive() bool { return true }
func (h *adoptOrderHandle) Adopt(context.Context, string, string, string) error {
	h.q.mu.Lock()
	h.limitedBefore = h.q.limits[h.id] != 0
	h.q.mu.Unlock()
	h.adopted = true
	return nil
}
func (h *adoptOrderHandle) Close() error { return nil }

// A warm slot's layer is limited to the request's DiskGB before the adopt;
// a failure stops the adopt, so tryWarmAdopt destroys the slot and the
// create goes cold.
func TestAdoptLimitsTheSlotsWritableLayer(t *testing.T) {
	for _, tc := range []struct {
		name    string
		fail    bool
		infoErr error
	}{
		{name: "limited, then adopted"},
		{name: "a failed limit stops the adopt", fail: true},
		{name: "an unreadable container stops the adopt", infoErr: errors.New("info boom")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := withDiskQuotaFakes(t, fakeSnapshots{numbers: map[string]int{"park-q-snap": 55}})
			if tc.fail {
				q.limitErr = errors.New("ESRCH")
			}
			tr := newFakeTransport()
			tr.containers["park-q"] = &fakeContainer{
				id: "park-q", labels: map[string]string{poolParkLabelKey: poolParkLabelValue}, infoErr: tc.infoErr,
			}
			d := quotaTestDriver(t, tr)
			h := &adoptOrderHandle{q: q, id: 55}
			_, err := d.adoptParked(context.Background(), models.CreateSandboxRequest{DiskGB: 3}, "sb-q", "tok", &containerdpool.ParkedSlot{
				ID: "park-q", ContainerID: "park-q", ContainerIP: "10.88.0.7", Handle: h,
			})
			if tc.fail || tc.infoErr != nil {
				if err == nil || h.adopted {
					t.Fatalf("err %v, adopted %v; want an error before the adopt", err, h.adopted)
				}
				return
			}
			if err != nil || !h.adopted || !h.limitedBefore || q.limits[55] != 3<<30 {
				t.Fatalf("err %v adopted %v limitedBefore %v limits %v", err, h.adopted, h.limitedBefore, q.limits)
			}
		})
	}
}

func TestFromDaemonConfigCarriesDiskQuota(t *testing.T) {
	if !FromDaemonConfig(config.Config{ContainerdDiskQuota: true}).DiskQuota {
		t.Fatal("SB_CONTAINERD_DISK_QUOTA did not reach the driver")
	}
	if FromDaemonConfig(config.Config{}).DiskQuota {
		t.Fatal("the disk limit is on by default")
	}
}

// A snapshotter whose layout is not overlay's fails the create rather than
// guessing a project ID.
type nativeSnapshots struct{}

func (nativeSnapshots) Mounts(context.Context, string) ([]mount.Mount, error) {
	return []mount.Mount{{Type: "bind", Source: "/var/lib/containerd/io.containerd.snapshotter.v1.native/snapshots/5"}}, nil
}

func TestLimitWritableLayerNeedsOverlay(t *testing.T) {
	q := withDiskQuotaFakes(t, nativeSnapshots{})
	d := New(Config{DiskQuota: true}, nil, nil)
	err := d.limitWritableLayer(context.Background(), NewTestClient("aerolvm", newFakeTransport()), "sb-1", 1)
	if err == nil || !strings.Contains(err.Error(), "overlayfs") || q.enforcedCalls != 0 {
		t.Fatalf("err %v, checks %d", err, q.enforcedCalls)
	}
}

func TestSnapshotMountsFnWithoutAConnection(t *testing.T) {
	if snapshotMountsFn(nil) != nil || snapshotMountsFn(NewTestClient("aerolvm", newFakeTransport())) != nil {
		t.Fatal("a snapshotter from no connection")
	}
}

// A create that waited on the lock while another passed the check finds
// the latch set and does not check again.
func TestEnsureDiskQuotaReadyAfterWaiting(t *testing.T) {
	q := withDiskQuotaFakes(t, nil)
	d := New(Config{DiskQuota: true}, nil, nil)
	d.diskQuotaMu.Lock()
	done := make(chan error)
	go func() { done <- d.ensureDiskQuotaReady("/x") }()
	time.Sleep(50 * time.Millisecond) // let it reach the lock
	d.diskQuotaReady.Store(true)
	d.diskQuotaMu.Unlock()
	if err := <-done; err != nil || q.enforcedCalls != 0 {
		t.Fatalf("err %v, checks %d; want the latch honoured", err, q.enforcedCalls)
	}
}
