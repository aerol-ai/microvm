package rootpolicy

import (
	"encoding/json"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

const layers = testSnapRoot + "/snapshots"

// overlayRootfs is what the overlayfs snapshotter returns for an active
// snapshot with two layers below it.
func overlayRootfs() []Mount {
	return []Mount{{Type: "overlay", Source: "overlay", Options: []string{
		"index=off",
		"workdir=" + layers + "/9/work",
		"upperdir=" + layers + "/9/fs",
		"lowerdir=" + layers + "/2/fs:" + layers + "/1/fs",
		"userxattr",
	}}}
}

func baselineTask() TaskCreate {
	return TaskCreate{
		ContainerID: testID,
		Rootfs:      overlayRootfs(),
		Stdout:      testFIFO + "/1234/" + testID + "-stdout",
		Stderr:      testFIFO + "/1234/" + testID + "-stderr",
	}
}

func TestCheckTaskCreate(t *testing.T) {
	if err := CheckTaskCreate(testPolicy(), baselineTask()); err != nil {
		t.Fatalf("baseline task refused: %v", err)
	}
	single := baselineTask()
	single.Rootfs = []Mount{{Type: "bind", Source: layers + "/1/fs", Options: []string{"rw", "rbind"}}}
	if err := CheckTaskCreate(testPolicy(), single); err != nil {
		t.Fatalf("a one-layer rootfs refused: %v", err)
	}
	view := baselineTask() // a read-only view of two layers: lowerdir only
	view.Rootfs = []Mount{{Type: "overlay", Source: "overlay", Options: []string{"lowerdir=" + layers + "/2/fs:" + layers + "/1/fs", "index=off"}}}
	if err := CheckTaskCreate(testPolicy(), view); err != nil {
		t.Fatalf("a two-layer view refused: %v", err)
	}

	rootfs := func(m Mount) func(*TaskCreate) { return func(tc *TaskCreate) { tc.Rootfs = []Mount{m} } }
	overlay := func(opts ...string) func(*TaskCreate) {
		return rootfs(Mount{Type: "overlay", Source: "overlay", Options: opts})
	}
	upper, work, lower := "upperdir="+layers+"/9/fs", "workdir="+layers+"/9/work", "lowerdir="+layers+"/1/fs"
	for _, tc := range []struct {
		name   string
		mutate func(*TaskCreate)
		rule   Rule
	}{
		{"bad container ID", func(tc *TaskCreate) { tc.ContainerID = "a/b" }, RuleID},
		{"rootfs bind of /", rootfs(Mount{Type: "bind", Source: "/", Options: []string{"rbind"}}), RuleSnapshotMount},
		{"rootfs bind outside the snapshotter", rootfs(Mount{Type: "bind", Source: "/var/lib/containerd/io.containerd.snapshotter.v1.native/snapshots/1"}), RuleSnapshotMount},
		{"rootfs bind of the snapshotter's own database", rootfs(Mount{Type: "bind", Source: testSnapRoot + "/metadata.db"}), RuleSnapshotMount},
		{"rootfs bind climbing out", rootfs(Mount{Type: "bind", Source: layers + "/../../../../etc"}), RuleSnapshotMount},
		{"rootfs bind option", rootfs(Mount{Type: "bind", Source: layers + "/1/fs", Options: []string{"rshared"}}), RuleSnapshotMount},
		{"overlay lowerdir /", rootfs(Mount{Type: "overlay", Source: "overlay", Options: []string{"lowerdir=/"}}), RuleSnapshotMount},
		{"overlay lowerdir with one host dir", rootfs(Mount{Type: "overlay", Source: "overlay", Options: []string{"lowerdir=" + layers + "/1/fs:/etc"}}), RuleSnapshotMount},
		{"overlay upperdir outside", rootfs(Mount{Type: "overlay", Source: "overlay", Options: []string{"upperdir=/etc", "lowerdir=" + layers + "/1/fs"}}), RuleSnapshotMount},
		{"overlay workdir outside", rootfs(Mount{Type: "overlay", Source: "overlay", Options: []string{"workdir=/tmp"}}), RuleSnapshotMount},
		{"overlay uid remap", rootfs(Mount{Type: "overlay", Source: "overlay", Options: []string{"uidmap=0:0:1"}}), RuleSnapshotMount},
		// Reviewer C1: containerd joins options with commas into the
		// kernel's mount data, so a comma in a value is more options.
		{"comma smuggles upperdir=/etc into lowerdir", overlay("index=off", lower+",upperdir=/etc,workdir=/var/tmp"), RuleSnapshotMount},
		{"comma smuggles into upperdir", overlay(upper+",lowerdir=/", work, lower), RuleSnapshotMount},
		{"comma smuggles into workdir", overlay(upper, work+",upperdir=/etc", lower), RuleSnapshotMount},
		{"comma in a lowerdir list entry", overlay("lowerdir=" + layers + "/2/fs:" + layers + "/1/fs,upperdir=/etc"), RuleSnapshotMount},
		// Reviewer C1b: a path below a layer's folder can be a symlink the
		// sandbox left in its own writable layer.
		{"bind of a path inside a layer", rootfs(Mount{Type: "bind", Source: layers + "/5/fs/h", Options: []string{"rbind", "rw"}}), RuleSnapshotMount},
		{"bind of a layer's parent folder", rootfs(Mount{Type: "bind", Source: layers + "/5", Options: []string{"rbind", "rw"}}), RuleSnapshotMount},
		{"bind of a layer's work folder", rootfs(Mount{Type: "bind", Source: layers + "/5/work", Options: []string{"rbind", "rw"}}), RuleSnapshotMount},
		{"upperdir inside a layer", overlay("upperdir="+layers+"/5/fs/h", "workdir="+layers+"/5/work", lower), RuleSnapshotMount},
		{"lowerdir inside a layer", overlay("lowerdir=" + layers + "/1/fs/etc"), RuleSnapshotMount},
		{"snapshot ID that is not a number", rootfs(Mount{Type: "bind", Source: layers + "/x1/fs", Options: []string{"rbind"}}), RuleSnapshotMount},
		{"snapshot ID with a space", rootfs(Mount{Type: "bind", Source: layers + "/1 /fs", Options: []string{"rbind"}}), RuleSnapshotMount},
		{"empty snapshot ID", rootfs(Mount{Type: "bind", Source: layers + "//fs", Options: []string{"rbind"}}), RuleSnapshotMount},
		{"snapshot ID too long", rootfs(Mount{Type: "bind", Source: layers + "/123456789012345678901/fs", Options: []string{"rbind"}}), RuleSnapshotMount},
		{"empty lowerdir entry", overlay("lowerdir=" + layers + "/1/fs::" + layers + "/2/fs"), RuleSnapshotMount},
		{"upperdir given twice", overlay(upper, "upperdir="+layers+"/8/fs", work, lower), RuleSnapshotMount},
		{"lowerdir given twice", overlay(lower, lower), RuleSnapshotMount},
		{"upperdir and workdir of different layers", overlay(upper, "workdir="+layers+"/8/work", lower), RuleSnapshotMount},
		{"upperdir with no workdir", overlay(upper, lower), RuleSnapshotMount},
		{"no lowerdir", overlay(upper, work), RuleSnapshotMount},
		{"an overlay flag the snapshotter does not set", overlay(lower, "volatile"), RuleSnapshotMount},
		{"index on", overlay(lower, "index=on"), RuleSnapshotMount},
		{"redirect_dir", overlay(lower, "redirect_dir=on"), RuleSnapshotMount},
		{"bind option bind", rootfs(Mount{Type: "bind", Source: layers + "/1/fs", Options: []string{"bind"}}), RuleSnapshotMount},
		{"overlay source", rootfs(Mount{Type: "overlay", Source: "/", Options: []string{"lowerdir=" + layers + "/1/fs"}}), RuleSnapshotMount},
		{"block device", rootfs(Mount{Type: "ext4", Source: "/dev/sda1"}), RuleSnapshotMount},
		{"mount with a target", rootfs(Mount{Type: "bind", Source: layers + "/1/fs", Target: "/etc"}), RuleSnapshotMount},
		{"stdout runs a binary", func(tc *TaskCreate) { tc.Stdout = "binary:///bin/sh?-c" }, RuleTaskIO},
		{"stdout opens a file", func(tc *TaskCreate) { tc.Stdout = "file:///etc/passwd" }, RuleTaskIO},
		{"stderr a host file", func(tc *TaskCreate) { tc.Stderr = "/etc/shadow" }, RuleTaskIO},
		{"stdin climbing out of the FIFO dir", func(tc *TaskCreate) { tc.Stdin = testFIFO + "/../../etc/passwd" }, RuleTaskIO},
		{"stdout with a query", func(tc *TaskCreate) { tc.Stdout = testFIFO + "/x?y" }, RuleTaskIO},
		{"terminal", func(tc *TaskCreate) { tc.Terminal = true }, RuleTask},
		{"restore from a checkpoint", func(tc *TaskCreate) { tc.Checkpoint = "sha256:abc" }, RuleCheckpoint},
		{"task runtime options", func(tc *TaskCreate) { tc.OptionsTypeURL = "containerd.runc.v1.Options" }, RuleRuntimeOptions},
		{"shim binary", func(tc *TaskCreate) { tc.RuntimePath = "/tmp/evil-shim" }, RuleRuntime},
		{"task API address", func(tc *TaskCreate) { tc.TaskAPIAddress = "unix:///tmp/x" }, RuleTask},
		{"task API version", func(tc *TaskCreate) { tc.TaskAPIVersion = 3 }, RuleTask},
	} {
		t.Run(tc.name, func(t *testing.T) {
			task := baselineTask()
			tc.mutate(&task)
			wantRule(t, CheckTaskCreate(testPolicy(), task), tc.rule)
		})
	}
}

func TestCheckCheckpointPath(t *testing.T) {
	for dir, ok := range map[string]bool{
		testMoves + "/in/sb-1":       true,
		testMoves + "/out/sb-1/x":    true,
		testMoves:                    false,
		testMoves + "/../hosts":      false,
		"/etc":                       false,
		"in/sb-1":                    false,
		testMoves + "X/in":           false,
		testMoves + "/in/sb-1/../..": false,
	} {
		if err := CheckCheckpointPath(testPolicy(), dir); (err == nil) != ok {
			t.Errorf("CheckCheckpointPath(%q) = %v, want ok=%v", dir, err, ok)
		}
	}
}

func TestCheckTaskUpdate(t *testing.T) {
	enc := func(r specs.LinuxResources) []byte {
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	resize := specs.LinuxResources{
		Memory: &specs.LinuxMemory{Limit: i64(1 << 30)},
		CPU:    &specs.LinuxCPU{Quota: i64(50000), Period: u64(100000)},
		Pids:   &specs.LinuxPids{Limit: i64(10)},
	}
	bounded := testPolicy()
	bounded.Limits = Limits{MemoryBytes: 2 << 30, Pids: 100, CPUs: 2}
	for _, p := range []Policy{testPolicy(), bounded} {
		if err := CheckTaskUpdate(p, ResourcesTypeURL, enc(resize), nil); err != nil {
			t.Fatalf("a resize refused: %v", err)
		}
		if err := CheckTaskUpdate(p, "", nil, nil); err != nil {
			t.Fatalf("an empty update refused: %v", err)
		}
		// A resize names only what it changes.
		if err := CheckTaskUpdate(p, ResourcesTypeURL, enc(specs.LinuxResources{Memory: &specs.LinuxMemory{Limit: i64(1 << 20)}}), nil); err != nil {
			t.Fatalf("a memory-only resize refused: %v", err)
		}
	}
	with := func(mutate func(*specs.LinuxResources)) []byte {
		m, c, pd := *resize.Memory, *resize.CPU, *resize.Pids
		r := specs.LinuxResources{Memory: &m, CPU: &c, Pids: &pd}
		mutate(&r)
		return enc(r)
	}
	for _, tc := range []struct {
		name        string
		p           Policy
		url         string
		raw         []byte
		annotations map[string]string
		rule        Rule
	}{
		{"opens devices", testPolicy(), ResourcesTypeURL, with(func(r *specs.LinuxResources) {
			r.Devices = []specs.LinuxDeviceCgroup{{Allow: true, Access: "rwm"}}
		}), nil, RuleDevice},
		{"any device rule", testPolicy(), ResourcesTypeURL, with(func(r *specs.LinuxResources) {
			r.Devices = []specs.LinuxDeviceCgroup{{Allow: false, Access: "rwm"}}
		}), nil, RuleDevice},
		{"unified cgroup files", testPolicy(), ResourcesTypeURL, with(func(r *specs.LinuxResources) {
			r.Unified = map[string]string{"cgroup.subtree_control": "+cpu"}
		}), nil, RuleField},
		{"annotations", testPolicy(), "", nil, map[string]string{"a": "b"}, RuleResources},
		{"wrong type", testPolicy(), SpecTypeURL, enc(resize), nil, RuleResources},
		{"not JSON", testPolicy(), ResourcesTypeURL, []byte("{"), nil, RuleResources},
		{"unknown field", testPolicy(), ResourcesTypeURL, []byte(`{"futureKnob":1}`), nil, RuleResources},
		{"bytes after", testPolicy(), ResourcesTypeURL, append(enc(resize), []byte("{}")...), nil, RuleResources},
		// Reviewer finding 5: -1 is runc's "unlimited", and 0 sets no limit.
		{"memory unlimited", testPolicy(), ResourcesTypeURL, with(func(r *specs.LinuxResources) { r.Memory.Limit = i64(-1) }), nil, RuleResources},
		{"memory zero", testPolicy(), ResourcesTypeURL, with(func(r *specs.LinuxResources) { r.Memory.Limit = i64(0) }), nil, RuleResources},
		{"pids unlimited", testPolicy(), ResourcesTypeURL, with(func(r *specs.LinuxResources) { r.Pids.Limit = i64(-1) }), nil, RuleResources},
		{"cpu quota unlimited", testPolicy(), ResourcesTypeURL, with(func(r *specs.LinuxResources) { r.CPU.Quota = i64(-1) }), nil, RuleResources},
		{"cpu period zero", testPolicy(), ResourcesTypeURL, with(func(r *specs.LinuxResources) { r.CPU.Period = u64(0) }), nil, RuleResources},
		{"memory above the bound", bounded, ResourcesTypeURL, with(func(r *specs.LinuxResources) { r.Memory.Limit = i64(3 << 30) }), nil, RuleResources},
		{"pids above the bound", bounded, ResourcesTypeURL, with(func(r *specs.LinuxResources) { r.Pids.Limit = i64(101) }), nil, RuleResources},
		{"cpus above the bound", bounded, ResourcesTypeURL, with(func(r *specs.LinuxResources) { r.CPU.Quota = i64(300000) }), nil, RuleResources},
		{"a shorter period alone raises the cpus", bounded, ResourcesTypeURL, enc(specs.LinuxResources{CPU: &specs.LinuxCPU{Period: u64(1000)}}), nil, RuleResources},
		{"a quota alone under a bound", bounded, ResourcesTypeURL, enc(specs.LinuxResources{CPU: &specs.LinuxCPU{Quota: i64(1000)}}), nil, RuleResources},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wantRule(t, CheckTaskUpdate(tc.p, tc.url, tc.raw, tc.annotations), tc.rule)
		})
	}
}

func i64(v int64) *int64   { return &v }
func u64(v uint64) *uint64 { return &v }

func TestCheckSnapshotter(t *testing.T) {
	if err := CheckSnapshotter(testPolicy(), "overlayfs"); err != nil {
		t.Fatal(err)
	}
	wantRule(t, CheckSnapshotter(testPolicy(), ""), RuleSnapshotter)
	wantRule(t, CheckSnapshotter(testPolicy(), "devmapper"), RuleSnapshotter)
}
