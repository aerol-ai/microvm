package rootpolicy

import (
	"encoding/json"
	"math"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// The second independent review's proofs of concept against ac2d0aef that
// rootpolicy itself answers. The bind-source symlink (its finding 1) is
// checked on disk by the gate: internal/rootd/gate/binds_linux_test.go.

// Finding 3: a second sysfs at another path is read-only but unmasked:
// <dest>/firmware and <dest>/devices/virtual/powercap are hidden at /sys only.
func TestReview2SecondSysfs(t *testing.T) {
	for name, m := range map[string]specs.Mount{
		"a second sysfs":      {Destination: "/s2", Type: "sysfs", Source: "sysfs", Options: []string{"ro", "nosuid", "noexec", "nodev"}},
		"sysfs at /sys twice": {Destination: "/sys", Type: "sysfs", Source: "sysfs", Options: []string{"ro"}},
	} {
		t.Run(name, func(t *testing.T) {
			s := baselineSpec(t)
			s.Mounts = append(s.Mounts, m)
			wantRule(t, CheckSpec(testPolicy(), testID, s), RuleMount)
		})
	}
	t.Run("the only sysfs moved off /sys", func(t *testing.T) {
		s := baselineSpec(t)
		for i := range s.Mounts {
			if s.Mounts[i].Type == "sysfs" {
				s.Mounts[i].Destination = "/hostsys"
			}
		}
		wantRule(t, CheckSpec(testPolicy(), testID, s), RuleMount)
	})
}

// Finding 2: resource bounds were opt-in, so the zero policy allowed
// MaxInt64 limits and a create with no limits at all. Now the policy must
// bound every resource, and a create must set every limit.
func TestReview2HugeLimits(t *testing.T) {
	big := int64(math.MaxInt64)
	period := uint64(1000)
	b, err := json.Marshal(specs.LinuxResources{Memory: &specs.LinuxMemory{Limit: &big}, Pids: &specs.LinuxPids{Limit: &big}, CPU: &specs.LinuxCPU{Quota: &big, Period: &period}})
	if err != nil {
		t.Fatal(err)
	}
	wantRule(t, CheckTaskUpdate(testPolicy(), ResourcesTypeURL, b, nil), RuleResources)

	s := baselineSpec(t)
	s.Linux.Resources = nil
	wantRule(t, CheckSpec(testPolicy(), testID, s), RuleResources)

	unbounded := testPolicy()
	unbounded.Limits = Limits{}
	if err := unbounded.Validate(); err == nil {
		t.Fatal("a policy with no limits validated")
	}
	for name, mutate := range map[string]func(*specs.LinuxResources){
		"no memory limit": func(r *specs.LinuxResources) { r.Memory = nil },
		"no pids limit":   func(r *specs.LinuxResources) { r.Pids = nil },
		"no cpu limit":    func(r *specs.LinuxResources) { r.CPU = nil },
		"no cpu period":   func(r *specs.LinuxResources) { r.CPU.Period = nil },
	} {
		t.Run(name, func(t *testing.T) {
			s := baselineSpec(t)
			mutate(s.Linux.Resources)
			wantRule(t, CheckSpec(testPolicy(), testID, s), RuleResources)
		})
	}
}

// The first review's overlay and bind variants, kept refused.
func TestReview2OverlayVariants(t *testing.T) {
	L := testSnapRoot + "/snapshots"
	for name, opts := range map[string][]string{
		"lowerdir+":      {"lowerdir+=" + L + "/1/fs"},
		"leading space":  {"lowerdir=" + L + "/1/fs", " upperdir=/etc", "workdir=" + L + "/9/work"},
		"capital key":    {"lowerdir=" + L + "/1/fs", "Upperdir=/etc"},
		"nul in value":   {"lowerdir=" + L + "/1/fs\x00,upperdir=/etc"},
		"trailing slash": {"lowerdir=" + L + "/1/fs/"},
		"dot segment":    {"lowerdir=" + L + "/1/./fs"},
		"dotdot id":      {"lowerdir=" + L + "/../1/fs"},
		"escaped comma":  {"lowerdir=" + L + "/1/fs\\,upperdir=/etc"},
		"metacopy":       {"lowerdir=" + L + "/1/fs", "metacopy=on"},
		"X-containerd":   {"lowerdir=" + L + "/1/fs", "X-containerd.mkdir.path=/etc/x"},
		"index twice":    {"lowerdir=" + L + "/1/fs", "index=off", "index=on"},
	} {
		if err := CheckSnapshotMounts(testPolicy(), []Mount{{Type: "overlay", Source: "overlay", Options: opts}}); RuleOf(err) != RuleSnapshotMount {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, m := range map[string]Mount{
		"rbind type":         {Type: "rbind", Source: L + "/1/fs", Options: []string{"rw"}},
		"none type bind opt": {Type: "none", Source: "/", Options: []string{"rbind"}},
		"fuse":               {Type: "fuse.sshfs", Source: "x"},
	} {
		if err := CheckSnapshotMounts(testPolicy(), []Mount{m}); RuleOf(err) != RuleSnapshotMount {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A second procfs by any other spelling stays refused, and the builder's
// own tmpfs options still pass.
func TestReview2ProcSpellingsAndLegitOptions(t *testing.T) {
	for name, m := range map[string]specs.Mount{
		"dest trailing slash": {Destination: "/proc/", Type: "proc", Source: "proc"},
		"dest double slash":   {Destination: "//proc", Type: "proc", Source: "proc"},
		"type procfs":         {Destination: "/p2", Type: "procfs", Source: "proc"},
		"bind of /proc":       {Destination: "/p2", Type: "bind", Source: "/proc", Options: []string{"rbind"}},
		"bind opt on proc":    {Destination: "/p2", Type: "proc", Source: "proc", Options: []string{"rbind"}},
		"empty type":          {Destination: "/p2", Type: "", Source: "proc"},
	} {
		s := baselineSpec(t)
		s.Mounts = append(s.Mounts, m)
		if err := CheckSpec(testPolicy(), testID, s); err == nil {
			t.Errorf("%s: passed", name)
		}
	}
	s := baselineSpec(t)
	s.Mounts = append(s.Mounts, specs.Mount{Destination: "/dev/shm2", Type: "tmpfs", Source: "shm", Options: []string{"nosuid", "noexec", "nodev", "mode=1777", "size=65536k"}})
	if err := CheckSpec(testPolicy(), testID, s); err != nil {
		t.Fatalf("the builder's tmpfs options refused: %v", err)
	}
}

func TestBindRootFor(t *testing.T) {
	p := testPolicy()
	p.BindRoots = append(p.BindRoots, testMounts+"/nested")
	for src, want := range map[string]string{
		testToolbox:                            "/usr/local/lib/aerolvm",
		testRunDir + "/hosts/sb-1/resolv.conf": testRunDir + "/hosts",
		testMounts + "/sb-1/0":                 testMounts,
		testMounts + "/nested/x":               testMounts + "/nested",
		"/etc/shadow":                          "",
		testMounts:                             "",
	} {
		got, ok := BindRootFor(p, src)
		if got != want || ok != (want != "") {
			t.Errorf("BindRootFor(%q) = %q, %v; want %q", src, got, ok, want)
		}
	}
}

func TestSpecBindSources(t *testing.T) {
	got, err := SpecBindSources(baselineContainer(t, baselineSpec(t)))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{testToolbox, testRunDir + "/hosts/" + testID + "/resolv.conf", testReady + "/" + testID + ".abc.sock", testMounts + "/" + testID + "/0"}
	if len(got) != len(want) {
		t.Fatalf("sources %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("sources %v, want %v", got, want)
		}
	}
	c := baselineContainer(t, baselineSpec(t))
	c.Spec = []byte("[")
	if _, err := SpecBindSources(c); RuleOf(err) != RuleSpec {
		t.Fatalf("bad spec: %v", err)
	}
}
