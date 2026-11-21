package rootpolicy

import (
	"strings"
	"testing"
)

func TestPolicyValidate(t *testing.T) {
	if err := testPolicy().Validate(); err != nil {
		t.Fatalf("test policy: %v", err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*Policy)
		want   string
	}{
		{"no namespace", func(p *Policy) { p.Namespace = "" }, "namespace"},
		{"namespace with a slash", func(p *Policy) { p.Namespace = "a/b" }, "invalid character"},
		{"namespace starting with a dot", func(p *Policy) { p.Namespace = ".a" }, "invalid character"},
		{"namespace too long", func(p *Policy) { p.Namespace = strings.Repeat("a", 77) }, "1 to 76"},
		{"no snapshotter", func(p *Policy) { p.Snapshotter = " " }, "snapshotter is required"},
		{"relative snapshotter root", func(p *Policy) { p.SnapshotterRoot = "var/lib" }, "snapshotter root"},
		{"netns dir /", func(p *Policy) { p.NetnsDir = "/" }, "netns dir"},
		{"moves dir unclean", func(p *Policy) { p.MovesDir = "/a/../b" }, "moves dir"},
		{"no FIFO dir", func(p *Policy) { p.FIFODir = "" }, "FIFO dir"},
		{"cgroup parent relative", func(p *Policy) { p.CgroupParent = "aerolvm" }, "cgroup parent"},
		{"cgroup parent /", func(p *Policy) { p.CgroupParent = "/" }, "cgroup parent"},
		{"forbidden root /", func(p *Policy) { p.ForbiddenRoots = []string{"/"} }, "forbidden root"},
		{"bind root /", func(p *Policy) { p.BindRoots = []string{"/"} }, "bind root"},
		{"bind root relative", func(p *Policy) { p.BindRoots = []string{"tmp"} }, "bind root"},
		{"bind root /proc", func(p *Policy) { p.BindRoots = []string{"/proc"} }, "inside forbidden /proc"},
		{"bind root under /dev", func(p *Policy) { p.BindRoots = []string{"/dev/shm"} }, "inside forbidden /dev"},
		{"bind root in the sockets folder", func(p *Policy) { p.BindRoots = []string{"/run/containerd/x"} }, "inside forbidden /run/containerd"},
		{"bind file relative", func(p *Policy) { p.BindFiles = []string{"toolboxd"} }, "bind file"},
		{"bind file in /sys", func(p *Policy) { p.BindFiles = []string{"/sys/kernel/uevent_helper"} }, "inside forbidden /sys"},
		{"runsc config relative", func(p *Policy) { p.RunscConfigPaths = []string{"runsc.toml"} }, "runsc config"},
		{"helper file root /", func(p *Policy) { p.HelperFileRoots = []string{"/"} }, "helper file root"},
		{"helper file root relative", func(p *Policy) { p.HelperFileRoots = []string{"run/ready"} }, "helper file root"},
		{"helper file root in the sockets folder", func(p *Policy) { p.HelperFileRoots = []string{"/run/containerd/ready"} }, "inside forbidden /run/containerd"},
		// What a sandbox may bind never holds, or sits in, what root reads
		// on the agent's word.
		{"a bind root holding the moves dir", func(p *Policy) { p.BindRoots = append(p.BindRoots, testRunDir) }, "overlaps the moves dir"},
		{"a bind root inside the moves dir", func(p *Policy) { p.BindRoots = append(p.BindRoots, testMoves+"/in") }, "overlaps the moves dir"},
		{"a bind root holding the FIFO dir", func(p *Policy) { p.BindRoots = append(p.BindRoots, "/run/aerolvm") }, "overlaps the FIFO dir"},
		{"a bind root holding a runsc config", func(p *Policy) { p.BindRoots = append(p.BindRoots, testRunDir+"/runsc") }, "overlaps the runsc config"},
		{"a bind file that is a runsc config", func(p *Policy) { p.BindFiles = append(p.BindFiles, testRestore) }, "overlaps the runsc config"},
		{"a helper file root holding the moves dir", func(p *Policy) { p.HelperFileRoots = []string{testRunDir + "/moves"} }, "overlaps the moves dir"},
		{"a helper file root holding the FIFO dir", func(p *Policy) { p.HelperFileRoots = []string{"/run/aerolvm"} }, "overlaps the FIFO dir"},
		// The looser bind rule must never cover a helper's files.
		{"a bind root inside a helper file root", func(p *Policy) { p.BindRoots = append(p.BindRoots, testHelperHosts+"/sb-1") }, "overlaps the helper file root"},
		{"a bind root holding a helper file root", func(p *Policy) { p.BindRoots = append(p.BindRoots, "/var/lib/aerolvm-rootd") }, "overlaps the helper file root"},
		{"a helper file root that is a bind root", func(p *Policy) { p.HelperFileRoots = append(p.HelperFileRoots, testMounts) }, "overlaps the helper file root"},
		{"a bind file in a helper file root", func(p *Policy) { p.BindFiles = append(p.BindFiles, testHelperHosts+"/sb-1/hosts") }, "overlaps the helper file root"},
		{"nested helper file roots", func(p *Policy) { p.HelperFileRoots = []string{testHelperHosts, testHelperHosts + "/ready"} }, "overlap"},
		{"negative memory bound", func(p *Policy) { p.Limits.MemoryBytes = -1 }, "policy limits"},
		{"no limits at all", func(p *Policy) { p.Limits = Limits{} }, "policy limits"},
		{"no pids bound", func(p *Policy) { p.Limits.Pids = 0 }, "policy limits"},
		{"no cpu bound", func(p *Policy) { p.Limits.CPUs = 0 }, "policy limits"},
		{"negative cpu bound", func(p *Policy) { p.Limits.CPUs = -0.5 }, "policy limits"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := testPolicy()
			tc.mutate(&p)
			err := p.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestPathHelpers(t *testing.T) {
	for _, tc := range []struct {
		p, root string
		want    bool
	}{
		{"/a/b", "/a", true},
		{"/a", "/a", false},
		{"/ab", "/a", false},
		{"/x", "/", true},
		{"/", "/", false},
	} {
		if got := within(tc.p, tc.root); got != tc.want {
			t.Errorf("within(%q, %q) = %v", tc.p, tc.root, got)
		}
	}
	if !equalOrWithin("/a", "/a") || equalOrWithin("/b", "/a") {
		t.Fatal("equalOrWithin")
	}
	for p, want := range map[string]bool{"/a": true, "/a/": false, "a": false, "": false, "/a/./b": false, "/": true} {
		if cleanAbs(p) != want {
			t.Errorf("cleanAbs(%q) != %v", p, want)
		}
	}
}

func TestOnlyFieldsNil(t *testing.T) {
	type s struct{ A, B int }
	var nilPtr *s
	if err := onlyFields(nilPtr, "x"); err != nil {
		t.Fatal(err)
	}
	if err := onlyFields(s{A: 1}, "x", "A"); err != nil {
		t.Fatal(err)
	}
	if err := onlyFields(s{B: 1}, "x", "A"); RuleOf(err) != RuleField || !strings.Contains(err.Error(), "x.B") {
		t.Fatalf("onlyFields = %v", err)
	}
}
