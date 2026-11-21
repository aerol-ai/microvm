package rootpolicy

import (
	"strings"
	"testing"
)

func TestCheckProbeSlot(t *testing.T) {
	for _, ok := range []uint32{0, 1, MaxProbeSlots - 1} {
		if err := CheckProbeSlot(ok); err != nil {
			t.Fatalf("%d: %v", ok, err)
		}
	}
	for _, bad := range []uint32{MaxProbeSlots, 1 << 31} {
		if RuleOf(CheckProbeSlot(bad)) != RuleProbe {
			t.Fatalf("%d passed", bad)
		}
	}
}

func TestCheckProcessMatch(t *testing.T) {
	m, err := CheckProcessMatch(4242, "10.88.0.5:40000", "1.2.3.4:443", []string{"/usr/bin/curl", "/usr/local/bin/python3"})
	if err != nil || m.PID != 4242 || m.Local.String() != "10.88.0.5:40000" || len(m.Paths) != 2 {
		t.Fatalf("%+v %v", m, err)
	}
	long := "/" + strings.Repeat("a", maxMatchPath)
	for _, tc := range []struct {
		pid           uint32
		local, remote string
		paths         []string
	}{
		{0, "10.88.0.5:1", "1.2.3.4:443", []string{"/a"}},
		{1, "10.88.0.5:1", "1.2.3.4:443", []string{"/a"}},
		{1 << 23, "10.88.0.5:1", "1.2.3.4:443", []string{"/a"}},
		{9, "10.88.0.5", "1.2.3.4:443", []string{"/a"}},
		{9, "10.88.0.5:0", "1.2.3.4:443", []string{"/a"}},
		{9, "10.88.0.5:1", " 1.2.3.4:443", []string{"/a"}},
		{9, "10.88.0.5:1", "[fe80::1%eth0]:443", []string{"/a"}},
		{9, "10.88.0.5:1", "1.2.3.4:443", nil},
		{9, "10.88.0.5:1", "1.2.3.4:443", []string{"a"}},
		{9, "10.88.0.5:1", "1.2.3.4:443", []string{"/a/../b"}},
		{9, "10.88.0.5:1", "1.2.3.4:443", []string{"/a\x00"}},
		{9, "10.88.0.5:1", "1.2.3.4:443", []string{long}},
		{9, "10.88.0.5:1", "1.2.3.4:443", []string{"/a", "/a"}},
		{9, "10.88.0.5:1", "1.2.3.4:443", make([]string, MaxMatchPaths+1)},
	} {
		if _, err := CheckProcessMatch(tc.pid, tc.local, tc.remote, tc.paths); RuleOf(err) != RuleProcessMatch {
			t.Errorf("%+v passed: %v", tc, err)
		}
	}
}

func TestCheckSandboxCgroup(t *testing.T) {
	def := Policy{Namespace: "aerolvm"}
	parent := Policy{Namespace: "aerolvm", CgroupParent: "/kubepods/pod1/sandboxes"}
	for _, ok := range []struct {
		p  Policy
		cg string
	}{
		{def, "0::/aerolvm/sb-1\n"},
		{def, "0::/aerolvm/sb-1/init.scope"},
		{parent, "0::/kubepods/pod1/sandboxes/sb-1"},
		{def, "12:pids:/x\n0::/aerolvm/sb-2\n"},
	} {
		if err := CheckSandboxCgroup(ok.p, ok.cg); err != nil {
			t.Errorf("%q: %v", ok.cg, err)
		}
	}
	for _, bad := range []struct {
		p  Policy
		cg string
	}{
		{def, ""},
		{def, "0::/"},
		{def, "0::/aerolvm"},
		{def, "0::/aerolvm/"},
		{def, "0::/system.slice/containerd.service"},
		{def, "0::/aerolvmx/sb-1"},
		{def, "0::/aerolvm/../system.slice"},
		{def, "0::/aerolvm/sb 1"},
		{parent, "0::/aerolvm/sb-1"},
		{parent, "0::/kubepods/pod1/agent"},
		{def, "1:name=systemd:/aerolvm/sb-1"},
	} {
		if RuleOf(CheckSandboxCgroup(bad.p, bad.cg)) != RuleProcessMatch {
			t.Errorf("%q passed", bad.cg)
		}
	}
}

// FuzzCheckProcessMatch: what passes is a real process id, two parsed
// ends, and clean absolute paths, each once.
func FuzzCheckProcessMatch(f *testing.F) {
	f.Add(uint32(42), "10.88.0.5:40000", "1.2.3.4:443", "/usr/bin/curl")
	f.Add(uint32(1), "x", "y", "../etc")
	f.Fuzz(func(t *testing.T, pid uint32, local, remote, p string) {
		m, err := CheckProcessMatch(pid, local, remote, []string{p})
		if err != nil {
			return
		}
		if m.PID < 2 || m.Local.String() != local || m.Remote.String() != remote || m.Paths[0] != p ||
			!strings.HasPrefix(p, "/") || strings.Contains(p, "/../") || strings.ContainsRune(p, 0) {
			t.Fatalf("passed %+v", m)
		}
	})
}

// FuzzCheckSandboxCgroup: what passes sits strictly under the parent, in
// a valid sandbox id's cgroup.
func FuzzCheckSandboxCgroup(f *testing.F) {
	f.Add("0::/aerolvm/sb-1")
	f.Add("0::/aerolvm/../x")
	f.Fuzz(func(t *testing.T, cg string) {
		if CheckSandboxCgroup(Policy{Namespace: "aerolvm"}, cg) != nil {
			return
		}
		var path string
		for _, line := range strings.Split(strings.TrimRight(cg, "\n"), "\n") {
			if v, ok := strings.CutPrefix(line, "0::"); ok {
				path = v
			}
		}
		rest, ok := strings.CutPrefix(path, "/aerolvm/")
		id, _, _ := strings.Cut(rest, "/")
		if !ok || ValidateID(id) != nil || strings.Contains(path, "..") {
			t.Fatalf("passed %q", cg)
		}
	})
}
