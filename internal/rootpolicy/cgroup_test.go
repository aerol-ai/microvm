package rootpolicy

import (
	"path"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/ownerlease"
)

const testCgroupParent = "/kubepods/pod1/sandboxes"

func TestSandboxCgroup(t *testing.T) {
	for _, tc := range []struct {
		parent, id string
		want       string // "" when refused
	}{
		{testCgroupParent, "sb-a36d11bff9ff6787", testCgroupParent + "/sb-a36d11bff9ff6787"},
		{testCgroupParent, "park-0a1b", testCgroupParent + "/park-0a1b"},
		{testCgroupParent, "sb_x", testCgroupParent + "/sb_x"},
		{"/sandboxes", "aerol-netns-3", "/sandboxes/aerol-netns-3"},
		// The machinery beside the sandboxes: containerd, every shim and
		// the root helper; the host-process runtimes' groups.
		{testCgroupParent, "_runtime", ""},
		{testCgroupParent, "_x", ""},
		{testCgroupParent, "aerolvm-vmm", ""},
		{testCgroupParent, "aerolvm-wasm", ""},
		{testCgroupParent, "aerolvm-mounts", ""},
		// A path out of the parent, or below a sandbox's own group.
		{testCgroupParent, "..", ""},
		{testCgroupParent, "../supervisor", ""},
		{testCgroupParent, "/system.slice", ""},
		{testCgroupParent, "sb-1/child", ""},
		{testCgroupParent, ".", ""},
		{testCgroupParent, "", ""},
		{testCgroupParent, "sb\x00", ""},
		{testCgroupParent, strings.Repeat("a", 129), ""},
		// The helper's own setting must be a real group.
		{"", "sb-1", ""},
		{"/", "sb-1", ""},
		{"sandboxes", "sb-1", ""},
		{"/a/../b", "sb-1", ""},
	} {
		got, err := SandboxCgroup(tc.parent, tc.id)
		if tc.want == "" {
			if err == nil || RuleOf(err) != RuleCgroup {
				t.Errorf("SandboxCgroup(%q, %q) = %q, %v; want a cgroup refusal", tc.parent, tc.id, got, err)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("SandboxCgroup(%q, %q) = %q, %v; want %q", tc.parent, tc.id, got, err, tc.want)
		}
	}
}

func TestCheckSparesHelper(t *testing.T) {
	const helper = testCgroupParent + "/_runtime/aerolvm-rootd"
	for _, tc := range []struct {
		group, helper string
		ok            bool
	}{
		{testCgroupParent + "/sb-1", helper, true},
		// A group inside the helper's own is no risk to the helper.
		{helper + "/cni", helper, true},
		{testCgroupParent + "/_runtime", helper, false},
		{testCgroupParent, helper, false},
		{helper, helper, false},
		{"/", helper, false},
		// A name that only starts like the helper's group is another group.
		{testCgroupParent + "/_runtime/aerolvm-rootd-2", helper, true},
		{testCgroupParent + "/sb", testCgroupParent + "/sb-1", true},
		{"relative", helper, false},
		{testCgroupParent + "/sb-1", "", false},
		{testCgroupParent + "/sb-1", "relative", false},
	} {
		err := CheckSparesHelper(tc.group, tc.helper)
		if tc.ok != (err == nil) {
			t.Errorf("CheckSparesHelper(%q, %q) = %v, want ok %v", tc.group, tc.helper, err, tc.ok)
		}
		if err != nil && RuleOf(err) != RuleCgroup {
			t.Errorf("CheckSparesHelper(%q, %q) refused with rule %q", tc.group, tc.helper, RuleOf(err))
		}
	}
}

func TestCgroupV2PathAndInGroup(t *testing.T) {
	for raw, want := range map[string]string{
		"0::/sandboxes/sb-1\n":                         "/sandboxes/sb-1",
		"12:memory:/x\n0::/sandboxes/sb-1/sub\n":       "/sandboxes/sb-1/sub",
		"0::/\n":                                       "/",
		"12:memory:/docker/abc\n11:pids:/docker/abc\n": "",
		"": "",
	} {
		got, ok := CgroupV2Path(raw)
		if got != want || ok != (want != "") {
			t.Errorf("CgroupV2Path(%q) = %q, %v; want %q", raw, got, ok, want)
		}
	}
	for _, tc := range []struct {
		proc, group string
		in          bool
	}{
		{"/s/sb-1", "/s/sb-1", true},
		{"/s/sb-1/sub", "/s/sb-1", true},
		{"/s/sb-10", "/s/sb-1", false},
		{"/s", "/s/sb-1", false},
		{"/s/_runtime", "/s/sb-1", false},
	} {
		if got := InGroup(tc.proc, tc.group); got != tc.in {
			t.Errorf("InGroup(%q, %q) = %v", tc.proc, tc.group, got)
		}
	}
}

// FuzzSandboxCgroup: whatever the agent names, a group the rule lets
// through is exactly one element directly under the helper's parent, and
// never a group the machinery keeps.
func FuzzSandboxCgroup(f *testing.F) {
	for _, s := range []string{"sb-a36d11bff9ff6787", "_runtime", "..", "../_runtime", "aerolvm-vmm", "a/b", "", "sb\x00", "_"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, id string) {
		got, err := SandboxCgroup(testCgroupParent, id)
		if err != nil {
			if RuleOf(err) != RuleCgroup {
				t.Fatalf("refusal names rule %q: %v", RuleOf(err), err)
			}
			return
		}
		leaf := path.Base(got)
		switch {
		case path.Dir(got) != testCgroupParent, path.Clean(got) != got, leaf != id:
			t.Fatalf("SandboxCgroup(%q) = %q: not one element under %s", id, got, testCgroupParent)
		case strings.HasPrefix(leaf, "_"), strings.HasPrefix(leaf, "aerolvm-"), ownerlease.ReservedGroup(leaf):
			t.Fatalf("SandboxCgroup(%q) = %q: a machinery group", id, got)
		case strings.ContainsAny(leaf, "./\x00"):
			t.Fatalf("SandboxCgroup(%q) = %q: a separator or dot", id, got)
		}
		if err := CheckSparesHelper(got, testCgroupParent+"/_runtime/aerolvm-rootd"); err != nil {
			t.Fatalf("a sandbox's group %q refused as the helper's: %v", got, err)
		}
	})
}

// FuzzCheckSparesHelper: a group the check lets through never holds the
// helper's own group.
func FuzzCheckSparesHelper(f *testing.F) {
	f.Add("/s/sb-1", "/s/_runtime/aerolvm-rootd")
	f.Add("/s", "/s/_runtime/aerolvm-rootd")
	f.Add("/", "/x")
	f.Add("/s/_runtime/aerolvm-rootd", "/s/_runtime/aerolvm-rootd")
	f.Fuzz(func(t *testing.T, group, helper string) {
		if CheckSparesHelper(group, helper) != nil {
			return
		}
		if InGroup(helper, group) {
			t.Fatalf("CheckSparesHelper(%q, %q) passed a group holding the helper", group, helper)
		}
	})
}
