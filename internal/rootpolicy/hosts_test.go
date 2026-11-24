package rootpolicy

import (
	"strings"
	"testing"
)

func TestCheckHostID(t *testing.T) {
	for _, tc := range []struct {
		kind HostKind
		id   string
		ok   bool
	}{
		// V8 group keys, as the isolate driver makes them.
		{HostWorkerd, "default", true},
		{HostWorkerd, "tenant.a_b-1", true},
		{HostWorkerd, "warm-6560a1-3", true},
		{HostWorkerd, strings.Repeat("a", 64), true},
		{HostWorkerd, strings.Repeat("a", 65), false},
		{HostWorkerd, "", false},
		{HostWorkerd, ".", false},
		{HostWorkerd, "..", false},
		{HostWorkerd, ".base", false},
		{HostWorkerd, "a..b", false},
		{HostWorkerd, "a/b", false},
		{HostWorkerd, "-rf", false},
		{HostWorkerd, "a\x00", false},
		{HostWorkerd, "a b", false},
		// WASM hosts: a sandbox ID's shape.
		{HostWasmWorker, "sb-a36d11bff9ff6787", true},
		{HostWasmWorker, "slot_1", true},
		{HostWasmResident, "o0123456789abcdef-0123456789abcdef-128mb-2", true},
		{HostWasmWorker, "a.b", false},
		{HostWasmWorker, "../x", false},
		{HostWasmWorker, "_runtime", false},
		{HostWasmResident, "aerolvm-vmm", false},
		{HostWasmResident, strings.Repeat("a", 129), false},
		// A Firecracker VM: its sandbox ID.
		{HostFirecracker, "sb-a36d11bff9ff6787", true},
		{HostFirecracker, "../sb-1", false},
		{HostFirecracker, "aerolvm-vmm", false},
		{HostFirecracker, "", false},
		// A kind no rule knows.
		{"", "default", false},
		{"docker", "default", false},
	} {
		err := CheckHostID(tc.kind, tc.id)
		if (err == nil) != tc.ok {
			t.Errorf("CheckHostID(%q, %q) = %v, want ok %v", tc.kind, tc.id, err, tc.ok)
		}
		if err != nil && RuleOf(err) != RuleHost {
			t.Errorf("CheckHostID(%q, %q) broke rule %q, want %q", tc.kind, tc.id, RuleOf(err), RuleHost)
		}
	}
}

func TestHostGroupRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		kind  HostKind
		id    string
		group string
	}{
		{HostWorkerd, "default", "aerolvm-isolate/default"},
		{HostWasmWorker, "sb-1", "aerolvm-wasm/w-sb-1"},
		{HostWasmResident, "sb-1", "aerolvm-wasm/r-sb-1"},
		{HostFirecracker, "sb-1", "aerolvm-vmm/sb-1"},
	} {
		if got := HostGroup(tc.kind, tc.id); got != tc.group {
			t.Errorf("HostGroup(%q, %q) = %q, want %q", tc.kind, tc.id, got, tc.group)
		}
		kind, id, ok := HostOfGroup(tc.group)
		if !ok || kind != tc.kind || id != tc.id {
			t.Errorf("HostOfGroup(%q) = %q %q %v", tc.group, kind, id, ok)
		}
	}
	if HostGroup("docker", "x") != "" {
		t.Error("a kind no rule knows has a group")
	}
	for _, g := range []string{"", "aerolvm-isolate", "aerolvm-isolate/.base", "aerolvm-isolate/a/b", "aerolvm-wasm/x-sb-1",
		"aerolvm-wasm/w-../x", "aerolvm-vmm/../x", "aerolvm-vmm", "aerolvm-vmm/a/b", "_runtime/x", "aerolvm-wasm/w-"} {
		if kind, id, ok := HostOfGroup(g); ok {
			t.Errorf("HostOfGroup(%q) = %q %q, want none", g, kind, id)
		}
	}
}

func TestCheckHostLimits(t *testing.T) {
	node := Limits{MemoryBytes: 4 << 30, Pids: 9216, CPUs: 2}
	for _, tc := range []struct {
		name string
		l    HostLimits
		node Limits
		ok   bool
	}{
		{"none", HostLimits{}, node, true},
		{"the node's whole", HostLimits{CPUMillis: 2000, MemoryMB: 4096, Pids: 9216}, node, true},
		{"more CPU", HostLimits{CPUMillis: 2001}, node, false},
		{"more memory", HostLimits{MemoryMB: 4097}, node, false},
		{"more pids", HostLimits{Pids: 9217}, node, false},
		{"memory past a machine", HostLimits{MemoryMB: 1 << 62}, Limits{}, false},
		{"a node that names no bound", HostLimits{CPUMillis: 1 << 30, MemoryMB: 1 << 30, Pids: 1 << 30}, Limits{}, true},
	} {
		err := CheckHostLimits(tc.l, tc.node)
		if (err == nil) != tc.ok {
			t.Errorf("%s: %v, want ok %v", tc.name, err, tc.ok)
		}
		if err != nil && RuleOf(err) != RuleHostLimits {
			t.Errorf("%s: rule %q", tc.name, RuleOf(err))
		}
	}
}

func TestCheckWasmCache(t *testing.T) {
	for _, tc := range []struct {
		cache string
		ok    bool
	}{
		{"", true},
		{"operator", true},
		{"owner-0123456789abcdef", true},
		{"slots/0123456789abcdef/cache", true},
		{"owners/owner-0123456789abcdef", false},
		{"../operator", false},
		{"owner-0123456789ABCDEF", false},
		{"slots/0123456789abcdef", false},
		{"slots/0123456789abcdef/cache/..", false},
		{"/etc", false},
	} {
		err := CheckWasmCache(tc.cache)
		if (err == nil) != tc.ok {
			t.Errorf("cache %q: %v, want ok %v", tc.cache, err, tc.ok)
		}
		if err != nil && RuleOf(err) != RuleHost {
			t.Errorf("cache %q: rule %q", tc.cache, RuleOf(err))
		}
	}
}

func TestWasmHostSocket(t *testing.T) {
	for _, tc := range []struct {
		dir  string
		kind HostKind
		id   string
		want string
	}{
		{"/run/aerolvm-rootd/wasm", HostWasmWorker, "sb-1", "/run/aerolvm-rootd/wasm/w-sb-1.sock"},
		{"/run/aerolvm-rootd/wasm", HostWasmResident, "b-2", "/run/aerolvm-rootd/wasm/r-b-2.sock"},
		{"/run/aerolvm-rootd/wasm", HostWorkerd, "g", ""},
		{"/run/aerolvm-rootd/wasm", HostWasmWorker, "../x", ""},
		{"/run/aerolvm-rootd/wasm", HostWasmWorker, strings.Repeat("a", 90), ""},
		{"relative", HostWasmWorker, "sb-1", ""},
		{"/", HostWasmWorker, "sb-1", ""},
		{"/run/x/", HostWasmWorker, "sb-1", ""},
	} {
		got, err := WasmHostSocket(tc.dir, tc.kind, tc.id)
		if got != tc.want || (err == nil) != (tc.want != "") {
			t.Errorf("WasmHostSocket(%q, %q, %q) = %q, %v, want %q", tc.dir, tc.kind, tc.id, got, err, tc.want)
		}
		if err != nil && RuleOf(err) != RuleHost {
			t.Errorf("rule %q", RuleOf(err))
		}
	}
}

// TestWasmHostOfSocket: a WASM host's socket reads back to the kind and id
// it was named for, and nothing else reads back at all.
func TestWasmHostOfSocket(t *testing.T) {
	const dir = "/run/aerolvm-rootd/wasm"
	for _, tc := range []struct {
		socket string
		kind   HostKind
		id     string
	}{
		{dir + "/w-sb-1.sock", HostWasmWorker, "sb-1"},
		{dir + "/w-pool-0123456789abcdef.sock", HostWasmWorker, "pool-0123456789abcdef"},
		{dir + "/r-o0123456789abcdef-b.sock", HostWasmResident, "o0123456789abcdef-b"},
		{dir + "/w-../x.sock", "", ""},
		{dir + "/w-_hidden.sock", "", ""},
		{dir + "/w-sb-1.sockx", "", ""},
		{dir + "/x-sb-1.sock", "", ""},
		{dir + "/w-.sock", "", ""},
		{"/elsewhere/w-sb-1.sock", "", ""},
		{dir + "/sub/w-sb-1.sock", "", ""},
		{dir + "/w-" + strings.Repeat("a", 90) + ".sock", "", ""},
	} {
		kind, id, ok := WasmHostOfSocket(dir, tc.socket)
		if ok != (tc.kind != "") || kind != tc.kind || id != tc.id {
			t.Errorf("WasmHostOfSocket(%q) = %q %q %v, want %q %q", tc.socket, kind, id, ok, tc.kind, tc.id)
		}
	}
	// The folder must be one WasmHostSocket names sockets in.
	if _, _, ok := WasmHostOfSocket("relative", "relative/w-sb-1.sock"); ok {
		t.Error("a relative folder")
	}
}

// FuzzHostOfGroup: whatever a group's name, reading it back never yields an
// id that leaves the kind's group, and an id read back names that group.
func FuzzHostOfGroup(f *testing.F) {
	for _, s := range []string{"aerolvm-isolate/default", "aerolvm-wasm/w-sb-1", "aerolvm-wasm/r-x", "aerolvm-isolate/../x", "aerolvm-vmm/sb-1"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, group string) {
		kind, id, ok := HostOfGroup(group)
		if !ok {
			return
		}
		if CheckHostID(kind, id) != nil || HostGroup(kind, id) != group || strings.Contains(id, "/") {
			t.Fatalf("HostOfGroup(%q) = %q %q", group, kind, id)
		}
	})
}
