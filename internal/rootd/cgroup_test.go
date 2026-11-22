package rootd

import (
	"context"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/encoding/protowire"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// The cgroup part on a tree of plain files laid out as the worker pod's
// supervisor lays out the kernel's (internal/supervisor):
//
//	/sandboxes/                  the parent, memory.oom.group 0
//	├── _runtime/                containerd and the shims (pids 10, 11)
//	│   └── aerolvm-rootd/       the helper itself (pid 12)
//	├── aerolvm-wasm/            a host-process runtime's group (pid 13)
//	├── sb-a/                    a sandbox (pids 20, 21)
//	│   └── sub/                 a group gVisor made below it (pid 22)
//	└── sb-b/                    another sandbox (pid 30)
//
// Every process starts at the machinery's -999, the score gVisor's
// processes inherit from the shim.

const testSandboxParent = "/sandboxes"

type cgroupTree struct {
	root, proc string
}

// newCgroupTree builds the tree; self is the helper's own group, as its
// /proc/self/cgroup says.
func newCgroupTree(t *testing.T, self string) *cgroupTree {
	t.Helper()
	base := t.TempDir()
	c := &cgroupTree{root: filepath.Join(base, "cgroup"), proc: filepath.Join(base, "proc")}
	c.group(t, testSandboxParent)
	c.group(t, testSandboxParent+"/_runtime", 10, 11)
	c.group(t, testSandboxParent+"/_runtime/aerolvm-rootd", 12)
	c.group(t, testSandboxParent+"/aerolvm-wasm", 13)
	c.group(t, testSandboxParent+"/sb-a", 20, 21)
	c.group(t, testSandboxParent+"/sb-a/sub", 22)
	c.group(t, testSandboxParent+"/sb-b", 30)
	writeTestFile(t, filepath.Join(c.proc, "self", "cgroup"), "0::"+self+"\n")
	return c
}

// group makes a group holding pids, each a process of /proc in it.
func (c *cgroupTree) group(t *testing.T, group string, pids ...int) {
	t.Helper()
	dir := filepath.Join(c.root, filepath.FromSlash(group))
	var list []string
	for _, pid := range pids {
		list = append(list, strconv.Itoa(pid))
		c.process(t, pid, group)
	}
	writeTestFile(t, filepath.Join(dir, "cgroup.procs"), strings.Join(list, "\n")+"\n")
	writeTestFile(t, filepath.Join(dir, "memory.oom.group"), "0\n")
}

// process makes pid's /proc folder: in group, at score -999.
func (c *cgroupTree) process(t *testing.T, pid int, group string) {
	t.Helper()
	dir := filepath.Join(c.proc, strconv.Itoa(pid))
	writeTestFile(t, filepath.Join(dir, "cgroup"), "0::"+group+"\n")
	writeTestFile(t, filepath.Join(dir, "oom_score_adj"), "-999\n")
}

// snapshot reads every file of the tree, for "nothing changed" checks.
func (c *cgroupTree) snapshot(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, root := range []string{c.root, c.proc} {
		err := filepath.WalkDir(root, func(p string, e fs.DirEntry, err error) error {
			if err != nil || e.IsDir() {
				return err
			}
			raw, err := os.ReadFile(p)
			out[p] = string(raw)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}

func (c *cgroupTree) score(t *testing.T, pid int) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(c.proc, strconv.Itoa(pid), "oom_score_adj"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(raw))
}

func (c *cgroupTree) oomGroup(t *testing.T, group string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(c.root, filepath.FromSlash(group), "memory.oom.group"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(raw))
}

func writeTestFile(t *testing.T, p, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// cgroupRig is a helper with the sandboxes' parent and the tree, and with
// a network when net is set.
func cgroupRig(t *testing.T, tree *cgroupTree, net bool) (*rig, rootdpb.RootHelperClient) {
	t.Helper()
	r := newRig(t, func(c *Config, o *Options) {
		c.Policy.CgroupParent = testSandboxParent
		o.CgroupRoot, o.ProcRoot = tree.root, tree.proc
		if net {
			o.Network = newFakeNet()
		}
	})
	return r, rootdpb.NewRootHelperClient(r.conn)
}

func markReq(id string) *rootdpb.PrepareSandboxRequest {
	return &rootdpb.PrepareSandboxRequest{Parts: []string{rootdpb.PartCgroup}, Cgroup: &rootdpb.SandboxCgroup{ContainerId: id}}
}

// TestCgroupPartMarksTheWholeGroup: the sandbox's own group gets
// memory.oom.group 1 and every process in it and below it score 500, as
// single mode writes them; nothing above it or beside it changes, and a
// repeat writes the same.
func TestCgroupPartMarksTheWholeGroup(t *testing.T) {
	for _, net := range []bool{false, true} {
		tree := newCgroupTree(t, testSandboxParent+"/_runtime/aerolvm-rootd")
		r, c := cgroupRig(t, tree, net)
		before := tree.snapshot(t)
		for range 2 {
			if _, err := c.PrepareSandbox(callCtx(t), markReq("sb-a")); err != nil {
				t.Fatalf("network %v: %v", net, err)
			}
		}
		after := tree.snapshot(t)
		changed := map[string]string{}
		for p, v := range after {
			if before[p] != v {
				rel, _ := filepath.Rel(filepath.Dir(tree.root), p)
				changed[rel] = strings.TrimSpace(v)
			}
		}
		want := map[string]string{
			"cgroup/sandboxes/sb-a/memory.oom.group": "1",
			"proc/20/oom_score_adj":                  "500",
			"proc/21/oom_score_adj":                  "500",
			"proc/22/oom_score_adj":                  "500",
		}
		if !maps.Equal(changed, want) {
			t.Fatalf("network %v: changed %v, want %v", net, changed, want)
		}
		if len(r.refused()) != 0 {
			t.Fatalf("refusals %+v", r.refused())
		}
	}
}

// TestCgroupPartLeavesWhatIsNotInTheGroup: a pid the group listed that is
// no longer its process (it exited, or its pid went to a process
// elsewhere) is left alone; only the group's own processes are marked.
func TestCgroupPartLeavesWhatIsNotInTheGroup(t *testing.T) {
	tree := newCgroupTree(t, testSandboxParent+"/_runtime/aerolvm-rootd")
	// 40 exited after the listing; 11 is containerd's, listed when the pid
	// was a sandbox's; 0 is a process this pid namespace cannot see.
	writeTestFile(t, filepath.Join(tree.root, "sandboxes", "sb-a", "cgroup.procs"), "20\n40\n11\n0\n")
	_, c := cgroupRig(t, tree, false)
	if _, err := c.PrepareSandbox(callCtx(t), markReq("sb-a")); err != nil {
		t.Fatal(err)
	}
	if tree.score(t, 20) != "500" || tree.score(t, 11) != "-999" || tree.score(t, 10) != "-999" {
		t.Fatalf("scores: sandbox %s, containerd %s and %s", tree.score(t, 20), tree.score(t, 11), tree.score(t, 10))
	}
}

// TestCgroupPartBrokenAgent: what a compromised agent might ask for is
// refused, recorded as a refusal (or answered as a version skew), and
// writes nothing anywhere.
func TestCgroupPartBrokenAgent(t *testing.T) {
	unknown := protowire.AppendVarint(protowire.AppendTag(nil, 99, protowire.VarintType), 1)
	withUnknown := markReq("sb-a")
	withUnknown.GetCgroup().ProtoReflect().SetUnknown(unknown)
	for _, tc := range []struct {
		name   string
		req    *rootdpb.PrepareSandboxRequest
		code   codes.Code
		reason string // "" when not a refusal
	}{
		// The machinery's groups beside the sandboxes.
		{"containerd's group", markReq("_runtime"), codes.InvalidArgument, string(rootpolicy.RuleCgroup)},
		{"a host-process runtime's group", markReq("aerolvm-wasm"), codes.InvalidArgument, string(rootpolicy.RuleCgroup)},
		// Paths out of the parent, or past the sandbox's own group.
		{"a dot-dot", markReq(".."), codes.InvalidArgument, string(rootpolicy.RuleCgroup)},
		{"a path out of the parent", markReq("../supervisor"), codes.InvalidArgument, string(rootpolicy.RuleCgroup)},
		{"an absolute path", markReq("/sandboxes/sb-a"), codes.InvalidArgument, string(rootpolicy.RuleCgroup)},
		{"the helper's group by path", markReq("_runtime/aerolvm-rootd"), codes.InvalidArgument, string(rootpolicy.RuleCgroup)},
		{"a group below a sandbox's", markReq("sb-a/sub"), codes.InvalidArgument, string(rootpolicy.RuleCgroup)},
		{"no container", markReq(""), codes.InvalidArgument, string(rootpolicy.RuleCgroup)},
		{"no cgroup at all", &rootdpb.PrepareSandboxRequest{Parts: []string{rootdpb.PartCgroup}}, codes.InvalidArgument, ReasonBadRequest},
		// The part comes alone.
		{"with a namespace", &rootdpb.PrepareSandboxRequest{NetnsName: "sb-a", Parts: []string{rootdpb.PartCgroup},
			Cgroup: &rootdpb.SandboxCgroup{ContainerId: "sb-a"}}, codes.InvalidArgument, ReasonBadRequest},
		{"with an address", &rootdpb.PrepareSandboxRequest{ContainerIp: "10.88.0.2", Parts: []string{rootdpb.PartCgroup},
			Cgroup: &rootdpb.SandboxCgroup{ContainerId: "sb-a"}}, codes.InvalidArgument, ReasonBadRequest},
		{"with rules", &rootdpb.PrepareSandboxRequest{Parts: []string{rootdpb.PartCgroup}, Firewall: &rootdpb.SandboxFirewall{},
			Cgroup: &rootdpb.SandboxCgroup{ContainerId: "sb-a"}}, codes.InvalidArgument, ReasonBadRequest},
		{"with another part", &rootdpb.PrepareSandboxRequest{NetnsName: "sb-a", Parts: []string{rootdpb.PartNetns, rootdpb.PartCgroup},
			Cgroup: &rootdpb.SandboxCgroup{ContainerId: "sb-a"}}, codes.InvalidArgument, ReasonBadRequest},
		{"listed twice", &rootdpb.PrepareSandboxRequest{Parts: []string{rootdpb.PartCgroup, rootdpb.PartCgroup},
			Cgroup: &rootdpb.SandboxCgroup{ContainerId: "sb-a"}}, codes.InvalidArgument, ReasonBadRequest},
		{"a cgroup without the part", &rootdpb.PrepareSandboxRequest{NetnsName: "sb-a", Parts: []string{rootdpb.PartNetns},
			Cgroup: &rootdpb.SandboxCgroup{ContainerId: "sb-a"}}, codes.InvalidArgument, ReasonBadRequest},
		// A newer agent's part or field: a version skew, never skipped.
		{"an unknown part", &rootdpb.PrepareSandboxRequest{Parts: []string{rootdpb.PartCgroup, "cgroup-v3"},
			Cgroup: &rootdpb.SandboxCgroup{ContainerId: "sb-a"}}, codes.Unimplemented, ""},
		{"an unknown field", withUnknown, codes.Unimplemented, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := newCgroupTree(t, testSandboxParent+"/_runtime/aerolvm-rootd")
			r, c := cgroupRig(t, tree, true)
			before := tree.snapshot(t)
			_, err := c.PrepareSandbox(callCtx(t), tc.req)
			if tc.reason == "" {
				wantCode(t, err, tc.code)
				if len(r.refused()) != 0 {
					t.Fatalf("a version skew counted as a refusal: %+v", r.refused())
				}
			} else {
				wantRefusal(t, r, err, tc.code, tc.reason)
			}
			if after := tree.snapshot(t); !maps.Equal(before, after) {
				t.Fatal("a refused request changed the tree")
			}
		})
	}
	// ReleaseSandbox has no cgroup part: the runtime removes the group.
	tree := newCgroupTree(t, testSandboxParent+"/_runtime/aerolvm-rootd")
	r, c := cgroupRig(t, tree, true)
	_, err := c.ReleaseSandbox(callCtx(t), &rootdpb.ReleaseSandboxRequest{NetnsName: "sb-a", Parts: []string{rootdpb.PartCgroup}})
	wantRefusal(t, r, err, codes.InvalidArgument, ReasonBadRequest)
}

// TestCgroupPartSparesTheHelper: on a layout where the helper's own group
// is a sandbox-shaped name directly under the parent, marking it is
// refused from what /proc/self/cgroup says, and so is its parent.
func TestCgroupPartSparesTheHelper(t *testing.T) {
	tree := newCgroupTree(t, testSandboxParent+"/sb-b/helper")
	tree.group(t, testSandboxParent+"/sb-b/helper", 50)
	r, c := cgroupRig(t, tree, false)
	before := tree.snapshot(t)
	_, err := c.PrepareSandbox(callCtx(t), markReq("sb-b"))
	wantRefusal(t, r, err, codes.PermissionDenied, string(rootpolicy.RuleCgroup))
	if !maps.Equal(before, tree.snapshot(t)) {
		t.Fatal("the refused mark changed the tree")
	}
	// Another sandbox's group is the agent's to name (plan R9): it gets
	// the values every sandbox has, and nothing beside it changes.
	tree = newCgroupTree(t, testSandboxParent+"/_runtime/aerolvm-rootd")
	_, c = cgroupRig(t, tree, false)
	if _, err := c.PrepareSandbox(callCtx(t), markReq("sb-b")); err != nil {
		t.Fatal(err)
	}
	if tree.oomGroup(t, testSandboxParent+"/sb-b") != "1" || tree.score(t, 30) != "500" ||
		tree.oomGroup(t, testSandboxParent+"/sb-a") != "0" || tree.score(t, 20) != "-999" {
		t.Fatal("marking sb-b reached past it")
	}
}

// TestCgroupPartFailures: a group that is gone is NotFound (the sandbox
// died while it started), not a refusal; a group the helper cannot read
// or write fails the call; a helper with no cgroup parent does not serve
// the part.
func TestCgroupPartFailures(t *testing.T) {
	ctx := callCtx(t)
	tree := newCgroupTree(t, testSandboxParent+"/_runtime/aerolvm-rootd")
	r, c := cgroupRig(t, tree, false)
	_, err := c.PrepareSandbox(ctx, markReq("sb-gone"))
	wantCode(t, err, codes.NotFound)
	if len(r.refused()) != 0 {
		t.Fatal("a gone group counted as a refusal")
	}
	// A file where the group should be; no memory controller (no
	// memory.oom.group); an unreadable process list; a score file that
	// cannot be written.
	writeTestFile(t, filepath.Join(tree.root, "sandboxes", "sb-file"), "")
	tree.group(t, testSandboxParent+"/sb-nomem", 60)
	if err := os.Remove(filepath.Join(tree.root, "sandboxes", "sb-nomem", "memory.oom.group")); err != nil {
		t.Fatal(err)
	}
	tree.group(t, testSandboxParent+"/sb-noprocs")
	if err := os.Remove(filepath.Join(tree.root, "sandboxes", "sb-noprocs", "cgroup.procs")); err != nil {
		t.Fatal(err)
	}
	tree.group(t, testSandboxParent+"/sb-badpid")
	writeTestFile(t, filepath.Join(tree.root, "sandboxes", "sb-badpid", "cgroup.procs"), "x1\n")
	tree.group(t, testSandboxParent+"/sb-noscore", 61)
	if err := os.Remove(filepath.Join(tree.proc, "61", "oom_score_adj")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(tree.proc, "61", "oom_score_adj"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"sb-file", "sb-nomem", "sb-noprocs", "sb-badpid", "sb-noscore"} {
		_, err := c.PrepareSandbox(ctx, markReq(id))
		wantCode(t, err, codes.Internal)
	}
	if len(r.refused()) != 0 {
		t.Fatalf("a failure counted as a refusal: %+v", r.refused())
	}

	// The helper's own group cannot be read, or has no cgroup v2 path:
	// the part fails closed.
	for _, self := range []string{"", "12:memory:/x\n"} {
		bad := newCgroupTree(t, "/x")
		p := filepath.Join(bad.proc, "self", "cgroup")
		if self == "" {
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
		} else {
			writeTestFile(t, p, self)
		}
		_, c := cgroupRig(t, bad, false)
		_, err := c.PrepareSandbox(ctx, markReq("sb-a"))
		wantCode(t, err, codes.Internal)
		if bad.score(t, 20) != "-999" {
			t.Fatal("marked without knowing the helper's own group")
		}
	}

	// No cgroup parent: the part is not served, a version skew, and the
	// helper's network parts still are.
	plain := newRig(t, func(_ *Config, o *Options) { o.Network = newFakeNet() })
	_, err = rootdpb.NewRootHelperClient(plain.conn).PrepareSandbox(ctx, markReq("sb-a"))
	wantCode(t, err, codes.Unimplemented)
	if len(plain.refused()) != 0 {
		t.Fatal("an unserved part counted as a refusal")
	}
	// With a parent and no network, the network parts are not served.
	tree = newCgroupTree(t, "/x")
	_, c = cgroupRig(t, tree, false)
	_, err = c.PrepareSandbox(ctx, &rootdpb.PrepareSandboxRequest{NetnsName: "sb-a", Parts: []string{rootdpb.PartNetns}})
	wantCode(t, err, codes.Unimplemented)
}

// TestCgroupPartStopsWithItsCaller: a walk whose caller gave up stops.
func TestCgroupPartStopsWithItsCaller(t *testing.T) {
	tree := newCgroupTree(t, "/x")
	cg := newSandboxCgroups(Config{Policy: rootpolicy.Policy{CgroupParent: testSandboxParent}}, Options{CgroupRoot: tree.root, ProcRoot: tree.proc}, &keyedLocks{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := cg.markWhole(ctx, testSandboxParent+"/sb-a"); err == nil {
		t.Fatal("a cancelled walk went on")
	}
	if tree.score(t, 20) != "-999" {
		t.Fatal("a cancelled walk marked a process")
	}
	if newSandboxCgroups(Config{}, Options{}, nil) != nil {
		t.Fatal("a helper with no cgroup parent serves the part")
	}
	def := newSandboxCgroups(Config{Policy: rootpolicy.Policy{CgroupParent: testSandboxParent}}, Options{}, nil)
	if def.root != defaultCgroupRoot || def.proc != defaultProcRoot {
		t.Fatalf("kernel roots %q %q", def.root, def.proc)
	}
}

// TestCgroupPartCallsForOneContainerRunInOrder (D11): marks of one
// container never overlap; each takes the container's lock.
func TestCgroupPartCallsForOneContainerRunInOrder(t *testing.T) {
	tree := newCgroupTree(t, "/x")
	_, c := cgroupRig(t, tree, false)
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for range 16 {
		wg.Go(func() {
			_, err := c.PrepareSandbox(callCtx(t), markReq("sb-a"))
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if tree.score(t, 22) != "500" {
		t.Fatal("not marked")
	}
}
