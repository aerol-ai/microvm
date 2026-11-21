package gate

import (
	"context"
	"crypto/sha256"
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	containersapi "github.com/containerd/containerd/api/services/containers/v1"
	tasksapi "github.com/containerd/containerd/api/services/tasks/v1"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// cCreate and tCreate are in regression_test.go.
const cDelete = "/containerd.services.containers.v1.Containers/Delete"

// specBytes is goodSpec for id, changed by mutate, as containerd stores it.
func specBytes(t testing.TB, id string, mutate func(*specs.Spec)) []byte {
	t.Helper()
	s := specFor(t, id)
	if mutate != nil {
		mutate(s)
	}
	return specAny(t, s).GetValue()
}

// withBind adds a read-only bind of an external mount under the mounts root.
func withBind(name string) func(*specs.Spec) {
	return func(s *specs.Spec) {
		s.Mounts = append(s.Mounts, specs.Mount{Type: "bind", Source: testMounts + "/" + testID + "/" + name, Destination: "/" + name, Options: []string{"rbind", "ro"}})
	}
}

func noSeccomp(s *specs.Spec) { s.Linux.Seccomp = nil }

// memoBinds is what the gate's container check reads as c's bind sources
// with the memo's answer for its spec.
func memoBinds(t testing.TB, m *specMemo, c rootpolicy.Container) ([]string, error) {
	t.Helper()
	got, err := rootpolicy.CheckContainerWith(m.policy, c, m.check)
	return got.BindSources, err
}

func recordWith(id string, raw []byte) rootpolicy.Container {
	return rootpolicy.Container{ID: id, Runtime: rootpolicy.Runtime{Name: rootpolicy.RuntimeRunc},
		SpecTypeURL: rootpolicy.SpecTypeURL, Spec: raw, Snapshotter: "overlayfs", SnapshotKey: id}
}

// TestSpecMemoAnswersOnlyForItsBytes: a hit needs the same container ID and
// the same bytes; anything else is decoded and checked in full.
func TestSpecMemoAnswersOnlyForItsBytes(t *testing.T) {
	m := newSpecMemo(testPolicy(), 8, memoEntryBytes)
	good := specBytes(t, testID, nil)
	first, err := m.check(testID, good)
	if err != nil {
		t.Fatal(err)
	}
	if again, err := m.check(testID, slices.Clone(good)); err != nil || again != first {
		t.Fatalf("the same bytes again: %p %v, want the kept answer %p", again, err, first)
	}
	// Other bytes under the same ID: a refused spec is refused, and the
	// pass stays the answer for its own bytes only.
	if _, err := m.check(testID, specBytes(t, testID, noSeccomp)); rootpolicy.RuleOf(err) != rootpolicy.RuleSeccomp {
		t.Fatalf("a spec with no seccomp under a kept ID: %v", err)
	}
	// One byte apart: the JSON has a space where the original has none.
	spaced := append([]byte(" "), good...)
	if f, err := m.check(testID, spaced); err != nil || f == first {
		t.Fatalf("bytes one apart: %p %v; want a fresh check", f, err)
	}
	// The same bytes under another ID: its cgroup names sb-1, so a spec
	// checked for sb-1 is not one for sb-2.
	if _, err := m.check("sb-2", good); rootpolicy.RuleOf(err) != rootpolicy.RuleCgroup {
		t.Fatalf("sb-1's spec for sb-2: %v", err)
	}
	// What a hit hands back says what those bytes say.
	other := specBytes(t, testID, withBind("x"))
	binds, err := memoBinds(t, m, recordWith(testID, other))
	if err != nil || !slices.Contains(binds, testMounts+"/"+testID+"/x") {
		t.Fatalf("binds %v, %v", binds, err)
	}
	binds, err = memoBinds(t, m, recordWith(testID, good))
	if err != nil || slices.Contains(binds, testMounts+"/"+testID+"/x") {
		t.Fatalf("the first spec's binds after another spec under its ID: %v, %v", binds, err)
	}
	if n := m.entries(); n != 1 {
		t.Fatalf("%d entries for one ID", n)
	}
}

// TestSpecMemoIsBounded: a broken agent cannot grow it: one entry per ID,
// a fixed number of IDs (least recently used out first), and no entry for
// a spec whose facts are big.
func TestSpecMemoIsBounded(t *testing.T) {
	p := testPolicy()
	t.Run("IDs", func(t *testing.T) {
		m := newSpecMemo(p, 4, memoEntryBytes)
		ids := []string{"sb-a", "sb-b", "sb-c", "sb-d"}
		raw := map[string][]byte{}
		for _, id := range append(ids, "sb-e", "sb-f") {
			raw[id] = specBytes(t, id, nil)
		}
		for _, id := range ids {
			if _, err := m.check(id, raw[id]); err != nil {
				t.Fatal(err)
			}
		}
		// Touch the oldest, then add two: the two least recently used go.
		if f, _ := m.get("sb-a", sha256.Sum256(raw["sb-a"])); f == nil {
			t.Fatal("sb-a missing")
		}
		for _, id := range []string{"sb-e", "sb-f"} {
			if _, err := m.check(id, raw[id]); err != nil {
				t.Fatal(err)
			}
		}
		if n := m.entries(); n != 4 {
			t.Fatalf("%d entries, bound 4", n)
		}
		for id, want := range map[string]bool{"sb-a": true, "sb-b": false, "sb-c": false, "sb-d": true, "sb-e": true, "sb-f": true} {
			if f, _ := m.get(id, sha256.Sum256(raw[id])); (f != nil) != want {
				t.Errorf("%s kept %v, want %v", id, f != nil, want)
			}
		}
	})
	t.Run("one entry per ID", func(t *testing.T) {
		m := newSpecMemo(p, 4, memoEntryBytes)
		for i := range 50 {
			if _, err := m.check(testID, specBytes(t, testID, withBind(fmt.Sprint(i)))); err != nil {
				t.Fatal(err)
			}
		}
		if n := m.entries(); n != 1 {
			t.Fatalf("%d entries for one ID", n)
		}
	})
	t.Run("big facts", func(t *testing.T) {
		m := newSpecMemo(p, 4, memoEntryBytes)
		big := specBytes(t, testID, func(s *specs.Spec) {
			for i := range 200 {
				withBind(fmt.Sprintf("mount-%03d", i))(s)
			}
		})
		f1, err := m.check(testID, big)
		if err != nil {
			t.Fatal(err)
		}
		if f1.Size() <= memoEntryBytes {
			t.Fatalf("facts of %d bytes are not big; the test needs more binds", f1.Size())
		}
		f2, err := m.check(testID, big)
		if err != nil || f2 == f1 || m.entries() != 0 {
			t.Fatalf("a big spec was kept: %p %p %v, %d entries", f1, f2, err, m.entries())
		}
	})
	t.Run("through the gate", func(t *testing.T) {
		r := newRig(t, p)
		base := string(specAny(t, goodSpec(t)).GetValue())
		for i := range memoEntries + 64 {
			c := goodContainer(t)
			c.ID = fmt.Sprintf("sb-%d", i)
			c.Spec = &anypb.Any{TypeUrl: rootpolicy.SpecTypeURL, Value: []byte(strings.ReplaceAll(base, testID, c.ID))}
			if _, err := r.invoke(nsCtx(), cCreate, &containersapi.CreateContainerRequest{Container: c}); err != nil {
				t.Fatal(err)
			}
		}
		if n := r.gate.specs.entries(); n != memoEntries {
			t.Fatalf("%d entries, bound %d", n, memoEntries)
		}
	})
}

// TestSpecMemoDroppedOnDelete: a delete drops the ID's entry, and a check
// that began before the delete does not put its answer back after it.
func TestSpecMemoDroppedOnDelete(t *testing.T) {
	r := newRig(t, testPolicy())
	if _, err := r.invoke(nsCtx(), cCreate, &containersapi.CreateContainerRequest{Container: goodContainer(t)}); err != nil {
		t.Fatal(err)
	}
	if n := r.gate.specs.entries(); n != 1 {
		t.Fatalf("%d entries after a create", n)
	}
	if _, err := r.invoke(nsCtx(), cDelete, &containersapi.DeleteContainerRequest{ID: testID}); err != nil {
		t.Fatal(err)
	}
	if n := r.gate.specs.entries(); n != 0 {
		t.Fatalf("%d entries after its delete", n)
	}
	if !slices.Contains(r.fake.methodsSeen(), cDelete) || len(r.refused()) != 0 {
		t.Fatalf("the delete did not reach containerd: %v %v", r.fake.methodsSeen(), r.refused())
	}

	m := newSpecMemo(testPolicy(), 8, memoEntryBytes)
	raw := specBytes(t, testID, nil)
	sum := sha256.Sum256(raw)
	facts, drops := m.get(testID, sum)
	if facts != nil {
		t.Fatal("a hit in an empty memo")
	}
	facts, err := rootpolicy.CheckSpecFacts(m.policy, testID, raw)
	if err != nil {
		t.Fatal(err)
	}
	m.drop(testID) // the delete lands while the check runs
	m.put(testID, sum, facts, drops)
	if n := m.entries(); n != 0 {
		t.Fatalf("a check from before the delete put its answer in after it (%d entries)", n)
	}
	_, drops = m.get(testID, sum)
	m.put(testID, sum, facts, drops)
	if n := m.entries(); n != 1 {
		t.Fatalf("a check after the delete was not kept (%d entries)", n)
	}
}

// switchBinds refuses every bind once refuse is set.
type switchBinds struct {
	acceptBinds
	refuse atomic.Bool
}

func (s *switchBinds) CheckBind(root, src string, folder bool) error {
	if s.refuse.Load() {
		return bindViolation(src, "a link now")
	}
	return s.acceptBinds.CheckBind(root, src, folder)
}

// switchReads refuses every path root reads once refuse is set.
type switchReads struct {
	acceptReads
	refuse atomic.Bool
}

func (s *switchReads) CheckRead(r rootpolicy.RootRead) error {
	if s.refuse.Load() {
		return readViolation(r, "writable by the agent now")
	}
	return s.acceptReads.CheckRead(r)
}

// switchNetns vouches for each container's own namespace until refuse.
type switchNetns struct{ refuse atomic.Bool }

func (s *switchNetns) Bound(_ context.Context, netns, id string) (bool, error) {
	return !s.refuse.Load() && netns == id, nil
}

// TestSpecMemoAtTaskCreate: Tasks.Create checks the container containerd
// stored. The memo answers for the stored spec only when it is the bytes
// checked at create; the on-disk checks run every time.
func TestSpecMemoAtTaskCreate(t *testing.T) {
	task := &tasksapi.CreateTaskRequest{ContainerID: testID, Rootfs: overlayRootfs()}
	create := func(t *testing.T, r *rig, c *containersapi.Container) {
		t.Helper()
		if _, err := r.invoke(nsCtx(), cCreate, &containersapi.CreateContainerRequest{Container: c}); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("the stored spec is the one checked: a hit, disk checked again", func(t *testing.T) {
		binds := &switchBinds{}
		reads := &switchReads{}
		netns := &switchNetns{}
		r := newRig(t, testPolicy(), func(c *Config) { c.Binds, c.Reads, c.NetnsBinding = binds, reads, netns })
		c := goodRunscContainer(t)
		create(t, r, c)
		kept, _ := r.gate.specs.get(testID, sha256.Sum256(c.GetSpec().GetValue()))
		if kept == nil {
			t.Fatal("the create's answer was not kept")
		}
		r.storedContainer(c)
		if _, err := r.invoke(nsCtx(), tCreate, task); err != nil {
			t.Fatal(err)
		}
		if again, _ := r.gate.specs.get(testID, sha256.Sum256(c.GetSpec().GetValue())); again != kept {
			t.Fatal("the task create decoded the spec again; want the kept answer")
		}
		binds.mu.Lock()
		seen := len(binds.seen)
		binds.mu.Unlock()
		if want := 2 * 2; seen != want { // goodSpec binds two paths, checked at each call
			t.Fatalf("%d bind checks on disk, want %d", seen, want)
		}
		reads.mu.Lock()
		readsSeen := len(reads.seen)
		reads.mu.Unlock()
		if readsSeen != 2 { // the runsc config, at each call
			t.Fatalf("%d read checks on disk, want 2", readsSeen)
		}
		// containerd has seen one task create; a refused one must not reach it.
		refusedAgain := func(rule rootpolicy.Rule) {
			t.Helper()
			before := len(r.fake.seen())
			_, err := r.invoke(nsCtx(), tCreate, task)
			if got, ok := rootdpb.RefusalReason(err); !ok || got != string(rule) {
				t.Fatalf("err %v, want a %s refusal", err, rule)
			}
			for _, c := range r.fake.seen()[before:] {
				if c.method == tCreate {
					t.Fatal("containerd saw the refused task create")
				}
			}
		}
		// A bind source swapped for a link after the create.
		binds.refuse.Store(true)
		refusedAgain(rootpolicy.RuleMount)
		// The runsc config made writable by the agent.
		binds.refuse.Store(false)
		reads.refuse.Store(true)
		refusedAgain(rootpolicy.RuleRuntimeOptions)
		// The namespace no longer the helper's.
		reads.refuse.Store(false)
		netns.refuse.Store(true)
		refusedAgain(rootpolicy.RuleHostNamespace)
	})
	t.Run("containerd holds other bytes under the ID", func(t *testing.T) {
		r := newRig(t, testPolicy())
		create(t, r, goodContainer(t))
		swapped := goodContainer(t)
		s := goodSpec(t)
		s.Linux.Seccomp = nil
		swapped.Spec = specAny(t, s)
		r.storedContainer(swapped)
		_, err := r.invoke(nsCtx(), tCreate, task)
		r.wantRefused(err, tCreate, string(rootpolicy.RuleSeccomp))
	})
	t.Run("delete and create again under the ID", func(t *testing.T) {
		r := newRig(t, testPolicy())
		create(t, r, goodContainer(t))
		if _, err := r.invoke(nsCtx(), cDelete, &containersapi.DeleteContainerRequest{ID: testID}); err != nil {
			t.Fatal(err)
		}
		again := goodContainer(t)
		s := goodSpec(t)
		withBind("again")(s)
		again.Spec = specAny(t, s)
		create(t, r, again)
		r.storedContainer(again)
		r.binds.mu.Lock()
		r.binds.seen = nil
		r.binds.mu.Unlock()
		if _, err := r.invoke(nsCtx(), tCreate, task); err != nil {
			t.Fatal(err)
		}
		r.binds.mu.Lock()
		defer r.binds.mu.Unlock()
		if !slices.ContainsFunc(r.binds.seen, func(b [2]string) bool { return b[1] == testMounts+"/"+testID+"/again" }) {
			t.Fatalf("the task create checked %v, not the new container's binds", r.binds.seen)
		}
	})
}

// TestSpecMemoUnderRace: checks of different specs under one ID, deletes
// of it and creates of other IDs (pushing it out), all at once. Every
// answer is the one its own bytes give. Run with -race.
func TestSpecMemoUnderRace(t *testing.T) {
	p := testPolicy()
	m := newSpecMemo(p, 4, memoEntryBytes)
	a, b := specBytes(t, testID, withBind("a")), specBytes(t, testID, withBind("b"))
	bad := specBytes(t, testID, noSeccomp)
	others := make([][]byte, 6)
	for i := range others {
		others[i] = specBytes(t, fmt.Sprintf("sb-o%d", i), nil)
	}
	has := func(binds []string, name string) bool { return slices.Contains(binds, testMounts+"/"+testID+"/"+name) }
	var wg sync.WaitGroup
	var failures atomic.Int32
	fail := func(format string, args ...any) {
		if failures.Add(1) < 5 {
			t.Errorf(format, args...)
		}
	}
	for w := range 16 {
		wg.Go(func() {
			rng := rand.New(rand.NewPCG(uint64(w), 7))
			for range 300 {
				switch rng.IntN(5) {
				case 0:
					if binds, err := memoBinds(t, m, recordWith(testID, a)); err != nil || !has(binds, "a") || has(binds, "b") {
						fail("spec a: %v %v", binds, err)
					}
				case 1:
					if binds, err := memoBinds(t, m, recordWith(testID, b)); err != nil || !has(binds, "b") || has(binds, "a") {
						fail("spec b: %v %v", binds, err)
					}
				case 2:
					if _, err := memoBinds(t, m, recordWith(testID, bad)); rootpolicy.RuleOf(err) != rootpolicy.RuleSeccomp {
						fail("the bad spec: %v", err)
					}
				case 3:
					m.drop(testID)
				case 4:
					i := rng.IntN(len(others))
					if _, err := m.check(fmt.Sprintf("sb-o%d", i), others[i]); err != nil {
						fail("other %d: %v", i, err)
					}
				}
			}
		})
	}
	wg.Wait()
	if n := m.entries(); n > 4 {
		t.Fatalf("%d entries, bound 4", n)
	}
}

// TestGateWithoutMemo: a Gate not made by New checks with rootpolicy's own
// decode, and a delete through it drops nothing.
func TestGateWithoutMemo(t *testing.T) {
	g := &Gate{policy: testPolicy(), binds: &acceptBinds{}, reads: &acceptReads{}}
	if err := g.checkContainer(context.Background(), policyContainer(goodContainer(t))); err != nil {
		t.Fatal(err)
	}
	if err := checkContainerDelete(context.Background(), g, &containersapi.DeleteContainerRequest{ID: testID}); err != nil {
		t.Fatal(err)
	}
}

// FuzzSpecMemo: two specs checked under one ID in turn, the first again
// at the end (a hit, when it passed). Every answer is the one a fresh
// check of those bytes gives, facts included.
func FuzzSpecMemo(f *testing.F) {
	good := specBytes(f, testID, nil)
	f.Add(good, specBytes(f, testID, withBind("x")))
	f.Add(good, specBytes(f, testID, noSeccomp))
	f.Add(specBytes(f, testID, noSeccomp), good)
	f.Add(good, append([]byte(" "), good...))
	p := testPolicy()
	f.Fuzz(func(t *testing.T, a, b []byte) {
		m := newSpecMemo(p, 2, memoEntryBytes)
		for _, raw := range [][]byte{a, b, a} {
			c := recordWith(testID, raw)
			want, wantErr := rootpolicy.CheckContainerWith(p, c, nil)
			got, err := rootpolicy.CheckContainerWith(p, c, m.check)
			if rootpolicy.RuleOf(err) != rootpolicy.RuleOf(wantErr) || (err == nil) != (wantErr == nil) {
				t.Fatalf("memo %v, fresh %v", err, wantErr)
			}
			if !slices.Equal(got.BindSources, want.BindSources) || !slices.Equal(got.RootReads, want.RootReads) || got.Netns != want.Netns {
				t.Fatalf("memo %+v, fresh %+v", got, want)
			}
		}
	})
}
