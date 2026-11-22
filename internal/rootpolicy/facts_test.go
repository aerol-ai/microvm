package rootpolicy

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"slices"
	"sync"
	"testing"

	runcoptions "github.com/containerd/containerd/api/types/runc/options"
	runtimeoptions "github.com/containerd/containerd/api/types/runtimeoptions/v1"
	"github.com/containerd/containerd/v2/contrib/seccomp"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"google.golang.org/protobuf/proto"
)

// factContainers are container records CheckContainer passes, one of each
// shape whose facts differ.
func factContainers(t *testing.T) map[string]Container {
	t.Helper()
	gv := baselineContainer(t, gvisorSpec(t))
	gv.Runtime = runscRuntime(t, &runtimeoptions.Options{TypeUrl: RunscOptionsTypeURL, ConfigPath: testRestore})
	own := baselineSpec(t)
	for i := range own.Linux.Namespaces {
		own.Linux.Namespaces[i].Path = ""
	}
	criu := baselineContainer(t, baselineSpec(t))
	b, err := proto.Marshal(&runcoptions.Options{CriuImagePath: testMoves + "/a", CriuWorkPath: testMoves + "/w"})
	if err != nil {
		t.Fatal(err)
	}
	criu.Runtime = Runtime{Name: RuntimeRunc, OptionsTypeURL: "containerd.runc.v1.Options", Options: b}
	return map[string]Container{
		"runc in a pooled namespace":  baselineContainer(t, baselineSpec(t)),
		"gVisor restored from a move": gv,
		"a namespace of its own":      baselineContainer(t, own),
		"runc checkpoint folders":     criu,
	}
}

// TestCheckContainerWithMatchesItsParts: the one decode answers what the
// separate readers answer, each of which decodes on its own.
func TestCheckContainerWithMatchesItsParts(t *testing.T) {
	p := testPolicy()
	for name, c := range factContainers(t) {
		t.Run(name, func(t *testing.T) {
			binds, err := SpecBindSources(c)
			if err != nil {
				t.Fatal(err)
			}
			reads, err := ContainerRootReads(c)
			if err != nil {
				t.Fatal(err)
			}
			netns, err := ContainerNetns(c)
			if err != nil {
				t.Fatal(err)
			}
			viaFacts := func(id string, raw []byte) (*SpecFacts, error) { return CheckSpecFacts(p, id, raw) }
			for how, spec := range map[string]SpecCheck{"rootpolicy's own": nil, "a stand-in": viaFacts} {
				got, err := CheckContainerWith(p, c, spec)
				if err != nil {
					t.Fatalf("%s: %v", how, err)
				}
				if !slices.Equal(got.BindSources, binds) || !slices.Equal(got.RootReads, reads) || got.Netns != netns {
					t.Fatalf("%s: got %+v, want binds %v reads %v netns %q", how, got, binds, reads, netns)
				}
			}
		})
	}
}

// TestCheckContainerWithRefusesAsCheckContainer: the record's checks still
// come first, the spec's last, and every refusal names the same rule.
func TestCheckContainerWithRefusesAsCheckContainer(t *testing.T) {
	p := testPolicy()
	base := func() Container { return baselineContainer(t, baselineSpec(t)) }
	withSpec := func(mutate func(*specs.Spec)) Container {
		s := baselineSpec(t)
		mutate(s)
		return baselineContainer(t, s)
	}
	for _, tc := range []struct {
		name string
		c    Container
		rule Rule
	}{
		{"bad ID", func() Container { c := base(); c.ID = "../x"; return c }(), RuleID},
		{"containerd's label", func() Container {
			c := base()
			c.Labels = map[string]string{"containerd.io/restart.loguri": "binary:///x"}
			return c
		}(), RuleLabel},
		{"another snapshotter", func() Container { c := base(); c.Snapshotter = "native"; return c }(), RuleSnapshotter},
		{"an extension", func() Container { c := base(); c.Extensions = []string{"x"}; return c }(), RuleField},
		{"a containerd sandbox", func() Container { c := base(); c.Sandbox = "s"; return c }(), RuleRuntime},
		{"another runtime", func() Container { c := base(); c.Runtime.Name = "io.containerd.kata.v2"; return c }(), RuleRuntime},
		{"another spec type", func() Container { c := base(); c.SpecTypeURL = "x"; return c }(), RuleSpec},
		{"a spec that does not decode", func() Container { c := base(); c.Spec = []byte("{"); return c }(), RuleSpec},
		{"a hook", withSpec(func(s *specs.Spec) { s.Hooks = &specs.Hooks{} }), RuleHook},
		{"a bind of /", withSpec(func(s *specs.Spec) {
			s.Mounts = append(s.Mounts, specs.Mount{Type: "bind", Source: "/", Destination: "/h", Options: []string{"rbind"}})
		}), RuleMount},
		{"another container's cgroup", withSpec(func(s *specs.Spec) { s.Linux.CgroupsPath = "/aerolvm/sb-2" }), RuleCgroup},
		{"a restore image outside moves", withSpec(func(s *specs.Spec) { s.Annotations = map[string]string{RestoreAnnotation: "/etc"} }), RuleCheckpoint},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wantRule(t, CheckContainer(p, tc.c), tc.rule)
			_, err := CheckContainerWith(p, tc.c, nil)
			wantRule(t, err, tc.rule)
		})
	}
}

// TestCheckContainerWithStandIns: a stand-in's error is the answer; one
// that answers nothing fails closed; and the record is checked before the
// stand-in is asked at all.
func TestCheckContainerWithStandIns(t *testing.T) {
	p := testPolicy()
	c := baselineContainer(t, baselineSpec(t))
	boom := errors.New("boom")
	if _, err := CheckContainerWith(p, c, func(string, []byte) (*SpecFacts, error) { return nil, boom }); !errors.Is(err, boom) {
		t.Fatalf("err %v, want the stand-in's", err)
	}
	_, err := CheckContainerWith(p, c, func(string, []byte) (*SpecFacts, error) { return nil, nil })
	wantRule(t, err, RuleSpec)
	asked := false
	bad := c
	bad.Snapshotter = "native"
	_, err = CheckContainerWith(p, bad, func(string, []byte) (*SpecFacts, error) { asked = true; return &SpecFacts{}, nil })
	wantRule(t, err, RuleSnapshotter)
	if asked {
		t.Fatal("the spec check ran for a record that failed")
	}
	// What the caller gets is its own: changing it changes no shared facts.
	facts, err := CheckSpecFacts(p, c.ID, c.Spec)
	if err != nil {
		t.Fatal(err)
	}
	shared := func(string, []byte) (*SpecFacts, error) { return facts, nil }
	got, err := CheckContainerWith(p, c, shared)
	if err != nil {
		t.Fatal(err)
	}
	got.BindSources[0] = "/"
	again, _ := CheckContainerWith(p, c, shared)
	if again.BindSources[0] == "/" {
		t.Fatal("a caller's change reached the shared facts")
	}
}

// TestCheckSpecFactsAgreesWithCheckSpecJSON: the facts' check is the spec
// check, rule for rule.
func TestCheckSpecFactsAgreesWithCheckSpecJSON(t *testing.T) {
	p := testPolicy()
	specsToTry := []*specs.Spec{baselineSpec(t), gvisorSpec(t)}
	for _, mutate := range []func(*specs.Spec){
		func(s *specs.Spec) { s.Linux.Seccomp = nil },
		func(s *specs.Spec) { s.Process.NoNewPrivileges = false },
		func(s *specs.Spec) { s.Linux.CgroupsPath = "/aerolvm/sb-2" },
		func(s *specs.Spec) {
			s.Mounts = append(s.Mounts, specs.Mount{Type: "bind", Source: "/etc", Destination: "/e", Options: []string{"rbind"}})
		},
	} {
		s := baselineSpec(t)
		mutate(s)
		specsToTry = append(specsToTry, s)
	}
	for i, s := range specsToTry {
		raw := specJSON(t, s)
		want := CheckSpecJSON(p, testID, raw)
		facts, err := CheckSpecFacts(p, testID, raw)
		if RuleOf(err) != RuleOf(want) || (err == nil) != (want == nil) {
			t.Fatalf("spec %d: facts err %v, CheckSpecJSON %v", i, err, want)
		}
		if err == nil && facts == nil {
			t.Fatalf("spec %d: a pass with no facts", i)
		}
	}
	for name, err := range map[string]error{"CheckSpecFacts": func() error { _, err := CheckSpecFacts(p, testID, []byte("{")); return err }(),
		"CheckSpecJSON": CheckSpecJSON(p, testID, []byte("{"))} {
		if RuleOf(err) != RuleSpec {
			t.Fatalf("%s of a spec that does not decode: %v", name, err)
		}
	}
}

func TestSpecFactsSize(t *testing.T) {
	f := &SpecFacts{bindSources: []string{"/a", "/bc"}, restore: "/r", netns: "n"}
	if got := f.Size(); got != 2+16+3+16+2+1 {
		t.Fatalf("size %d", got)
	}
}

// TestPolicyCloneOwnsItsLists: every list in a Policy is copied, so a
// caller changing its own policy after handing it over changes nothing in
// the clone. Reflection, so a list field added later is held to it too.
func TestPolicyCloneOwnsItsLists(t *testing.T) {
	var p Policy
	v := reflect.ValueOf(&p).Elem()
	for i := range v.NumField() {
		f := v.Field(i)
		switch f.Kind() {
		case reflect.Slice:
			f.Set(reflect.ValueOf([]string{"/orig"}))
		case reflect.Map, reflect.Pointer:
			t.Fatalf("Policy.%s is a %s; Clone must copy it", v.Type().Field(i).Name, f.Kind())
		}
	}
	c := p.Clone()
	if !reflect.DeepEqual(c, p) {
		t.Fatalf("the clone differs: %+v", c)
	}
	cv := reflect.ValueOf(&c).Elem()
	for i := range cv.NumField() {
		if cv.Field(i).Kind() == reflect.Slice {
			cv.Field(i).Index(0).SetString("/changed")
		}
	}
	for i := range v.NumField() {
		if f := v.Field(i); f.Kind() == reflect.Slice && f.Index(0).String() != "/orig" {
			t.Fatalf("Policy.%s shares its list with the clone", v.Type().Field(i).Name)
		}
	}
}

func directProfileJSON(t *testing.T, bounding []string) []byte {
	t.Helper()
	b, err := json.Marshal(seccomp.DefaultProfile(&specs.Spec{Process: &specs.Process{Capabilities: &specs.LinuxCapabilities{Bounding: bounding}}}))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestDefaultProfileMemo: the memo answers what building the profile
// answers, for sets whose names run together, in either order of first
// use; it stays bounded; and parallel checks agree.
func TestDefaultProfileMemo(t *testing.T) {
	sandbox := SandboxCapabilities()
	noChroot := slices.DeleteFunc(slices.Clone(sandbox), func(c string) bool { return c == "CAP_SYS_CHROOT" })
	sets := [][]string{
		// "CAP_SYS_" + "CHROOT" spells CAP_SYS_CHROOT run together.
		{"CAP_SYS_", "CHROOT"}, {"CAP_SYS_CHROOT"},
		nil, {}, sandbox, noChroot, privilegedCapabilities(),
	}
	for round := range 2 {
		for i, set := range sets {
			if got, want := defaultProfileJSON(set), directProfileJSON(t, set); string(got) != string(want) {
				t.Fatalf("round %d set %d %v: the memo's profile differs", round, i, set)
			}
		}
	}
	if runtime.GOOS == "linux" && string(defaultProfileJSON(sandbox)) == string(defaultProfileJSON(noChroot)) {
		t.Fatal("the profile does not depend on CAP_SYS_CHROOT; this test no longer tells sets apart")
	}
	for i := range 3 * maxDefaultProfiles {
		defaultProfileJSON([]string{fmt.Sprintf("CAP_%d", i)})
		defaultProfiles.Lock()
		n := len(defaultProfiles.json)
		defaultProfiles.Unlock()
		if n > maxDefaultProfiles {
			t.Fatalf("%d sets kept, bound %d", n, maxDefaultProfiles)
		}
	}
	var wg sync.WaitGroup
	for i := range 32 {
		wg.Go(func() {
			set := sets[i%len(sets)]
			if string(defaultProfileJSON(set)) != string(directProfileJSON(t, set)) {
				t.Errorf("set %v: a parallel check got another profile", set)
			}
		})
	}
	wg.Wait()
	// A spec carrying the profile of another set is refused, memo or not.
	s := baselineSpec(t)
	s.Linux.Seccomp = seccomp.DefaultProfile(&specs.Spec{Process: &specs.Process{Capabilities: &specs.LinuxCapabilities{Bounding: noChroot}}})
	wantRule(t, CheckSpec(testPolicy(), testID, s), seccompRuleOnLinux())
}

// FuzzCheckContainerWith: whatever the spec bytes, the one-decode check
// passes and refuses exactly as CheckContainer, and its facts are what the
// separate readers find.
func FuzzCheckContainerWith(f *testing.F) {
	f.Add(specJSON(f, baselineSpec(f)))
	f.Add(specJSON(f, gvisorSpec(f)))
	s := baselineSpec(f)
	s.Linux.Seccomp = nil
	f.Add(specJSON(f, s))
	p := testPolicy()
	f.Fuzz(func(t *testing.T, raw []byte) {
		c := baselineContainer(t, baselineSpec(t))
		c.Spec = raw
		want := CheckContainer(p, c)
		got, err := CheckContainerWith(p, c, nil)
		if RuleOf(err) != RuleOf(want) || (err == nil) != (want == nil) {
			t.Fatalf("CheckContainerWith %v, CheckContainer %v", err, want)
		}
		if err != nil {
			return
		}
		binds, _ := SpecBindSources(c)
		reads, _ := ContainerRootReads(c)
		netns, _ := ContainerNetns(c)
		if !slices.Equal(got.BindSources, binds) || !slices.Equal(got.RootReads, reads) || got.Netns != netns {
			t.Fatalf("facts %+v, want binds %v reads %v netns %q", got, binds, reads, netns)
		}
	})
}
