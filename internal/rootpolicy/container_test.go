package rootpolicy

import (
	"runtime"
	"strings"
	"testing"

	runcoptions "github.com/containerd/containerd/api/types/runc/options"
	runtimeoptions "github.com/containerd/containerd/api/types/runtimeoptions/v1"
	"github.com/containerd/containerd/v2/defaults"
	"github.com/containerd/typeurl/v2"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	// Registers the OCI spec types with typeurl, as the agent's client does.
	_ "github.com/containerd/containerd/v2/client"
)

func TestSharedNames(t *testing.T) {
	// containerd's default runtime is per platform; sandboxes run on Linux.
	if runtime.GOOS == "linux" && RuntimeRunc != defaults.DefaultRuntime {
		t.Fatalf("RuntimeRunc %q, containerd's default runtime %q", RuntimeRunc, defaults.DefaultRuntime)
	}
	for _, tc := range []struct {
		v    any
		want string
	}{{&specs.Spec{}, SpecTypeURL}, {&specs.LinuxResources{}, ResourcesTypeURL}} {
		got, err := typeurl.TypeURL(tc.v)
		if err != nil || got != tc.want {
			t.Fatalf("typeurl of %T = %q, %v; want %q", tc.v, got, err, tc.want)
		}
	}
	for _, c := range DroppedCapabilities() {
		for _, k := range SandboxCapabilities() {
			if c == k {
				t.Fatalf("%s is both granted and dropped", c)
			}
		}
	}
}

func runcRuntime(t *testing.T, o *runcoptions.Options) Runtime {
	t.Helper()
	b, err := proto.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	return Runtime{Name: RuntimeRunc, OptionsTypeURL: "containerd.runc.v1.Options", Options: b}
}

func TestCheckRuntime(t *testing.T) {
	allowRunc := testPolicy()
	allowRunc.RuncBinaryNames = []string{"/usr/bin/runc"}
	allowRunc.RuncRoots = []string{"/run/containerd/runc"}
	allowRunc.RuncShimCgroups = []string{"/aerolvm-shims"}
	withUnknown := func(r Runtime) Runtime {
		r.Options = protowire.AppendTag(append([]byte(nil), r.Options...), 99, protowire.VarintType)
		r.Options = protowire.AppendVarint(r.Options, 1)
		return r
	}
	for _, tc := range []struct {
		name string
		p    Policy
		r    Runtime
		rule Rule // "" means allowed
	}{
		{"runc with no options", testPolicy(), Runtime{Name: RuntimeRunc}, ""},
		{"runc with empty options", testPolicy(), runcRuntime(t, &runcoptions.Options{}), ""},
		{"runc BinaryName /bin/sh", testPolicy(), runcRuntime(t, &runcoptions.Options{BinaryName: "/bin/sh"}), RuleRuntimeOptions},
		{"runc BinaryName the helper allows", allowRunc, runcRuntime(t, &runcoptions.Options{BinaryName: "/usr/bin/runc"}), ""},
		{"runc Root elsewhere", allowRunc, runcRuntime(t, &runcoptions.Options{Root: "/"}), RuleRuntimeOptions},
		{"runc Root the helper allows", allowRunc, runcRuntime(t, &runcoptions.Options{Root: "/run/containerd/runc"}), ""},
		{"runc ShimCgroup", testPolicy(), runcRuntime(t, &runcoptions.Options{ShimCgroup: "/"}), RuleRuntimeOptions},
		{"runc ShimCgroup the helper allows", allowRunc, runcRuntime(t, &runcoptions.Options{ShimCgroup: "/aerolvm-shims"}), ""},
		{"runc CRIU image path outside moves", testPolicy(), runcRuntime(t, &runcoptions.Options{CriuImagePath: "/etc"}), RuleCheckpoint},
		{"runc CRIU work path outside moves", testPolicy(), runcRuntime(t, &runcoptions.Options{CriuWorkPath: "/root"}), RuleCheckpoint},
		{"runc CRIU image path in moves", testPolicy(), runcRuntime(t, &runcoptions.Options{CriuImagePath: testMoves + "/out/sb-1"}), ""},
		{"runc no pivot root", testPolicy(), runcRuntime(t, &runcoptions.Options{NoPivotRoot: true}), RuleRuntimeOptions},
		{"runc systemd cgroup", testPolicy(), runcRuntime(t, &runcoptions.Options{SystemdCgroup: true}), RuleRuntimeOptions},
		{"runc IO uid", testPolicy(), runcRuntime(t, &runcoptions.Options{IoUid: 1}), RuleRuntimeOptions},
		{"runc task API address", testPolicy(), runcRuntime(t, &runcoptions.Options{TaskApiAddress: "/tmp/x.sock"}), RuleRuntimeOptions},
		{"runc options of the wrong type", testPolicy(), Runtime{Name: RuntimeRunc, OptionsTypeURL: "runtimeoptions.v1.Options"}, RuleRuntimeOptions},
		{"runc options that do not decode", testPolicy(), Runtime{Name: RuntimeRunc, OptionsTypeURL: "containerd.runc.v1.Options", Options: []byte{0xff}}, RuleRuntimeOptions},
		{"runc options with an unknown field", testPolicy(), withUnknown(runcRuntime(t, &runcoptions.Options{})), RuleRuntimeOptions},
		{"runsc with the helper's config", testPolicy(), runscRuntime(t, &runtimeoptions.Options{TypeUrl: RunscOptionsTypeURL, ConfigPath: testRunscCfg}), ""},
		{"runsc with the restore config", testPolicy(), runscRuntime(t, &runtimeoptions.Options{TypeUrl: RunscOptionsTypeURL, ConfigPath: testRestore}), ""},
		{"runsc options under a googleapis URL", testPolicy(), func() Runtime {
			r := runscRuntime(t, &runtimeoptions.Options{TypeUrl: RunscOptionsTypeURL, ConfigPath: testRunscCfg})
			r.OptionsTypeURL = "type.googleapis.com/runtimeoptions.v1.Options"
			return r
		}(), ""},
		{"runsc ConfigPath elsewhere", testPolicy(), runscRuntime(t, &runtimeoptions.Options{TypeUrl: RunscOptionsTypeURL, ConfigPath: "/tmp/runsc.toml"}), RuleRuntimeOptions},
		{"runsc inline ConfigBody", testPolicy(), runscRuntime(t, &runtimeoptions.Options{TypeUrl: RunscOptionsTypeURL, ConfigPath: testRunscCfg, ConfigBody: []byte("network = \"host\"")}), RuleRuntimeOptions},
		{"runsc with no config", testPolicy(), runscRuntime(t, &runtimeoptions.Options{TypeUrl: RunscOptionsTypeURL}), RuleRuntimeOptions},
		{"runsc inner type wrong", testPolicy(), runscRuntime(t, &runtimeoptions.Options{TypeUrl: "x", ConfigPath: testRunscCfg}), RuleRuntimeOptions},
		{"runsc with no options", testPolicy(), Runtime{Name: RuntimeRunsc}, RuleRuntimeOptions},
		{"runsc with runc options", testPolicy(), func() Runtime {
			r := runcRuntime(t, &runcoptions.Options{})
			r.Name = RuntimeRunsc
			return r
		}(), RuleRuntimeOptions},
		{"kata", testPolicy(), Runtime{Name: "io.containerd.kata.v2"}, RuleRuntime},
		{"runc v1 shim", testPolicy(), Runtime{Name: "io.containerd.runc.v1"}, RuleRuntime},
		{"no runtime", testPolicy(), Runtime{}, RuleRuntime},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckRuntime(tc.p, tc.r)
			if tc.rule == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			wantRule(t, err, tc.rule)
		})
	}
}

func TestCheckContainer(t *testing.T) {
	gv := baselineContainer(t, gvisorSpec(t))
	gv.Runtime = runscRuntime(t, &runtimeoptions.Options{TypeUrl: RunscOptionsTypeURL, ConfigPath: testRestore})
	for _, c := range []Container{baselineContainer(t, baselineSpec(t)), gv} {
		if err := CheckContainer(testPolicy(), c); err != nil {
			t.Fatalf("baseline container %s refused: %v", c.Runtime.Name, err)
		}
	}
	for _, tc := range []struct {
		name   string
		mutate func(*Container)
		rule   Rule
	}{
		{"ID with ../", func(c *Container) { c.ID = "../etc" }, RuleID},
		{"restart monitor label", func(c *Container) { c.Labels = map[string]string{"containerd.io/restart.loguri": "binary:///bin/sh"} }, RuleLabel},
		{"another snapshotter", func(c *Container) { c.Snapshotter = "native" }, RuleSnapshotter},
		{"extensions", func(c *Container) { c.Extensions = []string{"x"} }, RuleField},
		{"a containerd sandbox", func(c *Container) { c.Sandbox = "sbx" }, RuleRuntime},
		{"kata runtime", func(c *Container) { c.Runtime = Runtime{Name: "io.containerd.kata.v2"} }, RuleRuntime},
		{"spec under another type", func(c *Container) { c.SpecTypeURL = "types.containerd.io/opencontainers/runtime-spec/1/Process" }, RuleSpec},
		{"spec that does not decode", func(c *Container) { c.Spec = []byte("not json") }, RuleSpec},
		{"spec with a field this build does not know", func(c *Container) {
			c.Spec = []byte(strings.Replace(string(c.Spec), `"ociVersion"`, `"futureField":1,"ociVersion"`, 1))
		}, RuleSpec},
		{"spec of another container's cgroup", func(c *Container) { c.ID = "sb-2" }, RuleCgroup},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := baselineContainer(t, baselineSpec(t))
			tc.mutate(&c)
			wantRule(t, CheckContainer(testPolicy(), c), tc.rule)
		})
	}
}

func TestCheckContainerUpdate(t *testing.T) {
	for _, tc := range []struct {
		name  string
		paths []string
		rule  Rule
	}{
		{"one label", []string{"labels.aerolvm.sandbox_id"}, ""},
		{"all labels", []string{"labels"}, ""},
		{"no mask replaces the record", nil, RuleUpdate},
		{"spec", []string{"labels.x", "spec"}, RuleUpdate},
		{"runtime", []string{"runtime"}, RuleUpdate},
		{"snapshot key", []string{"snapshotkey"}, RuleUpdate},
		{"restart monitor label", []string{"labels.containerd.io/restart.status"}, RuleLabel},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckContainerUpdate(tc.paths)
			if tc.rule == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			wantRule(t, err, tc.rule)
		})
	}
}

func TestValidateID(t *testing.T) {
	for id, want := range map[string]string{
		"sb-1_A":                 "",
		"":                       "sandbox ID is required",
		strings.Repeat("a", 129): "exceeds 128",
		"a/b":                    "invalid character",
		"..":                     "invalid character",
		"sb 1":                   "invalid character",
	} {
		err := ValidateID(id)
		if want == "" {
			if err != nil {
				t.Errorf("ValidateID(%q) = %v", id, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), want) || RuleOf(err) != RuleID {
			t.Errorf("ValidateID(%q) = %v, want %q", id, err, want)
		}
	}
}

func TestContainerNetns(t *testing.T) {
	if name, err := ContainerNetns(baselineContainer(t, baselineSpec(t))); err != nil || name != testID {
		t.Fatalf("netns %q, %v", name, err)
	}
	fresh := baselineSpec(t)
	for i := range fresh.Linux.Namespaces {
		fresh.Linux.Namespaces[i].Path = ""
	}
	if name, err := ContainerNetns(baselineContainer(t, fresh)); err != nil || name != "" {
		t.Fatalf("a sandbox with its own netns: %q, %v", name, err)
	}
	noLinux := baselineSpec(t)
	noLinux.Linux = nil
	if name, err := ContainerNetns(baselineContainer(t, noLinux)); err != nil || name != "" {
		t.Fatalf("no linux section: %q, %v", name, err)
	}
	c := baselineContainer(t, baselineSpec(t))
	c.Spec = []byte("{")
	if _, err := ContainerNetns(c); RuleOf(err) != RuleSpec {
		t.Fatalf("bad spec: %v", err)
	}
}

func TestNamespaceChecks(t *testing.T) {
	if err := CheckNamespace(testPolicy(), "aerolvm"); err != nil {
		t.Fatal(err)
	}
	wantRule(t, CheckNamespace(testPolicy(), "k8s.io"), RuleNamespace)
	wantRule(t, CheckNamespace(testPolicy(), ""), RuleNamespace)
	if err := CheckNamespaceLabels(map[string]string{"owner": "aerolvm"}); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"containerd.io/defaults/runtime", "containerd.io/defaults/snapshotter", "containerd.io/defaults/sandboxer"} {
		wantRule(t, CheckNamespaceLabels(map[string]string{k: "x"}), RuleNamespace)
	}
	if RuleOf(nil) != "" {
		t.Fatal("RuleOf(nil)")
	}
}
