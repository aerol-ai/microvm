package rootpolicy

import (
	"runtime"
	"strings"
	"testing"

	"github.com/containerd/containerd/v2/contrib/seccomp"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func TestBaselineSpecsPass(t *testing.T) {
	for name, s := range map[string]*specs.Spec{"runc": baselineSpec(t), "gvisor restore": gvisorSpec(t)} {
		t.Run(name, func(t *testing.T) {
			if err := CheckSpec(testPolicy(), testID, s); err != nil {
				t.Fatalf("baseline refused: %v", err)
			}
			if err := CheckSpecJSON(testPolicy(), testID, specJSON(t, s)); err != nil {
				t.Fatalf("baseline JSON refused: %v", err)
			}
		})
	}
}

// TestSpecMutationsRefused is the broken-agent table for the OCI spec
// (plans/security-gaps-m1-m4.md §3.6): each row changes one field of a
// spec the gate accepts into something a compromised agent would send,
// and the check must refuse it under the named rule.
func TestSpecMutationsRefused(t *testing.T) {
	addMount := func(m specs.Mount) func(*specs.Spec) {
		return func(s *specs.Spec) { s.Mounts = append(s.Mounts, m) }
	}
	bind := func(src string) func(*specs.Spec) {
		return addMount(specs.Mount{Type: "bind", Source: src, Destination: "/host", Options: []string{"rbind"}})
	}
	setNetns := func(p string) func(*specs.Spec) {
		return func(s *specs.Spec) {
			for i, ns := range s.Linux.Namespaces {
				if ns.Type == specs.NetworkNamespace {
					s.Linux.Namespaces[i].Path = p
				}
			}
		}
	}
	dropNS := func(typ specs.LinuxNamespaceType) func(*specs.Spec) {
		return func(s *specs.Spec) {
			var out []specs.LinuxNamespace
			for _, ns := range s.Linux.Namespaces {
				if ns.Type != typ {
					out = append(out, ns)
				}
			}
			s.Linux.Namespaces = out
		}
	}
	annotate := func(k, v string) func(*specs.Spec) {
		return func(s *specs.Spec) { s.Annotations = map[string]string{k: v} }
	}
	without := func(list []string, drop string) []string {
		var out []string
		for _, v := range list {
			if v != drop {
				out = append(out, v)
			}
		}
		return out
	}
	neg := -1000
	for _, tc := range []struct {
		name   string
		mutate func(*specs.Spec)
		rule   Rule
	}{
		{"prestart hook", func(s *specs.Spec) { s.Hooks = &specs.Hooks{Prestart: []specs.Hook{{Path: "/bin/sh"}}} }, RuleHook},
		{"createRuntime hook", func(s *specs.Spec) { s.Hooks = &specs.Hooks{CreateRuntime: []specs.Hook{{Path: "/tmp/x"}}} }, RuleHook},
		{"empty hooks section", func(s *specs.Spec) { s.Hooks = &specs.Hooks{} }, RuleHook},
		{"bind of /", bind("/"), RuleMount},
		{"bind of /proc", bind("/proc"), RuleMount},
		{"bind of /proc/1/root", bind("/proc/1/root"), RuleMount},
		{"bind of /sys/fs/cgroup", bind("/sys/fs/cgroup"), RuleMount},
		{"bind of /dev/sda", bind("/dev/sda"), RuleMount},
		{"bind of the sockets folder", bind("/run/containerd/containerd.sock"), RuleMount},
		{"bind source outside the roots", bind("/etc/shadow"), RuleMount},
		{"bind source escaping a root with ..", bind(testMounts + "/../../../etc"), RuleMount},
		{"bind source equal to a root", bind(testMounts), RuleMount},
		{"bind source relative", bind("etc/shadow"), RuleMount},
		{"tmpfs with rbind binds /", addMount(specs.Mount{Type: "tmpfs", Source: "/", Destination: "/host", Options: []string{"rbind"}}), RuleMount},
		{"none with bind binds /", addMount(specs.Mount{Type: "none", Source: "/", Destination: "/host", Options: []string{"bind"}}), RuleMount},
		{"overlay mount of host dirs", addMount(specs.Mount{Type: "overlay", Source: "overlay", Destination: "/host", Options: []string{"lowerdir=/"}}), RuleMount},
		{"ext4 mount of a host disk", addMount(specs.Mount{Type: "ext4", Source: "/dev/sda1", Destination: "/host"}), RuleMount},
		{"tmpfs source naming a host path", addMount(specs.Mount{Type: "tmpfs", Source: "/etc", Destination: "/x"}), RuleMount},
		{"tmpfs with an unknown option", addMount(specs.Mount{Type: "tmpfs", Source: "tmpfs", Destination: "/x", Options: []string{"exec"}}), RuleMount},
		{"writable sysfs", addMount(specs.Mount{Type: "sysfs", Source: "sysfs", Destination: "/sys2", Options: []string{"nosuid"}}), RuleMount},
		// Reviewer finding 2: a second procfs has no masked or read-only
		// paths, so its sys/kernel/core_pattern is the host's, writable.
		{"second procfs elsewhere", addMount(specs.Mount{Destination: "/p2", Type: "proc", Source: "proc", Options: []string{"nosuid", "noexec", "nodev"}}), RuleMount},
		{"second procfs at /proc", addMount(specs.Mount{Destination: "/proc", Type: "proc", Source: "proc"}), RuleMount},
		{"procfs moved off /proc", func(s *specs.Spec) {
			for i := range s.Mounts {
				if s.Mounts[i].Type == "proc" {
					s.Mounts[i].Destination = "/hostproc"
				}
			}
		}, RuleMount},
		// runc joins key=value options into the kernel's mount data with
		// commas, so a comma in a value is another option.
		{"comma in a tmpfs option value", addMount(specs.Mount{Type: "tmpfs", Source: "tmpfs", Destination: "/x", Options: []string{"size=1m,huge=always"}}), RuleMount},
		{"cgroup release_agent smuggled in a value", addMount(specs.Mount{Type: "cgroup", Source: "cgroup", Destination: "/cg", Options: []string{"ro", "mode=1,release_agent=/x"}}), RuleMount},
		{"empty option value", addMount(specs.Mount{Type: "tmpfs", Source: "tmpfs", Destination: "/x", Options: []string{"size="}}), RuleMount},
		{"memory limit -1", func(s *specs.Spec) { v := int64(-1); s.Linux.Resources.Memory.Limit = &v }, RuleResources},
		{"cpu quota -1", func(s *specs.Spec) { v := int64(-1); s.Linux.Resources.CPU.Quota = &v }, RuleResources},
		{"pids limit 0", func(s *specs.Spec) { v := int64(0); s.Linux.Resources.Pids.Limit = &v }, RuleResources},
		{"sysfs ro then rw", addMount(specs.Mount{Type: "sysfs", Source: "sysfs", Destination: "/sys2", Options: []string{"ro", "rw"}}), RuleMount},
		{"bind with shared propagation", addMount(specs.Mount{Type: "bind", Source: testMounts + "/x", Destination: "/x", Options: []string{"rbind", "rshared"}}), RuleMount},
		{"relative destination", addMount(specs.Mount{Type: "tmpfs", Source: "tmpfs", Destination: "x"}), RuleMount},
		{"idmapped bind", addMount(specs.Mount{Type: "bind", Source: testMounts + "/x", Destination: "/x", Options: []string{"rbind"}, UIDMappings: []specs.LinuxIDMapping{{Size: 1}}}), RuleField},
		{"device node", func(s *specs.Spec) { s.Linux.Devices = []specs.LinuxDevice{{Path: "/dev/sda", Type: "b", Major: 8}} }, RuleDevice},
		{"host network device", func(s *specs.Spec) { s.Linux.NetDevices = map[string]specs.LinuxNetDevice{"eth0": {}} }, RuleDevice},
		{"cgroup device allow", func(s *specs.Spec) {
			s.Linux.Resources.Devices = append(s.Linux.Resources.Devices, specs.LinuxDeviceCgroup{Allow: true, Access: "rwm"})
		}, RuleDevice},
		{"extra capability", func(s *specs.Spec) {
			s.Process.Capabilities.Bounding = append(s.Process.Capabilities.Bounding, "CAP_SYS_ADMIN")
		}, RuleCapability},
		{"CAP_NET_RAW back", func(s *specs.Spec) {
			s.Process.Capabilities.Effective = append(s.Process.Capabilities.Effective, "CAP_NET_RAW")
		}, RuleCapability},
		{"ambient capability", func(s *specs.Spec) { s.Process.Capabilities.Ambient = []string{"CAP_SYS_PTRACE"} }, RuleCapability},
		{"missing seccomp", func(s *specs.Spec) { s.Linux.Seccomp = nil }, RuleSeccomp},
		{"seccomp that allows everything", func(s *specs.Spec) {
			s.Linux.Seccomp = &specs.LinuxSeccomp{DefaultAction: specs.ActAllow}
		}, RuleSeccomp},
		{"NoNewPrivileges off", func(s *specs.Spec) { s.Process.NoNewPrivileges = false }, RuleNoNewPrivileges},
		{"negative OOM score", func(s *specs.Spec) { s.Process.OOMScoreAdj = &neg }, RuleProcess},
		{"no process", func(s *specs.Spec) { s.Process = nil }, RuleProcess},
		{"terminal", func(s *specs.Spec) { s.Process.Terminal = true }, RuleField},
		{"apparmor profile", func(s *specs.Spec) { s.Process.ApparmorProfile = "unconfined" }, RuleField},
		{"selinux label", func(s *specs.Spec) { s.Process.SelinuxLabel = "system_u:system_r:spc_t:s0" }, RuleField},
		{"scheduler", func(s *specs.Spec) { s.Process.Scheduler = &specs.Scheduler{Policy: specs.SchedFIFO} }, RuleField},
		{"username", func(s *specs.Spec) { s.Process.User.Username = "root" }, RuleField},
		{"/proc/kcore not masked", func(s *specs.Spec) { s.Linux.MaskedPaths = without(s.Linux.MaskedPaths, "/proc/kcore") }, RuleMaskedPaths},
		{"/proc/sys writable", func(s *specs.Spec) { s.Linux.ReadonlyPaths = without(s.Linux.ReadonlyPaths, "/proc/sys") }, RuleReadonlyPaths},
		{"host pid namespace", dropNS(specs.PIDNamespace), RuleHostNamespace},
		{"host network namespace", dropNS(specs.NetworkNamespace), RuleHostNamespace},
		{"joins the host mount namespace", func(s *specs.Spec) {
			for i, ns := range s.Linux.Namespaces {
				if ns.Type == specs.MountNamespace {
					s.Linux.Namespaces[i].Path = "/proc/1/ns/mnt"
				}
			}
		}, RuleHostNamespace},
		{"netns path with ../", setNetns("/run/netns/../../proc/1/ns/net"), RuleHostNamespace},
		{"netns path outside /run/netns", setNetns("/proc/1/ns/net"), RuleHostNamespace},
		{"netns name with a bad character", setNetns("/run/netns/sb.1"), RuleHostNamespace},
		{"user namespace", func(s *specs.Spec) {
			s.Linux.Namespaces = append(s.Linux.Namespaces, specs.LinuxNamespace{Type: specs.UserNamespace})
		}, RuleHostNamespace},
		{"network namespace twice", func(s *specs.Spec) {
			s.Linux.Namespaces = append(s.Linux.Namespaces, specs.LinuxNamespace{Type: specs.NetworkNamespace, Path: "/proc/1/ns/net"})
		}, RuleHostNamespace},
		{"cgroup outside the parent", func(s *specs.Spec) { s.Linux.CgroupsPath = "/system.slice/" + testID }, RuleCgroup},
		{"cgroup climbing out with ..", func(s *specs.Spec) { s.Linux.CgroupsPath = "/aerolvm/../" + testID }, RuleCgroup},
		{"cgroup of another container", func(s *specs.Spec) { s.Linux.CgroupsPath = "/aerolvm/sb-2" }, RuleCgroup},
		{"cgroup leaf with a bad character", func(s *specs.Spec) { s.Linux.CgroupsPath = "/aerolvm/sb.1" }, RuleCgroup},
		{"systemd cgroup", func(s *specs.Spec) { s.Linux.CgroupsPath = "system.slice:aerolvm:" + testID }, RuleCgroup},
		{"gVisor host network flag", annotate("dev.gvisor.flag.network", "host"), RuleAnnotation},
		{"gVisor mount hint", annotate("dev.gvisor.spec.mount.x.source", "/"), RuleAnnotation},
		{"runc CRIU config", annotate("org.criu.config", "/tmp/criu.conf"), RuleAnnotation},
		{"CRI container type not sandbox", annotate(CRIContainerTypeAnnotation, "container"), RuleAnnotation},
		{"restore image outside moves", annotate(RestoreAnnotation, "/etc"), RuleCheckpoint},
		{"root path /", func(s *specs.Spec) { s.Root.Path = "/" }, RuleRootfsPath},
		{"no root", func(s *specs.Spec) { s.Root = nil }, RuleRootfsPath},
		{"ip_nonlocal_bind", func(s *specs.Spec) { s.Linux.Sysctl["net.ipv4.ip_nonlocal_bind"] = "1" }, RuleSysctl},
		{"IPv6 back on", func(s *specs.Spec) { s.Linux.Sysctl["net.ipv6.conf.all.disable_ipv6"] = "0" }, RuleSysctl},
		{"OOM killer off", func(s *specs.Spec) { off := true; s.Linux.Resources.Memory.DisableOOMKiller = &off }, RuleField},
		{"cgroup v2 unified file", func(s *specs.Spec) { s.Linux.Resources.Unified = map[string]string{"memory.oom.group": "0"} }, RuleField},
		{"cpuset pinning", func(s *specs.Spec) { s.Linux.Resources.CPU.Cpus = "0" }, RuleField},
		{"pids beyond limit field", func(s *specs.Spec) { s.Linux.Resources.BlockIO = &specs.LinuxBlockIO{} }, RuleField},
		{"intelRdt", func(s *specs.Spec) { s.Linux.IntelRdt = &specs.LinuxIntelRdt{ClosID: "x"} }, RuleField},
		{"user ID mappings", func(s *specs.Spec) { s.Linux.UIDMappings = []specs.LinuxIDMapping{{Size: 1}} }, RuleField},
		{"shared rootfs propagation", func(s *specs.Spec) { s.Linux.RootfsPropagation = "shared" }, RuleField},
		{"personality", func(s *specs.Spec) { s.Linux.Personality = &specs.LinuxPersonality{Domain: specs.PerLinux32} }, RuleField},
		{"windows section", func(s *specs.Spec) { s.Windows = &specs.Windows{} }, RuleField},
		{"vm section", func(s *specs.Spec) { s.VM = &specs.VM{Hypervisor: specs.VMHypervisor{Path: "/bin/sh"}} }, RuleField},
		{"no linux section", func(s *specs.Spec) { s.Linux = nil }, RuleSpec},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := baselineSpec(t)
			tc.mutate(s)
			wantRule(t, CheckSpec(testPolicy(), testID, s), tc.rule)
			// The same mutation through the bytes containerd stores.
			wantRule(t, CheckSpecJSON(testPolicy(), testID, specJSON(t, s)), tc.rule)
		})
	}
}

// seccompRuleOnLinux is the rule a profile computed for other capabilities
// breaks. containerd's default profile exists only on Linux; elsewhere it is
// empty for every spec, so nothing differs.
func seccompRuleOnLinux() Rule {
	if runtime.GOOS == "linux" {
		return RuleSeccomp
	}
	return ""
}

// TestSpecLimitBounds: with the node's limits in the policy, every sandbox
// must have each bounded limit, within the bound. The baseline asks for
// 512 MiB, 1.5 CPUs and 4096 processes.
func TestSpecLimitBounds(t *testing.T) {
	bound := func(l Limits) Policy {
		p := testPolicy()
		p.Limits = l
		return p
	}
	if err := CheckSpec(bound(Limits{MemoryBytes: 1 << 30, Pids: 8192, CPUs: 2}), testID, baselineSpec(t)); err != nil {
		t.Fatalf("a spec within the bounds: %v", err)
	}
	for _, tc := range []struct {
		name   string
		lim    Limits
		mutate func(*specs.Spec)
	}{
		{"memory above", Limits{MemoryBytes: 256 << 20}, func(*specs.Spec) {}},
		{"pids above", Limits{Pids: 1000}, func(*specs.Spec) {}},
		{"cpus above", Limits{CPUs: 1}, func(*specs.Spec) {}},
		{"no memory limit", Limits{MemoryBytes: 1 << 30}, func(s *specs.Spec) { s.Linux.Resources.Memory = nil }},
		{"no pids limit", Limits{Pids: 8192}, func(s *specs.Spec) { s.Linux.Resources.Pids = nil }},
		{"no cpu limit", Limits{CPUs: 2}, func(s *specs.Spec) { s.Linux.Resources.CPU = nil }},
		{"no resources at all", Limits{MemoryBytes: 1 << 30}, func(s *specs.Spec) { s.Linux.Resources = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := baselineSpec(t)
			tc.mutate(s)
			wantRule(t, CheckSpec(bound(tc.lim), testID, s), RuleResources)
		})
	}
}

func TestCheckSpecNil(t *testing.T) {
	wantRule(t, CheckSpec(testPolicy(), testID, nil), RuleSpec)
}

// TestPrivilegedPolicy: the helper's SB_CONTAINER_PRIVILEGED lets a spec go
// without the envelope the builder then skips, and nothing more.
func TestPrivilegedPolicy(t *testing.T) {
	priv := testPolicy()
	priv.Privileged = true
	bare := func(s *specs.Spec) {
		s.Linux.Seccomp = nil
		s.Linux.MaskedPaths, s.Linux.ReadonlyPaths = nil, nil
		s.Process.Capabilities.Bounding = append(s.Process.Capabilities.Bounding, "CAP_NET_RAW")
	}
	s := baselineSpec(t)
	bare(s)
	if err := CheckSpec(priv, testID, s); err != nil {
		t.Fatalf("privileged policy refused an envelope-less spec: %v", err)
	}
	wantRule(t, CheckSpec(testPolicy(), testID, s), RuleCapability)

	for _, tc := range []struct {
		name   string
		mutate func(*specs.Spec)
		rule   Rule
	}{
		{"still no CAP_SYS_ADMIN", func(s *specs.Spec) {
			s.Process.Capabilities.Bounding = append(s.Process.Capabilities.Bounding, "CAP_SYS_ADMIN")
		}, RuleCapability},
		{"still no hooks", func(s *specs.Spec) { s.Hooks = &specs.Hooks{Poststop: []specs.Hook{{Path: "/x"}}} }, RuleHook},
		{"still no bind of /", func(s *specs.Spec) {
			s.Mounts = append(s.Mounts, specs.Mount{Type: "bind", Source: "/", Destination: "/h", Options: []string{"rbind"}})
		}, RuleMount},
		{"a seccomp profile it carries is still the default", func(s *specs.Spec) {
			s.Linux.Seccomp = &specs.LinuxSeccomp{DefaultAction: specs.ActAllow}
		}, RuleSeccomp},
		{"still NoNewPrivileges", func(s *specs.Spec) { s.Process.NoNewPrivileges = false }, RuleNoNewPrivileges},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := baselineSpec(t)
			bare(s)
			tc.mutate(s)
			wantRule(t, CheckSpec(priv, testID, s), tc.rule)
		})
	}
}

func TestDecodeSpec(t *testing.T) {
	good := string(specJSON(t, baselineSpec(t)))
	for _, tc := range []struct {
		name, raw, want string
	}{
		{"not JSON", "{", "does not decode"},
		{"a field this runtime-spec does not know", `{"ociVersion":"1.2.0","linux":{"futureHostAccess":true}}`, "unknown field"},
		{"bytes after the object", good + `{}`, "bytes after"},
		{"a second spec after the first", good + good, "bytes after"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeSpec([]byte(tc.raw))
			wantRule(t, err, RuleSpec)
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err %v, want %q", err, tc.want)
			}
		})
	}
	if _, err := DecodeSpec([]byte(good + " \n")); err != nil {
		t.Fatalf("trailing space refused: %v", err)
	}
}

func TestCheckSpecWithoutContainerID(t *testing.T) {
	// A spec checked on its own (no container to name) still needs its
	// cgroup directly under the parent, named like an ID.
	if err := CheckSpec(testPolicy(), "", baselineSpec(t)); err != nil {
		t.Fatal(err)
	}
	p := testPolicy()
	p.CgroupParent = "/kubepods/aerolvm"
	wantRule(t, CheckSpec(p, "", baselineSpec(t)), RuleCgroup)
	s := baselineSpec(t)
	s.Linux.CgroupsPath = "/kubepods/aerolvm/" + testID
	if err := CheckSpec(p, testID, s); err != nil {
		t.Fatalf("cgroup under a configured parent: %v", err)
	}
	// No capabilities at all; the default profile then allows fewer
	// syscalls (no chroot without CAP_SYS_CHROOT), and must be that one.
	s.Process.Capabilities = nil
	wantRule(t, CheckSpec(p, testID, s), seccompRuleOnLinux())
	s.Linux.Seccomp = seccomp.DefaultProfile(&specs.Spec{Process: &specs.Process{Capabilities: &specs.LinuxCapabilities{}}})
	if err := CheckSpec(p, testID, s); err != nil {
		t.Fatalf("a spec with no capabilities at all: %v", err)
	}
	// Review round 2, finding 2: fail closed. SB_RESOURCE_LIMITS_OFF builds
	// a spec with no limits; the gate refuses it, whatever the policy says.
	s.Linux.Resources = nil
	wantRule(t, CheckSpec(p, testID, s), RuleResources)
	unbounded := p
	unbounded.Limits = Limits{}
	wantRule(t, CheckSpec(unbounded, testID, s), RuleResources)
}

func TestCheckExecProcess(t *testing.T) {
	good := baselineSpec(t).Process
	if err := CheckExecProcess(testPolicy(), good); err != nil {
		t.Fatal(err)
	}
	wantRule(t, CheckExecProcess(testPolicy(), nil), RuleProcess)
	bad := *good
	bad.Capabilities = &specs.LinuxCapabilities{Permitted: []string{"CAP_SYS_MODULE"}}
	wantRule(t, CheckExecProcess(testPolicy(), &bad), RuleCapability)
	bad = *good
	bad.NoNewPrivileges = false
	wantRule(t, CheckExecProcess(testPolicy(), &bad), RuleNoNewPrivileges)
}

func TestCheckBindSource(t *testing.T) {
	p := testPolicy()
	p.ForbiddenRoots = append(p.ForbiddenRoots, testMounts+"/secret")
	for _, tc := range []struct {
		src string
		ok  bool
	}{
		{testToolbox, true},
		{testMounts + "/sb-1/0", true},
		{testReady + "/sb-1.n.sock", true},
		{testToolbox + "/x", false},
		{testMounts + "/secret/x", false},
		{testMounts + "/secret", false},
		{"/", false},
		{"", false},
		{"/var/lib/sandboxd/mountsX/y", false},
		{testMounts + "/./x", false},
		{testMounts + "//x", false},
		{testMounts + "/x/", false},
		{testHelperHosts + "/sb-1/resolv.conf", true},
		{testHelperReady + "/sb-1/ready.sock", true},
		{testHelperHosts + "/sb-1", false},
		{testHelperReady + "/sb-1/a/ready.sock", false},
	} {
		err := CheckBindSource(p, tc.src)
		if (err == nil) != tc.ok {
			t.Errorf("CheckBindSource(%q) = %v, want ok=%v", tc.src, err, tc.ok)
		}
	}
}
