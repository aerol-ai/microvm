package rootpolicy

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// The fuzz targets below check the checkers against invariants written out
// a second, simpler way: whatever bytes the fuzzer finds, a spec the check
// lets through never carries a hook, a bind from outside the allowed
// folders, a device, a capability outside the trimmed set, a namespace
// joined anywhere but /run/netns/<id>, and so on. A refusal must always
// name its rule.

func FuzzCheckSpecJSON(f *testing.F) {
	f.Add(specJSON(f, baselineSpec(f)))
	f.Add(specJSON(f, gvisorSpec(f)))
	for _, mutate := range []func(*specs.Spec){
		func(s *specs.Spec) { s.Hooks = &specs.Hooks{Prestart: []specs.Hook{{Path: "/bin/sh"}}} },
		func(s *specs.Spec) { s.Mounts[1].Source = "/" },
		func(s *specs.Spec) { s.Mounts[1].Source = testHelperHosts + "/" + testID + "/resolv.conf" },
		func(s *specs.Spec) { s.Mounts[2].Source = testHelperReady + "/" + testID + "/0a1b.sock" },
		func(s *specs.Spec) { s.Mounts[1].Type = "tmpfs" },
		func(s *specs.Spec) { s.Linux.Namespaces[0].Path = "/proc/1/ns/pid" },
		func(s *specs.Spec) { s.Annotations = map[string]string{"dev.gvisor.flag.network": "host"} },
		func(s *specs.Spec) {
			s.Process.Capabilities.Bounding = append(s.Process.Capabilities.Bounding, "CAP_SYS_ADMIN")
		},
	} {
		s := baselineSpec(f)
		mutate(s)
		f.Add(specJSON(f, s))
	}
	p := testPolicy()
	f.Fuzz(func(t *testing.T, raw []byte) {
		err := CheckSpecJSON(p, testID, raw)
		if err != nil {
			if RuleOf(err) == "" {
				t.Fatalf("refusal names no rule: %v", err)
			}
			return
		}
		s, err := DecodeSpec(raw)
		if err != nil {
			t.Fatalf("passed the check but does not decode: %v", err)
		}
		assertEnvelope(t, p, s)
	})
}

// assertEnvelope restates the envelope's invariants without the checker's
// code paths.
func assertEnvelope(t *testing.T, p Policy, s *specs.Spec) {
	t.Helper()
	if s.Hooks != nil {
		t.Fatal("a spec with hooks passed")
	}
	if s.Root == nil || s.Root.Path != "rootfs" {
		t.Fatalf("root %+v passed", s.Root)
	}
	if s.Process == nil || !s.Process.NoNewPrivileges {
		t.Fatal("a spec without NoNewPrivileges passed")
	}
	if c := s.Process.Capabilities; c != nil {
		for _, set := range [][]string{c.Bounding, c.Effective, c.Inheritable, c.Permitted, c.Ambient} {
			for _, cap := range set {
				if !slices.Contains(SandboxCapabilities(), cap) {
					t.Fatalf("capability %s passed", cap)
				}
			}
		}
	}
	procs, sysfs := 0, 0
	for _, m := range s.Mounts {
		if m.Type == "sysfs" {
			if sysfs++; sysfs > 1 || m.Destination != "/sys" {
				t.Fatalf("sysfs at %q passed", m.Destination)
			}
		}
		bind := m.Type == "bind" || slices.Contains(m.Options, "bind") || slices.Contains(m.Options, "rbind")
		if bind {
			if assertBindSource(t, p, m.Source) && (!slices.Contains(m.Options, "ro") || slices.Contains(m.Options, "rw")) {
				t.Fatalf("a writable bind of the helper's file %q passed", m.Source)
			}
		} else if strings.Contains(m.Source, "/") {
			t.Fatalf("non-bind mount with a path source %q passed", m.Source)
		}
		if m.Type == "proc" {
			if procs++; procs > 1 || m.Destination != "/proc" {
				t.Fatalf("procfs at %q passed", m.Destination)
			}
		}
		for _, o := range m.Options {
			if strings.Contains(o, ",") {
				t.Fatalf("mount option %q with a comma passed", o)
			}
		}
	}
	if s.Linux == nil || s.Linux.Seccomp == nil {
		t.Fatal("a spec without seccomp passed")
	}
	if len(s.Linux.Devices) > 0 || len(s.Linux.NetDevices) > 0 {
		t.Fatal("a spec with devices passed")
	}
	r := s.Linux.Resources
	if r == nil || r.Memory == nil || r.Memory.Limit == nil || *r.Memory.Limit <= 0 || *r.Memory.Limit > p.Limits.MemoryBytes ||
		r.Pids == nil || r.Pids.Limit == nil || *r.Pids.Limit <= 0 || *r.Pids.Limit > p.Limits.Pids {
		t.Fatalf("resources %+v passed", r)
	}
	for _, d := range r.Devices {
		if d.Allow {
			t.Fatal("a device allow rule passed")
		}
	}
	types := map[specs.LinuxNamespaceType]bool{}
	for _, ns := range s.Linux.Namespaces {
		types[ns.Type] = true
		if ns.Path == "" {
			continue
		}
		name, ok := strings.CutPrefix(ns.Path, p.NetnsDir+"/")
		if ns.Type != specs.NetworkNamespace || !ok || name == "" || strings.ContainsAny(name, "/.") {
			t.Fatalf("namespace %s at %q passed", ns.Type, ns.Path)
		}
	}
	for _, need := range []specs.LinuxNamespaceType{"pid", "ipc", "uts", "mount", "network"} {
		if !types[need] {
			t.Fatalf("a spec sharing the host's %s namespace passed", need)
		}
	}
	if !strings.HasPrefix(s.Linux.CgroupsPath, "/aerolvm/") || strings.Count(s.Linux.CgroupsPath, "/") != 2 || unclean(s.Linux.CgroupsPath) {
		t.Fatalf("cgroup %q passed", s.Linux.CgroupsPath)
	}
	for k := range s.Annotations {
		if k != CRIContainerTypeAnnotation && k != RestoreAnnotation {
			t.Fatalf("annotation %q passed", k)
		}
	}
	for k := range s.Linux.Sysctl {
		if _, ok := allowedSysctls[k]; !ok {
			t.Fatalf("sysctl %q passed", k)
		}
	}
}

// helperFile is <root>/<id>/<name> with a name the helper makes, written
// as a pattern rather than as the checker's cuts.
var helperFile = regexp.MustCompile(`^/[^/]+(/[^/]+)*/[A-Za-z0-9_-]{1,128}/(hostname|hosts|resolv\.conf|egress-ca\.pem|ready\.sock|([0-9a-f]{2}){1,32}\.sock)$`)

// assertBindSource fails unless src is a source the envelope allows, and
// reports whether it is a helper's file (which must be bound read-only).
func assertBindSource(t *testing.T, p Policy, src string) (helper bool) {
	t.Helper()
	if unclean(src) {
		t.Fatalf("unclean bind source %q passed", src)
	}
	for _, bad := range append([]string{"/proc", "/sys", "/dev"}, p.ForbiddenRoots...) {
		if src == bad || strings.HasPrefix(src, bad+"/") {
			t.Fatalf("bind source %q in %s passed", src, bad)
		}
	}
	for _, r := range p.HelperFileRoots {
		if rest, ok := strings.CutPrefix(src, r+"/"); ok {
			if strings.Count(rest, "/") != 1 || !helperFile.MatchString(src) {
				t.Fatalf("bind source %q in the helper's %s is not one of its files", src, r)
			}
			return true
		}
	}
	if slices.Contains(p.BindFiles, src) {
		return false
	}
	for _, r := range p.BindRoots {
		if strings.HasPrefix(src, r+"/") {
			return false
		}
	}
	t.Fatalf("bind source %q outside the roots passed", src)
	return false
}

// unclean reports a path that is not absolute, or has an empty, "." or ".."
// component: the forms a prefix test can be fooled by.
func unclean(p string) bool {
	if !strings.HasPrefix(p, "/") || p == "/" {
		return p != "/"
	}
	for _, part := range strings.Split(p[1:], "/") {
		if part == "" || part == "." || part == ".." {
			return true
		}
	}
	return false
}

func FuzzCheckBindSource(f *testing.F) {
	for _, s := range []string{testToolbox, testMounts + "/sb/0", "/", "/proc/1/root", testMounts + "/../etc", testReady + "/x.sock", "", "//", testMounts + "/./x",
		testHelperHosts + "/sb-1/resolv.conf", testHelperHosts + "/sb-1", testHelperReady + "/sb-1/0a1b.sock", testHelperReady + "/sb-1/x/ready.sock"} {
		f.Add(s)
	}
	p := testPolicy()
	f.Fuzz(func(t *testing.T, src string) {
		if CheckBindSource(p, src) == nil {
			assertBindSource(t, p, src)
		}
	})
}

// layerFolder is a layer's own folder, written as a pattern rather than as
// the checker's prefix cut.
var layerFolder = regexp.MustCompile(`^` + regexp.QuoteMeta(layers) + `/[0-9]{1,20}/(fs|work)$`)

// FuzzCheckSnapshotMounts checks what the kernel would get. Options are
// separated by "|" here so that a value can hold a comma, and the oracle
// reads them the way containerd hands them to mount(2): joined with
// commas, then split by the kernel.
func FuzzCheckSnapshotMounts(f *testing.F) {
	f.Add("overlay", "overlay", "index=off|workdir="+layers+"/9/work|upperdir="+layers+"/9/fs|lowerdir="+layers+"/2/fs:"+layers+"/1/fs")
	f.Add("overlay", "overlay", "index=off|lowerdir="+layers+"/1/fs,upperdir=/etc,workdir=/var/tmp")
	f.Add("bind", layers+"/1/fs", "rw|rbind")
	f.Add("bind", layers+"/1/fs/h", "rw|rbind")
	f.Add("overlay", "overlay", "lowerdir=/")
	f.Add("bind", "/", "rbind")
	f.Add("ext4", "/dev/sda", "")
	p := testPolicy()
	layer := func(t *testing.T, what, dir string) {
		t.Helper()
		if !layerFolder.MatchString(dir) {
			t.Fatalf("%s %q passed", what, dir)
		}
	}
	f.Fuzz(func(t *testing.T, typ, src, opts string) {
		var options []string
		if opts != "" {
			options = strings.Split(opts, "|")
		}
		if CheckSnapshotMounts(p, []Mount{{Type: typ, Source: src, Options: options}}) != nil {
			return
		}
		switch typ {
		case "bind":
			layer(t, "bind source", src)
		case "overlay":
			for _, o := range strings.Split(strings.Join(options, ","), ",") {
				key, value, _ := strings.Cut(o, "=")
				switch key {
				case "lowerdir":
					for _, d := range strings.Split(value, ":") {
						layer(t, "lowerdir", d)
					}
				case "upperdir", "workdir":
					layer(t, key, value)
				default:
					if o != "index=off" && o != "userxattr" {
						t.Fatalf("kernel overlay option %q passed", o)
					}
				}
			}
		default:
			t.Fatalf("mount type %q passed", typ)
		}
	})
}

func FuzzCheckTaskIO(f *testing.F) {
	for _, s := range []string{testFIFO + "/1/sb-stdout", "binary:///bin/sh", "file:///etc/passwd", "/etc/passwd", testFIFO + "/../x", ""} {
		f.Add(s)
	}
	p := testPolicy()
	f.Fuzz(func(t *testing.T, stdio string) {
		if CheckTaskIO(p, stdio) != nil || stdio == "" {
			return
		}
		if !strings.HasPrefix(stdio, p.FIFODir+"/") || unclean(stdio) || strings.Contains(stdio, "://") {
			t.Fatalf("stdio %q passed", stdio)
		}
	})
}
