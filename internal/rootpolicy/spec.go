package rootpolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/containerd/containerd/v2/contrib/seccomp"
	specs "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/aerol-ai/microvm/internal/ownerlease"
)

// DecodeSpec reads the spec bytes exactly as runc and runsc will: containerd
// writes a container's spec Any to config.json unchanged. A field this
// build's runtime-spec does not know is refused, not skipped: a newer runc
// could act on it (runtime-spec 1.2's linux.netDevices moves a host network
// device into the container) while this checker never saw it.
func DecodeSpec(raw []byte) (*specs.Spec, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var s specs.Spec
	if err := dec.Decode(&s); err != nil {
		return nil, violate(RuleSpec, "spec does not decode as this build's OCI runtime spec: %v", err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, violate(RuleSpec, "spec has bytes after its JSON object")
	}
	return &s, nil
}

// CheckSpecJSON decodes raw (DecodeSpec) and checks it (CheckSpec).
func CheckSpecJSON(p Policy, containerID string, raw []byte) error {
	s, err := DecodeSpec(raw)
	if err != nil {
		return err
	}
	return CheckSpec(p, containerID, s)
}

// SpecFacts is what a spec that passed CheckSpec tells the gate to check
// on disk: its bind sources, its restore image and the network namespace
// it joins. It is read from the same decode as the check, so the check and
// the disk walk cannot read the bytes two ways. It never changes once
// made, so one value may be shared between calls.
type SpecFacts struct {
	bindSources []string
	restore     string
	netns       string
}

// CheckSpecFacts decodes raw once, checks it for containerID (CheckSpec)
// and returns its facts. It is a pure function of p, containerID and the
// bytes of raw: that is what lets the gate keep its answer for the same
// three (gate.specMemo).
func CheckSpecFacts(p Policy, containerID string, raw []byte) (*SpecFacts, error) {
	s, err := DecodeSpec(raw)
	if err != nil {
		return nil, err
	}
	if err := CheckSpec(p, containerID, s); err != nil {
		return nil, err
	}
	return &SpecFacts{bindSources: bindSourcesOf(s), restore: s.Annotations[RestoreAnnotation], netns: netnsOf(s)}, nil
}

// Size is about how many bytes f holds, so a memo of facts can bound what
// it keeps: a spec may bind in as many paths as fit in a message.
func (f *SpecFacts) Size() int {
	n := len(f.restore) + len(f.netns)
	for _, s := range f.bindSources {
		n += len(s) + 16 // the string header
	}
	return n
}

// CheckSpec checks an OCI spec against the envelope. containerID, when set,
// is the container the spec belongs to: its cgroup must be named after it.
func CheckSpec(p Policy, containerID string, s *specs.Spec) error {
	if s == nil {
		return violate(RuleSpec, "the container has no spec")
	}
	if s.Hooks != nil {
		return violate(RuleHook, "the spec has OCI hooks; runc runs hooks as root on the host")
	}
	if err := onlyFields(s, "spec", "Version", "Process", "Root", "Hostname", "Mounts", "Hooks", "Annotations", "Linux"); err != nil {
		return err
	}
	if s.Root == nil || s.Root.Path != rootfsPath {
		return violate(RuleRootfsPath, "root.path must be %q, the snapshot containerd mounts in the bundle", rootfsPath)
	}
	if err := checkProcess(p, s.Process, "process"); err != nil {
		return err
	}
	// One procfs, at /proc, and one sysfs, at /sys: the masked and
	// read-only paths apply there only. A second procfs elsewhere has
	// neither, so its sys/kernel/core_pattern and sysrq-trigger are the
	// host's, writable; a second sysfs shows firmware and powercap.
	seen := map[string]bool{}
	for i, m := range s.Mounts {
		if err := checkSpecMount(p, containerID, i, m); err != nil {
			return err
		}
		if at, ok := singleMounts[m.Type]; ok {
			if seen[m.Type] || m.Destination != at {
				return violate(RuleMount, "mounts[%d] is a %s at %q; the envelope has one, at %s", i, m.Type, m.Destination, at)
			}
			seen[m.Type] = true
		}
	}
	if err := checkAnnotations(p, s.Annotations); err != nil {
		return err
	}
	return checkLinux(p, containerID, s)
}

// CheckExecProcess checks the process of a task exec against the same
// process rules a container's spec meets. The gate does not pass
// Tasks.Exec today (the agent runs commands through the in-sandbox
// toolbox), so this is the rule waiting for the day it does.
func CheckExecProcess(p Policy, proc *specs.Process) error {
	return checkProcess(p, proc, "exec process")
}

func checkProcess(p Policy, proc *specs.Process, where string) error {
	if proc == nil {
		return violate(RuleProcess, "%s is missing", where)
	}
	if err := onlyFields(proc, where, "User", "Args", "Env", "Cwd", "Capabilities", "Rlimits", "NoNewPrivileges", "OOMScoreAdj"); err != nil {
		return err
	}
	if err := onlyFields(&proc.User, where+".user", "UID", "GID", "Umask", "AdditionalGids"); err != nil {
		return err
	}
	if !proc.NoNewPrivileges {
		return violate(RuleNoNewPrivileges, "%s.noNewPrivileges is off; a setuid binary could gain privileges", where)
	}
	// A negative score shields the sandbox from the OOM killer and leaves
	// the machinery to be killed in its place (Kubernetes finding F10).
	if proc.OOMScoreAdj != nil && *proc.OOMScoreAdj < 0 {
		return violate(RuleProcess, "%s.oomScoreAdj %d is negative", where, *proc.OOMScoreAdj)
	}
	caps := proc.Capabilities
	if caps == nil {
		return nil
	}
	allowed := p.capabilities()
	for _, set := range []struct {
		name string
		caps []string
	}{
		{"bounding", caps.Bounding}, {"effective", caps.Effective}, {"inheritable", caps.Inheritable},
		{"permitted", caps.Permitted}, {"ambient", caps.Ambient},
	} {
		for _, c := range set.caps {
			if !slices.Contains(allowed, c) {
				return violate(RuleCapability, "%s.capabilities.%s has %s, outside the trimmed set", where, set.name, c)
			}
		}
	}
	return nil
}

var (
	// pseudoMountTypes are kernel filesystems mounted fresh inside the
	// sandbox's own namespaces; none of them names a host path.
	pseudoMountTypes = []string{"proc", "tmpfs", "devpts", "mqueue", "sysfs", "cgroup"}
	// readOnlyMountTypes must be read-only: a writable sysfs exposes
	// files such as /sys/kernel/uevent_helper, which the host kernel runs.
	readOnlyMountTypes = []string{"sysfs", "cgroup"}
	bindMountOptions   = []string{"bind", "rbind", "ro", "rw", "nosuid", "nodev", "noexec", "private", "rprivate", "slave", "rslave"}
	pseudoMountOptions = []string{"nosuid", "nodev", "noexec", "ro", "rw", "strictatime", "relatime", "noatime", "newinstance"}
	pseudoMountKeys    = []string{"mode", "size", "ptmxmode", "gid", "uid", "nr_inodes"}
)

const alphanumeric = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

// singleMounts are the kernel filesystems a spec may mount once, and where.
var singleMounts = map[string]string{"proc": "/proc", "sysfs": "/sys"}

func checkSpecMount(p Policy, containerID string, i int, m specs.Mount) error {
	where := fmt.Sprintf("mounts[%d]", i)
	if err := onlyFields(&m, where, "Destination", "Type", "Source", "Options"); err != nil {
		return err
	}
	if !path.IsAbs(m.Destination) {
		return violate(RuleMount, "%s destination %q is not absolute", where, m.Destination)
	}
	// runc binds whenever the options say so, whatever the type says, so
	// the options decide what is a bind.
	if m.Type == "bind" || slices.Contains(m.Options, "bind") || slices.Contains(m.Options, "rbind") {
		if m.Type != "bind" {
			return violate(RuleMount, "%s is a %q mount with bind options, which binds a host path", where, m.Type)
		}
		if err := CheckBindSource(p, m.Source); err != nil {
			return err
		}
		if p.MountsRoot != "" && within(m.Source, p.MountsRoot) {
			if err := CheckMountBind(p.MountsRoot, containerID, m.Source); err != nil {
				return err
			}
		}
		for _, o := range m.Options {
			if !slices.Contains(bindMountOptions, o) {
				return violate(RuleMount, "%s bind option %q is not one the envelope uses", where, o)
			}
		}
		// A bind of one of the helper's files is read-only: a sandbox
		// that could write it could change what root left there. A
		// read-only bind of a socket still connects.
		if _, ok := p.helperFileRootFor(m.Source); ok && (!slices.Contains(m.Options, "ro") || slices.Contains(m.Options, "rw")) {
			return violate(RuleMount, "%s binds the helper's file %q; it must be read-only", where, m.Source)
		}
		return nil
	}
	if !slices.Contains(pseudoMountTypes, m.Type) {
		return violate(RuleMount, "%s type %q is not one the envelope uses", where, m.Type)
	}
	if strings.Contains(m.Source, "/") {
		return violate(RuleMount, "%s %s source %q looks like a host path", where, m.Type, m.Source)
	}
	for _, o := range m.Options {
		// runc passes key=value options on as the kernel's mount data,
		// joined with commas: a value holding a comma would be another
		// option (a cgroup v1 release_agent, for one). Values are numbers
		// and sizes, so letters and digits only.
		key, value, hasValue := strings.Cut(o, "=")
		if hasValue && slices.Contains(pseudoMountKeys, key) && value != "" && strings.Trim(value, alphanumeric) == "" {
			continue
		}
		if !slices.Contains(pseudoMountOptions, o) {
			return violate(RuleMount, "%s %s option %q is not one the envelope uses", where, m.Type, o)
		}
	}
	if slices.Contains(readOnlyMountTypes, m.Type) && (!slices.Contains(m.Options, "ro") || slices.Contains(m.Options, "rw")) {
		return violate(RuleMount, "%s %s mount must be read-only", where, m.Type)
	}
	return nil
}

// CheckBindSource checks the host side of a bind mount: the source, not only
// where it lands (Kata's CVE-2026-77176 came from checking the destination
// alone). It must be a clean absolute path that is one of the policy's bind
// files, strictly inside one of its bind roots, or one file the helper made
// in a helper file root (checkHelperFile), and never /, /proc, /sys, /dev or
// a sockets folder.
func CheckBindSource(p Policy, src string) error {
	if !cleanAbs(src) {
		return violate(RuleMount, "bind source %q is not a clean absolute path", src)
	}
	if src == "/" {
		return violate(RuleMount, "a bind of / gives the sandbox the host's whole filesystem")
	}
	if f, ok := p.forbiddenFor(src); ok {
		return violate(RuleMount, "bind source %q is inside %s", src, f)
	}
	// Validate keeps the helper file roots apart from the other sources,
	// so a source in one meets that root's rule alone.
	if root, ok := p.helperFileRootFor(src); ok {
		return checkHelperFile(root, src)
	}
	if slices.Contains(p.BindFiles, src) || withinAny(src, p.BindRoots) {
		return nil
	}
	return violate(RuleMount, "bind source %q is outside every folder sandboxes may bind from", src)
}

// BindRootFor returns the folder a bind source is checked from on disk: the
// bind root or helper file root it is inside (the deepest, if bind roots
// nest), or a bind file's own folder. folder says whether the source may be
// a folder: only inside a bind root (the external mounts). A bind file and
// a helper's file are files. This check is on the text alone; runc follows
// links in a source, so the gate also walks each source on disk
// (gate.BindChecker), and every folder from this root down must be one only
// root can write.
func BindRootFor(p Policy, src string) (root string, folder, ok bool) {
	if slices.Contains(p.BindFiles, src) {
		return path.Dir(src), false, true
	}
	if r, ok := p.helperFileRootFor(src); ok {
		return r, false, true
	}
	for _, r := range p.BindRoots {
		if within(src, r) && len(r) > len(root) {
			root = r
		}
	}
	return root, root != "", root != ""
}

// SpecBindSources returns the host paths a container's spec binds in, as
// runc reads them: every mount whose options say bind, whatever its type.
func SpecBindSources(c Container) ([]string, error) {
	s, err := DecodeSpec(c.Spec)
	if err != nil {
		return nil, err
	}
	return bindSourcesOf(s), nil
}

func bindSourcesOf(s *specs.Spec) []string {
	var out []string
	for _, m := range s.Mounts {
		if m.Type == "bind" || slices.Contains(m.Options, "bind") || slices.Contains(m.Options, "rbind") {
			out = append(out, m.Source)
		}
	}
	return out
}

func checkAnnotations(p Policy, ann map[string]string) error {
	for _, k := range sortedKeys(ann) {
		v := ann[k]
		switch {
		case k == CRIContainerTypeAnnotation:
			if v != CRIContainerTypeSandbox {
				return violate(RuleAnnotation, "annotation %s=%q: the envelope only sets %q", k, v, CRIContainerTypeSandbox)
			}
		case k == RestoreAnnotation:
			if err := CheckCheckpointPath(p, v); err != nil {
				return err
			}
		case strings.HasPrefix(k, "dev.gvisor."):
			return violate(RuleAnnotation, "annotation %q: runsc reads dev.gvisor.* as its own flags and mount hints (dev.gvisor.flag.network=host would leave the network namespace)", k)
		default:
			return violate(RuleAnnotation, "annotation %q is not one the envelope sets", k)
		}
	}
	return nil
}

func checkLinux(p Policy, containerID string, s *specs.Spec) error {
	l := s.Linux
	if l == nil {
		return violate(RuleSpec, "the spec has no linux section")
	}
	if len(l.Devices) > 0 {
		return violate(RuleDevice, "the spec creates %d device node(s) in the sandbox", len(l.Devices))
	}
	if len(l.NetDevices) > 0 {
		return violate(RuleDevice, "the spec moves %d host network device(s) into the sandbox", len(l.NetDevices))
	}
	if err := onlyFields(l, "linux", "Sysctl", "Resources", "CgroupsPath", "Namespaces", "Devices", "NetDevices", "Seccomp", "MaskedPaths", "ReadonlyPaths"); err != nil {
		return err
	}
	for _, k := range sortedKeys(l.Sysctl) {
		if want, ok := allowedSysctls[k]; !ok || l.Sysctl[k] != want {
			return violate(RuleSysctl, "sysctl %s=%q is not one the envelope sets", k, l.Sysctl[k])
		}
	}
	if err := checkResources(l.Resources, "linux.resources", true, p.Limits, true); err != nil {
		return err
	}
	if err := checkCgroup(p, containerID, l.CgroupsPath); err != nil {
		return err
	}
	if err := checkNamespaces(p, l.Namespaces); err != nil {
		return err
	}
	if err := checkSeccomp(p, s); err != nil {
		return err
	}
	if p.Privileged {
		return nil
	}
	for _, m := range MaskedPaths() {
		if !slices.Contains(l.MaskedPaths, m) {
			return violate(RuleMaskedPaths, "%s is not masked", m)
		}
	}
	for _, r := range ReadonlyPaths() {
		if !slices.Contains(l.ReadonlyPaths, r) {
			return violate(RuleReadonlyPaths, "%s is not read-only", r)
		}
	}
	return nil
}

// checkResources allows the limits the builder sets (memory, CPU quota,
// pids) and nothing else. allowDeviceDeny lets a spec keep containerd's
// deny-all device rule; a rule that allows any device is always refused:
// the sandbox has CAP_MKNOD, so an allowed block device is the host's disk.
//
// A limit that is set must be a real one, above zero (zero and -1 both mean
// "no limit" to runc) and within lim's bound. required is a container's
// spec, which must set memory, pids and CPU (quota and period) at all; a
// resize names only what it changes. Fail closed: a bound of zero (a
// policy that skipped Validate) caps nothing but still requires the limit.
func checkResources(r *specs.LinuxResources, where string, allowDeviceDeny bool, lim Limits, required bool) error {
	if r == nil {
		r = &specs.LinuxResources{}
	}
	if err := onlyFields(r, where, "Devices", "Memory", "CPU", "Pids"); err != nil {
		return err
	}
	for i, d := range r.Devices {
		if d.Allow || !allowDeviceDeny {
			return violate(RuleDevice, "%s.devices[%d] is a device rule the envelope does not set", where, i)
		}
	}
	if err := onlyFields(r.Memory, where+".memory", "Limit"); err != nil {
		return err
	}
	if err := onlyFields(r.CPU, where+".cpu", "Quota", "Period"); err != nil {
		return err
	}
	if err := onlyFields(r.Pids, where+".pids", "Limit"); err != nil {
		return err
	}
	var memory, pids, quota *int64
	var period *uint64
	if r.Memory != nil {
		memory = r.Memory.Limit
	}
	if r.Pids != nil {
		pids = r.Pids.Limit
	}
	if r.CPU != nil {
		quota, period = r.CPU.Quota, r.CPU.Period
	}
	if err := checkLimit(where+".memory.limit", memory, lim.MemoryBytes, required); err != nil {
		return err
	}
	if err := checkLimit(where+".pids.limit", pids, lim.Pids, required); err != nil {
		return err
	}
	if err := checkLimit(where+".cpu.quota", quota, 0, false); err != nil {
		return err
	}
	if period != nil && *period == 0 {
		return violate(RuleResources, "%s.cpu.period is 0", where)
	}
	// A resize may leave CPU alone; one that changes the period alone
	// changes the CPUs too (quota/period), so it needs both.
	if quota == nil && period == nil && !required {
		return nil
	}
	if quota == nil || period == nil {
		return violate(RuleResources, "%s has no CPU quota and period; every sandbox needs a CPU limit", where)
	}
	if cpus := float64(*quota) / float64(*period); lim.CPUs > 0 && cpus > lim.CPUs {
		return violate(RuleResources, "%s asks for %g CPUs, above the helper's bound of %g", where, cpus, lim.CPUs)
	}
	return nil
}

func checkLimit(where string, v *int64, bound int64, required bool) error {
	switch {
	case v == nil && required:
		return violate(RuleResources, "%s is not set; every sandbox needs one", where)
	case v == nil:
		return nil
	case *v <= 0:
		return violate(RuleResources, "%s is %d; zero and negative values lift the limit", where, *v)
	case bound > 0 && *v > bound:
		return violate(RuleResources, "%s %d is above the helper's bound of %d", where, *v, bound)
	}
	return nil
}

func checkCgroup(p Policy, containerID, cg string) error {
	parent := p.cgroupParent()
	if !cleanAbs(cg) {
		return violate(RuleCgroup, "cgroups path %q is not a clean absolute path", cg)
	}
	if path.Dir(cg) != parent {
		return violate(RuleCgroup, "cgroups path %q is not directly under the sandbox parent %s", cg, parent)
	}
	leaf := path.Base(cg)
	if err := ValidateID(leaf); err != nil {
		return violate(RuleCgroup, "cgroups path %q: %v", cg, err)
	}
	// A machinery group beside the sandboxes (containerd's _runtime, a
	// host-process runtime's aerolvm-*) is never a sandbox's.
	if ownerlease.ReservedGroup(leaf) {
		return violate(RuleCgroup, "cgroups path %q is a group the sandboxes' parent keeps for AerolVM's own processes", cg)
	}
	if containerID != "" && leaf != containerID {
		return violate(RuleCgroup, "cgroups path %q is not the container's own (%s)", cg, containerID)
	}
	return nil
}

// requiredNamespaces must each be the sandbox's own: a type left out of the
// list is shared with the host.
var requiredNamespaces = []specs.LinuxNamespaceType{
	specs.PIDNamespace, specs.IPCNamespace, specs.UTSNamespace, specs.MountNamespace, specs.NetworkNamespace,
}

func checkNamespaces(p Policy, nss []specs.LinuxNamespace) error {
	seen := map[specs.LinuxNamespaceType]bool{}
	for _, ns := range nss {
		if seen[ns.Type] {
			return violate(RuleHostNamespace, "namespace %q is listed twice", ns.Type)
		}
		seen[ns.Type] = true
		switch ns.Type {
		case specs.NetworkNamespace:
			if ns.Path != "" {
				if err := CheckNetnsPath(p, ns.Path); err != nil {
					return err
				}
			}
		case specs.PIDNamespace, specs.IPCNamespace, specs.UTSNamespace, specs.MountNamespace, specs.CgroupNamespace:
			if ns.Path != "" {
				return violate(RuleHostNamespace, "the sandbox joins an existing %s namespace at %q", ns.Type, ns.Path)
			}
		default:
			return violate(RuleHostNamespace, "namespace type %q is not one the envelope uses", ns.Type)
		}
	}
	for _, t := range requiredNamespaces {
		if !seen[t] {
			return violate(RuleHostNamespace, "the sandbox shares the host's %s namespace", t)
		}
	}
	return nil
}

// CheckNetnsPath allows a network namespace only at <NetnsDir>/<name>, where
// name is a valid sandbox or slot ID: the namespaces the netns pool makes.
// It checks the form only. That the namespace there is one the helper
// made is the gate's NetnsBinding; which sandbox's it is stays the agent
// pool's to say, so a broken agent can put one sandbox in another's
// namespace, which gains it no root: it already reaches every sandbox on
// its node (plans/security-gaps-m1-m4.md, R9).
func CheckNetnsPath(p Policy, nsPath string) error {
	if !cleanAbs(nsPath) || path.Dir(nsPath) != p.NetnsDir {
		return violate(RuleHostNamespace, "network namespace %q is not directly under %s", nsPath, p.NetnsDir)
	}
	if err := ValidateID(path.Base(nsPath)); err != nil {
		return violate(RuleHostNamespace, "network namespace %q: %v", nsPath, err)
	}
	return nil
}

// checkSeccomp requires containerd's default profile for the spec, exactly:
// the profile the builder asks for (seccomp.WithDefaultProfile). Equality,
// not "a profile is present", because a profile that allows everything is
// present too. In privileged mode the builder sets none, and a spec may
// have none; one it does carry must still be the default.
func checkSeccomp(p Policy, s *specs.Spec) error {
	have := s.Linux.Seccomp
	if have == nil {
		if p.Privileged {
			return nil
		}
		return violate(RuleSeccomp, "the spec has no seccomp profile")
	}
	var bounding []string
	if s.Process != nil && s.Process.Capabilities != nil {
		bounding = s.Process.Capabilities.Bounding
	}
	// Compared as JSON, the form runc reads: an empty list and a missing
	// one are the same profile.
	haveJSON, _ := json.Marshal(have)
	if !bytes.Equal(haveJSON, defaultProfileJSON(bounding)) {
		return violate(RuleSeccomp, "the seccomp profile is not containerd's default profile for this spec")
	}
	return nil
}

// defaultProfiles keeps the JSON of containerd's default seccomp profile
// for the few bounding sets specs carry; building and encoding the profile
// was a good part of every container check. The profile depends only on
// the bounding set, the build's architecture and the running kernel's
// version, which containerd reads once per process, so one set's JSON never
// changes. The key spells out each name's length, so two different sets
// never share one. Bounded, and emptied when full: a caller sending ever
// new sets costs the memo its hits, never a wrong answer.
var defaultProfiles = struct {
	sync.Mutex
	json map[string][]byte
}{json: map[string][]byte{}}

const maxDefaultProfiles = 8

func defaultProfileJSON(bounding []string) []byte {
	var key strings.Builder
	for _, c := range bounding {
		key.WriteString(strconv.Itoa(len(c)))
		key.WriteByte(':')
		key.WriteString(c)
	}
	k := key.String()
	defaultProfiles.Lock()
	b, ok := defaultProfiles.json[k]
	defaultProfiles.Unlock()
	if ok {
		return b
	}
	probe := &specs.Spec{Process: &specs.Process{Capabilities: &specs.LinuxCapabilities{Bounding: bounding}}}
	b, _ = json.Marshal(seccomp.DefaultProfile(probe))
	defaultProfiles.Lock()
	if len(defaultProfiles.json) >= maxDefaultProfiles {
		clear(defaultProfiles.json)
	}
	defaultProfiles.json[k] = b
	defaultProfiles.Unlock()
	return b
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
