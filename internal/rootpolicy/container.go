package rootpolicy

import (
	"fmt"
	"path"
	"slices"
	"strings"

	runcoptions "github.com/containerd/containerd/api/types/runc/options"
	runtimeoptions "github.com/containerd/containerd/api/types/runtimeoptions/v1"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/aerol-ai/microvm/internal/ownerlease"
)

// Container is the part of a containerd container record the envelope
// reads, in containerd-neutral form so the agent's builder output and the
// gate's decoded request check alike.
type Container struct {
	ID          string
	Labels      map[string]string
	Runtime     Runtime
	SpecTypeURL string
	// Spec is the spec Any's bytes: the JSON containerd writes to
	// config.json unchanged.
	Spec        []byte
	Snapshotter string
	SnapshotKey string
	// Extensions names the container's extensions; the agent sets none.
	Extensions []string
	// Sandbox is the containerd sandbox the container belongs to. Its
	// controller, not the runtime checked here, would run it.
	Sandbox string
}

// Runtime is a container's runtime: the shim and its options Any.
type Runtime struct {
	Name           string
	OptionsTypeURL string
	Options        []byte
}

// CheckContainer checks a container record as Containers.Create would store
// it: its ID, labels, snapshotter, runtime and OCI spec.
func CheckContainer(p Policy, c Container) error {
	_, err := CheckContainerWith(p, c, nil)
	return err
}

// Checked is what the gate checks on disk for a container CheckContainer
// passed: the paths runc binds in, the paths root reads, and the network
// namespace it joins. All of it comes from the decode the check read.
type Checked struct {
	// BindSources are SpecBindSources.
	BindSources []string
	// RootReads are ContainerRootReads.
	RootReads []RootRead
	// Netns is ContainerNetns.
	Netns string
}

// SpecCheck checks a container's spec bytes for its ID and returns the
// spec's facts. CheckSpecFacts is the check; anything put in its place (the
// gate's memo) must answer exactly as CheckSpecFacts would for those bytes.
type SpecCheck func(containerID string, raw []byte) (*SpecFacts, error)

// CheckContainerWith is CheckContainer, and on a pass what the gate then
// checks on disk. The spec is decoded once. spec, when set, stands in for
// CheckSpecFacts(p, ...); nil means CheckSpecFacts itself.
func CheckContainerWith(p Policy, c Container, spec SpecCheck) (Checked, error) {
	if err := checkContainerRecord(p, c); err != nil {
		return Checked{}, err
	}
	var facts *SpecFacts
	var err error
	if spec != nil {
		facts, err = spec(c.ID, c.Spec)
	} else {
		facts, err = CheckSpecFacts(p, c.ID, c.Spec)
	}
	if err != nil {
		return Checked{}, err
	}
	if facts == nil { // fail closed on a stand-in that answers nothing
		return Checked{}, violate(RuleSpec, "the spec check gave no answer")
	}
	reads, err := runtimeRootReads(c.Runtime)
	if err != nil {
		return Checked{}, err
	}
	if facts.restore != "" {
		reads = append(reads, RootRead{Path: facts.restore, Folder: true, Rule: RuleCheckpoint})
	}
	// A copy: the facts may be shared, and the caller owns what it gets.
	return Checked{BindSources: slices.Clone(facts.bindSources), RootReads: reads, Netns: facts.netns}, nil
}

// checkContainerRecord is CheckContainer without the spec, which comes last.
func checkContainerRecord(p Policy, c Container) error {
	if err := ValidateID(c.ID); err != nil {
		return err
	}
	if err := CheckContainerLabels(c.Labels); err != nil {
		return err
	}
	if err := CheckSnapshotter(p, c.Snapshotter); err != nil {
		return err
	}
	if len(c.Extensions) > 0 {
		return violate(RuleField, "container extensions %v are set; the agent sets none", c.Extensions)
	}
	if c.Sandbox != "" {
		return violate(RuleRuntime, "the container belongs to containerd sandbox %q, whose controller would run it", c.Sandbox)
	}
	if err := CheckRuntime(p, c.Runtime); err != nil {
		return err
	}
	if c.SpecTypeURL != SpecTypeURL {
		return violate(RuleSpec, "spec type %q is not the OCI runtime spec (%s)", c.SpecTypeURL, SpecTypeURL)
	}
	return nil
}

// reservedLabelPrefix is containerd's own label space on containers. Its
// restart monitor acts on containerd.io/restart.* labels: it restarts the
// task as root, with its stdio at containerd.io/restart.loguri, and a
// binary:// URI there is a program containerd runs as root.
const reservedLabelPrefix = "containerd.io/"

// CheckContainerLabels refuses labels in containerd's own space.
func CheckContainerLabels(labels map[string]string) error {
	for _, k := range sortedKeys(labels) {
		if strings.HasPrefix(k, reservedLabelPrefix) {
			return violate(RuleLabel, "container label %q is in containerd's own label space", k)
		}
	}
	return nil
}

// CheckContainerUpdate allows an update of a container's labels and nothing
// else: the agent only relabels (SetLabels, on warm-pool adoption). An
// update with no field mask replaces the whole record, spec included.
func CheckContainerUpdate(paths []string) error {
	if len(paths) == 0 {
		return violate(RuleUpdate, "a container update with no field mask replaces its spec")
	}
	for _, fp := range paths {
		key, isLabel := strings.CutPrefix(fp, "labels.")
		if fp != "labels" && !isLabel {
			return violate(RuleUpdate, "container update of %q: only labels change after create", fp)
		}
		if strings.HasPrefix(key, reservedLabelPrefix) {
			return violate(RuleLabel, "container label %q is in containerd's own label space", key)
		}
	}
	return nil
}

// CheckSnapshotter allows only the policy's snapshotter.
func CheckSnapshotter(p Policy, name string) error {
	if name != p.Snapshotter {
		return violate(RuleSnapshotter, "snapshotter %q is not %s", name, p.Snapshotter)
	}
	return nil
}

// CheckRuntime allows runc and runsc, and checks every option each shim
// takes. Each option below names a host binary or folder the shim (root)
// acts on: a runc BinaryName of /bin/sh is root code execution, and a runsc
// config can set the binary it runs or turn on host networking.
func CheckRuntime(p Policy, r Runtime) error {
	switch r.Name {
	case RuntimeRunc:
		// The agent sends no runc options: the shim's defaults.
		if r.OptionsTypeURL == "" && len(r.Options) == 0 {
			return nil
		}
		var o runcoptions.Options
		if err := decodeOptions(r, &o); err != nil {
			return err
		}
		return onlyOptions(r.Name, &o, map[protoreflect.Name]func(string) error{
			"binary_name":     oneOf("binary_name", p.RuncBinaryNames),
			"root":            oneOf("root", p.RuncRoots),
			"shim_cgroup":     oneOf("shim_cgroup", p.RuncShimCgroups),
			"criu_image_path": func(v string) error { return CheckCheckpointPath(p, v) },
			"criu_work_path":  func(v string) error { return CheckCheckpointPath(p, v) },
		})
	case RuntimeRunsc:
		var o runtimeoptions.Options
		if err := decodeOptions(r, &o); err != nil {
			return err
		}
		if o.GetTypeUrl() != RunscOptionsTypeURL {
			return violate(RuleRuntimeOptions, "runsc options type %q is not %s", o.GetTypeUrl(), RunscOptionsTypeURL)
		}
		if o.GetConfigPath() == "" {
			return violate(RuleRuntimeOptions, "runsc options name no config; the helper's own config is required")
		}
		return onlyOptions(r.Name, &o, map[protoreflect.Name]func(string) error{
			"type_url":    func(string) error { return nil },
			"config_path": oneOf("config_path", p.RunscConfigPaths),
		})
	default:
		return violate(RuleRuntime, "runtime %q is not %s or %s", r.Name, RuntimeRunc, RuntimeRunsc)
	}
}

// decodeOptions decodes a runtime's options Any into m, accepting the type
// URL forms containerd accepts: the message's full name, alone or after a
// "/" (protoregistry's FindMessageByURL).
func decodeOptions(r Runtime, m proto.Message) error {
	want := string(m.ProtoReflect().Descriptor().FullName())
	url := r.OptionsTypeURL
	if url[strings.LastIndex(url, "/")+1:] != want {
		return violate(RuleRuntimeOptions, "%s options have type %q, not %s", r.Name, url, want)
	}
	if err := proto.Unmarshal(r.Options, m); err != nil {
		return violate(RuleRuntimeOptions, "%s options do not decode: %v", r.Name, err)
	}
	if len(m.ProtoReflect().GetUnknown()) > 0 {
		return violate(RuleRuntimeOptions, "%s options carry fields this build does not know", r.Name)
	}
	return nil
}

// onlyOptions refuses any set option that has no check, and runs the check
// of each one that does.
func onlyOptions(runtime string, m proto.Message, checks map[protoreflect.Name]func(string) error) error {
	var err error
	m.ProtoReflect().Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		check, ok := checks[fd.Name()]
		if !ok {
			err = violate(RuleRuntimeOptions, "%s option %s is set; the agent never sets it", runtime, fd.Name())
			return false
		}
		err = check(v.String())
		return err == nil
	})
	return err
}

func oneOf(name string, allowed []string) func(string) error {
	return func(v string) error {
		if slices.Contains(allowed, v) {
			return nil
		}
		return violate(RuleRuntimeOptions, "runtime option %s=%q is not one the helper allows", name, v)
	}
}

// ValidateID restricts a sandbox, slot or container ID to a filesystem-safe
// charset before anything builds a host path from it (a host files folder,
// a cgroup, a network namespace). The ID can arrive attacker-controlled
// (the X-Cluster-Create-ID header), so a "../" in it must never reach a path.
//
// An ID may not take a name the sandboxes' cgroup parent keeps for the
// machinery either (ownerlease.ReservedGroup): a sandbox's cgroup is
// <parent>/<id>, the worker pod's supervisor keeps containerd, every shim
// and the root helper in <parent>/_runtime, and the host-process runtimes
// keep theirs in <parent>/aerolvm-*. The rule is the same in both privilege
// modes, so a sandbox that single mode creates is one split mode can also
// run. No generated ID takes either form ("sb-", "aerol-netns-", "park-").
func ValidateID(id string) error {
	if id == "" {
		return violate(RuleID, "sandbox ID is required")
	}
	if len(id) > 128 {
		return violate(RuleID, "sandbox ID exceeds 128 chars (%d)", len(id))
	}
	if ownerlease.ReservedGroup(id) {
		return violate(RuleID, "sandbox ID %q starts with \"_\" or \"aerolvm-\", which the sandboxes' cgroup parent keeps for AerolVM's own processes", id)
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_':
		default:
			return violate(RuleID, "invalid character %q in sandbox ID %q", r, id)
		}
	}
	return nil
}

// ContainerNetns returns the name of the network namespace a container's
// spec joins under the netns folder, or "" when the sandbox gets one of its
// own. CheckNetnsPath only checks that name's form; whose namespace it is
// is the helper's to say (gate.NetnsBinding).
func ContainerNetns(c Container) (string, error) {
	s, err := DecodeSpec(c.Spec)
	if err != nil {
		return "", err
	}
	return netnsOf(s), nil
}

func netnsOf(s *specs.Spec) string {
	if s.Linux == nil {
		return ""
	}
	for _, ns := range s.Linux.Namespaces {
		if ns.Type == specs.NetworkNamespace && ns.Path != "" {
			return path.Base(ns.Path)
		}
	}
	return ""
}

// CheckNamespace allows only the agent's own containerd namespace.
func CheckNamespace(p Policy, ns string) error {
	if ns != p.Namespace {
		return violate(RuleNamespace, "containerd namespace %q is not the agent's (%s)", ns, p.Namespace)
	}
	return nil
}

// defaultsLabelPrefix holds a namespace's default runtime, snapshotter and
// sandboxer: a label there changes what every create in the namespace that
// names none runs.
const defaultsLabelPrefix = "containerd.io/defaults/"

// CheckNamespaceLabels refuses a namespace that carries default labels.
func CheckNamespaceLabels(labels map[string]string) error {
	for _, k := range sortedKeys(labels) {
		if strings.HasPrefix(k, defaultsLabelPrefix) {
			return violate(RuleNamespace, "namespace label %s=%q sets a default for every container", k, labels[k])
		}
	}
	return nil
}

// checkNamespaceName mirrors containerd's namespace name rule, enough to
// keep a policy from naming something containerd would not.
func checkNamespaceName(ns string) error {
	if ns == "" || len(ns) > 76 {
		return fmt.Errorf("namespace %q: want 1 to 76 characters", ns)
	}
	for i, r := range ns {
		alnum := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
		if !alnum && (i == 0 || (r != '.' && r != '_' && r != '-')) {
			return fmt.Errorf("namespace %q: invalid character %q", ns, r)
		}
	}
	return nil
}
