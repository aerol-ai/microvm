package rootpolicy

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
)

// Rule names the part of the envelope a request broke. It is a short,
// stable code: the gate reports it as the refusal's reason, and a metric
// label must not grow with request content (eng review D9).
type Rule string

const (
	RuleID              Rule = "id"
	RuleSpec            Rule = "spec"
	RuleField           Rule = "field"
	RuleHook            Rule = "hook"
	RuleRootfsPath      Rule = "rootfs_path"
	RuleHostNamespace   Rule = "host_namespace"
	RuleMount           Rule = "mount"
	RuleDevice          Rule = "device"
	RuleCapability      Rule = "capability"
	RuleSeccomp         Rule = "seccomp"
	RuleNoNewPrivileges Rule = "no_new_privileges"
	RuleProcess         Rule = "process"
	RuleMaskedPaths     Rule = "masked_paths"
	RuleReadonlyPaths   Rule = "readonly_paths"
	RuleSysctl          Rule = "sysctl"
	RuleResources       Rule = "resources"
	RuleCgroup          Rule = "cgroup"
	RuleAnnotation      Rule = "annotation"
	RuleLabel           Rule = "label"
	RuleRuntime         Rule = "runtime"
	RuleRuntimeOptions  Rule = "runtime_options"
	RuleSnapshotter     Rule = "snapshotter"
	RuleSnapshotMount   Rule = "snapshot_mount"
	RuleTaskIO          Rule = "task_io"
	RuleTask            Rule = "task"
	RuleCheckpoint      Rule = "checkpoint"
	RuleNamespace       Rule = "namespace"
	RuleUpdate          Rule = "update"
	// The root helper's network calls (network.go).
	RuleNetns   Rule = "netns"
	RuleAddress Rule = "address"
	// The root helper's firewall calls (firewall.go).
	RuleCIDR     Rule = "cidr"
	RuleNodePort Rule = "node_port"
	RuleLease    Rule = "lease"
	// The root helper's calls for the hostname egress gateway (egress.go).
	RuleProbe        Rule = "probe"
	RuleProcessMatch Rule = "process_match"
	// The root helper's raw-TCP host-port forwarding (hostport.go).
	RuleHostPort Rule = "host_port"
	// The root helper's host-process calls (hosts.go).
	RuleHost       Rule = "host"
	RuleHostLimits Rule = "host_limits"
)

// Violation is a refused request: which rule, and what about the request
// broke it. Error returns the detail alone, so callers that only show text
// (the agent's own ID check) read as before.
type Violation struct {
	Rule   Rule
	Detail string
}

func (v *Violation) Error() string { return v.Detail }

func violate(rule Rule, format string, args ...any) error {
	return &Violation{Rule: rule, Detail: fmt.Sprintf(format, args...)}
}

// RuleOf returns the rule err broke, or "" when err is not a Violation.
func RuleOf(err error) Rule {
	var v *Violation
	if errors.As(err, &v) {
		return v.Rule
	}
	return ""
}

// onlyFields refuses any field of the struct v points at, other than
// allowed, that is set. It is how every spec struct is checked: a field the
// builder never sets (and every field a future runtime-spec adds) is
// refused, rather than passed because no rule names it. where prefixes the
// JSON name in the message.
func onlyFields(v any, where string, allowed ...string) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			return nil
		}
		rv = rv.Elem()
	}
	rt := rv.Type()
	for i := range rt.NumField() {
		f := rt.Field(i)
		if !f.IsExported() || slices.Contains(allowed, f.Name) {
			continue
		}
		if !rv.Field(i).IsZero() {
			return violate(RuleField, "%s.%s is set; the sandbox envelope never sets it", where, jsonName(f))
		}
	}
	return nil
}

func jsonName(f reflect.StructField) string {
	name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
	if name == "" {
		return f.Name
	}
	return name
}
