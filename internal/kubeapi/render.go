package kubeapi

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/kubeview"
)

// SpecSummary is what a rendered Sandbox shows of the sandbox's create
// request. The placement row does not carry the spec, so it is read from
// the servers in batches and may be missing; a Sandbox renders without it.
// Environment values are never shown: they may be secrets.
type SpecSummary struct {
	Image    string
	Runtime  string
	CPU      float64
	MemoryMB int
	Command  []string
	// Tags are the object's labels.
	Tags map[string]string
}

// dnsSubdomain is the Kubernetes object-name rule (RFC 1123 subdomain).
var dnsSubdomain = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)

// ValidName reports whether s can name a Kubernetes object.
func ValidName(s string) bool {
	return len(s) <= 253 && dnsSubdomain.MatchString(s)
}

// ObjectName is the name a sandbox has in Kubernetes: its AerolVM name when
// that is a valid object name, else its ID (which always is).
func ObjectName(p cluster.Placement) string {
	if ValidName(p.Name) {
		return p.Name
	}
	return p.SandboxID
}

func rfc3339(unix int64) string {
	if unix <= 0 {
		return ""
	}
	return time.Unix(unix, 0).UTC().Format(time.RFC3339)
}

// runtimeClass maps an AerolVM runtime to the RuntimeClass name shown.
// AerolVM's runtimes are not the cluster's RuntimeClasses; the name only
// tells a reader which isolation the sandbox has.
func runtimeClass(runtime string) string {
	switch runtime {
	case "", "docker":
		return ""
	default:
		return runtime
	}
}

// SandboxFrom renders one sandbox for namespace ns.
func SandboxFrom(item kubeview.Item, ns string, spec *SpecSummary) Sandbox {
	p := item.Placement
	annotations := map[string]string{AnnotationSandboxID: p.SandboxID}
	if p.Name != "" && !ValidName(p.Name) {
		annotations[AnnotationName] = p.Name
	}
	container := Container{Name: "sandbox"}
	var runtimeClassName string
	var labels map[string]string
	if spec != nil {
		container.Image = spec.Image
		container.Command = spec.Command
		if spec.CPU > 0 || spec.MemoryMB > 0 {
			limits := map[string]string{}
			if spec.CPU > 0 {
				limits["cpu"] = strconv.FormatFloat(spec.CPU, 'f', -1, 64)
			}
			if spec.MemoryMB > 0 {
				limits["memory"] = strconv.Itoa(spec.MemoryMB) + "Mi"
			}
			container.Resources = &ResourceRequirements{Limits: limits}
		}
		runtimeClassName = runtimeClass(spec.Runtime)
		labels = spec.Tags
		if spec.Runtime != "" {
			annotations[AnnotationRuntime] = spec.Runtime
		}
	}
	created := rfc3339(p.CreatedUnix)
	out := Sandbox{
		TypeMeta: TypeMeta{APIVersion: GroupVersion(), Kind: SandboxKind},
		Metadata: ObjectMeta{
			Name:              ObjectName(p),
			Namespace:         ns,
			UID:               uid(p),
			ResourceVersion:   strconv.FormatUint(item.RV, 10),
			Generation:        1,
			CreationTimestamp: created,
			Labels:            labels,
			Annotations:       annotations,
		},
		Spec: SandboxSpec{
			PodTemplate:   PodTemplate{Spec: PodSpec{Containers: []Container{container}, RuntimeClassName: runtimeClassName}},
			OperatingMode: OperatingModeRunning,
		},
		Status: SandboxStatus{NodeName: p.OwnerNodeID},
	}
	if p.IsDeleting() {
		out.Metadata.DeletionTimestamp = rfc3339(p.UpdatedUnix)
	}
	out.Status.Conditions = conditions(p, created)
	if p.RunState == cluster.RunStateSuspended {
		out.Spec.OperatingMode = OperatingModeSuspended
	}
	return out
}

// uid is the sandbox's lifetime: an ID made again (an Idempotency-Key
// create after a delete) is a new object to Kubernetes.
func uid(p cluster.Placement) string {
	if p.IncarnationID != "" {
		return p.IncarnationID
	}
	return p.SandboxID
}

// conditions follow upstream: Ready is the signal clients wait on. A placed
// sandbox is running (the placement is promoted only once it runs) until
// its owner reports otherwise.
func conditions(p cluster.Placement, created string) []Condition {
	when := created
	if p.UpdatedUnix > 0 {
		when = rfc3339(p.UpdatedUnix)
	}
	switch {
	case p.IsDeleting():
		return []Condition{
			{Type: ConditionReady, Status: "False", LastTransitionTime: when, Reason: ReasonPodTerminating, Message: "the sandbox is being deleted"},
		}
	case p.RunState == cluster.RunStateSuspended:
		return []Condition{
			{Type: ConditionReady, Status: "False", LastTransitionTime: when, Reason: ReasonSandboxSuspended, Message: "the sandbox is stopped"},
			{Type: ConditionSuspended, Status: "True", LastTransitionTime: when, Reason: ReasonPodTerminated, Message: "the sandbox is stopped"},
		}
	case p.RunState == cluster.RunStateFailed:
		msg := strings.TrimSpace(p.RunStateReason)
		if msg == "" {
			msg = "the sandbox failed"
		}
		return []Condition{
			{Type: ConditionReady, Status: "False", LastTransitionTime: when, Reason: ReasonPodFailed, Message: msg},
			{Type: ConditionFinished, Status: "True", LastTransitionTime: when, Reason: ReasonPodFailed, Message: msg},
		}
	}
	return []Condition{
		{Type: ConditionReady, Status: "True", LastTransitionTime: when, Reason: ReasonDependenciesReady, Message: "the sandbox is running"},
		{Type: ConditionSuspended, Status: "False", LastTransitionTime: when, Reason: ReasonNotSuspended, Message: "the sandbox is running"},
	}
}
