package kubeapi

import (
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"net/http"
	"slices"
	"strings"
	"time"
)

// A second `kubectl apply` (plan §16.1, a C17 follow-up). kubectl sends a
// merge patch with its own last-applied annotation and every field of the
// file that differs from what this server shows. What it shows is the
// sandbox's spec summary: image, command, runtime class, CPU, memory and
// labels. So a patch is applied to the shown object and judged by what it
// would change:
//
//	patch ─► merged onto the shown object ─► the create's own checks
//	  ─► image, command, runtime, CPU, memory, labels: a change is refused
//	     (a sandbox changes in place only by spec.operatingMode)
//	  ─► env, disk, shutdown time: not shown, so not compared; kept as they
//	     are, with a Warning kubectl prints
//	  ─► annotations: not kept, as on create
//
// Env is never compared: a server holds no sandbox's env in the clear
// (secrets hardening), and a hash of it would be a way to guess it.

// mergedSandbox is a Sandbox patch applied to the shown object, with what
// the create's checks make of it.
type mergedSandbox struct {
	sb       Sandbox
	mode     string
	warnings []string
}

// mergeSandboxPatch merges patch onto cur and checks the result as a
// create would. created dates a shutdownTime as the create did.
func mergeSandboxPatch(cur Sandbox, spec *SpecSummary, patch map[string]any, created time.Time) (mergedSandbox, error) {
	if spec == nil {
		// The shown object has no image or size then: nothing to compare.
		return mergedSandbox{}, &StatusError{Code: http.StatusServiceUnavailable, Reason: "ServiceUnavailable",
			Message: "the sandbox's spec could not be read just now, so the patch cannot be checked; try again"}
	}
	merged, err := mergeOnto(cur, patch)
	if err != nil {
		return mergedSandbox{}, err
	}
	var refused []string
	refusedFields(merged, fieldTable, "", &refused)
	if len(refused) > 0 {
		return mergedSandbox{}, invalid("not supported: " + strings.Join(refused, "; "))
	}
	var sb Sandbox
	if err := remarshal(merged, &sb); err != nil {
		return mergedSandbox{}, invalid(err.Error())
	}
	if sb.Metadata.Name != cur.Metadata.Name || sb.Metadata.Namespace != cur.Metadata.Namespace {
		return mergedSandbox{}, invalid("metadata.name and metadata.namespace cannot change")
	}
	out := mergedSandbox{sb: sb, mode: sb.Spec.OperatingMode}
	switch out.mode {
	case "", OperatingModeRunning, OperatingModeSuspended:
	default:
		return mergedSandbox{}, invalid("spec.operatingMode: must be Running or Suspended")
	}
	// The create's checks, with the mode it refuses set aside: a sandbox
	// is created Running, and suspended by this patch.
	sb.Spec.OperatingMode = ""
	req, problems := createRequest(&sb, created, func() string { return "" })
	if len(problems) > 0 {
		return mergedSandbox{}, invalid(strings.Join(problems, "; "))
	}
	var changed []string
	if req.Image != spec.Image {
		changed = append(changed, "image")
	}
	if !slices.Equal(req.ContainerCommand, spec.Command) {
		changed = append(changed, "command and args")
	}
	if req.Runtime != spec.Runtime {
		changed = append(changed, "runtimeClassName")
	}
	if math.Abs(req.CPU-spec.CPU) > 1e-9 {
		changed = append(changed, "cpu")
	}
	if req.MemoryMB != spec.MemoryMB {
		changed = append(changed, "memory")
	}
	if !maps.Equal(req.Tags, spec.Tags) && (len(req.Tags) > 0 || len(spec.Tags) > 0) {
		changed = append(changed, "labels")
	}
	if len(changed) > 0 {
		return mergedSandbox{}, invalid("a sandbox changes in place only by spec.operatingMode; delete it and create it again to change: " + strings.Join(changed, ", "))
	}
	c := sb.Spec.PodTemplate.Spec.Containers[0]
	if len(c.Env) > 0 {
		out.warnings = append(out.warnings, notCompared("spec.podTemplate.spec.containers[0].env"))
	}
	if c.Resources != nil && (c.Resources.Limits["ephemeral-storage"] != "" || c.Resources.Requests["ephemeral-storage"] != "") {
		out.warnings = append(out.warnings, notCompared("spec.podTemplate.spec.containers[0].resources ephemeral-storage"))
	}
	if sb.Spec.ShutdownTime != "" || sb.Spec.ShutdownPolicy != "" {
		out.warnings = append(out.warnings, notCompared("spec.shutdownTime and spec.shutdownPolicy"))
	}
	return out, nil
}

// mergeClaimPatch is mergeSandboxPatch for a claim: only its warm pool and
// labels are shown, so only they are compared.
func mergeClaimPatch(cur map[string]any, pool string, tags map[string]string, patch map[string]any) ([]string, error) {
	merged, err := mergeOnto(cur, patch)
	if err != nil {
		return nil, err
	}
	var refused []string
	refusedFields(merged, claimTable, "", &refused)
	if len(refused) > 0 {
		return nil, invalid("not supported: " + strings.Join(refused, "; "))
	}
	var c claimSpec
	if err := remarshal(merged, &c); err != nil {
		return nil, invalid(err.Error())
	}
	curMeta, _ := cur["metadata"].(map[string]any)
	if c.Metadata.Name != curMeta["name"] || c.Metadata.Namespace != curMeta["namespace"] {
		return nil, invalid("metadata.name and metadata.namespace cannot change")
	}
	var changed []string
	if c.Spec.WarmPoolRef.Name != pool {
		changed = append(changed, "spec.warmPoolRef")
	}
	for k, v := range c.Metadata.Labels {
		if tags[k] != v {
			changed = append(changed, "metadata.labels")
			break
		}
	}
	if len(changed) > 0 {
		return nil, invalid("a claim cannot change; delete it and claim again to change: " + strings.Join(changed, ", "))
	}
	var warnings []string
	if len(c.Spec.Env) > 0 {
		warnings = append(warnings, notCompared("spec.env"))
	}
	if c.Spec.Lifecycle != nil {
		warnings = append(warnings, notCompared("spec.lifecycle"))
	}
	if len(c.Spec.AdditionalPodMetadata.Labels) > 0 || len(c.Spec.AdditionalPodMetadata.Annotations) > 0 {
		warnings = append(warnings, notCompared("spec.additionalPodMetadata"))
	}
	return warnings, nil
}

// serverSetMetadata are the shown object's metadata fields the server
// sets; a create may not send them, and neither may a patch.
var serverSetMetadata = []string{"uid", "resourceVersion", "generation", "creationTimestamp", "deletionTimestamp", "managedFields", "selfLink"}

// mergeOnto applies a JSON merge patch to obj, as a JSON object, without
// the metadata the server sets.
func mergeOnto(obj any, patch map[string]any) (map[string]any, error) {
	var cur map[string]any
	if err := remarshal(obj, &cur); err != nil {
		return nil, err
	}
	if md, ok := cur["metadata"].(map[string]any); ok {
		for _, k := range serverSetMetadata {
			delete(md, k)
		}
	}
	merged, _ := mergePatch(cur, patch).(map[string]any)
	return merged, nil
}

func remarshal(in, out any) error {
	raw, err := json.Marshal(in)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

func invalid(msg string) error {
	return &StatusError{Code: http.StatusUnprocessableEntity, Reason: "Invalid", Message: msg}
}

func notCompared(field string) string {
	return field + ": not shown by this server, so not compared with the running sandbox, and not changed (it is set when the sandbox is created)"
}

// warn adds Kubernetes warnings, which kubectl prints.
func warn(w http.ResponseWriter, warnings []string) {
	for _, msg := range warnings {
		w.Header().Add("Warning", fmt.Sprintf("299 - %q", msg))
	}
}
