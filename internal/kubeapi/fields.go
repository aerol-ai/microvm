package kubeapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// The field table (plan §16, C17): every upstream Sandbox field a create may
// set is either supported, and mapped onto an AerolVM create, or refused
// with its path named. Nothing is ignored silently: a field AerolVM cannot
// honour (a Kubernetes service account, IRSA, volumes, node placement,
// security contexts, a second container) would otherwise look accepted and
// not apply.
//
// fieldTable is the supported tree. A map is an object whose listed keys
// are supported; "*" is a map of any keys; "[1]" is a list of exactly one
// item of the given shape; true is a leaf.
var fieldTable = map[string]any{
	"apiVersion": true,
	"kind":       true,
	"metadata": map[string]any{
		"name": true, "generateName": true, "namespace": true,
		"labels": "*", "annotations": "*",
	},
	"spec": map[string]any{
		"podTemplate": map[string]any{
			"metadata": map[string]any{"labels": "*", "annotations": "*"},
			"spec": map[string]any{
				"containers": []any{map[string]any{
					"name": true, "image": true, "command": true, "args": true,
					"env": []any{map[string]any{"name": true, "value": true}},
					"resources": map[string]any{
						"limits":   map[string]any{"cpu": true, "memory": true},
						"requests": map[string]any{"cpu": true, "memory": true},
					},
				}},
				"runtimeClassName": true,
			},
		},
		"shutdownTime":   true,
		"shutdownPolicy": true,
		"operatingMode":  true,
	},
	// Status is the server's; a client's copy is dropped, as Kubernetes
	// drops it for a resource with a status subresource.
	"status": "*",
}

// FieldError is a create that names fields AerolVM refuses or values it
// cannot use. The API answers 422 Invalid with every one listed.
type FieldError struct {
	Fields []string
}

func (e *FieldError) Error() string {
	return "not supported by AerolVM: " + strings.Join(e.Fields, "; ")
}

// refusedFields walks v against the table and returns every path outside it.
func refusedFields(v any, table any, path string, out *[]string) {
	switch t := table.(type) {
	case bool:
		return
	case string: // "*": any keys, any values
		return
	case map[string]any:
		obj, ok := v.(map[string]any)
		if !ok {
			if v != nil {
				*out = append(*out, path+": must be an object")
			}
			return
		}
		keys := make([]string, 0, len(obj))
		for k := range obj {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			sub, ok := t[k]
			p := k
			if path != "" {
				p = path + "." + k
			}
			if !ok {
				*out = append(*out, p)
				continue
			}
			refusedFields(obj[k], sub, p, out)
		}
	case []any:
		list, ok := v.([]any)
		if !ok {
			if v != nil {
				*out = append(*out, path+": must be a list")
			}
			return
		}
		item := t[0]
		for i, el := range list {
			refusedFields(el, item, fmt.Sprintf("%s[%d]", path, i), out)
		}
	}
}

// CreateFrom checks a Sandbox create body and turns it into an AerolVM
// create. now dates a shutdownTime; random names a generateName.
func CreateFrom(body []byte, now time.Time, random func() string) (models.CreateSandboxRequest, Sandbox, error) {
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return models.CreateSandboxRequest{}, Sandbox{}, fmt.Errorf("the body is not a JSON object: %w", err)
	}
	var refused []string
	refusedFields(raw, fieldTable, "", &refused)
	var sb Sandbox
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(&sb); err != nil {
		refused = append(refused, "body: "+err.Error())
	}
	if len(refused) > 0 {
		return models.CreateSandboxRequest{}, sb, &FieldError{Fields: refused}
	}
	req, problems := createRequest(&sb, now, random)
	if len(problems) > 0 {
		return models.CreateSandboxRequest{}, sb, &FieldError{Fields: problems}
	}
	return req, sb, nil
}

func createRequest(sb *Sandbox, now time.Time, random func() string) (models.CreateSandboxRequest, []string) {
	var problems []string
	bad := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }
	if sb.APIVersion != "" && sb.APIVersion != GroupVersion() {
		bad("apiVersion: must be %s", GroupVersion())
	}
	if sb.Kind != "" && sb.Kind != SandboxKind {
		bad("kind: must be %s", SandboxKind)
	}
	name := sb.Metadata.Name
	if name == "" && sb.Metadata.GenerateName != "" {
		name = sb.Metadata.GenerateName + random()
		sb.Metadata.Name = name
	}
	switch {
	case name == "":
		bad("metadata.name: required")
	case !ValidName(name):
		bad("metadata.name: %q is not a valid Kubernetes name", name)
	default:
		if err := models.ValidateSandboxName(name); err != nil {
			bad("metadata.name: %v", err)
		}
	}
	containers := sb.Spec.PodTemplate.Spec.Containers
	if len(containers) != 1 {
		bad("spec.podTemplate.spec.containers: exactly one container (a sandbox is one machine)")
		return models.CreateSandboxRequest{}, problems
	}
	c := containers[0]
	req := models.CreateSandboxRequest{Name: name, Image: strings.TrimSpace(c.Image), Tags: sandboxTags(sb)}
	if req.Image == "" {
		bad("spec.podTemplate.spec.containers[0].image: required")
	}
	req.ContainerCommand = append(append([]string(nil), c.Command...), c.Args...)
	if len(c.Env) > 0 {
		req.Env = make(map[string]string, len(c.Env))
		for i, e := range c.Env {
			if strings.TrimSpace(e.Name) == "" {
				bad("spec.podTemplate.spec.containers[0].env[%d].name: required", i)
				continue
			}
			if _, dup := req.Env[e.Name]; dup {
				bad("spec.podTemplate.spec.containers[0].env[%d].name: %q is set twice", i, e.Name)
			}
			req.Env[e.Name] = e.Value
		}
	}
	if r := c.Resources; r != nil {
		pick := func(key string) (string, string) {
			if v, ok := r.Limits[key]; ok {
				return v, "limits." + key
			}
			if v, ok := r.Requests[key]; ok {
				return v, "requests." + key
			}
			return "", ""
		}
		if v, at := pick("cpu"); v != "" {
			cpu, err := ParseCPU(v)
			if err != nil {
				bad("spec.podTemplate.spec.containers[0].resources.%s: %v", at, err)
			}
			req.CPU = cpu
		}
		if v, at := pick("memory"); v != "" {
			mb, err := ParseMemoryMB(v)
			if err != nil {
				bad("spec.podTemplate.spec.containers[0].resources.%s: %v", at, err)
			}
			req.MemoryMB = mb
		}
	}
	runtime, err := RuntimeFor(sb.Spec.PodTemplate.Spec.RuntimeClassName)
	if err != nil {
		bad("spec.podTemplate.spec.runtimeClassName: %v", err)
	}
	req.Runtime = runtime
	switch sb.Spec.OperatingMode {
	case "", OperatingModeRunning:
	case OperatingModeSuspended:
		bad("spec.operatingMode: a sandbox is created Running; set Suspended once it exists")
	default:
		bad("spec.operatingMode: must be Running or Suspended")
	}
	if sb.Spec.ShutdownTime != "" {
		at, err := time.Parse(time.RFC3339, sb.Spec.ShutdownTime)
		if err != nil {
			bad("spec.shutdownTime: not an RFC 3339 time")
		} else if !at.After(now) {
			bad("spec.shutdownTime: must be in the future")
		} else {
			age := at.Sub(now).Round(time.Second)
			switch sb.Spec.ShutdownPolicy {
			case "", ShutdownPolicyRetain:
				// Retain keeps the object and ends the workload: AerolVM stops it.
				req.Lifecycle = &models.Lifecycle{StopAtAge: age}
			case ShutdownPolicyDelete:
				req.Lifecycle = &models.Lifecycle{DestroyAtAge: age}
			default:
				bad("spec.shutdownPolicy: must be Delete or Retain")
			}
		}
	} else if sb.Spec.ShutdownPolicy != "" && sb.Spec.ShutdownPolicy != ShutdownPolicyDelete && sb.Spec.ShutdownPolicy != ShutdownPolicyRetain {
		bad("spec.shutdownPolicy: must be Delete or Retain")
	}
	return req, problems
}

// sandboxTags are the sandbox's tags: its pod template's labels (where an
// upstream template often puts them), then its own, which win. A sandbox is
// one object, so both sets describe it.
func sandboxTags(sb *Sandbox) map[string]string {
	pod, own := sb.Spec.PodTemplate.Metadata.Labels, sb.Metadata.Labels
	if len(pod) == 0 {
		return own
	}
	tags := make(map[string]string, len(pod))
	for k, v := range pod {
		tags[k] = v
	}
	for k, v := range own {
		tags[k] = v
	}
	return tags
}

// RuntimeFor maps a RuntimeClass name onto an AerolVM runtime. The names
// are AerolVM's own: the sandbox does not run as a pod, so the cluster's
// RuntimeClasses do not apply.
func RuntimeFor(class string) (string, error) {
	switch strings.TrimSpace(class) {
	case "":
		return "", nil
	case "runc", models.RuntimeDocker:
		return models.RuntimeDocker, nil
	case "runsc", models.RuntimeGvisor:
		return models.RuntimeGvisor, nil
	case models.RuntimeFirecracker:
		return models.RuntimeFirecracker, nil
	}
	return "", fmt.Errorf("%q is not one of: gvisor (or runsc), firecracker, docker (or runc)", class)
}

// ParseCPU reads a Kubernetes CPU quantity ("500m", "2", "1.5") as cores.
func ParseCPU(q string) (float64, error) {
	q = strings.TrimSpace(q)
	var v float64
	var err error
	if strings.HasSuffix(q, "m") {
		v, err = strconv.ParseFloat(strings.TrimSuffix(q, "m"), 64)
		v /= 1000
	} else {
		v, err = strconv.ParseFloat(q, 64)
	}
	if err != nil || v <= 0 || math.IsInf(v, 0) || math.IsNaN(v) {
		return 0, fmt.Errorf("%q is not a CPU quantity such as 500m or 2", q)
	}
	return v, nil
}

var memoryUnits = []struct {
	suffix string
	bytes  float64
}{
	{"Ki", 1 << 10}, {"Mi", 1 << 20}, {"Gi", 1 << 30}, {"Ti", 1 << 40},
	{"k", 1e3}, {"M", 1e6}, {"G", 1e9}, {"T", 1e12},
}

// ParseMemoryMB reads a Kubernetes memory quantity ("512Mi", "1Gi", "1G",
// a plain byte count) as whole MiB, rounding up.
func ParseMemoryMB(q string) (int, error) {
	q = strings.TrimSpace(q)
	mult, num := 1.0, q
	for _, u := range memoryUnits {
		if strings.HasSuffix(q, u.suffix) {
			mult, num = u.bytes, strings.TrimSuffix(q, u.suffix)
			break
		}
	}
	v, err := strconv.ParseFloat(num, 64)
	if err != nil || v <= 0 || math.IsInf(v, 0) || math.IsNaN(v) {
		return 0, fmt.Errorf("%q is not a memory quantity such as 512Mi or 2Gi", q)
	}
	mb := math.Ceil(v * mult / (1 << 20))
	if mb > math.MaxInt32 {
		return 0, fmt.Errorf("%q is too large", q)
	}
	return int(mb), nil
}
