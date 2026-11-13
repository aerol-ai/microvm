package kubeapi

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/kubeview"
	"github.com/aerol-ai/microvm/pkg/models"
)

var now = time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)

func fixed() string { return "x7k2p" }

func TestValidNameAndObjectName(t *testing.T) {
	for name, ok := range map[string]bool{
		"web": true, "web-1.prod": true, "Web": false, "-web": false, "web_1": false, strings.Repeat("a", 254): false,
	} {
		if ValidName(name) != ok {
			t.Errorf("ValidName(%q) = %v", name, !ok)
		}
	}
	if got := ObjectName(cluster.Placement{SandboxID: "sb-1", Name: "web"}); got != "web" {
		t.Fatalf("named = %q", got)
	}
	if got := ObjectName(cluster.Placement{SandboxID: "sb-1", Name: "My App"}); got != "sb-1" {
		t.Fatalf("an invalid name = %q", got)
	}
	// A cluster stores names qualified with their owner (p6-kubeapi-3 showed
	// every sandbox under its ID until this was decoded).
	if got := ObjectName(cluster.Placement{SandboxID: "sb-1", Name: cluster.QualifiedSandboxName("team:a", "web")}); got != "web" {
		t.Fatalf("a qualified name = %q", got)
	}
	q := SandboxFrom(kubeview.Item{Placement: cluster.Placement{SandboxID: "sb-1", Name: cluster.QualifiedSandboxName("team:a", "My App")}}, "a", nil)
	if q.Metadata.Name != "sb-1" || q.Metadata.Annotations[AnnotationName] != "My App" {
		t.Fatalf("a qualified invalid name = %+v", q.Metadata)
	}
}

func TestSandboxFrom(t *testing.T) {
	p := cluster.Placement{SandboxID: "sb-1", Name: "My App", OwnerRef: "team:a", OwnerNodeID: "w1",
		IncarnationID: "inc-1", CreatedUnix: now.Unix(), UpdatedUnix: now.Unix() + 5, Version: 7}
	sb := SandboxFrom(kubeview.Item{Placement: p, RV: 9}, "a", &SpecSummary{Image: "python:3.12", Runtime: "gvisor", CPU: 0.5, MemoryMB: 512, Command: []string{"sleep", "inf"}})
	m := sb.Metadata
	if sb.APIVersion != "agents.x-k8s.io/v1beta1" || sb.Kind != "Sandbox" || m.Name != "sb-1" || m.Namespace != "a" || m.UID != "inc-1" || m.ResourceVersion != "9" {
		t.Fatalf("metadata = %+v %+v", sb.TypeMeta, m)
	}
	if m.Annotations[AnnotationName] != "My App" || m.Annotations[AnnotationSandboxID] != "sb-1" || m.Annotations[AnnotationRuntime] != "gvisor" {
		t.Fatalf("annotations = %v", m.Annotations)
	}
	c := sb.Spec.PodTemplate.Spec.Containers[0]
	if c.Image != "python:3.12" || c.Resources.Limits["cpu"] != "0.5" || c.Resources.Limits["memory"] != "512Mi" || sb.Spec.PodTemplate.Spec.RuntimeClassName != "gvisor" {
		t.Fatalf("container = %+v", c)
	}
	if sb.Spec.OperatingMode != OperatingModeRunning || sb.Status.NodeName != "w1" || sb.Status.Conditions[0].Status != "True" {
		t.Fatalf("running = %+v %+v", sb.Spec, sb.Status)
	}

	// Stopped, failed, being deleted; and no spec summary at all.
	p.RunState = cluster.RunStateSuspended
	if sb := SandboxFrom(kubeview.Item{Placement: p}, "a", nil); sb.Spec.OperatingMode != OperatingModeSuspended || sb.Status.Conditions[0].Reason != ReasonSandboxSuspended {
		t.Fatalf("stopped = %+v", sb)
	}
	p.RunState, p.RunStateReason = cluster.RunStateFailed, "exited 137"
	if sb := SandboxFrom(kubeview.Item{Placement: p}, "a", nil); sb.Status.Conditions[0].Message != "exited 137" || sb.Status.Conditions[1].Type != ConditionFinished {
		t.Fatalf("failed = %+v", sb.Status)
	}
	p.RunStateReason = ""
	if sb := SandboxFrom(kubeview.Item{Placement: p}, "a", nil); sb.Status.Conditions[0].Message != "the sandbox failed" {
		t.Fatalf("failed without a reason = %+v", sb.Status)
	}
	p.State = cluster.PlacementStateDeleting
	if sb := SandboxFrom(kubeview.Item{Placement: p}, "a", nil); sb.Metadata.DeletionTimestamp == "" || sb.Status.Conditions[0].Reason != ReasonPodTerminating {
		t.Fatalf("deleting = %+v", sb)
	}
	// The JSON is Kubernetes' shape.
	raw, _ := json.Marshal(SandboxFrom(kubeview.Item{Placement: cluster.Placement{SandboxID: "sb-2"}}, "a", nil))
	for _, want := range []string{`"apiVersion":"agents.x-k8s.io/v1beta1"`, `"podTemplate":{"spec":{"containers":[{"name":"sandbox"}]}`, `"uid":"sb-2"`} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("JSON %s lacks %s", raw, want)
		}
	}
}

const goodCreate = `{
  "apiVersion": "agents.x-k8s.io/v1beta1", "kind": "Sandbox",
  "metadata": {"name": "web", "namespace": "a", "labels": {"app": "agent"}, "annotations": {"note": "x"}},
  "spec": {
    "podTemplate": {
      "metadata": {"labels": {"x": "y"}},
      "spec": {
        "runtimeClassName": "gvisor",
        "containers": [{
          "name": "main", "image": "python:3.12", "command": ["python"], "args": ["-m", "http.server"],
          "env": [{"name": "MODE", "value": "dev"}],
          "resources": {"limits": {"cpu": "500m", "memory": "1Gi"}}
        }]
      }
    },
    "shutdownTime": "2026-11-13T13:00:00Z", "shutdownPolicy": "Delete"
  },
  "status": {"conditions": []}
}`

func TestCreateFrom(t *testing.T) {
	req, sb, err := CreateFrom([]byte(goodCreate), now, fixed)
	if err != nil {
		t.Fatal(err)
	}
	if req.Name != "web" || req.Image != "python:3.12" || req.Runtime != models.RuntimeGvisor || req.CPU != 0.5 || req.MemoryMB != 1024 {
		t.Fatalf("req = %+v", req)
	}
	if strings.Join(req.ContainerCommand, " ") != "python -m http.server" || req.Env["MODE"] != "dev" || req.Tags["app"] != "agent" {
		t.Fatalf("req = %+v", req)
	}
	// Upstream's defaults, spelled out, are accepted (v1.0.11).
	defaults := strings.Replace(goodCreate, `"shutdownTime"`, `"service": false, "failedPodPolicy": "Retain", "shutdownTime"`, 1)
	if _, _, err := CreateFrom([]byte(defaults), now, fixed); err != nil {
		t.Fatalf("upstream's defaults = %v", err)
	}
	// The pod template's labels are tags too; the sandbox's own win.
	if req.Tags["x"] != "y" || len(req.Tags) != 2 {
		t.Fatalf("tags = %v, want the pod template's label x too", req.Tags)
	}
	clash := strings.Replace(goodCreate, `{"labels": {"x": "y"}}`, `{"labels": {"x": "y", "app": "pod"}}`, 1)
	if req, _, err := CreateFrom([]byte(clash), now, fixed); err != nil || req.Tags["app"] != "agent" || req.Tags["x"] != "y" {
		t.Fatalf("a clash = %v %v, want the sandbox's own label", req.Tags, err)
	}
	if req.Lifecycle == nil || req.Lifecycle.DestroyAtAge != time.Hour || sb.Metadata.Name != "web" {
		t.Fatalf("lifecycle = %+v", req.Lifecycle)
	}

	// Retain stops; generateName names; requests stand in for limits.
	body := `{"metadata":{"generateName":"job-"},"spec":{"podTemplate":{"spec":{"containers":[{"name":"m","image":"alpine","resources":{"requests":{"cpu":"2","memory":"512Mi"}}}]}},"shutdownTime":"2026-11-13T12:30:00Z"}}`
	req, sb, err = CreateFrom([]byte(body), now, fixed)
	if err != nil {
		t.Fatal(err)
	}
	if req.Name != "job-x7k2p" || sb.Metadata.Name != "job-x7k2p" || req.CPU != 2 || req.MemoryMB != 512 || req.Lifecycle.StopAtAge != 30*time.Minute {
		t.Fatalf("req = %+v %+v", req, req.Lifecycle)
	}
}

func TestCreateFromRefuses(t *testing.T) {
	container := func(extra string) string {
		return `{"metadata":{"name":"web"},"spec":{"podTemplate":{"spec":{"containers":[{"name":"m","image":"alpine"` + extra + `}]}}}}`
	}
	for _, tc := range []struct {
		name, body, want string
	}{
		{"service account", `{"metadata":{"name":"web"},"spec":{"podTemplate":{"spec":{"serviceAccountName":"x","containers":[{"name":"m","image":"alpine"}]}}}}`, "spec.podTemplate.spec.serviceAccountName"},
		{"volumes", `{"metadata":{"name":"web"},"spec":{"volumeClaimTemplates":[],"podTemplate":{"spec":{"containers":[{"name":"m","image":"alpine"}]}}}}`, "spec.volumeClaimTemplates"},
		{"security context", container(`,"securityContext":{"privileged":true}`), "spec.podTemplate.spec.containers[0].securityContext"},
		{"env from", container(`,"env":[{"name":"A","valueFrom":{}}]`), "spec.podTemplate.spec.containers[0].env[0].valueFrom"},
		{"two containers", `{"metadata":{"name":"web"},"spec":{"podTemplate":{"spec":{"containers":[{"name":"a","image":"x"},{"name":"b","image":"y"}]}}}}`, "exactly one container"},
		{"no image", `{"metadata":{"name":"web"},"spec":{"podTemplate":{"spec":{"containers":[{"name":"a"}]}}}}`, "image: required"},
		{"no name", `{"spec":{"podTemplate":{"spec":{"containers":[{"name":"a","image":"x"}]}}}}`, "metadata.name: required"},
		{"bad name", `{"metadata":{"name":"Web"},"spec":{"podTemplate":{"spec":{"containers":[{"name":"a","image":"x"}]}}}}`, "not a valid Kubernetes name"},
		{"an ID as a name", `{"metadata":{"name":"sb-0123456789abcdef"},"spec":{"podTemplate":{"spec":{"containers":[{"name":"a","image":"x"}]}}}}`, "metadata.name"},
		{"bad cpu", container(`,"resources":{"limits":{"cpu":"lots"}}`), "resources.limits.cpu"},
		{"bad memory", container(`,"resources":{"limits":{"memory":"-1Gi"}}`), "resources.limits.memory"},
		{"other resource", container(`,"resources":{"limits":{"nvidia.com/gpu":"1"}}`), "resources.limits.nvidia.com/gpu"},
		{"runtime", `{"metadata":{"name":"web"},"spec":{"podTemplate":{"spec":{"runtimeClassName":"kata","containers":[{"name":"a","image":"x"}]}}}}`, "runtimeClassName"},
		{"a service", `{"metadata":{"name":"web"},"spec":{"service":true,"podTemplate":{"spec":{"containers":[{"name":"a","image":"x"}]}}}}`, "spec.service"},
		{"recreate on failure", `{"metadata":{"name":"web"},"spec":{"failedPodPolicy":"Recreate","podTemplate":{"spec":{"containers":[{"name":"a","image":"x"}]}}}}`, "only Retain"},
		{"unknown failure policy", `{"metadata":{"name":"web"},"spec":{"failedPodPolicy":"Restart","podTemplate":{"spec":{"containers":[{"name":"a","image":"x"}]}}}}`, "must be Retain"},
		{"created suspended", `{"metadata":{"name":"web"},"spec":{"operatingMode":"Suspended","podTemplate":{"spec":{"containers":[{"name":"a","image":"x"}]}}}}`, "created Running"},
		{"unknown mode", `{"metadata":{"name":"web"},"spec":{"operatingMode":"Paused","podTemplate":{"spec":{"containers":[{"name":"a","image":"x"}]}}}}`, "Running or Suspended"},
		{"past shutdown", `{"metadata":{"name":"web"},"spec":{"shutdownTime":"2026-11-13T11:00:00Z","podTemplate":{"spec":{"containers":[{"name":"a","image":"x"}]}}}}`, "in the future"},
		{"bad shutdown", `{"metadata":{"name":"web"},"spec":{"shutdownTime":"soon","podTemplate":{"spec":{"containers":[{"name":"a","image":"x"}]}}}}`, "RFC 3339"},
		{"bad policy", `{"metadata":{"name":"web"},"spec":{"shutdownPolicy":"Keep","podTemplate":{"spec":{"containers":[{"name":"a","image":"x"}]}}}}`, "Delete or Retain"},
		{"bad policy with a time", `{"metadata":{"name":"web"},"spec":{"shutdownTime":"2026-11-13T13:00:00Z","shutdownPolicy":"Keep","podTemplate":{"spec":{"containers":[{"name":"a","image":"x"}]}}}}`, "Delete or Retain"},
		{"duplicate env", container(`,"env":[{"name":"A","value":"1"},{"name":"A","value":"2"}]`), "set twice"},
		{"nameless env", container(`,"env":[{"value":"1"}]`), "env[0].name: required"},
		{"wrong kind", `{"kind":"Pod","metadata":{"name":"web"},"spec":{"podTemplate":{"spec":{"containers":[{"name":"a","image":"x"}]}}}}`, "kind: must be Sandbox"},
		{"wrong version", `{"apiVersion":"agents.x-k8s.io/v1alpha1","metadata":{"name":"web"},"spec":{"podTemplate":{"spec":{"containers":[{"name":"a","image":"x"}]}}}}`, "apiVersion"},
		{"not an object", `{"metadata":"web"}`, "metadata: must be an object"},
		{"not a list", `{"metadata":{"name":"web"},"spec":{"podTemplate":{"spec":{"containers":{"name":"a"}}}}}`, "containers: must be a list"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := CreateFrom([]byte(tc.body), now, fixed)
			var fe *FieldError
			if !errors.As(err, &fe) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("CreateFrom = %v, want a field error naming %q", err, tc.want)
			}
		})
	}
	if _, _, err := CreateFrom([]byte("not json"), now, fixed); err == nil {
		t.Fatal("a body that is not JSON")
	}
}

func TestQuantities(t *testing.T) {
	for q, want := range map[string]float64{"500m": 0.5, "2": 2, "1.5": 1.5, " 250m ": 0.25} {
		if got, err := ParseCPU(q); err != nil || got != want {
			t.Errorf("ParseCPU(%q) = %v %v", q, got, err)
		}
	}
	for _, q := range []string{"", "0", "-1", "lots", "NaNm", "Inf"} {
		if _, err := ParseCPU(q); err == nil {
			t.Errorf("ParseCPU(%q) took a bad value", q)
		}
	}
	for q, want := range map[string]int{"512Mi": 512, "1Gi": 1024, "1G": 954, "1048576": 1, "1500k": 2, "1Ki": 1, "1Ti": 1 << 20, "1T": 953675, "1M": 1} {
		if got, err := ParseMemoryMB(q); err != nil || got != want {
			t.Errorf("ParseMemoryMB(%q) = %v %v, want %d", q, got, err, want)
		}
	}
	for _, q := range []string{"", "0Mi", "-1Gi", "lots", "1e300Ti"} {
		if _, err := ParseMemoryMB(q); err == nil {
			t.Errorf("ParseMemoryMB(%q) took a bad value", q)
		}
	}
	for class, want := range map[string]string{"": "", "runc": "docker", "docker": "docker", "runsc": "gvisor", "gvisor": "gvisor", "firecracker": "firecracker"} {
		if got, err := RuntimeFor(class); err != nil || got != want {
			t.Errorf("RuntimeFor(%q) = %q %v", class, got, err)
		}
	}
}
