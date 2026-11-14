package kubeapi

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/kubeview"
)

// A second `kubectl apply` of a Sandbox: kubectl's patch carries its own
// annotation and every field of the file this server does not show the
// same way. It passes when nothing shown changes; env, disk and shutdown
// time are not compared, and a Warning says so.
func TestSecondKubectlApplyOfASandbox(t *testing.T) {
	r := newRig(t, p("sb-1", "web", "team:a", 3))
	r.be.tags = map[string]map[string]string{"sb-1": {"app": "proof"}}
	merge := "application/merge-patch+json"
	const second = `{
	  "metadata": {"annotations": {"kubectl.kubernetes.io/last-applied-configuration": "{}"}, "labels": {"app": "proof"}},
	  "spec": {
	    "shutdownTime": "2030-01-01T00:00:00Z",
	    "podTemplate": {"spec": {"containers": [{
	      "name": "main", "image": "img-sb-1", "imagePullPolicy": "IfNotPresent",
	      "env": [{"name": "MODE", "value": "prod"}],
	      "resources": {"limits": {"ephemeral-storage": "10Gi"}}
	    }]}}
	  }
	}`
	rr, out := r.call(t, http.MethodPatch, base+"/namespaces/a/sandboxes/web", second, "Content-Type", merge)
	if rr.Code != http.StatusOK || out["metadata"].(map[string]any)["name"] != "web" {
		t.Fatalf("a second apply = %d %v", rr.Code, out)
	}
	warnings := strings.Join(rr.Header().Values("Warning"), "\n")
	for _, want := range []string{"env", "ephemeral-storage", "shutdownTime"} {
		if !strings.Contains(warnings, want) {
			t.Errorf("no warning for %s: %q", want, warnings)
		}
	}
	if len(r.be.running) != 0 {
		t.Fatalf("a second apply that names no mode changed it: %v", r.be.running)
	}
	// A file that says Running, applied again, starts the sandbox.
	if rr, _ := r.call(t, http.MethodPatch, base+"/namespaces/a/sandboxes/web", `{"spec":{"operatingMode":"Running"}}`, "Content-Type", merge); rr.Code != http.StatusOK || !r.be.running["sb-1"] {
		t.Fatalf("Running = %d %v", rr.Code, r.be.running)
	}
	for body, want := range map[string]string{
		`{"spec":{"podTemplate":{"spec":{"containers":[{"name":"main","image":"img-sb-1","command":["sleep"]}]}}}}`:        "command and args",
		`{"spec":{"podTemplate":{"spec":{"runtimeClassName":"runc"}}}}`:                                                    "runtimeClassName",
		`{"metadata":{"labels":{"app":"other"}}}`:                                                                          "labels",
		`{"metadata":{"name":"renamed"}}`:                                                                                  "cannot change",
		`{"spec":{"podTemplate":{"spec":{"hostNetwork":true}}}}`:                                                           "not supported",
		`{"spec":{"podTemplate":{"spec":{"containers":[{"name":"main","image":"img-sb-1","imagePullPolicy":"Always"}]}}}}`: "imagePullPolicy",
		`{"metadata":{"uid":"x"}}`:                                                                                         "not supported",
	} {
		if rr, out := r.call(t, http.MethodPatch, base+"/namespaces/a/sandboxes/web", body, "Content-Type", merge); rr.Code != http.StatusUnprocessableEntity || !strings.Contains(out["message"].(string), want) {
			t.Errorf("patch %s = %d %v, want %q", body, rr.Code, out["message"], want)
		}
	}
	// Without the spec, nothing can be compared.
	r.be.specless = true
	if rr, _ := r.call(t, http.MethodPatch, base+"/namespaces/a/sandboxes/web", `{}`, "Content-Type", merge); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("no spec = %d", rr.Code)
	}
}

// Quantities are compared by value, not by spelling.
func TestMergeSandboxPatchComparesValues(t *testing.T) {
	spec := &SpecSummary{Image: "python:3.12", Runtime: "gvisor", CPU: 0.5, MemoryMB: 1024, Command: []string{"sleep", "infinity"}}
	cur := SandboxFrom(kubeview.Item{Placement: p("sb-1", "web", "team:a", 3), RV: 3}, "a", spec)
	patch := map[string]any{"spec": map[string]any{"podTemplate": map[string]any{"spec": map[string]any{
		"runtimeClassName": "gvisor",
		"containers": []any{map[string]any{
			"name": "main", "image": "python:3.12", "command": []any{"sleep"}, "args": []any{"infinity"},
			"resources": map[string]any{"requests": map[string]any{"cpu": "500m", "memory": "1Gi"}, "limits": map[string]any{"cpu": "500m", "memory": "1Gi"}},
		}},
	}}}}
	m, err := mergeSandboxPatch(cur, spec, patch, time.Unix(1700000000, 0))
	if err != nil || len(m.warnings) != 0 || m.mode != OperatingModeRunning {
		t.Fatalf("same values, other spelling = %+v %v", m, err)
	}
	patch["spec"].(map[string]any)["podTemplate"].(map[string]any)["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)["resources"] =
		map[string]any{"limits": map[string]any{"cpu": "1", "memory": "1Gi"}}
	if _, err := mergeSandboxPatch(cur, spec, patch, time.Unix(1700000000, 0)); err == nil || !strings.Contains(err.Error(), "cpu") {
		t.Fatalf("another CPU = %v", err)
	}
	if _, err := mergeSandboxPatch(cur, spec, map[string]any{"spec": map[string]any{"operatingMode": "Paused"}}, time.Unix(1700000000, 0)); err == nil {
		t.Fatal("an unknown mode passed")
	}
}

// The rest of what a patch can get wrong: another memory size, a label that
// is not a string, and a claim's fields this server does not show.
func TestMergePatchRefusalsAndWarnings(t *testing.T) {
	spec := &SpecSummary{Image: "python:3.12", Runtime: "gvisor", CPU: 0.5, MemoryMB: 1024}
	cur := SandboxFrom(kubeview.Item{Placement: p("sb-1", "web", "team:a", 3), RV: 3}, "a", spec)
	created := time.Unix(1700000000, 0)
	mem := map[string]any{"spec": map[string]any{"podTemplate": map[string]any{"spec": map[string]any{
		"containers": []any{map[string]any{"name": "main", "image": "python:3.12",
			"resources": map[string]any{"limits": map[string]any{"cpu": "500m", "memory": "2Gi"}}}},
	}}}}
	if _, err := mergeSandboxPatch(cur, spec, mem, created); err == nil || !strings.Contains(err.Error(), "memory") {
		t.Fatalf("another memory size = %v", err)
	}
	notString := map[string]any{"metadata": map[string]any{"labels": map[string]any{"app": 1}}}
	if _, err := mergeSandboxPatch(cur, spec, notString, created); err == nil {
		t.Fatal("a label that is a number passed")
	}

	claim := map[string]any{
		"apiVersion": ExtensionsAPIVersion(), "kind": SandboxClaimKind,
		"metadata": map[string]any{"name": "job", "namespace": "a", "uid": "u", "labels": map[string]any{"team": "ml"}},
		"spec":     map[string]any{"warmPoolRef": map[string]any{"name": "pool"}},
	}
	tags := map[string]string{"team": "ml", TagWarmPool: "pool"}
	warnings, err := mergeClaimPatch(claim, "pool", tags, map[string]any{"spec": map[string]any{
		"lifecycle":             map[string]any{"shutdownPolicy": "Delete"},
		"additionalPodMetadata": map[string]any{"labels": map[string]any{"x": "y"}},
	}})
	if err != nil || len(warnings) != 2 || !strings.Contains(strings.Join(warnings, " "), "spec.lifecycle") ||
		!strings.Contains(strings.Join(warnings, " "), "spec.additionalPodMetadata") {
		t.Fatalf("lifecycle and pod metadata = %v %v", warnings, err)
	}
	if _, err := mergeClaimPatch(claim, "pool", tags, notString); err == nil {
		t.Fatal("a claim label that is a number passed")
	}
}
