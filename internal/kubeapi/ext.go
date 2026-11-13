package kubeapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// The extensions group (extensions.agents.x-k8s.io/v1beta1): templates and
// warm pools, stored as internal CRDs and passed through (objects.go).
// Every write is checked first, so the store never holds a template a
// claim could not be made from.

const (
	SandboxTemplatesResource  = "sandboxtemplates"
	SandboxWarmPoolsResource  = "sandboxwarmpools"
	SandboxTemplateKind       = "SandboxTemplate"
	SandboxWarmPoolKind       = "SandboxWarmPool"
	maxWarmPoolReplicas       = 128
	warmPoolUpdateRecreate    = "Recreate"
	warmPoolUpdateOnReplenish = "OnReplenish"
)

var storedKinds = map[string]string{
	SandboxTemplatesResource: SandboxTemplateKind,
	SandboxWarmPoolsResource: SandboxWarmPoolKind,
}

// templateTable is what a SandboxTemplate may hold: the Sandbox podTemplate
// AerolVM honours, and how claims may set env.
var templateTable = map[string]any{
	"apiVersion": true, "kind": true, "metadata": "*", "status": "*",
	"spec": map[string]any{
		"podTemplate":             fieldTable["spec"].(map[string]any)["podTemplate"],
		"envVarsInjectionPolicy":  true,
		"networkPolicyManagement": true,
	},
}

var warmPoolTable = map[string]any{
	"apiVersion": true, "kind": true, "metadata": "*", "status": "*",
	"spec": map[string]any{
		"replicas":           true,
		"sandboxTemplateRef": map[string]any{"name": true},
		"updateStrategy":     map[string]any{"type": true},
	},
}

// validateStored checks an object a client wants stored.
func validateStored(resource string, obj map[string]any) error {
	var refused []string
	invalid := func(format string, args ...any) { refused = append(refused, fmt.Sprintf(format, args...)) }
	kind := storedKinds[resource]
	if v, _ := obj["apiVersion"].(string); v != "" && v != ExtensionsAPIVersion() {
		invalid("apiVersion: must be %s", ExtensionsAPIVersion())
	}
	if k, _ := obj["kind"].(string); k != "" && k != kind {
		invalid("kind: must be %s", kind)
	}
	spec, _ := obj["spec"].(map[string]any)
	switch resource {
	case SandboxTemplatesResource:
		refusedFields(obj, templateTable, "", &refused)
		// The pod template must make a valid create, as a claim will.
		probe, _ := json.Marshal(map[string]any{"metadata": map[string]any{"name": "template-check"}, "spec": map[string]any{"podTemplate": spec["podTemplate"]}})
		if _, _, err := CreateFrom(probe, time.Now(), func() string { return "" }); err != nil {
			if fe, ok := err.(*FieldError); ok {
				refused = append(refused, fe.Fields...)
			} else {
				invalid("spec.podTemplate: %v", err)
			}
		}
		switch spec["envVarsInjectionPolicy"] {
		case nil, "Allowed", "Overrides", "Disallowed":
		default:
			invalid("spec.envVarsInjectionPolicy: must be Allowed, Overrides or Disallowed")
		}
		switch spec["networkPolicyManagement"] {
		case nil, "Unmanaged":
		default:
			invalid("spec.networkPolicyManagement: a sandbox is not a pod; only Unmanaged applies (use AerolVM's network rules)")
		}
	case SandboxWarmPoolsResource:
		refusedFields(obj, warmPoolTable, "", &refused)
		if r, ok := spec["replicas"]; ok {
			n, isNum := r.(float64)
			if !isNum || n != float64(int(n)) || n < 0 || n > maxWarmPoolReplicas {
				invalid("spec.replicas: a whole number from 0 to %d", maxWarmPoolReplicas)
			}
		}
		ref, _ := spec["sandboxTemplateRef"].(map[string]any)
		if name, _ := ref["name"].(string); strings.TrimSpace(name) == "" {
			invalid("spec.sandboxTemplateRef.name: required")
		}
		if us, _ := spec["updateStrategy"].(map[string]any); us != nil {
			switch us["type"] {
			case nil, warmPoolUpdateRecreate, warmPoolUpdateOnReplenish:
			default:
				invalid("spec.updateStrategy.type: must be Recreate or OnReplenish")
			}
		}
	}
	if len(refused) > 0 {
		md, _ := obj["metadata"].(map[string]any)
		name, _ := md["name"].(string)
		return &StatusError{Code: http.StatusUnprocessableEntity, Reason: "Invalid",
			Message: fmt.Sprintf("%s %q is invalid: not supported by AerolVM: %s", kind, name, strings.Join(refused, "; "))}
	}
	return nil
}

// mergePatch applies an RFC 7386 JSON merge patch.
func mergePatch(target, patch any) any {
	p, ok := patch.(map[string]any)
	if !ok {
		return patch
	}
	t, ok := target.(map[string]any)
	if !ok {
		t = map[string]any{}
	}
	for k, v := range p {
		if v == nil {
			delete(t, k)
			continue
		}
		t[k] = mergePatch(t[k], v)
	}
	return t
}

// serveStored answers a verb on a stored kind.
func (s *Server) serveStored(w http.ResponseWriter, r *http.Request, verb, resource, ns, name string) error {
	if s.Store == nil {
		return &StatusError{Code: http.StatusServiceUnavailable, Reason: "ServiceUnavailable", Message: "templates and warm pools are not stored on this gateway"}
	}
	ctx, q := r.Context(), r.URL.Query()
	readBody := func() (map[string]any, error) {
		var obj map[string]any
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&obj); err != nil {
			return nil, &StatusError{Code: http.StatusBadRequest, Reason: "BadRequest", Message: "the body is not a JSON object"}
		}
		return obj, nil
	}
	var out map[string]any
	var err error
	switch verb {
	case "list":
		out, err = s.Store.List(ctx, resource, ns, q)
	case "get":
		out, err = s.Store.Get(ctx, resource, ns, name)
	case "create", "update":
		var obj map[string]any
		if obj, err = readBody(); err != nil {
			return err
		}
		if md, _ := obj["metadata"].(map[string]any); md != nil {
			if n, _ := md["namespace"].(string); n != "" && n != ns {
				return &StatusError{Code: http.StatusBadRequest, Reason: "BadRequest", Message: "metadata.namespace does not match the request's namespace"}
			}
		}
		if err := validateStored(resource, obj); err != nil {
			return err
		}
		obj["kind"] = storedKinds[resource]
		if verb == "create" {
			out, err = s.Store.Create(ctx, resource, ns, obj)
		} else {
			out, err = s.Store.Update(ctx, resource, ns, name, obj)
		}
	case "patch":
		ct := r.Header.Get("Content-Type")
		if !strings.HasPrefix(ct, "application/merge-patch+json") && !strings.HasPrefix(ct, "application/strategic-merge-patch+json") {
			return &StatusError{Code: http.StatusUnsupportedMediaType, Reason: "UnsupportedMediaType", Message: "only merge patches are supported"}
		}
		var patch map[string]any
		if patch, err = readBody(); err != nil {
			return err
		}
		// Patched here, checked, then stored at the version it was read at,
		// so a concurrent write is a conflict, never a lost update.
		cur, err := s.Store.Get(ctx, resource, ns, name)
		if err != nil {
			return err
		}
		next, _ := mergePatch(cur, patch).(map[string]any)
		if err := validateStored(resource, next); err != nil {
			return err
		}
		out, err = s.Store.Update(ctx, resource, ns, name, next)
		if err != nil {
			return err
		}
	case "delete":
		out, err = s.Store.Delete(ctx, resource, ns, name)
	case "watch":
		stream, err := s.Store.Watch(ctx, resource, ns, q)
		if err != nil {
			return err
		}
		defer stream.Close()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		if flusher != nil {
			flusher.Flush()
		}
		buf := make([]byte, 32<<10)
		for {
			n, rerr := stream.Read(buf)
			if n > 0 {
				if _, werr := w.Write(buf[:n]); werr != nil {
					return nil
				}
				if flusher != nil {
					flusher.Flush()
				}
			}
			if rerr != nil {
				return nil
			}
		}
	}
	if err != nil {
		return err
	}
	code := http.StatusOK
	if verb == "create" {
		code = http.StatusCreated
	}
	writeJSON(w, code, out)
	return nil
}

// extensionsResourceList is the extensions group's discovery document.
func extensionsResourceList() APIResourceList {
	verbs := []string{"create", "delete", "get", "list", "patch", "update", "watch"}
	return APIResourceList{
		TypeMeta:     TypeMeta{APIVersion: "v1", Kind: "APIResourceList"},
		GroupVersion: ExtensionsAPIVersion(),
		APIResources: []APIResource{
			{Name: SandboxTemplatesResource, SingularName: "sandboxtemplate", Namespaced: true, Kind: SandboxTemplateKind, Verbs: verbs, ShortNames: []string{"sandboxtemplate"}},
			{Name: SandboxWarmPoolsResource, SingularName: "sandboxwarmpool", Namespaced: true, Kind: SandboxWarmPoolKind, Verbs: verbs, ShortNames: []string{"swp"}},
			{Name: SandboxClaimsResource, SingularName: "sandboxclaim", Namespaced: true, Kind: SandboxClaimKind,
				Verbs: []string{"create", "delete", "get", "list", "watch"}, ShortNames: []string{"sandboxclaim"}},
		},
	}
}
