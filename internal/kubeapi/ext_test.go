package kubeapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// memStore is an ObjectStore in memory, keyed resource/ns/name.
type memStore struct {
	mu   sync.Mutex
	objs map[string]map[string]any
	err  error
}

func (m *memStore) key(resource, ns, name string) string { return resource + "/" + ns + "/" + name }

func (m *memStore) Get(_ context.Context, resource, ns, name string) (map[string]any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if o, ok := m.objs[m.key(resource, ns, name)]; ok {
		raw, _ := json.Marshal(o)
		var c map[string]any
		_ = json.Unmarshal(raw, &c)
		return c, nil
	}
	return nil, &StatusError{Code: http.StatusNotFound, Reason: "NotFound", Message: name + " not found"}
}

func (m *memStore) List(_ context.Context, resource, ns string, _ url.Values) (map[string]any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var items []any
	for k, o := range m.objs {
		if strings.HasPrefix(k, resource+"/"+ns+"/") {
			items = append(items, o)
		}
	}
	return map[string]any{"apiVersion": ExtensionsAPIVersion(), "kind": "List", "items": items}, m.err
}

func (m *memStore) put(resource, ns string, obj map[string]any) map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.objs == nil {
		m.objs = map[string]map[string]any{}
	}
	name := obj["metadata"].(map[string]any)["name"].(string)
	obj["apiVersion"] = ExtensionsAPIVersion()
	m.objs[m.key(resource, ns, name)] = obj
	return obj
}

func (m *memStore) Create(_ context.Context, resource, ns string, obj map[string]any) (map[string]any, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.put(resource, ns, obj), nil
}

func (m *memStore) Update(_ context.Context, resource, ns, _ string, obj map[string]any) (map[string]any, error) {
	return m.put(resource, ns, obj), m.err
}

func (m *memStore) Patch(context.Context, string, string, string, string, []byte) (map[string]any, error) {
	return nil, errors.New("not used: the server patches through Get and Update")
}

func (m *memStore) Delete(_ context.Context, resource, ns, name string) (map[string]any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.objs, m.key(resource, ns, name))
	return map[string]any{"kind": "Status", "status": "Success"}, nil
}

func (m *memStore) Watch(context.Context, string, string, url.Values) (io.ReadCloser, error) {
	if m.err != nil {
		return nil, m.err
	}
	return io.NopCloser(strings.NewReader(`{"type":"ADDED","object":{"kind":"SandboxTemplate"}}` + "\n")), nil
}

const ext = "/apis/extensions.agents.x-k8s.io/v1beta1"

const goodTemplate = `{"apiVersion":"extensions.agents.x-k8s.io/v1beta1","kind":"SandboxTemplate","metadata":{"name":"python"},
"spec":{"envVarsInjectionPolicy":"Allowed","podTemplate":{"spec":{"runtimeClassName":"gvisor","containers":[{"name":"m","image":"python:3.12"}]}}}}`

const goodPool = `{"metadata":{"name":"pool"},"spec":{"replicas":2,"sandboxTemplateRef":{"name":"python"},"updateStrategy":{"type":"Recreate"}}}`

func TestExtensionsTemplatesAndPools(t *testing.T) {
	r := newRig(t)
	store := &memStore{}
	r.srv.Store = store
	if _, res := r.call(t, http.MethodGet, ext, ""); len(res["resources"].([]any)) != 3 {
		t.Fatalf("discovery = %v", res)
	}
	if _, g := r.call(t, http.MethodGet, "/apis/extensions.agents.x-k8s.io", ""); g["name"] != ExtensionsGroup {
		t.Fatalf("group = %v", g)
	}
	if rr, out := r.call(t, http.MethodPost, ext+"/namespaces/a/sandboxtemplates", goodTemplate); rr.Code != http.StatusCreated || out["kind"] != SandboxTemplateKind {
		t.Fatalf("create template = %d %v", rr.Code, out)
	}
	if rr, _ := r.call(t, http.MethodPost, ext+"/namespaces/a/sandboxwarmpools", goodPool); rr.Code != http.StatusCreated {
		t.Fatalf("create pool = %d", rr.Code)
	}
	last := r.authz.seen[len(r.authz.seen)-1]
	if last.Group != ExtensionsGroup || last.Resource != SandboxWarmPoolsResource || last.Verb != "create" {
		t.Fatalf("RBAC asked = %+v", last)
	}
	if rr, out := r.call(t, http.MethodGet, ext+"/namespaces/a/sandboxtemplates/python", ""); rr.Code != http.StatusOK || out["metadata"].(map[string]any)["name"] != "python" {
		t.Fatalf("get = %d %v", rr.Code, out)
	}
	if rr, out := r.call(t, http.MethodGet, ext+"/namespaces/a/sandboxwarmpools", ""); rr.Code != http.StatusOK || len(out["items"].([]any)) != 1 {
		t.Fatalf("list = %d %v", rr.Code, out)
	}
	// A merge patch is checked before it is stored.
	merge := "application/merge-patch+json"
	if rr, _ := r.call(t, http.MethodPatch, ext+"/namespaces/a/sandboxwarmpools/pool", `{"spec":{"replicas":5}}`, "Content-Type", merge); rr.Code != http.StatusOK {
		t.Fatalf("patch = %d", rr.Code)
	}
	if got, _ := store.Get(context.Background(), SandboxWarmPoolsResource, "a", "pool"); got["spec"].(map[string]any)["replicas"] != float64(5) {
		t.Fatalf("patched = %v", got)
	}
	if rr, _ := r.call(t, http.MethodPatch, ext+"/namespaces/a/sandboxwarmpools/pool", `{"spec":{"replicas":-1}}`, "Content-Type", merge); rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("a bad patch = %d", rr.Code)
	}
	if rr, _ := r.call(t, http.MethodPatch, ext+"/namespaces/a/sandboxwarmpools/pool", `[]`, "Content-Type", "application/json-patch+json"); rr.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("a JSON patch = %d", rr.Code)
	}
	if rr, _ := r.call(t, http.MethodPatch, ext+"/namespaces/a/sandboxwarmpools/nope", `{}`, "Content-Type", merge); rr.Code != http.StatusNotFound {
		t.Fatalf("patch of nothing = %d", rr.Code)
	}
	if rr, _ := r.call(t, http.MethodPut, ext+"/namespaces/a/sandboxtemplates/python", goodTemplate); rr.Code != http.StatusOK {
		t.Fatalf("update = %d", rr.Code)
	}
	if rr, _ := r.call(t, http.MethodGet, ext+"/namespaces/a/sandboxtemplates?watch=true", ""); rr.Code != http.StatusOK {
		t.Fatalf("watch = %d", rr.Code)
	}
	if rr, out := r.call(t, http.MethodDelete, ext+"/namespaces/a/sandboxwarmpools/pool", ""); rr.Code != http.StatusOK || out["status"] != "Success" {
		t.Fatalf("delete = %d %v", rr.Code, out)
	}
	for name, tc := range map[string]struct {
		method, path, body string
		code               int
	}{
		"a pod field":         {http.MethodPost, "/namespaces/a/sandboxtemplates", `{"metadata":{"name":"x"},"spec":{"podTemplate":{"spec":{"volumes":[],"containers":[{"name":"m","image":"x"}]}}}}`, 422},
		"no image":            {http.MethodPost, "/namespaces/a/sandboxtemplates", `{"metadata":{"name":"x"},"spec":{"podTemplate":{"spec":{"containers":[{"name":"m"}]}}}}`, 422},
		"network policy":      {http.MethodPost, "/namespaces/a/sandboxtemplates", `{"metadata":{"name":"x"},"spec":{"networkPolicy":{},"podTemplate":{"spec":{"containers":[{"name":"m","image":"x"}]}}}}`, 422},
		"unknown management":  {http.MethodPost, "/namespaces/a/sandboxtemplates", `{"metadata":{"name":"x"},"spec":{"networkPolicyManagement":"Strict","podTemplate":{"spec":{"containers":[{"name":"m","image":"x"}]}}}}`, 422},
		"upstream defaults":   {http.MethodPost, "/namespaces/a/sandboxtemplates", `{"metadata":{"name":"defaults"},"spec":{"networkPolicyManagement":"Managed","envVarsInjectionPolicy":"Disallowed","volumeClaimTemplatesPolicy":"Disallowed","service":false,"failedPodPolicy":"Retain","podTemplate":{"spec":{"containers":[{"name":"m","image":"x"}]}}}}`, 201},
		"volume claim policy": {http.MethodPost, "/namespaces/a/sandboxtemplates", `{"metadata":{"name":"x"},"spec":{"volumeClaimTemplatesPolicy":"Allowed","podTemplate":{"spec":{"containers":[{"name":"m","image":"x"}]}}}}`, 422},
		"a service":           {http.MethodPost, "/namespaces/a/sandboxtemplates", `{"metadata":{"name":"x"},"spec":{"service":true,"podTemplate":{"spec":{"containers":[{"name":"m","image":"x"}]}}}}`, 422},
		"recreate":            {http.MethodPost, "/namespaces/a/sandboxtemplates", `{"metadata":{"name":"x"},"spec":{"failedPodPolicy":"Recreate","podTemplate":{"spec":{"containers":[{"name":"m","image":"x"}]}}}}`, 422},
		"template volumes":    {http.MethodPost, "/namespaces/a/sandboxtemplates", `{"metadata":{"name":"x"},"spec":{"volumeClaimTemplates":[],"podTemplate":{"spec":{"containers":[{"name":"m","image":"x"}]}}}}`, 422},
		"env policy":          {http.MethodPost, "/namespaces/a/sandboxtemplates", `{"metadata":{"name":"x"},"spec":{"envVarsInjectionPolicy":"Sometimes","podTemplate":{"spec":{"containers":[{"name":"m","image":"x"}]}}}}`, 422},
		"wrong kind":          {http.MethodPost, "/namespaces/a/sandboxtemplates", `{"kind":"Pod","metadata":{"name":"x"},"spec":{"podTemplate":{"spec":{"containers":[{"name":"m","image":"x"}]}}}}`, 422},
		"wrong version":       {http.MethodPost, "/namespaces/a/sandboxwarmpools", `{"apiVersion":"v1","metadata":{"name":"p"},"spec":{"sandboxTemplateRef":{"name":"t"}}}`, 422},
		"too many replicas":   {http.MethodPost, "/namespaces/a/sandboxwarmpools", `{"metadata":{"name":"p"},"spec":{"replicas":1000,"sandboxTemplateRef":{"name":"t"}}}`, 422},
		"half a replica":      {http.MethodPost, "/namespaces/a/sandboxwarmpools", `{"metadata":{"name":"p"},"spec":{"replicas":1.5,"sandboxTemplateRef":{"name":"t"}}}`, 422},
		"no template":         {http.MethodPost, "/namespaces/a/sandboxwarmpools", `{"metadata":{"name":"p"},"spec":{}}`, 422},
		"bad strategy":        {http.MethodPost, "/namespaces/a/sandboxwarmpools", `{"metadata":{"name":"p"},"spec":{"sandboxTemplateRef":{"name":"t"},"updateStrategy":{"type":"Rolling"}}}`, 422},
		"namespace mismatch":  {http.MethodPost, "/namespaces/a/sandboxwarmpools", `{"metadata":{"name":"p","namespace":"b"},"spec":{"sandboxTemplateRef":{"name":"t"}}}`, 400},
		"not JSON":            {http.MethodPost, "/namespaces/a/sandboxwarmpools", `x`, 400},
		"not served":          {http.MethodGet, "/namespaces/a/sandboxthings", ``, 404},
		"PUT on the core API": {http.MethodPut, "/namespaces/a/sandboxtemplates", `{}`, 405},
	} {
		path := ext + tc.path
		if name == "PUT on the core API" {
			path = base + "/namespaces/a/sandboxes/web"
		}
		if rr, out := r.call(t, tc.method, path, tc.body); rr.Code != tc.code {
			t.Errorf("%s = %d %v, want %d", name, rr.Code, out["message"], tc.code)
		}
	}
	store.err = &StatusError{Code: http.StatusConflict, Reason: "AlreadyExists", Message: "exists"}
	if rr, out := r.call(t, http.MethodPost, ext+"/namespaces/a/sandboxtemplates", goodTemplate); rr.Code != http.StatusConflict || out["reason"] != "AlreadyExists" {
		t.Fatalf("a store refusal = %d %v", rr.Code, out)
	}
	if rr, _ := r.call(t, http.MethodGet, ext+"/namespaces/a/sandboxtemplates?watch=true", ""); rr.Code != http.StatusConflict {
		t.Fatalf("a failed watch = %d", rr.Code)
	}
	r.srv.Store = nil
	if rr, _ := r.call(t, http.MethodGet, ext+"/namespaces/a/sandboxtemplates", ""); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("no store = %d", rr.Code)
	}
}

func TestMergePatch(t *testing.T) {
	got := mergePatch(map[string]any{"a": 1.0, "b": map[string]any{"c": 2.0, "d": 3.0}}, map[string]any{"a": nil, "b": map[string]any{"c": 9.0}, "e": "x"})
	raw, _ := json.Marshal(got)
	if string(raw) != `{"b":{"c":9,"d":3},"e":"x"}` {
		t.Fatalf("merge = %s", raw)
	}
	if got := mergePatch(map[string]any{"a": 1.0}, "scalar"); got != "scalar" {
		t.Fatalf("a scalar patch = %v", got)
	}
	if raw, _ := json.Marshal(mergePatch("x", map[string]any{"a": 1.0})); string(raw) != `{"a":1}` {
		t.Fatalf("onto a scalar = %s", raw)
	}
}

// The client passes each call through to the internal CRDs, translating the
// group both ways, and turns the kube-apiserver's refusals into its status.
func TestKubeClientObjects(t *testing.T) {
	var seen []string
	var body []byte
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.RequestURI())
		body, _ = io.ReadAll(r.Body)
		if strings.HasSuffix(r.URL.Path, "/missing") {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(Status{Code: 404, Reason: "NotFound", Message: "missing not found"})
			return
		}
		if strings.HasSuffix(r.URL.Path, "/broken") {
			http.Error(w, "plain failure", http.StatusBadGateway)
			return
		}
		if r.URL.Query().Get("watch") == "true" {
			_, _ = io.WriteString(w, `{"type":"ADDED","object":{"apiVersion":"k8s.aerolvm.io/v1alpha1","kind":"SandboxTemplate"}}`+"\nnot json\n")
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": "k8s.aerolvm.io/v1alpha1", "kind": "SandboxTemplateList",
			"items": []any{map[string]any{"apiVersion": "k8s.aerolvm.io/v1alpha1"}}})
	}))
	defer ts.Close()
	k := &KubeClient{Host: ts.URL, Token: func() (string, error) { return "tok", nil }, Client: ts.Client()}
	ctx := context.Background()
	out, err := k.List(ctx, SandboxTemplatesResource, "a", url.Values{"limit": {"5"}})
	if err != nil || out["apiVersion"] != ExtensionsAPIVersion() || out["items"].([]any)[0].(map[string]any)["apiVersion"] != ExtensionsAPIVersion() {
		t.Fatalf("list = %v %v", out, err)
	}
	if _, err := k.Get(ctx, SandboxTemplatesResource, "a", "t"); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Create(ctx, SandboxTemplatesResource, "a", map[string]any{"apiVersion": ExtensionsAPIVersion()}); err != nil || !bytes.Contains(body, []byte(`"k8s.aerolvm.io/v1alpha1"`)) {
		t.Fatalf("create sent %s, %v", body, err)
	}
	if _, err := k.Update(ctx, SandboxTemplatesResource, "a", "t", map[string]any{}); err != nil || !bytes.Contains(body, []byte(`"k8s.aerolvm.io/v1alpha1"`)) {
		t.Fatalf("update sent %s, %v", body, err)
	}
	if _, err := k.Patch(ctx, SandboxTemplatesResource, "a", "t", "application/merge-patch+json", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Delete(ctx, SandboxTemplatesResource, "a", "t"); err != nil {
		t.Fatal(err)
	}
	stream, err := k.Watch(ctx, SandboxTemplatesResource, "a", nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(stream)
	if !strings.Contains(string(raw), ExtensionsAPIVersion()) || strings.Contains(string(raw), "not json") {
		t.Fatalf("watch = %s", raw)
	}
	want := []string{
		"GET /apis/k8s.aerolvm.io/v1alpha1/namespaces/a/sandboxtemplates?limit=5",
		"GET /apis/k8s.aerolvm.io/v1alpha1/namespaces/a/sandboxtemplates/t",
		"POST /apis/k8s.aerolvm.io/v1alpha1/namespaces/a/sandboxtemplates",
		"PUT /apis/k8s.aerolvm.io/v1alpha1/namespaces/a/sandboxtemplates/t",
		"PATCH /apis/k8s.aerolvm.io/v1alpha1/namespaces/a/sandboxtemplates/t",
		"DELETE /apis/k8s.aerolvm.io/v1alpha1/namespaces/a/sandboxtemplates/t",
		"GET /apis/k8s.aerolvm.io/v1alpha1/namespaces/a/sandboxtemplates?watch=true",
	}
	if strings.Join(seen, "\n") != strings.Join(want, "\n") {
		t.Fatalf("calls:\n%s", strings.Join(seen, "\n"))
	}
	var se *StatusError
	if _, err := k.Get(ctx, SandboxTemplatesResource, "a", "missing"); !errors.As(err, &se) || se.Code != 404 || se.Reason != "NotFound" {
		t.Fatalf("a 404 = %#v", err)
	}
	if _, err := k.Get(ctx, SandboxTemplatesResource, "a", "broken"); !errors.As(err, &se) || se.Code != http.StatusBadGateway {
		t.Fatalf("a plain failure = %#v", err)
	}
	if _, err := k.Watch(ctx, SandboxTemplatesResource, "", url.Values{"labelSelector": {"a=b"}}); err != nil {
		t.Fatal(err)
	}
	k.Token = func() (string, error) { return "", errors.New("no token") }
	if _, err := k.Get(ctx, SandboxTemplatesResource, "a", "t"); err == nil {
		t.Fatal("no token")
	}
}
