package kubeapi

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/kubeview"
	"github.com/aerol-ai/microvm/pkg/models"
)

type headerAuth struct{}

func (headerAuth) Authenticate(r *http.Request) (User, error) {
	if u := r.Header.Get("X-Test-User"); u != "" {
		return User{Name: u, Groups: r.Header.Values("X-Test-Group")}, nil
	}
	return User{}, ErrUnauthenticated
}

type fakeAuthz struct {
	mu     sync.Mutex
	deny   map[string]bool // verb
	err    error
	seen   []Attributes
	reason string
}

func (a *fakeAuthz) Authorize(_ context.Context, _ User, at Attributes) (bool, string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.seen = append(a.seen, at)
	if a.err != nil {
		return false, "", a.err
	}
	return !a.deny[at.Verb], a.reason, nil
}

// fakeBackend creates by putting the sandbox into the hub, as the feed
// would.
type fakeBackend struct {
	hub      *kubeview.Hub
	mu       sync.Mutex
	next     uint64
	created  []models.CreateSandboxRequest
	keys     []string
	deleted  []string
	running  map[string]bool
	tags     map[string]map[string]string
	err      error
	noFeed   bool
	specless bool
}

func (b *fakeBackend) Create(_ context.Context, owner string, req models.CreateSandboxRequest, key string) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.err != nil {
		return "", b.err
	}
	b.created, b.keys = append(b.created, req), append(b.keys, key)
	b.next++
	id := fmt.Sprintf("sb-new%d", b.next)
	if b.tags == nil {
		b.tags = map[string]map[string]string{}
	}
	b.tags[id] = req.Tags
	if !b.noFeed {
		p := cluster.Placement{SandboxID: id, Name: req.Name, OwnerRef: owner, OwnerNodeID: "w1", Version: 100 + b.next}
		b.hub.Apply(cluster.PlacementFeedEvent{Changes: []cluster.PlacementChange{{SandboxID: id, Index: p.Version, Placement: &p}}, Next: p.Version})
	}
	return id, nil
}

func (b *fakeBackend) Delete(_ context.Context, _ string, id string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.err != nil {
		return b.err
	}
	b.deleted = append(b.deleted, id)
	return nil
}

func (b *fakeBackend) SetRunning(_ context.Context, _ string, id string, running bool) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.err != nil {
		return b.err
	}
	if b.running == nil {
		b.running = map[string]bool{}
	}
	b.running[id] = running
	return nil
}

func (b *fakeBackend) Specs(_ context.Context, refs []SpecRef) map[string]SpecSummary {
	out := map[string]SpecSummary{}
	if b.specless {
		return out
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, r := range refs {
		out[r.ID] = SpecSummary{Image: "img-" + r.ID, Tags: b.tags[r.ID]}
	}
	return out
}

// p is a placement as a cluster stores it: the name qualified with its
// owner (cluster.QualifiedSandboxName).
func p(id, name, owner string, version uint64, tags ...string) cluster.Placement {
	return cluster.Placement{SandboxID: id, Name: cluster.QualifiedSandboxName(owner, name), OwnerRef: owner, OwnerNodeID: "w1", Version: version, CreatedUnix: 1700000000}
}

type rig struct {
	srv   *Server
	hub   *kubeview.Hub
	be    *fakeBackend
	authz *fakeAuthz
}

func newRig(t *testing.T, rows ...cluster.Placement) *rig {
	t.Helper()
	hub := kubeview.New(kubeview.Options{TooNewWait: 50 * time.Millisecond})
	hub.Apply(cluster.PlacementFeedEvent{View: true, Full: rows, Next: 50})
	be := &fakeBackend{hub: hub}
	authz := &fakeAuthz{deny: map[string]bool{}}
	srv := &Server{Hub: hub, Auth: headerAuth{}, Authz: authz, Backend: be,
		Owners: OwnerMap{Explicit: map[string]string{"acct": "acct:k1"}},
		Now:    func() time.Time { return now }, Random: fixed, CreateWait: 200 * time.Millisecond, BookmarkEvery: 20 * time.Millisecond}
	return &rig{srv: srv, hub: hub, be: be, authz: authz}
}

func (r *rig) call(t *testing.T, method, path, body string, headers ...string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("X-Test-User", "alice")
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	rr := httptest.NewRecorder()
	r.srv.ServeHTTP(rr, req)
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr, out
}

const base = "/apis/agents.x-k8s.io/v1beta1"

func names(out map[string]any) string {
	var n []string
	items, _ := out["items"].([]any)
	for _, it := range items {
		md := it.(map[string]any)["metadata"].(map[string]any)
		n = append(n, md["namespace"].(string)+"/"+md["name"].(string))
	}
	return strings.Join(n, ",")
}

func TestServerHealthAndDiscovery(t *testing.T) {
	r := newRig(t)
	for _, path := range []string{"/healthz", "/livez", "/readyz"} {
		rr := httptest.NewRecorder()
		r.srv.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("%s = %d", path, rr.Code)
		}
	}
	notReady := &Server{Hub: kubeview.New(kubeview.Options{})}
	rr := httptest.NewRecorder()
	notReady.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("readyz before a view = %d", rr.Code)
	}
	unauth := httptest.NewRecorder()
	r.srv.ServeHTTP(unauth, httptest.NewRequest(http.MethodGet, base, nil))
	if unauth.Code != http.StatusUnauthorized {
		t.Fatalf("no caller = %d", unauth.Code)
	}
	_, list := r.call(t, http.MethodGet, base, "")
	res := list["resources"].([]any)[0].(map[string]any)
	if list["groupVersion"] != "agents.x-k8s.io/v1beta1" || res["name"] != "sandboxes" || res["namespaced"] != true {
		t.Fatalf("resources = %v", list)
	}
	if _, g := r.call(t, http.MethodGet, "/apis/agents.x-k8s.io", ""); g["name"] != Group {
		t.Fatalf("group = %v", g)
	}
	if _, gl := r.call(t, http.MethodGet, "/apis", ""); len(gl["groups"].([]any)) != 2 {
		t.Fatalf("group list = %v", gl)
	}
	for _, path := range []string{"/openapi/v2", "/openapi/v3"} {
		if rr, _ := r.call(t, http.MethodGet, path, ""); rr.Code != http.StatusOK {
			t.Fatalf("%s = %d", path, rr.Code)
		}
	}
	for path, code := range map[string]int{
		"/apis/other/v1/x": http.StatusNotFound,
		base + "/pods":     http.StatusNotFound,
		base + "/namespaces/a/sandboxes/x/status": http.StatusMethodNotAllowed,
		base + "/namespaces//sandboxes":           http.StatusNotFound,
		base + "/sandboxes/x":                     http.StatusNotFound,
		base + "/namespaces/a/sandboxes/x/y/z":    http.StatusNotFound,
		base + "/namespaces/a/sandboxes/":         http.StatusOK, // a trailing slash: the list
	} {
		if rr, _ := r.call(t, http.MethodGet, path, ""); rr.Code != code {
			t.Errorf("%s = %d, want %d", path, rr.Code, code)
		}
	}
	if rr, _ := r.call(t, http.MethodPut, base+"/namespaces/a/sandboxes/x", "{}"); rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("PUT = %d", rr.Code)
	}
}

func TestServerList(t *testing.T) {
	r := newRig(t,
		p("sb-1", "web", "team:a", 3), p("sb-2", "Bad Name", "team:a", 4), p("sb-3", "db", "team:b", 5),
		p("sb-4", "api", "acct:k1", 6), p("sb-5", "x", "team:UPPER", 7))
	rr, out := r.call(t, http.MethodGet, base+"/namespaces/a/sandboxes", "")
	if rr.Code != http.StatusOK || names(out) != "a/sb-2,a/web" || out["metadata"].(map[string]any)["resourceVersion"] != "50" {
		t.Fatalf("list = %d %s %v", rr.Code, names(out), out["metadata"])
	}
	if _, out := r.call(t, http.MethodGet, base+"/sandboxes", ""); names(out) != "a/sb-2,a/web,acct/api,b/db" {
		t.Fatalf("all namespaces = %s", names(out))
	}
	if _, out := r.call(t, http.MethodGet, base+"/namespaces/acct/sandboxes", ""); names(out) != "acct/api" {
		t.Fatalf("an explicit owner = %s", names(out))
	}
	if _, out := r.call(t, http.MethodGet, base+"/sandboxes?fieldSelector=metadata.name%3Dweb,metadata.namespace%3Da", ""); names(out) != "a/web" {
		t.Fatalf("field selector = %s", names(out))
	}
	// Paging: one per page, continue, the rest.
	_, page := r.call(t, http.MethodGet, base+"/sandboxes?limit=1", "")
	cont := page["metadata"].(map[string]any)["continue"].(string)
	if names(page) != "a/sb-2" || cont == "" {
		t.Fatalf("page 1 = %s %q", names(page), cont)
	}
	_, page = r.call(t, http.MethodGet, base+"/sandboxes?limit=10&continue="+cont, "")
	if names(page) != "a/web,acct/api,b/db" || page["metadata"].(map[string]any)["continue"] != nil {
		t.Fatalf("page 2 = %s %v", names(page), page["metadata"])
	}
	// A continue from a gateway further ahead.
	ahead := encodeContinue(continueToken{RV: 999, After: "a/web"})
	if rr, _ := r.call(t, http.MethodGet, base+"/sandboxes?continue="+ahead, ""); rr.Code != http.StatusGatewayTimeout {
		t.Fatalf("a continue from ahead = %d", rr.Code)
	}
	for q, code := range map[string]int{
		"?continue=bm90IGpzb24":                          http.StatusBadRequest,
		"?limit=x":                                       http.StatusBadRequest,
		"?labelSelector=a+in+(b)":                        http.StatusBadRequest,
		"?fieldSelector=status.phase%3DRunning":          http.StatusBadRequest,
		"?resourceVersion=x":                             http.StatusBadRequest,
		"?resourceVersion=10&resourceVersionMatch=Exact": http.StatusGone,
		"?resourceVersion=50&resourceVersionMatch=Exact": http.StatusOK,
		"?resourceVersion=0":                             http.StatusOK,
	} {
		if rr, _ := r.call(t, http.MethodGet, base+"/namespaces/a/sandboxes"+q, ""); rr.Code != code {
			t.Errorf("list%s = %d, want %d", q, rr.Code, code)
		}
	}
	if rr, _ := r.call(t, http.MethodGet, base+"/namespaces/Bad_NS/sandboxes", ""); rr.Code != http.StatusNotFound {
		t.Fatalf("an unmappable namespace = %d", rr.Code)
	}
	// RBAC asked with the right attributes.
	last := r.authz.seen[len(r.authz.seen)-1]
	if last.Verb != "list" || last.Group != Group || last.Resource != "sandboxes" || last.Namespace != "Bad_NS" {
		t.Fatalf("attributes = %+v", last)
	}
}

func TestServerLabelSelector(t *testing.T) {
	sel, err := parseSelector("app=agent, tier!=db,env==prod")
	if err != nil {
		t.Fatal(err)
	}
	if !sel.matches(map[string]string{"app": "agent", "env": "prod"}) || sel.matches(map[string]string{"app": "agent", "env": "prod", "tier": "db"}) || sel.matches(map[string]string{"app": "x", "env": "prod"}) {
		t.Fatal("selector")
	}
	r := newRig(t, p("sb-1", "web", "team:a", 3))
	// Rendered objects carry no labels yet: app=agent matches nothing.
	if _, out := r.call(t, http.MethodGet, base+"/namespaces/a/sandboxes?labelSelector=app%3Dagent", ""); names(out) != "" {
		t.Fatalf("selected = %s", names(out))
	}
	if _, out := r.call(t, http.MethodGet, base+"/namespaces/a/sandboxes?labelSelector=app!%3Dagent&limit=1", ""); names(out) != "a/web" {
		t.Fatalf("selected = %s", names(out))
	}
}

func TestServerGet(t *testing.T) {
	r := newRig(t, p("sb-1", "web", "team:a", 3), p("sb-2", "Bad Name", "team:a", 4))
	rr, out := r.call(t, http.MethodGet, base+"/namespaces/a/sandboxes/web", "")
	md := out["metadata"].(map[string]any)
	if rr.Code != http.StatusOK || md["name"] != "web" || md["resourceVersion"] != "3" {
		t.Fatalf("get = %d %v", rr.Code, md)
	}
	if img := out["spec"].(map[string]any)["podTemplate"].(map[string]any)["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)["image"]; img != "img-sb-1" {
		t.Fatalf("spec summary = %v", img)
	}
	if rr, _ := r.call(t, http.MethodGet, base+"/namespaces/a/sandboxes/sb-2", ""); rr.Code != http.StatusOK {
		t.Fatalf("by ID = %d", rr.Code)
	}
	for path, code := range map[string]int{"/namespaces/a/sandboxes/nope": 404, "/namespaces/b/sandboxes/web": 404, "/namespaces/Bad_NS/sandboxes/web": 404} {
		if rr, _ := r.call(t, http.MethodGet, base+path, ""); rr.Code != code {
			t.Errorf("%s = %d", path, rr.Code)
		}
	}
	r.be.specless = true
	if _, out := r.call(t, http.MethodGet, base+"/namespaces/a/sandboxes/web", ""); out["spec"].(map[string]any)["podTemplate"].(map[string]any)["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)["image"] != nil {
		t.Fatal("an image without a spec summary")
	}
}

const createBody = `{"apiVersion":"agents.x-k8s.io/v1beta1","kind":"Sandbox","metadata":{"name":"job","namespace":"a"},"spec":{"podTemplate":{"spec":{"containers":[{"name":"m","image":"python:3.12"}]}}}}`

func TestServerCreate(t *testing.T) {
	r := newRig(t, p("sb-1", "web", "team:a", 3))
	rr, out := r.call(t, http.MethodPost, base+"/namespaces/a/sandboxes", createBody)
	if rr.Code != http.StatusCreated || out["metadata"].(map[string]any)["name"] != "job" || out["metadata"].(map[string]any)["annotations"].(map[string]any)[AnnotationSandboxID] != "sb-new1" {
		t.Fatalf("create = %d %v", rr.Code, out)
	}
	if r.be.keys[0] != "kubeapi/a/job" || r.be.created[0].Image != "python:3.12" {
		t.Fatalf("backend = %v %+v", r.be.keys, r.be.created)
	}
	conflict := strings.Replace(createBody, `"job"`, `"web"`, 1)
	if rr, out := r.call(t, http.MethodPost, base+"/namespaces/a/sandboxes", conflict); rr.Code != http.StatusConflict || out["reason"] != "AlreadyExists" {
		t.Fatalf("conflict = %d %v", rr.Code, out)
	}
	if rr, out := r.call(t, http.MethodPost, base+"/namespaces/a/sandboxes", `{"metadata":{"name":"x"},"spec":{"volumeClaimTemplates":[]}}`); rr.Code != http.StatusUnprocessableEntity || out["reason"] != "Invalid" {
		t.Fatalf("invalid = %d %v", rr.Code, out)
	}
	if rr, _ := r.call(t, http.MethodPost, base+"/namespaces/a/sandboxes", "x"); rr.Code != http.StatusBadRequest {
		t.Fatalf("not JSON = %d", rr.Code)
	}
	if rr, _ := r.call(t, http.MethodPost, base+"/namespaces/b/sandboxes", createBody); rr.Code != http.StatusBadRequest {
		t.Fatalf("namespace mismatch = %d", rr.Code)
	}
	if rr, _ := r.call(t, http.MethodPost, base+"/namespaces/Bad_NS/sandboxes", createBody); rr.Code != http.StatusNotFound {
		t.Fatalf("unmappable = %d", rr.Code)
	}
	dry := strings.Replace(createBody, `"job"`, `"dry"`, 1)
	if rr, _ := r.call(t, http.MethodPost, base+"/namespaces/a/sandboxes?dryRun=All", dry); rr.Code != http.StatusCreated || len(r.be.created) != 1 {
		t.Fatalf("dry run = %d, %d creates", rr.Code, len(r.be.created))
	}
	// Created, not yet seen by this gateway: still a 201.
	r.be.noFeed = true
	late := strings.Replace(createBody, `"job"`, `"late"`, 1)
	if rr, out := r.call(t, http.MethodPost, base+"/namespaces/a/sandboxes", late); rr.Code != http.StatusCreated || out["metadata"].(map[string]any)["name"] != "late" {
		t.Fatalf("late = %d %v", rr.Code, out)
	}
	r.be.err = &StatusError{Code: http.StatusTooManyRequests, Reason: "TooManyRequests", Message: "quota"}
	quota := strings.Replace(createBody, `"job"`, `"q"`, 1)
	if rr, out := r.call(t, http.MethodPost, base+"/namespaces/a/sandboxes", quota); rr.Code != http.StatusTooManyRequests || out["reason"] != "TooManyRequests" {
		t.Fatalf("backend status = %d %v", rr.Code, out)
	}
	r.be.err = errors.New("boom")
	if rr, _ := r.call(t, http.MethodPost, base+"/namespaces/a/sandboxes", quota); rr.Code != http.StatusInternalServerError {
		t.Fatalf("backend error = %d", rr.Code)
	}
}

func TestServerDeleteAndPatch(t *testing.T) {
	r := newRig(t, p("sb-1", "web", "team:a", 3))
	if rr, out := r.call(t, http.MethodDelete, base+"/namespaces/a/sandboxes/web", ""); rr.Code != http.StatusOK || out["status"] != "Success" || r.be.deleted[0] != "sb-1" {
		t.Fatalf("delete = %d %v %v", rr.Code, out, r.be.deleted)
	}
	if rr, _ := r.call(t, http.MethodDelete, base+"/namespaces/a/sandboxes/nope", ""); rr.Code != http.StatusNotFound {
		t.Fatalf("delete unknown = %d", rr.Code)
	}
	if rr, _ := r.call(t, http.MethodDelete, base+"/namespaces/Bad_NS/sandboxes/web", ""); rr.Code != http.StatusNotFound {
		t.Fatal("delete unmappable")
	}
	merge := "application/merge-patch+json"
	if rr, _ := r.call(t, http.MethodPatch, base+"/namespaces/a/sandboxes/web", `{"spec":{"operatingMode":"Suspended"}}`, "Content-Type", merge); rr.Code != http.StatusOK || r.be.running["sb-1"] {
		t.Fatalf("suspend = %d %v", rr.Code, r.be.running)
	}
	if rr, _ := r.call(t, http.MethodPatch, base+"/namespaces/a/sandboxes/web", `{"spec":{"operatingMode":"Running"}}`, "Content-Type", "application/strategic-merge-patch+json"); rr.Code != http.StatusOK || !r.be.running["sb-1"] {
		t.Fatalf("resume = %d %v", rr.Code, r.be.running)
	}
	if rr, _ := r.call(t, http.MethodPatch, base+"/namespaces/a/sandboxes/web", `{"metadata":{"name":"web"}}`, "Content-Type", merge); rr.Code != http.StatusOK {
		t.Fatalf("a no-op patch = %d", rr.Code)
	}
	for _, tc := range []struct {
		body, ct string
		code     int
	}{
		{`{"spec":{"operatingMode":"Paused"}}`, merge, 422},
		{`{"spec":{"podTemplate":{}}}`, merge, 422},
		{`x`, merge, 400},
		{`{}`, "application/json-patch+json", 415},
		{`{}`, "application/apply-patch+yaml", 415},
	} {
		if rr, _ := r.call(t, http.MethodPatch, base+"/namespaces/a/sandboxes/web", tc.body, "Content-Type", tc.ct); rr.Code != tc.code {
			t.Errorf("patch %s (%s) = %d, want %d", tc.body, tc.ct, rr.Code, tc.code)
		}
	}
	if rr, _ := r.call(t, http.MethodPatch, base+"/namespaces/a/sandboxes/nope", `{}`, "Content-Type", merge); rr.Code != http.StatusNotFound {
		t.Fatal("patch unknown")
	}
	if rr, _ := r.call(t, http.MethodPatch, base+"/namespaces/Bad_NS/sandboxes/web", `{}`, "Content-Type", merge); rr.Code != http.StatusNotFound {
		t.Fatal("patch unmappable")
	}
	r.be.err = errors.New("boom")
	if rr, _ := r.call(t, http.MethodDelete, base+"/namespaces/a/sandboxes/web", ""); rr.Code != http.StatusInternalServerError {
		t.Fatal("delete error")
	}
	if rr, _ := r.call(t, http.MethodPatch, base+"/namespaces/a/sandboxes/web", `{"spec":{"operatingMode":"Running"}}`, "Content-Type", merge); rr.Code != http.StatusInternalServerError {
		t.Fatal("patch error")
	}
}

func TestServerAuthorization(t *testing.T) {
	r := newRig(t, p("sb-1", "web", "team:a", 3))
	r.authz.deny["get"], r.authz.reason = true, "no role binding"
	if rr, out := r.call(t, http.MethodGet, base+"/namespaces/a/sandboxes/web", ""); rr.Code != http.StatusForbidden || !strings.Contains(out["message"].(string), "no role binding") {
		t.Fatalf("denied = %d %v", rr.Code, out)
	}
	r.authz.err = errors.New("apiserver down")
	if rr, _ := r.call(t, http.MethodGet, base+"/namespaces/a/sandboxes", ""); rr.Code != http.StatusInternalServerError {
		t.Fatalf("authz error = %d", rr.Code)
	}
}

func TestServerNotReady(t *testing.T) {
	r := newRig(t)
	r.srv.Hub = kubeview.New(kubeview.Options{})
	for _, path := range []string{"/namespaces/a/sandboxes", "/sandboxes", "/namespaces/a/sandboxes/web", "/namespaces/a/sandboxes?watch=true"} {
		if rr, _ := r.call(t, http.MethodGet, base+path, ""); rr.Code != http.StatusServiceUnavailable {
			t.Errorf("%s before a view = %d", path, rr.Code)
		}
	}
}

// watchLines runs a watch through a real HTTP server and returns its lines.
func watchLines(t *testing.T, r *rig, query string) (<-chan map[string]any, func()) {
	t.Helper()
	ts := httptest.NewServer(r.srv)
	req, _ := http.NewRequest(http.MethodGet, ts.URL+base+query, nil)
	req.Header.Set("X-Test-User", "alice")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	out := make(chan map[string]any, 64)
	go func() {
		defer close(out)
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			var ev map[string]any
			if json.Unmarshal(sc.Bytes(), &ev) == nil {
				out <- ev
			}
		}
	}()
	return out, func() { resp.Body.Close(); ts.Close() }
}

func nextLine(t *testing.T, ch <-chan map[string]any) map[string]any {
	t.Helper()
	select {
	case ev, ok := <-ch:
		if !ok {
			t.Fatal("the watch ended")
		}
		return ev
	case <-time.After(2 * time.Second):
		t.Fatal("no watch event")
	}
	return nil
}

func objName(ev map[string]any) string {
	return ev["object"].(map[string]any)["metadata"].(map[string]any)["name"].(string)
}

func TestServerWatch(t *testing.T) {
	r := newRig(t, p("sb-1", "web", "team:a", 3))
	ch, stop := watchLines(t, r, "/namespaces/a/sandboxes?watch=true&resourceVersion=50&allowWatchBookmarks=true")
	defer stop()
	db := p("sb-2", "db", "team:a", 51)
	other := p("sb-3", "x", "team:b", 51)
	r.hub.Apply(cluster.PlacementFeedEvent{Changes: []cluster.PlacementChange{{SandboxID: "sb-3", Index: 51, Placement: &other}, {SandboxID: "sb-2", Index: 51, Placement: &db}}, Next: 51})
	for {
		ev := nextLine(t, ch)
		if ev["type"] == "BOOKMARK" {
			continue
		}
		if ev["type"] != "ADDED" || objName(ev) != "db" {
			t.Fatalf("event = %v", ev)
		}
		break
	}
	// Bookmarks keep coming on an idle watch.
	for {
		if ev := nextLine(t, ch); ev["type"] == "BOOKMARK" {
			break
		}
	}
	// A resync ends the watch with a 410.
	r.hub.Apply(cluster.PlacementFeedEvent{View: true, Full: []cluster.Placement{db}, Next: 60})
	for {
		ev := nextLine(t, ch)
		if ev["type"] == "BOOKMARK" {
			continue
		}
		if ev["type"] != "ERROR" || ev["object"].(map[string]any)["code"] != float64(410) {
			t.Fatalf("after a resync = %v", ev)
		}
		break
	}
}

func TestServerWatchVariants(t *testing.T) {
	r := newRig(t, p("sb-1", "web", "team:a", 3), p("sb-2", "db", "team:b", 4))
	// sendInitialEvents: every sandbox, then the end-of-initial bookmark.
	ch, stop := watchLines(t, r, "/sandboxes?watch=true&sendInitialEvents=true&resourceVersionMatch=NotOlderThan&allowWatchBookmarks=true")
	seen := map[string]bool{}
	for {
		ev := nextLine(t, ch)
		if ev["type"] == "BOOKMARK" {
			md := ev["object"].(map[string]any)["metadata"].(map[string]any)
			if ann, _ := md["annotations"].(map[string]any); ann[initialEventsEnd] == "true" {
				break
			}
			continue
		}
		seen[objName(ev)] = true
	}
	stop()
	if !seen["web"] || !seen["db"] {
		t.Fatalf("initial events = %v", seen)
	}
	// A label filter, and timeoutSeconds ending the stream.
	ch, stop = watchLines(t, r, "/namespaces/a/sandboxes?watch=true&resourceVersion=50&labelSelector=app%3Dx&timeoutSeconds=1")
	defer stop()
	web := p("sb-1", "web", "team:a", 52)
	r.hub.Apply(cluster.PlacementFeedEvent{Changes: []cluster.PlacementChange{{SandboxID: "sb-1", Index: 52, Placement: &web}}, Next: 52})
	select {
	case ev, ok := <-ch:
		if ok {
			t.Fatalf("a filtered event got through: %v", ev)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeoutSeconds did not end the watch")
	}
	for q, code := range map[string]int{
		"?watch=true&resourceVersion=1":   http.StatusGone,
		"?watch=true&resourceVersion=999": http.StatusGatewayTimeout,
		"?watch=true&resourceVersion=x":   http.StatusBadRequest,
		"?watch=true&labelSelector=a+in":  http.StatusBadRequest,
	} {
		if rr, _ := r.call(t, http.MethodGet, base+"/namespaces/a/sandboxes"+q, ""); rr.Code != code {
			t.Errorf("watch%s = %d, want %d", q, rr.Code, code)
		}
	}
	if rr, _ := r.call(t, http.MethodGet, base+"/namespaces/Bad_NS/sandboxes?watch=1", ""); rr.Code != http.StatusNotFound {
		t.Fatal("watch unmappable")
	}
}

func TestOwnerMap(t *testing.T) {
	m := OwnerMap{Explicit: map[string]string{"acct": "acct:k1", "ops": "team:platform"}}
	for ns, want := range map[string]string{"a": "team:a", "acct": "acct:k1", "ops": "team:platform"} {
		if got, ok := m.Owner(ns); !ok || got != want {
			t.Errorf("Owner(%q) = %q %v", ns, got, ok)
		}
	}
	if _, ok := m.Owner("Bad_NS"); ok {
		t.Fatal("an invalid namespace mapped")
	}
	// team:platform is ops's: the namespace platform must not reach it too.
	if o, ok := m.Owner("platform"); ok {
		t.Fatalf("Owner(platform) = %q, but team:platform is mapped to ops", o)
	}
	for owner, want := range map[string]string{"team:a": "a", "acct:k1": "acct", "team:platform": "ops"} {
		if got, ok := m.Namespace(owner); !ok || got != want {
			t.Errorf("Namespace(%q) = %q %v", owner, got, ok)
		}
	}
	for _, owner := range []string{"team:ops", "acct:other", "team:UPPER", ""} {
		if ns, ok := m.Namespace(owner); ok {
			t.Errorf("Namespace(%q) = %q", owner, ns)
		}
	}
}

func TestRandomSuffix(t *testing.T) {
	a, b := randomSuffix(), randomSuffix()
	if len(a) != 5 || strings.Trim(a, suffixAlphabet) != "" || a == b && randomSuffix() == a {
		t.Fatalf("suffixes %q %q", a, b)
	}
}

func TestWriteStatusFallsBackTo500(t *testing.T) {
	rr := httptest.NewRecorder()
	writeStatus(rr, errors.New("x"))
	body, _ := io.ReadAll(rr.Body)
	if rr.Code != http.StatusInternalServerError || !strings.Contains(string(body), "InternalError") {
		t.Fatalf("%d %s", rr.Code, body)
	}
}

// A watch answers its headers at once, before any event: a quiet namespace
// must not leave kubectl waiting for a response.
func TestServerWatchSendsHeadersAtOnce(t *testing.T) {
	r := newRig(t)
	r.srv.Store = &memStore{}
	ts := httptest.NewServer(r.srv)
	defer ts.Close()
	for _, path := range []string{base + "/namespaces/a/sandboxes?watch=true", ext + "/namespaces/a/sandboxclaims?watch=true", ext + "/namespaces/a/sandboxtemplates?watch=true"} {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+path+"&timeoutSeconds=30", nil)
		req.Header.Set("X-Test-User", "alice")
		client := &http.Client{Timeout: 2 * time.Second}
		start := time.Now()
		resp, err := client.Do(req)
		if err != nil || resp.StatusCode != http.StatusOK || time.Since(start) > time.Second {
			t.Fatalf("%s: headers after %s: %v", path, time.Since(start), err)
		}
		resp.Body.Close()
	}
}

// noUserAuth is the kube-apiserver's own health check: a trusted
// certificate, no user.
type noUserAuth struct{}

func (noUserAuth) Authenticate(*http.Request) (User, error) { return User{}, ErrNoUser }

func TestDiscoveryWithoutAUser(t *testing.T) {
	r := newRig(t)
	r.srv.Auth = noUserAuth{}
	for _, path := range []string{"/apis", "/apis/agents.x-k8s.io", base, ext, "/openapi/v2"} {
		rr := httptest.NewRecorder()
		r.srv.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		if rr.Code != http.StatusOK {
			t.Errorf("%s = %d", path, rr.Code)
		}
	}
	rr := httptest.NewRecorder()
	r.srv.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, base+"/namespaces/a/sandboxes", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("a resource without a user = %d", rr.Code)
	}
}

// The end of the initial list comes where the hub's replay ends, even while
// changes keep arriving: a quiet spell never has to happen first (the old
// guess waited for 10 ms without an event, which a busy cluster may never
// give).
func TestServerWatchInitialEndUnderChurn(t *testing.T) {
	r := newRig(t, p("sb-1", "web", "team:a", 3))
	stopChurn := make(chan struct{})
	churned := make(chan struct{})
	go func() {
		defer close(churned)
		for v := uint64(100); ; v++ {
			select {
			case <-stopChurn:
				return
			case <-time.After(2 * time.Millisecond):
			}
			row := p("sb-1", "web", "team:a", v)
			r.hub.Apply(cluster.PlacementFeedEvent{Changes: []cluster.PlacementChange{{SandboxID: "sb-1", Index: v, Placement: &row}}, Next: v})
		}
	}()
	defer func() { close(stopChurn); <-churned }()
	time.Sleep(20 * time.Millisecond)
	ch, stop := watchLines(t, r, "/sandboxes?watch=true&sendInitialEvents=true&resourceVersionMatch=NotOlderThan&allowWatchBookmarks=true")
	defer stop()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				t.Fatal("the watch ended before the end of the initial list")
			}
			if ev["type"] != "BOOKMARK" {
				continue
			}
			md := ev["object"].(map[string]any)["metadata"].(map[string]any)
			if ann, _ := md["annotations"].(map[string]any); ann[initialEventsEnd] == "true" {
				return
			}
		case <-deadline:
			t.Fatal("no end of the initial list while changes kept arriving")
		}
	}
}
