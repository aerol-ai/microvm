package kubepod

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeAPI is an in-memory kube-apiserver for pods: create, get, delete
// (with grace and a UID precondition) and list (label selector, paging).
// A "kubelet" hook moves pods along: kubelet runs on every read of a pod
// and may change its status, as the real kubelet does between reads.
type fakeAPI struct {
	t   *testing.T
	srv *httptest.Server

	mu      sync.Mutex
	pods    map[string]*Pod // "namespace/name"
	nextUID int
	rv      int
	// kubelet, when set, runs on each GET of a pod (under mu).
	kubelet func(p *Pod)
	// goneAfter is how many reads a deleted pod stays for, terminating;
	// 0 removes it at once. -1 keeps it forever (a node nobody can reach).
	goneAfter int
	reads     map[string]int
	// fail answers a call with this status when its "METHOD path" starts
	// with a key; failOnce removes the key after one use.
	fail     map[string]int
	failOnce bool
	// token is the bearer token every call must carry, when set.
	token string
	// createDelay holds back a create's answer after the pod is stored.
	createDelay time.Duration
	calls       []string
	// deletes records each delete's grace and precondition.
	deletes []deleteCall
}

type deleteCall struct {
	name  string
	grace int64
	uid   string
}

func newFakeAPI(t *testing.T) *fakeAPI {
	f := &fakeAPI{t: t, pods: map[string]*Pod{}, reads: map[string]int{}, fail: map[string]int{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAPI) client() *Client {
	return NewClient(f.srv.URL, func() (string, error) { return f.token, nil }, nil)
}

// runningKubelet makes every pod Running with an address on its first read.
func runningKubelet(p *Pod) {
	if p.Status == nil || p.Status.Phase == "" || p.Status.Phase == PhasePending {
		started := time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)
		p.Status = &PodStatus{
			Phase: PhaseRunning,
			PodIP: "10.244.0." + strconv.Itoa(len(p.Metadata.Name)),
			ContainerStatuses: []ContainerStatus{{
				Name:  sandboxContainer,
				State: ContainerState{Running: &StateRunning{StartedAt: &started}},
			}},
		}
	}
}

func (f *fakeAPI) status(w http.ResponseWriter, code int, reason, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"kind": "Status", "apiVersion": "v1", "status": "Failure",
		"reason": reason, "message": msg, "code": code,
	})
}

func (f *fakeAPI) put(p *Pod) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.putLocked(p)
}

func (f *fakeAPI) putLocked(p *Pod) {
	f.rv++
	p.Metadata.ResourceVersion = strconv.Itoa(f.rv)
	if p.Metadata.UID == "" {
		f.nextUID++
		p.Metadata.UID = "uid-" + strconv.Itoa(f.nextUID)
	}
	f.pods[p.Metadata.Namespace+"/"+p.Metadata.Name] = p
}

func (f *fakeAPI) get(ns, name string) *Pod {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pods[ns+"/"+name]
}

func (f *fakeAPI) setPhase(ns, name, phase string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := f.pods[ns+"/"+name]
	if p.Status == nil {
		p.Status = &PodStatus{}
	}
	p.Status.Phase = phase
}

// Setters and getters take the lock the handler reads under, so a test
// that changes the fake between calls is ordered with the server's reads.

func (f *fakeAPI) setKubelet(fn func(*Pod)) {
	f.mu.Lock()
	f.kubelet = fn
	f.mu.Unlock()
}

func (f *fakeAPI) setGoneAfter(n int) {
	f.mu.Lock()
	f.goneAfter = n
	f.mu.Unlock()
}

func (f *fakeAPI) setToken(tok string) {
	f.mu.Lock()
	f.token = tok
	f.mu.Unlock()
}

// setFail answers calls starting with prefix with code; once removes the
// rule after its first use. Code 0 removes it.
func (f *fakeAPI) setFail(prefix string, code int, once bool) {
	f.mu.Lock()
	if code == 0 {
		delete(f.fail, prefix)
	} else {
		f.fail[prefix] = code
	}
	f.failOnce = once
	f.mu.Unlock()
}

func (f *fakeAPI) deleteCalls() []deleteCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.deletes)
}

func (f *fakeAPI) count(prefix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

func (f *fakeAPI) serve(w http.ResponseWriter, r *http.Request) {
	call := r.Method + " " + r.URL.Path
	f.mu.Lock()
	f.calls = append(f.calls, call)
	for k, code := range f.fail {
		if strings.HasPrefix(call, k) {
			if f.failOnce {
				delete(f.fail, k)
			}
			f.mu.Unlock()
			f.status(w, code, http.StatusText(code), "injected")
			return
		}
	}
	token := f.token
	f.mu.Unlock()
	if token != "" && r.Header.Get("Authorization") != "Bearer "+token {
		f.status(w, http.StatusUnauthorized, "Unauthorized", "bad token")
		return
	}
	rest, ok := strings.CutPrefix(r.URL.Path, "/api/v1/namespaces/")
	if !ok {
		f.status(w, http.StatusNotFound, "NotFound", "no route")
		return
	}
	parts := strings.Split(rest, "/")
	if len(parts) < 2 || parts[1] != "pods" {
		f.status(w, http.StatusNotFound, "NotFound", "no route")
		return
	}
	ns := parts[0]
	switch {
	case len(parts) == 2 && r.Method == http.MethodPost:
		f.create(w, r, ns)
	case len(parts) == 2 && r.Method == http.MethodGet:
		f.list(w, r, ns)
	case len(parts) == 3 && r.Method == http.MethodGet:
		f.read(w, ns, parts[2])
	case len(parts) == 3 && r.Method == http.MethodDelete:
		f.remove(w, r, ns, parts[2])
	default:
		f.status(w, http.StatusMethodNotAllowed, "MethodNotAllowed", call)
	}
}

func (f *fakeAPI) create(w http.ResponseWriter, r *http.Request, ns string) {
	var p Pod
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		f.status(w, http.StatusBadRequest, "BadRequest", err.Error())
		return
	}
	if p.Metadata.Namespace != "" && p.Metadata.Namespace != ns {
		f.status(w, http.StatusBadRequest, "BadRequest", "namespace mismatch")
		return
	}
	if p.Metadata.UID != "" || p.Metadata.ResourceVersion != "" {
		f.status(w, http.StatusBadRequest, "BadRequest", "uid or resourceVersion set on create")
		return
	}
	p.Metadata.Namespace = ns
	// Check and store under one lock: the API server's create is atomic,
	// and two concurrent creates of one name must not both succeed.
	f.mu.Lock()
	if f.pods[ns+"/"+p.Metadata.Name] != nil {
		f.mu.Unlock()
		f.status(w, http.StatusConflict, "AlreadyExists", fmt.Sprintf("pods %q already exists", p.Metadata.Name))
		return
	}
	p.Status = &PodStatus{Phase: PhasePending}
	f.putLocked(&p)
	raw, _ := json.Marshal(&p)
	delay := f.createDelay
	f.mu.Unlock()
	// The pod exists; the answer is late (a slow API server or network).
	time.Sleep(delay)
	_, _ = w.Write(raw)
}

func (f *fakeAPI) setCreateDelay(d time.Duration) {
	f.mu.Lock()
	f.createDelay = d
	f.mu.Unlock()
}

func (f *fakeAPI) read(w http.ResponseWriter, ns, name string) {
	f.mu.Lock()
	key := ns + "/" + name
	p := f.pods[key]
	if p != nil && p.Metadata.DeletionTimestamp != nil && f.goneAfter >= 0 {
		f.reads[key]++
		if f.reads[key] > f.goneAfter {
			delete(f.pods, key)
			delete(f.reads, key)
			p = nil
		}
	}
	if p != nil && f.kubelet != nil && p.Metadata.DeletionTimestamp == nil {
		f.kubelet(p)
	}
	var raw []byte
	if p != nil {
		raw, _ = json.Marshal(p)
	}
	f.mu.Unlock()
	if p == nil {
		f.status(w, http.StatusNotFound, "NotFound", fmt.Sprintf("pods %q not found", name))
		return
	}
	_, _ = w.Write(raw)
}

func (f *fakeAPI) remove(w http.ResponseWriter, r *http.Request, ns, name string) {
	var opts struct {
		GracePeriodSeconds *int64 `json:"gracePeriodSeconds"`
		Preconditions      struct {
			UID string `json:"uid"`
		} `json:"preconditions"`
	}
	body, _ := io.ReadAll(r.Body)
	if len(body) > 0 {
		if err := json.Unmarshal(body, &opts); err != nil {
			f.status(w, http.StatusBadRequest, "BadRequest", err.Error())
			return
		}
	}
	f.mu.Lock()
	key := ns + "/" + name
	p := f.pods[key]
	grace := int64(-1)
	if opts.GracePeriodSeconds != nil {
		grace = *opts.GracePeriodSeconds
	}
	f.deletes = append(f.deletes, deleteCall{name: name, grace: grace, uid: opts.Preconditions.UID})
	switch {
	case p == nil:
		f.mu.Unlock()
		f.status(w, http.StatusNotFound, "NotFound", fmt.Sprintf("pods %q not found", name))
		return
	case opts.Preconditions.UID != "" && opts.Preconditions.UID != p.Metadata.UID:
		f.mu.Unlock()
		f.status(w, http.StatusConflict, "Conflict", "Precondition failed: UID in precondition does not match")
		return
	case f.goneAfter == 0:
		delete(f.pods, key)
	default:
		now := time.Now().UTC()
		p.Metadata.DeletionTimestamp = &now
	}
	f.mu.Unlock()
	_ = json.NewEncoder(w).Encode(map[string]any{"kind": "Status", "status": "Success"})
}

func matchesSelector(labels map[string]string, selector string) bool {
	if selector == "" {
		return true
	}
	for _, term := range strings.Split(selector, ",") {
		k, v, ok := strings.Cut(term, "=")
		if !ok || labels[k] != v {
			return false
		}
	}
	return true
}

func (f *fakeAPI) list(w http.ResponseWriter, r *http.Request, ns string) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("continue"))
	f.mu.Lock()
	var names []string
	for key, p := range f.pods {
		if strings.HasPrefix(key, ns+"/") && matchesSelector(p.Metadata.Labels, q.Get("labelSelector")) {
			names = append(names, key)
		}
	}
	slices.Sort(names)
	end := len(names)
	if limit > 0 && offset+limit < end {
		end = offset + limit
	}
	out := struct {
		Metadata struct {
			Continue string `json:"continue,omitempty"`
		} `json:"metadata"`
		Items []Pod `json:"items"`
	}{Items: []Pod{}}
	for _, key := range names[min(offset, len(names)):end] {
		out.Items = append(out.Items, *f.pods[key])
	}
	if end < len(names) {
		out.Metadata.Continue = strconv.Itoa(end)
	}
	f.mu.Unlock()
	_ = json.NewEncoder(w).Encode(&out)
}
