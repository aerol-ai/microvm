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
// (with grace and a UID precondition), list (label selector, paging) and
// watch (from a resource version, with bookmarks, and 410 for a version
// older than the last compaction). A "kubelet" hook moves pods along: on
// every read of a pod, as the real kubelet does between reads, and, with
// runKubelet, on a timer, for clients that only watch.
type fakeAPI struct {
	t   *testing.T
	srv *httptest.Server

	mu      sync.Mutex
	pods    map[string]*Pod // "namespace/name"
	nextUID int
	rv      int
	// events is every change, in resource-version order, for watches.
	events    []fakeEvent
	notify    chan struct{} // closed and replaced on each new event
	compacted int           // a watch from a version below this gets 410
	cut       chan struct{} // closed to end every open watch
	watches   int           // watches opened
	failWatch int           // answer every watch with this status until cleared
	// kubelet, when set, runs on each GET of a pod (under mu), and on each
	// tick of runKubelet.
	kubelet func(p *Pod)
	// goneAfter is how many reads (or kubelet ticks) a deleted pod stays
	// for, terminating; 0 removes it at once. -1 keeps it forever (a node
	// nobody can reach).
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

type fakeEvent struct {
	rv  int
	typ string
	pod Pod
}

type deleteCall struct {
	name  string
	grace int64
	uid   string
}

func newFakeAPI(t *testing.T) *fakeAPI {
	f := &fakeAPI{
		t: t, pods: map[string]*Pod{}, reads: map[string]int{}, fail: map[string]int{},
		notify: make(chan struct{}), cut: make(chan struct{}),
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	t.Cleanup(f.cutWatches) // a watch handler must end before Close waits on it
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

// runKubelet runs the kubelet hook and the deletion countdown on a timer,
// for clients that watch instead of reading.
func (f *fakeAPI) runKubelet(every time.Duration) {
	stop := make(chan struct{})
	done := make(chan struct{})
	f.t.Cleanup(func() { close(stop); <-done })
	go func() {
		defer close(done)
		tick := time.NewTicker(every)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
			}
			f.mu.Lock()
			for key, p := range f.pods {
				f.advanceLocked(key, p)
			}
			f.mu.Unlock()
		}
	}()
}

// advanceLocked moves one pod along, as a read or a kubelet tick does:
// a deleted pod counts down to its removal; a live one gets the kubelet's
// changes. Either change is an event.
func (f *fakeAPI) advanceLocked(key string, p *Pod) (removed bool) {
	if p.Metadata.DeletionTimestamp != nil {
		if f.goneAfter < 0 {
			return false
		}
		f.reads[key]++
		if f.reads[key] > f.goneAfter {
			delete(f.pods, key)
			delete(f.reads, key)
			f.recordLocked("DELETED", p)
			return true
		}
		return false
	}
	if f.kubelet != nil {
		before, _ := json.Marshal(p.Status)
		f.kubelet(p)
		if after, _ := json.Marshal(p.Status); string(after) != string(before) {
			f.recordLocked("MODIFIED", p)
		}
	}
	return false
}

// recordLocked gives p a new resource version and logs the change for
// watches. The log keeps a copy: tests change pods in place.
func (f *fakeAPI) recordLocked(typ string, p *Pod) {
	f.rv++
	p.Metadata.ResourceVersion = strconv.Itoa(f.rv)
	var cp Pod
	raw, _ := json.Marshal(p)
	_ = json.Unmarshal(raw, &cp)
	f.events = append(f.events, fakeEvent{rv: f.rv, typ: typ, pod: cp})
	close(f.notify)
	f.notify = make(chan struct{})
}

// bookmark sends every watch the current version, with no change.
func (f *fakeAPI) bookmark() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rv++
	f.events = append(f.events, fakeEvent{rv: f.rv, typ: "BOOKMARK", pod: Pod{Metadata: ObjectMeta{ResourceVersion: strconv.Itoa(f.rv)}}})
	close(f.notify)
	f.notify = make(chan struct{})
}

// compact forgets the history before now: a watch from an older version
// gets 410 Gone and must list again.
func (f *fakeAPI) compact() {
	f.mu.Lock()
	f.compacted = f.rv
	f.mu.Unlock()
}

// cutWatches ends every open watch, as a dropped connection would.
func (f *fakeAPI) cutWatches() {
	f.mu.Lock()
	close(f.cut)
	f.cut = make(chan struct{})
	f.mu.Unlock()
}

func (f *fakeAPI) watchCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.watches
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
	if p.Metadata.UID == "" {
		f.nextUID++
		p.Metadata.UID = "uid-" + strconv.Itoa(f.nextUID)
	}
	key := p.Metadata.Namespace + "/" + p.Metadata.Name
	typ := "ADDED"
	if old := f.pods[key]; old != nil && old.Metadata.UID == p.Metadata.UID {
		typ = "MODIFIED"
	} else if old != nil {
		f.recordLocked("DELETED", old)
	}
	f.pods[key] = p
	f.recordLocked(typ, p)
}

func (f *fakeAPI) get(ns, name string) *Pod {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pods[ns+"/"+name]
}

// change edits a stored pod and records it, as the kubelet would.
func (f *fakeAPI) change(ns, name string, edit func(p *Pod)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := f.pods[ns+"/"+name]
	edit(p)
	f.recordLocked("MODIFIED", p)
}

// forceRemove removes a pod at once with no end seen, as a force delete
// or a lost node does.
func (f *fakeAPI) forceRemove(ns, name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := ns + "/" + name
	p := f.pods[key]
	now := time.Date(2026, 11, 26, 11, 0, 0, 0, time.UTC)
	p.Metadata.DeletionTimestamp = &now
	delete(f.pods, key)
	f.recordLocked("DELETED", p)
}

func (f *fakeAPI) setPhase(ns, name, phase string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := f.pods[ns+"/"+name]
	if p.Status == nil {
		p.Status = &PodStatus{}
	}
	p.Status.Phase = phase
	f.recordLocked("MODIFIED", p)
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

func (f *fakeAPI) setFailWatch(code int) {
	f.mu.Lock()
	f.failWatch = code
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
	if r.URL.Query().Get("watch") == "1" {
		call = "WATCH " + r.URL.Path
	}
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
	case len(parts) == 2 && r.Method == http.MethodGet && r.URL.Query().Get("watch") == "1":
		f.watch(w, r, ns)
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
	if p != nil && f.advanceLocked(key, p) {
		p = nil
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
		f.recordLocked("DELETED", p)
	default:
		now := time.Now().UTC()
		p.Metadata.DeletionTimestamp = &now
		f.recordLocked("MODIFIED", p)
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
			Continue        string `json:"continue,omitempty"`
			ResourceVersion string `json:"resourceVersion"`
		} `json:"metadata"`
		Items []Pod `json:"items"`
	}{Items: []Pod{}}
	out.Metadata.ResourceVersion = strconv.Itoa(f.rv)
	for _, key := range names[min(offset, len(names)):end] {
		out.Items = append(out.Items, *f.pods[key])
	}
	if end < len(names) {
		out.Metadata.Continue = strconv.Itoa(end)
	}
	f.mu.Unlock()
	_ = json.NewEncoder(w).Encode(&out)
}

func (f *fakeAPI) watch(w http.ResponseWriter, r *http.Request, ns string) {
	q := r.URL.Query()
	from, _ := strconv.Atoi(q.Get("resourceVersion"))
	selector := q.Get("labelSelector")
	f.mu.Lock()
	f.watches++
	if code := f.failWatch; code != 0 {
		f.mu.Unlock()
		f.status(w, code, http.StatusText(code), "injected")
		return
	}
	expired := from < f.compacted
	cut := f.cut
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	flush := func() {
		if fl, ok := w.(http.Flusher); ok {
			fl.Flush()
		}
	}
	if expired {
		_ = enc.Encode(map[string]any{"type": "ERROR", "object": map[string]any{
			"kind": "Status", "status": "Failure", "code": 410, "reason": "Expired", "message": "too old resource version",
		}})
		flush()
		return
	}
	cursor := from
	for {
		f.mu.Lock()
		var batch []fakeEvent
		for _, e := range f.events {
			if e.rv <= cursor {
				continue
			}
			cursor = e.rv
			if e.typ == "BOOKMARK" || (e.pod.Metadata.Namespace == ns && matchesSelector(e.pod.Metadata.Labels, selector)) {
				batch = append(batch, e)
			}
		}
		notify := f.notify
		f.mu.Unlock()
		for _, e := range batch {
			if err := enc.Encode(map[string]any{"type": e.typ, "object": e.pod}); err != nil {
				return
			}
		}
		flush()
		select {
		case <-notify:
		case <-cut:
			return
		case <-r.Context().Done():
			return
		}
	}
}
