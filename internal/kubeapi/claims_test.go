package kubeapi

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
)

func claimRig(t *testing.T, envPolicy string) *rig {
	t.Helper()
	r := newRig(t, p("sb-1", "plain", "team:a", 3))
	store := &memStore{}
	tpl := `{"metadata":{"name":"python"},"spec":{"podTemplate":{"spec":{"runtimeClassName":"gvisor","containers":[{"name":"m","image":"python:3.12","env":[{"name":"MODE","value":"prod"}]}]}}}}`
	if envPolicy != "" {
		tpl = strings.Replace(tpl, `"spec":{"podTemplate"`, `"spec":{"envVarsInjectionPolicy":"`+envPolicy+`","podTemplate"`, 1)
	}
	var tm, pm map[string]any
	_ = json.Unmarshal([]byte(tpl), &tm)
	_ = json.Unmarshal([]byte(goodPool), &pm)
	store.put(SandboxTemplatesResource, "a", tm)
	store.put(SandboxWarmPoolsResource, "a", pm)
	r.srv.Store = store
	return r
}

const claimBody = `{"apiVersion":"extensions.agents.x-k8s.io/v1beta1","kind":"SandboxClaim","metadata":{"name":"job","labels":{"team":"ml"}},
"spec":{"warmPoolRef":{"name":"pool"},"env":[{"name":"TASK","value":"t1"}],"additionalPodMetadata":{"labels":{"sandbox.users.io/x":"y"}}}}`

func TestClaimCreateGetListDelete(t *testing.T) {
	r := claimRig(t, "Allowed")
	claims := ext + "/namespaces/a/sandboxclaims"
	rr, out := r.call(t, http.MethodPost, claims, claimBody)
	if rr.Code != http.StatusCreated || out["kind"] != SandboxClaimKind || out["status"].(map[string]any)["sandbox"].(map[string]any)["name"] != "job" ||
		out["spec"].(map[string]any)["warmPoolRef"].(map[string]any)["name"] != "pool" {
		t.Fatalf("create = %d %v", rr.Code, out)
	}
	req := r.be.created[0]
	if req.Name != "job" || req.Image != "python:3.12" || req.Runtime != "gvisor" || req.Env["MODE"] != "prod" || req.Env["TASK"] != "t1" ||
		req.Tags[TagClaim] != "true" || req.Tags[TagWarmPool] != "pool" || req.Tags["team"] != "ml" || req.Tags["sandbox.users.io/x"] != "y" ||
		r.be.keys[0] != "kubeapi-claim/a/job" {
		t.Fatalf("create = %+v %v", req, r.be.keys)
	}
	if rr, out := r.call(t, http.MethodGet, claims+"/job", ""); rr.Code != http.StatusOK || out["metadata"].(map[string]any)["name"] != "job" {
		t.Fatalf("get = %d %v", rr.Code, out)
	}
	// A sandbox not made by a claim is not one.
	if rr, _ := r.call(t, http.MethodGet, claims+"/plain", ""); rr.Code != http.StatusNotFound {
		t.Fatalf("a plain sandbox as a claim = %d", rr.Code)
	}
	if rr, out := r.call(t, http.MethodGet, claims+"/nope", ""); rr.Code != http.StatusNotFound || !strings.Contains(out["message"].(string), "sandboxclaims") {
		t.Fatalf("an unknown claim = %d %v", rr.Code, out["message"])
	}
	for _, path := range []string{claims, ext + "/sandboxclaims"} {
		_, out := r.call(t, http.MethodGet, path, "")
		items := out["items"].([]any)
		if len(items) != 1 || items[0].(map[string]any)["metadata"].(map[string]any)["name"] != "job" {
			t.Fatalf("list %s = %v", path, items)
		}
	}
	// The sandbox shows the claim's labels.
	if _, sb := r.call(t, http.MethodGet, base+"/namespaces/a/sandboxes/job", ""); sb["metadata"].(map[string]any)["labels"].(map[string]any)[TagClaim] != "true" {
		t.Fatalf("sandbox labels = %v", sb["metadata"])
	}
	if rr, _ := r.call(t, http.MethodPost, claims, claimBody); rr.Code != http.StatusConflict {
		t.Fatalf("a taken name = %d", rr.Code)
	}
	// A claim cannot change; one sent as it is (a second kubectl apply)
	// passes, and its env, which this server does not show, is not
	// compared and is said so.
	merge := "application/merge-patch+json"
	if rr, _ := r.call(t, http.MethodPatch, claims+"/job", `{"metadata":{"annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{}"}},"spec":{"warmPoolRef":{"name":"pool"},"env":[{"name":"TASK","value":"t1"}]}}`, "Content-Type", merge); rr.Code != http.StatusOK ||
		!strings.Contains(rr.Header().Get("Warning"), "spec.env") {
		t.Fatalf("a second apply = %d %q", rr.Code, rr.Header().Get("Warning"))
	}
	for body, want := range map[string]string{
		`{"spec":{"warmPoolRef":{"name":"another"}}}`:  "spec.warmPoolRef",
		`{"metadata":{"labels":{"team":"other"}}}`:     "metadata.labels",
		`{"metadata":{"name":"renamed"}}`:              "cannot change",
		`{"spec":{"sandboxTemplateRef":{"name":"t"}}}`: "not supported",
	} {
		if rr, out := r.call(t, http.MethodPatch, claims+"/job", body, "Content-Type", merge); rr.Code != http.StatusUnprocessableEntity || !strings.Contains(out["message"].(string), want) {
			t.Fatalf("patch %s = %d %v", body, rr.Code, out["message"])
		}
	}
	if rr, _ := r.call(t, http.MethodPatch, claims+"/job", `{}`, "Content-Type", "application/json-patch+json"); rr.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("a JSON patch = %d", rr.Code)
	}
	if rr, _ := r.call(t, http.MethodPatch, claims+"/job", `x`, "Content-Type", merge); rr.Code != http.StatusBadRequest {
		t.Fatalf("not JSON = %d", rr.Code)
	}
	if rr, _ := r.call(t, http.MethodDelete, claims+"/plain", ""); rr.Code != http.StatusNotFound {
		t.Fatal("deleting a plain sandbox as a claim")
	}
	if rr, out := r.call(t, http.MethodDelete, claims+"/job", ""); rr.Code != http.StatusOK || out["status"] != "Success" || r.be.deleted[0] != "sb-new1" {
		t.Fatalf("delete = %d %v %v", rr.Code, out, r.be.deleted)
	}
	if rr, _ := r.call(t, http.MethodGet, ext+"/namespaces/Bad_NS/sandboxclaims", ""); rr.Code != http.StatusNotFound {
		t.Fatal("an unmappable namespace")
	}
	// generateName, a cold create the hub has not seen yet.
	r.be.noFeed = true
	gen := strings.Replace(claimBody, `"name":"job",`, `"generateName":"run-",`, 1)
	if rr, out := r.call(t, http.MethodPost, claims, gen); rr.Code != http.StatusCreated || out["metadata"].(map[string]any)["name"] != "run-x7k2p" {
		t.Fatalf("generateName = %d %v", rr.Code, out)
	}
}

func TestClaimEnvPolicies(t *testing.T) {
	override := `{"metadata":{"name":"o"},"spec":{"warmPoolRef":{"name":"pool"},"env":[{"name":"MODE","value":"dev"}]}}`
	r := claimRig(t, "Overrides")
	if rr, _ := r.call(t, http.MethodPost, ext+"/namespaces/a/sandboxclaims", override); rr.Code != http.StatusCreated || r.be.created[0].Env["MODE"] != "dev" {
		t.Fatalf("Overrides = %d %+v", rr.Code, r.be.created)
	}
	r = claimRig(t, "Allowed")
	if rr, out := r.call(t, http.MethodPost, ext+"/namespaces/a/sandboxclaims", override); rr.Code != http.StatusUnprocessableEntity || !strings.Contains(out["message"].(string), "not Overrides") {
		t.Fatalf("Allowed, overriding = %d %v", rr.Code, out)
	}
	r = claimRig(t, "Disallowed")
	if rr, _ := r.call(t, http.MethodPost, ext+"/namespaces/a/sandboxclaims", claimBody); rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("Disallowed = %d", rr.Code)
	}
	// Unset is Disallowed, as upstream: a template opts in to claim env.
	r = claimRig(t, "")
	if rr, out := r.call(t, http.MethodPost, ext+"/namespaces/a/sandboxclaims", claimBody); rr.Code != http.StatusUnprocessableEntity || !strings.Contains(out["message"].(string), "Disallowed") {
		t.Fatalf("an unset policy = %d %v", rr.Code, out["message"])
	}
	// A claim's DeleteForeground (upstream: delete the claim, waiting for
	// its sandbox) is Delete: a claim is its sandbox.
	fg := `{"metadata":{"name":"fg"},"spec":{"warmPoolRef":{"name":"pool"},"lifecycle":{"shutdownTime":"2099-01-01T00:00:00Z","shutdownPolicy":"DeleteForeground"}}}`
	if rr, out := r.call(t, http.MethodPost, ext+"/namespaces/a/sandboxclaims", fg); rr.Code != http.StatusCreated {
		t.Fatalf("DeleteForeground = %d %v", rr.Code, out["message"])
	}
	if lc := r.be.created[len(r.be.created)-1].Lifecycle; lc == nil || lc.DestroyAtAge <= 0 || lc.StopAtAge != 0 {
		t.Fatalf("DeleteForeground made %+v, want a delete at the time", lc)
	}
	// A claim without env needs no policy.
	if rr, _ := r.call(t, http.MethodPost, ext+"/namespaces/a/sandboxclaims", `{"metadata":{"name":"bare"},"spec":{"warmPoolRef":{"name":"pool"}}}`); rr.Code != http.StatusCreated {
		t.Fatalf("a claim without env, policy unset = %d", rr.Code)
	}
	r = claimRig(t, "Allowed")
	nameless := `{"metadata":{"name":"n"},"spec":{"warmPoolRef":{"name":"pool"},"env":[{"value":"x"}]}}`
	if rr, _ := r.call(t, http.MethodPost, ext+"/namespaces/a/sandboxclaims", nameless); rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("a nameless env = %d", rr.Code)
	}
}

func TestClaimRefusals(t *testing.T) {
	r := claimRig(t, "Allowed")
	for name, tc := range map[string]struct {
		body string
		code int
		want string
	}{
		"no pool":         {`{"metadata":{"name":"c"},"spec":{}}`, 422, "warmPoolRef.name: required"},
		"unknown pool":    {`{"metadata":{"name":"c"},"spec":{"warmPoolRef":{"name":"gone"}}}`, 422, "warm pool gone does not exist"},
		"volumes":         {`{"metadata":{"name":"c"},"spec":{"warmPoolRef":{"name":"pool"},"volumeClaimTemplates":[]}}`, 422, "volumeClaimTemplates"},
		"ttl":             {`{"metadata":{"name":"c"},"spec":{"warmPoolRef":{"name":"pool"},"lifecycle":{"ttlSecondsAfterFinished":5}}}`, 422, "ttlSecondsAfterFinished"},
		"wrong kind":      {`{"kind":"Pod","metadata":{"name":"c"},"spec":{"warmPoolRef":{"name":"pool"}}}`, 422, "kind"},
		"a bad name":      {`{"metadata":{"name":"C"},"spec":{"warmPoolRef":{"name":"pool"}}}`, 422, "metadata.name"},
		"past shutdown":   {`{"metadata":{"name":"c"},"spec":{"warmPoolRef":{"name":"pool"},"lifecycle":{"shutdownTime":"2020-01-01T00:00:00Z"}}}`, 422, "shutdownTime"},
		"wrong namespace": {`{"metadata":{"name":"c","namespace":"b"},"spec":{"warmPoolRef":{"name":"pool"}}}`, 400, "namespace"},
		"not JSON":        {`x`, 400, "JSON"},
	} {
		rr, out := r.call(t, http.MethodPost, ext+"/namespaces/a/sandboxclaims", tc.body)
		if rr.Code != tc.code || !strings.Contains(out["message"].(string), tc.want) {
			t.Errorf("%s = %d %v, want %d naming %q", name, rr.Code, out["message"], tc.code, tc.want)
		}
	}
	// A pool whose template is gone.
	var pm map[string]any
	_ = json.Unmarshal([]byte(strings.Replace(goodPool, `"pool"`, `"orphan"`, 1)), &pm)
	pm["spec"].(map[string]any)["sandboxTemplateRef"] = map[string]any{"name": "gone"}
	r.srv.Store.(*memStore).put(SandboxWarmPoolsResource, "a", pm)
	if rr, out := r.call(t, http.MethodPost, ext+"/namespaces/a/sandboxclaims", `{"metadata":{"name":"c"},"spec":{"warmPoolRef":{"name":"orphan"}}}`); rr.Code != 422 || !strings.Contains(out["message"].(string), "template gone") {
		t.Fatalf("a missing template = %d %v", rr.Code, out)
	}
	// A store failure that is not a 404 passes through.
	r.srv.Store.(*memStore).err = &StatusError{Code: 503, Reason: "ServiceUnavailable", Message: "etcd"}
	if rr, _ := r.call(t, http.MethodPost, ext+"/namespaces/a/sandboxclaims", claimBody); rr.Code != 200 && rr.Code != 201 && rr.Code != 503 {
		t.Fatalf("a store failure = %d", rr.Code)
	}
	r.srv.Store.(*memStore).err = nil
	r.be.err = &StatusError{Code: 429, Reason: "TooManyRequests", Message: "quota"}
	if rr, _ := r.call(t, http.MethodPost, ext+"/namespaces/a/sandboxclaims", strings.Replace(claimBody, `"job"`, `"q"`, 1)); rr.Code != 429 {
		t.Fatalf("a backend refusal = %d", rr.Code)
	}
}

func TestClaimWatch(t *testing.T) {
	r := claimRig(t, "Allowed")
	ts := httptest.NewServer(r.srv)
	defer ts.Close()
	for _, path := range []string{"/namespaces/a/sandboxclaims?watch=true&resourceVersion=50&timeoutSeconds=5", "/sandboxclaims?watch=true&timeoutSeconds=5"} {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+ext+path, nil)
		req.Header.Set("X-Test-User", "alice")
		resp, err := ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		lines := make(chan map[string]any, 8)
		go func() {
			defer close(lines)
			sc := bufio.NewScanner(resp.Body)
			for sc.Scan() {
				var ev map[string]any
				if json.Unmarshal(sc.Bytes(), &ev) == nil {
					lines <- ev
				}
			}
		}()
		// A plain sandbox, then a claim: only the claim is an event. The
		// plain one is marked no claim on its row, so its spec is never
		// read.
		plain := p("sb-p"+path[:3], "plain2", "team:a", 60)
		plain.KubeClaim = cluster.KubeClaimNo
		r.hub.Apply(cluster.PlacementFeedEvent{Changes: []cluster.PlacementChange{{SandboxID: plain.SandboxID, Index: 60, Placement: &plain}}, Next: 60})
		name := "w" + string(rune('a'+len(r.be.created)))
		if rr, _ := r.call(t, http.MethodPost, ext+"/namespaces/a/sandboxclaims", strings.Replace(claimBody, `"job"`, `"`+name+`"`, 1)); rr.Code != http.StatusCreated {
			t.Fatalf("create %s = %d", name, rr.Code)
		}
		// A watch from 0 replays the claims already made first.
		ev := nextLine(t, lines)
		for objName(ev) != name && ev["type"] == "ADDED" {
			ev = nextLine(t, lines)
		}
		if ev["type"] != "ADDED" || ev["object"].(map[string]any)["kind"] != SandboxClaimKind || objName(ev) != name {
			t.Fatalf("%s: event = %v", path, ev)
		}
		resp.Body.Close()
		r.be.mu.Lock()
		for _, id := range r.be.specIDs {
			if id == plain.SandboxID {
				t.Errorf("%s: the watch read the spec of a row marked no claim", path)
			}
		}
		r.be.mu.Unlock()
	}
	for q, code := range map[string]int{"?watch=true&resourceVersion=x": 400, "?watch=true&resourceVersion=1": 410} {
		if rr, _ := r.call(t, http.MethodGet, ext+"/namespaces/a/sandboxclaims"+q, ""); rr.Code != code {
			t.Errorf("watch%s = %d, want %d", q, rr.Code, code)
		}
	}
	// A resync ends a claim watch with a 410 event.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+ext+"/namespaces/a/sandboxclaims?watch=true&resourceVersion=0", nil)
	req.Header.Set("X-Test-User", "alice")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	r.hub.Apply(cluster.PlacementFeedEvent{View: true, Next: 900})
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		if strings.Contains(sc.Text(), `"ERROR"`) && strings.Contains(sc.Text(), "410") {
			return
		}
	}
	t.Fatal("no 410 after a resync")
}

// Claims honor a list's and a watch's selectors, as sandboxes do: kubectl
// wait sandboxclaim/x lists and watches by fieldSelector metadata.name.
func TestClaimSelectors(t *testing.T) {
	r := claimRig(t, "Allowed")
	claims := ext + "/namespaces/a/sandboxclaims"
	for name, team := range map[string]string{"job": "ml", "other": "web"} {
		body := strings.Replace(strings.Replace(claimBody, `"job"`, `"`+name+`"`, 1), `"ml"`, `"`+team+`"`, 1)
		if rr, _ := r.call(t, http.MethodPost, claims, body); rr.Code != http.StatusCreated {
			t.Fatalf("create %s = %d", name, rr.Code)
		}
	}
	names := func(out map[string]any) []string {
		var got []string
		for _, it := range out["items"].([]any) {
			got = append(got, it.(map[string]any)["metadata"].(map[string]any)["name"].(string))
		}
		return got
	}
	for q, want := range map[string]string{
		"":                                       "job,other",
		"?fieldSelector=metadata.name%3Djob":     "job",
		"?labelSelector=team%3Dweb":              "other",
		"?labelSelector=team%3Dweb,team%21%3Dml": "other",
		"?labelSelector=team%3Dnone":             "",
	} {
		rr, out := r.call(t, http.MethodGet, claims+q, "")
		if got := strings.Join(names(out), ","); rr.Code != http.StatusOK || got != want {
			t.Errorf("list%s = %d %q, want %q", q, rr.Code, got, want)
		}
	}
	// A claim shows the labels it was made with.
	if _, out := r.call(t, http.MethodGet, claims+"/job", ""); out["metadata"].(map[string]any)["labels"].(map[string]any)["team"] != "ml" {
		t.Fatalf("claim labels = %v", out["metadata"])
	}
	for _, q := range []string{"?fieldSelector=status.phase%3DRunning", "?watch=true&fieldSelector=status.phase%3DRunning"} {
		if rr, _ := r.call(t, http.MethodGet, claims+q, ""); rr.Code != http.StatusBadRequest {
			t.Errorf("list%s = %d, want 400", q, rr.Code)
		}
	}

	ts := httptest.NewServer(r.srv)
	defer ts.Close()
	req, _ := http.NewRequest(http.MethodGet, ts.URL+claims+"?watch=true&fieldSelector=metadata.name%3Dother&timeoutSeconds=1", nil)
	req.Header.Set("X-Test-User", "alice")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got []string
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		var ev map[string]any
		if json.Unmarshal(sc.Bytes(), &ev) == nil && ev["type"] != "BOOKMARK" {
			got = append(got, objName(ev))
		}
	}
	if strings.Join(got, ",") != "other" {
		t.Fatalf("a watch for other saw %v", got)
	}
}

// kubectl wait sandboxclaim/x asks for the initial list and waits for the
// bookmark that ends it (p6-kubeapi-4 timed out without one).
func TestClaimWatchInitialEvents(t *testing.T) {
	r := claimRig(t, "Allowed")
	if rr, _ := r.call(t, http.MethodPost, ext+"/namespaces/a/sandboxclaims", claimBody); rr.Code != http.StatusCreated {
		t.Fatalf("create = %d", rr.Code)
	}
	ts := httptest.NewServer(r.srv)
	defer ts.Close()
	req, _ := http.NewRequest(http.MethodGet, ts.URL+ext+"/namespaces/a/sandboxclaims?watch=true&sendInitialEvents=true&resourceVersionMatch=NotOlderThan&allowWatchBookmarks=true&fieldSelector=metadata.name%3Djob&timeoutSeconds=5", nil)
	req.Header.Set("X-Test-User", "alice")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var seen []string
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		var ev map[string]any
		if json.Unmarshal(sc.Bytes(), &ev) != nil {
			continue
		}
		obj := ev["object"].(map[string]any)
		if ev["type"] == "BOOKMARK" {
			md := obj["metadata"].(map[string]any)
			ann, _ := md["annotations"].(map[string]any)
			if obj["kind"] != SandboxClaimKind || ann[initialEventsEnd] != "true" {
				t.Fatalf("bookmark = %v", obj)
			}
			if strings.Join(seen, ",") != "ADDED job" {
				t.Fatalf("before the end of the initial list: %v", seen)
			}
			return
		}
		seen = append(seen, ev["type"].(string)+" "+objName(ev))
	}
	t.Fatalf("no end of the initial list; saw %v", seen)
}

// A claim list reads the spec of a claim, and of a row an older build left
// unmarked, never of a sandbox the hot row marks as no claim (C17).
func TestClaimListSkipsRowsMarkedNoClaim(t *testing.T) {
	mark := func(id, name string, m cluster.KubeClaimMark) cluster.Placement {
		row := p(id, name, "team:a", 3)
		row.KubeClaim = m
		return row
	}
	r := newRig(t,
		mark("sb-plain", "plain", cluster.KubeClaimNo),
		mark("sb-claim", "claimed", cluster.KubeClaimYes),
		mark("sb-old-claim", "old-claim", cluster.KubeClaimUnknown),
		mark("sb-old-plain", "old-plain", cluster.KubeClaimUnknown),
	)
	claimTags := map[string]string{TagClaim: "true", TagWarmPool: "pool"}
	r.be.tags = map[string]map[string]string{"sb-claim": claimTags, "sb-old-claim": claimTags, "sb-plain": claimTags}
	_, out := r.call(t, http.MethodGet, ext+"/namespaces/a/sandboxclaims", "")
	var got []string
	for _, it := range out["items"].([]any) {
		got = append(got, it.(map[string]any)["metadata"].(map[string]any)["name"].(string))
	}
	if strings.Join(got, ",") != "claimed,old-claim" {
		t.Fatalf("claims = %v", got)
	}
	for _, id := range r.be.specIDs {
		if id == "sb-plain" {
			t.Fatal("read the spec of a row marked no claim")
		}
	}
	if len(r.be.specIDs) != 3 {
		t.Fatalf("spec reads = %v, want the claim and the two unmarked rows", r.be.specIDs)
	}
}
