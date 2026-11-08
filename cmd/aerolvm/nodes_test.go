package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/agenttools"
	"github.com/aerol-ai/microvm/internal/agenttools/agenttoolstest"
)

// fakeCluster plays the /v1/cluster routes the node verbs call.
type fakeCluster struct {
	t   *testing.T
	srv *httptest.Server

	mu       sync.Mutex
	members  []map[string]any
	leader   string
	owned    map[string][]string // node -> sandbox ids
	runtimes map[string]string   // sandbox -> runtime
	running  map[string]int      // node -> running; missing means len(owned)
	unknown  map[string]bool     // running not known for this node
	cordoned map[string]bool
	deleted  map[string]bool
	queries  []string

	noCordonRoute bool
	fail          map[string]int // "METHOD path" -> fail this many times with 500
	failOnCall    map[string]int // "METHOD path" -> fail only the Nth call
	dropOnCall    map[string]int // "METHOD path" -> drop the connection on the Nth call
	status503     map[string]int // "METHOD path" -> answer 503 this many times
	calls         map[string]int
	slowNodeGet   time.Duration
	drainRunning  bool // each node GET lowers running by one
	busy          map[string]bool
	migrated      []string
	badMember     bool
	badNode       bool
}

func newFakeCluster(t *testing.T) *fakeCluster {
	f := &fakeCluster{t: t, owned: map[string][]string{}, runtimes: map[string]string{}, running: map[string]int{},
		unknown: map[string]bool{}, cordoned: map[string]bool{}, deleted: map[string]bool{}, fail: map[string]int{}, busy: map[string]bool{},
		failOnCall: map[string]int{}, calls: map[string]int{}, dropOnCall: map[string]int{}, status503: map[string]int{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeCluster) addMember(m map[string]any) { f.members = append(f.members, m) }

func (f *fakeCluster) member(id string) map[string]any {
	for _, m := range f.members {
		if m["node_id"] == id {
			return m
		}
	}
	return nil
}

func writeFakeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fakeCluster) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queries = append(f.queries, r.Method+" "+r.URL.RequestURI())
	if r.URL.Path == "/health" {
		writeFakeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": "v9.9.9"})
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+agenttoolstest.Token {
		writeFakeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	key := r.Method + " " + r.URL.Path
	f.calls[key]++
	if n := f.dropOnCall[key]; n > 0 && f.calls[key] == n {
		// A load balancer reset: no HTTP answer at all.
		if hj, ok := w.(http.Hijacker); ok {
			if conn, _, err := hj.Hijack(); err == nil {
				_ = conn.Close()
				return
			}
		}
	}
	if f.status503[key] > 0 {
		f.status503[key]--
		writeFakeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "catching up"})
		return
	}
	if n := f.failOnCall[key]; n > 0 && f.calls[key] == n {
		writeFakeJSON(w, http.StatusInternalServerError, map[string]string{"error": "boom"})
		return
	}
	if f.slowNodeGet > 0 && r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/cluster/nodes/") && f.calls[key] > 1 {
		// Read it before unlocking: the test turns it off while this sleeps.
		d := f.slowNodeGet
		f.mu.Unlock()
		time.Sleep(d)
		f.mu.Lock()
	}
	if f.fail[key] > 0 {
		f.fail[key]--
		writeFakeJSON(w, http.StatusInternalServerError, map[string]string{"error": "boom"})
		return
	}
	path := r.URL.Path
	switch {
	case path == "/v1/cluster/members" && r.Method == http.MethodGet:
		if f.badMember {
			writeFakeJSON(w, http.StatusOK, map[string]any{"members": []any{1}})
			return
		}
		out := []map[string]any{}
		for _, m := range f.members {
			id, _ := m["node_id"].(string)
			if f.deleted[id] {
				continue
			}
			c := map[string]any{}
			for k, v := range m {
				c[k] = v
			}
			if f.cordoned[id] {
				c["drained"] = true
			}
			out = append(out, c)
		}
		writeFakeJSON(w, http.StatusOK, map[string]any{"members": out})
	case path == "/v1/cluster/leader":
		writeFakeJSON(w, http.StatusOK, map[string]string{"leader": f.leader})
	case strings.HasPrefix(path, "/v1/cluster/nodes/"):
		f.serveNode(w, r, strings.TrimPrefix(path, "/v1/cluster/nodes/"))
	case path == "/v1/cluster/wasm-migrate" && r.Method == http.MethodPost:
		var body struct {
			SandboxID    string `json:"sandbox_id"`
			TargetNodeID string `json:"target_node_id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		for node, ids := range f.owned {
			f.owned[node] = without(ids, body.SandboxID)
		}
		f.owned[body.TargetNodeID] = append(f.owned[body.TargetNodeID], body.SandboxID)
		f.migrated = append(f.migrated, body.SandboxID+"->"+body.TargetNodeID)
		writeFakeJSON(w, http.StatusOK, map[string]string{"sandbox_id": body.SandboxID})
	case strings.HasPrefix(path, "/v1/sandboxes/"):
		id := strings.TrimPrefix(path, "/v1/sandboxes/")
		if _, ok := f.runtimes[id]; !ok {
			if r.Method == http.MethodDelete {
				// Gone already, placement and all.
				for node, ids := range f.owned {
					f.owned[node] = without(ids, id)
				}
			}
			writeFakeJSON(w, http.StatusNotFound, map[string]string{"error": "sandbox not found"})
			return
		}
		if r.Method == http.MethodDelete {
			delete(f.runtimes, id)
			for node, ids := range f.owned {
				f.owned[node] = without(ids, id)
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeFakeJSON(w, http.StatusOK, map[string]string{"id": id, "runtime": f.runtimes[id]})
	default:
		writeFakeJSON(w, http.StatusNotFound, map[string]string{"error": "no route"})
	}
}

func (f *fakeCluster) serveNode(w http.ResponseWriter, r *http.Request, rest string) {
	id, action, _ := strings.Cut(rest, "/")
	m := f.member(id)
	if m == nil || f.deleted[id] {
		writeFakeJSON(w, http.StatusNotFound, map[string]string{"error": "cluster: unknown node"})
		return
	}
	switch {
	case r.Method == http.MethodPost && action == "cordon":
		if f.noCordonRoute {
			writeFakeJSON(w, http.StatusNotFound, map[string]string{"error": "no route"})
			return
		}
		f.cordoned[id] = true
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodPost && action == "drain":
		f.cordoned[id] = true
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodPost && action == "uncordon":
		delete(f.cordoned, id)
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodDelete && action == "":
		if f.busy[id] {
			writeFakeJSON(w, http.StatusConflict, map[string]string{"error": "cluster: node is alive and still owns sandboxes"})
			return
		}
		f.deleted[id] = true
		writeFakeJSON(w, http.StatusOK, map[string]any{"node_id": id, "denied": true, "force": r.URL.Query().Get("force") == "true"})
	case r.Method == http.MethodGet && action == "":
		if f.badNode {
			writeFakeJSON(w, http.StatusOK, []int{1})
			return
		}
		detail := map[string]any{}
		for k, v := range m {
			detail[k] = v
		}
		owned := f.owned[id]
		running, ok := f.running[id]
		if !ok {
			running = len(owned)
		}
		if f.drainRunning && running > 0 {
			f.running[id] = running - 1
		}
		detail["drained"] = f.cordoned[id]
		detail["sandboxes_owned"] = len(owned)
		detail["sandboxes_running"] = running
		detail["running_known"] = !f.unknown[id]
		if limit, _ := strconv.Atoi(r.URL.Query().Get("sandboxes")); limit > 0 {
			ids := append([]string(nil), owned...)
			sort.Strings(ids)
			detail["sandbox_ids"] = ids
		}
		writeFakeJSON(w, http.StatusOK, detail)
	default:
		writeFakeJSON(w, http.StatusNotFound, map[string]string{"error": "no route"})
	}
}

func without(list []string, s string) []string {
	out := list[:0:0]
	for _, v := range list {
		if v != s {
			out = append(out, v)
		}
	}
	return out
}

func (f *fakeCluster) sawQuery(q string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, got := range f.queries {
		if got == q {
			return true
		}
	}
	return false
}

// standardFleet is a server leader, a cordoned worker with a heartbeat, a
// worker that is down, and a member on a build without role or version.
func standardFleet(t *testing.T) (*harness, *fakeCluster) {
	f := newFakeCluster(t)
	f.leader = "srv-a"
	f.addMember(map[string]any{"node_id": "srv-a", "role": "server", "alive": true, "version": "v0.6.12", "voter": true, "leader": true,
		"api_url": "https://srv-a:21212", "fsm_ops_version": 11, "capacity": map[string]any{}})
	f.addMember(map[string]any{"node_id": "wkr-1", "role": "worker", "alive": true, "version": "v0.6.12", "api_url": "https://wkr-1:21212",
		"zone": "az-1", "labels": map[string]string{"zone": "az-1", "gpu": "a10"}, "fsm_ops_version": 11, "node_name": "worker one",
		"internal_url": "https://wkr-1:7002", "data_plane_host": "10.0.0.11",
		"capacity": map[string]any{"host_cpu_cores": 8, "host_memory_total_mb": 8192, "reserved_cpu": 2, "cpu_budget": 8,
			"reserved_memory_mb": 1024, "memory_budget_mb": 4096, "sandboxes_active": 3, "parked_slots": 1}})
	f.addMember(map[string]any{"node_id": "wkr-2", "role": "worker", "alive": false, "version": "v0.6.11", "api_url": "https://wkr-2:21212",
		"capacity_stale": true, "fsm_ops_version": 10, "capacity": map[string]any{"host_cpu_cores": 8}})
	f.addMember(map[string]any{"node_id": "old-1", "alive": true, "api_url": "https://old-1:21212", "capacity": map[string]any{}})
	f.cordoned["wkr-1"] = true
	h := newHarness(t)
	h.env["SB_API_URL"] = f.srv.URL
	h.app.pollEvery = time.Millisecond
	return h, f
}

func (h *harness) transcript(code int) string {
	return fmt.Sprintf("exit %d\n--- stdout\n%s--- stderr\n%s", code, h.stdout.String(), h.stderr.String())
}

func TestGetNodesOutputs(t *testing.T) {
	h, f := standardFleet(t)
	for _, tc := range []struct {
		args   []string
		golden string
	}{
		{[]string{"get", "nodes"}, "get-nodes"},
		{[]string{"get", "no", "-o", "wide"}, "get-nodes-wide"},
		{[]string{"get", "nodes", "-o", "name"}, "get-nodes-name"},
		{[]string{"get", "node", "wkr-1", "-o", "json"}, "get-node-json"},
		{[]string{"get", "nodes", "srv-a", "wkr-2", "--output", "yaml"}, "get-nodes-yaml"},
		{[]string{"get", "--json", "nodes", "old-1"}, "get-node-old-json"},
	} {
		code := h.run(tc.args...)
		if code != exitOK {
			t.Fatalf("%v = %d %s", tc.args, code, h.stderr.String())
		}
		checkGoldenIn(t, "nodes", tc.golden+".golden", h.transcript(code))
	}
	// --json on a list prints {"nodes":[...]} with the server's objects.
	if code := h.run("get", "nodes", "--json"); code != exitOK {
		t.Fatal(h.stderr.String())
	}
	var list struct {
		Nodes []map[string]any `json:"nodes"`
	}
	h.jsonOut(&list)
	if len(list.Nodes) != 4 || list.Nodes[0]["node_id"] != "old-1" {
		t.Fatalf("list = %+v", list)
	}
	for _, tc := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"get", "nodes", "missing"}, exitError, `node "missing" not found`},
		{[]string{"get", "nodes", "-o", "bogus"}, exitUsage, "-o must be wide, json, yaml or name"},
		{[]string{"get", "box", "-o", "json"}, exitUsage, "-o is for kinds"},
	} {
		if code := h.run(tc.args...); code != tc.code || !strings.Contains(h.stderr.String(), tc.want) {
			t.Fatalf("%v = %d %q", tc.args, code, h.stderr.String())
		}
	}
	f.members = nil
	if code := h.run("get", "nodes"); code != exitOK || !strings.Contains(h.stderr.String(), "no nodes") || h.stdout.String() != "" {
		t.Fatalf("empty = %d %q %q", code, h.stdout.String(), h.stderr.String())
	}
	f.badMember = true
	if code := h.run("get", "nodes"); code != exitError || !strings.Contains(h.stderr.String(), "unreadable member") {
		t.Fatalf("bad member = %d %q", code, h.stderr.String())
	}
	f.badMember = false
	f.fail["GET /v1/cluster/members"] = 1
	if code := h.run("get", "nodes", "--json"); code != exitError || h.errorEnvelope().HTTPStatus != 500 {
		t.Fatalf("members failure = %d %q", code, h.stderr.String())
	}
}

func TestDescribeNode(t *testing.T) {
	h, f := standardFleet(t)
	f.owned["wkr-1"] = []string{"sb-1", "sb-2"}
	f.running["wkr-1"] = 1
	if code := h.run("describe", "node", "wkr-1"); code != exitOK {
		t.Fatal(h.stderr.String())
	}
	checkGoldenIn(t, "nodes", "describe-node.golden", h.transcript(exitOK))
	f.unknown["wkr-2"] = true
	f.owned["wkr-2"] = []string{"sb-9"}
	if code := h.run("describe", "nodes", "wkr-2"); code != exitOK || !strings.Contains(h.stdout.String(), "unknown (no fresh capacity heartbeat; at most 1)") {
		t.Fatalf("unknown running = %q", h.stdout.String())
	}
	if code := h.run("describe", "no", "srv-a", "-o", "yaml"); code != exitOK || !strings.Contains(h.stdout.String(), "node_id: srv-a") {
		t.Fatalf("yaml = %q", h.stdout.String())
	}
	if code := h.run("describe", "node", "srv-a", "--json"); code != exitOK {
		t.Fatal(h.stderr.String())
	}
	var obj map[string]any
	h.jsonOut(&obj)
	if obj["node_id"] != "srv-a" || obj["sandboxes_owned"] != float64(0) {
		t.Fatalf("json = %+v", obj)
	}
	for _, tc := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"describe", "node", "ghost"}, exitError, `node "ghost" not found`},
		{[]string{"describe"}, exitUsage, "expected a kind and a name"},
		// Not a kind: a sandbox (Phase 4), which takes one name.
		{[]string{"describe", "pod", "x"}, exitUsage, "expected one sandbox name"},
		{[]string{"describe", "node"}, exitUsage, "expected one node name"},
		{[]string{"describe", "node", "a", "-o", "wide"}, exitUsage, "-o must be json or yaml"},
		{[]string{"describe", "--nope"}, exitUsage, "nope"},
	} {
		if code := h.run(tc.args...); code != tc.code || !strings.Contains(h.stderr.String(), tc.want) {
			t.Fatalf("%v = %d %q", tc.args, code, h.stderr.String())
		}
	}
	f.badNode = true
	if code := h.run("describe", "node", "wkr-1"); code != exitError || !strings.Contains(h.stderr.String(), "unreadable node") {
		t.Fatalf("bad node = %d %q", code, h.stderr.String())
	}
}

func TestCordonAndUncordon(t *testing.T) {
	h, f := standardFleet(t)
	if code := h.run("cordon", "srv-a", "wkr-2"); code != exitOK || h.stdout.String() != "node/srv-a cordoned\nnode/wkr-2 cordoned\n" {
		t.Fatalf("cordon = %d %q %q", code, h.stdout.String(), h.stderr.String())
	}
	if !f.cordoned["srv-a"] || !f.cordoned["wkr-2"] {
		t.Fatal("cordon did not reach the server")
	}
	if code := h.run("uncordon", "wkr-2", "--json"); code != exitOK {
		t.Fatal(h.stderr.String())
	}
	var res map[string]any
	h.jsonOut(&res)
	if res["node_id"] != "wkr-2" || res["cordoned"] != false || f.cordoned["wkr-2"] {
		t.Fatalf("uncordon = %+v", res)
	}
	// A server older than the cordon route: drain is the same mark.
	f.noCordonRoute = true
	if code := h.run("cordon", "old-1"); code != exitOK || !f.cordoned["old-1"] || !f.sawQuery("POST /v1/cluster/nodes/old-1/drain") {
		t.Fatalf("fallback cordon = %d %q", code, h.stderr.String())
	}
	// One failure is reported and the rest still run; exit 1.
	if code := h.run("uncordon", "ghost", "srv-a"); code != exitError || !strings.Contains(h.stdout.String(), "node/srv-a uncordoned") {
		t.Fatalf("partial = %d %q %q", code, h.stdout.String(), h.stderr.String())
	}
	if code := h.run("cordon"); code != exitUsage {
		t.Fatalf("no name = %d", code)
	}
	if code := h.run("uncordon", "--bad"); code != exitUsage {
		t.Fatalf("bad flag = %d", code)
	}
}

func TestDrainWaitsUntilNothingRuns(t *testing.T) {
	h, f := standardFleet(t)
	f.running["wkr-2"] = 3
	f.drainRunning = true
	if code := h.run("drain", "wkr-2", "--timeout", "1m"); code != exitOK {
		t.Fatalf("drain = %d %q", code, h.stderr.String())
	}
	if h.stdout.String() != "node/wkr-2 cordoned\nnode/wkr-2 drained\n" || !strings.Contains(h.stderr.String(), "2 sandbox(es) left") {
		t.Fatalf("drain output = %q / %q", h.stdout.String(), h.stderr.String())
	}
	if !f.cordoned["wkr-2"] {
		t.Fatal("drain did not cordon")
	}
}

func TestDrainDeleteSandboxesAndMigrate(t *testing.T) {
	h, f := standardFleet(t)
	f.owned["wkr-1"] = []string{"sb-wasm", "sb-box", "sb-gone"}
	f.runtimes = map[string]string{"sb-wasm": "wasm", "sb-box": "docker"}
	f.owned["srv-a"] = nil
	f.fail["DELETE /v1/sandboxes/sb-box"] = 1 // retried on the next poll
	// srv-a is a server and wkr-1 the drained node; old-1 is the only ready,
	// uncordoned, sandbox-capable target (an empty role reads as mixed).
	if code := h.run("drain", "wkr-1", "--migrate", "--delete-sandboxes", "--json"); code != exitOK {
		t.Fatalf("drain = %d %q", code, h.stderr.String())
	}
	var res struct {
		Drained  bool     `json:"drained"`
		Migrated []string `json:"migrated"`
		Deleted  []string `json:"deleted"`
	}
	h.jsonOut(&res)
	if !res.Drained || strings.Join(res.Migrated, ",") != "sb-wasm" || strings.Join(res.Deleted, ",") != "sb-gone,sb-box" {
		t.Fatalf("drain result = %+v", res)
	}
	if strings.Join(f.migrated, ",") != "sb-wasm->old-1" {
		t.Fatalf("migrated = %v", f.migrated)
	}
	if h.stderr.String() != "" {
		t.Fatalf("--json must keep progress notes off stderr: %q", h.stderr.String())
	}

	// No ready target for a WASM sandbox.
	f.owned["wkr-1"] = []string{"sb-w2"}
	f.runtimes["sb-w2"] = "wasm"
	f.cordoned["old-1"] = true
	if code := h.run("drain", "wkr-1", "--migrate"); code != exitError || !strings.Contains(h.stderr.String(), "no ready, uncordoned worker") {
		t.Fatalf("no target = %d %q", code, h.stderr.String())
	}
	// A failed migration is reported and the drain goes on; so is a
	// failed delete, which the next poll retries.
	delete(f.cordoned, "old-1")
	f.fail["POST /v1/cluster/wasm-migrate"] = 1
	f.fail["DELETE /v1/sandboxes/sb-w2"] = 1
	code := h.run("drain", "wkr-1", "--migrate", "--delete-sandboxes")
	if code != exitOK || !strings.Contains(h.stderr.String(), "migrating sandbox sb-w2 failed") ||
		!strings.Contains(h.stderr.String(), "deleting sandbox sb-w2 failed (retrying)") || !strings.Contains(h.stderr.String(), "deleted sandbox sb-w2") {
		t.Fatalf("failed migration = %d %q", code, h.stderr.String())
	}
}

func TestDrainFailures(t *testing.T) {
	h, f := standardFleet(t)
	f.running["srv-a"] = 1
	if code := h.run("drain", "srv-a", "--timeout", "30ms", "--json"); code != exitError {
		t.Fatalf("timeout = %d", code)
	}
	// The deadline may land between polls ("still has 1 sandbox(es)") or
	// during a node read on a loaded machine ("still has sandboxes"); both
	// are the same timeout.
	if e := h.errorEnvelope(); e.Code != agenttools.CodeTimeout || !strings.Contains(e.Message, "node srv-a still has") || !strings.Contains(e.Message, "after 30ms") {
		t.Fatalf("timeout envelope = %+v", e)
	}
	if !f.cordoned["srv-a"] {
		t.Fatal("a timed-out drain must leave the node cordoned")
	}
	for _, tc := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"drain", "ghost"}, exitError, `node "ghost" not found`},
		{[]string{"drain"}, exitUsage, "expected one node name"},
		{[]string{"drain", "a", "b"}, exitUsage, "expected one node name"},
		{[]string{"drain", "a", "--timeout", "-1s"}, exitUsage, "must not be negative"},
		{[]string{"drain", "a", "--nope"}, exitUsage, "nope"},
	} {
		if code := h.run(tc.args...); code != tc.code || !strings.Contains(h.stderr.String(), tc.want) {
			t.Fatalf("%v = %d %q", tc.args, code, h.stderr.String())
		}
	}
	f.fail["POST /v1/cluster/nodes/wkr-2/cordon"] = 1
	if code := h.run("drain", "wkr-2"); code != exitError {
		t.Fatalf("cordon failure = %d", code)
	}
	// The node read fails mid-wait for a reason that is not the deadline.
	f.running["wkr-2"] = 1
	f.mu.Lock()
	f.fail["GET /v1/cluster/nodes/wkr-2"] = 0
	f.mu.Unlock()
	go func() {
		time.Sleep(20 * time.Millisecond)
		f.mu.Lock()
		f.fail["GET /v1/cluster/nodes/wkr-2"] = 1000
		f.mu.Unlock()
	}()
	if code := h.run("drain", "wkr-2", "--timeout", "0"); code != exitError || !strings.Contains(h.stderr.String(), "boom") {
		t.Fatalf("read failure = %d %q", code, h.stderr.String())
	}
	f.mu.Lock()
	f.fail = map[string]int{}
	f.mu.Unlock()
	// The deadline passes during a node read.
	if err := drainTimeout("n", time.Second, -1); !strings.Contains(err.Error(), "still has sandboxes after 1s") {
		t.Fatalf("drainTimeout = %v", err)
	}
	// --migrate needs the node's sandbox list and the member list.
	f.fail["GET /v1/cluster/members"] = 1
	if code := h.run("drain", "wkr-2", "--migrate"); code != exitError {
		t.Fatalf("members failure during migrate = %d", code)
	}
}

func TestDeleteNodeVerb(t *testing.T) {
	h, f := standardFleet(t)
	if code := h.run("delete", "node", "wkr-2"); code != exitOK || h.stdout.String() != "node \"wkr-2\" deleted\n" {
		t.Fatalf("delete = %d %q %q", code, h.stdout.String(), h.stderr.String())
	}
	// Already gone is success: a retry never fails on its own success.
	if code := h.run("delete", "nodes", "wkr-2", "--json"); code != exitOK {
		t.Fatalf("repeat delete = %d %q", code, h.stderr.String())
	}
	var res map[string]any
	h.jsonOut(&res)
	if res["already_gone"] != true {
		t.Fatalf("repeat result = %+v", res)
	}
	if code := h.run("delete", "no", "old-1", "--force", "--json"); code != exitOK || !f.sawQuery("DELETE /v1/cluster/nodes/old-1?force=true") {
		t.Fatalf("force = %d %q", code, h.stderr.String())
	}
	f.busy["wkr-1"] = true
	if code := h.run("delete", "node", "wkr-1", "srv-a"); code != exitError || !strings.Contains(h.stdout.String(), `node "srv-a" deleted`) {
		t.Fatalf("partial delete = %d %q %q", code, h.stdout.String(), h.stderr.String())
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"delete"}, "expected a kind and a name"},
		{[]string{"delete", "pod", "box"}, `unknown kind "pod"`},
		{[]string{"delete", "node"}, "name at least one node"},
	} {
		if code := h.run(tc.args...); code != exitUsage || !strings.Contains(h.stderr.String(), tc.want) {
			t.Fatalf("%v = %d %q", tc.args, code, h.stderr.String())
		}
	}
}

func TestClusterInfo(t *testing.T) {
	h, f := standardFleet(t)
	if code := h.run("cluster-info"); code != exitOK {
		t.Fatal(h.stderr.String())
	}
	checkGoldenIn(t, "nodes", "cluster-info.golden", strings.ReplaceAll(h.transcript(exitOK), f.srv.URL, "URL"))
	if code := h.run("cluster-info", "--json"); code != exitOK {
		t.Fatal(h.stderr.String())
	}
	var info map[string]any
	h.jsonOut(&info)
	if info["leader"] != "srv-a" || info["members"] != float64(4) || info["voters"] != float64(1) || info["fsm_ops_version"] != float64(0) {
		t.Fatalf("info = %+v", info)
	}
	f.leader = ""
	if code := h.run("cluster-info"); code != exitOK || !strings.Contains(h.stdout.String(), "Cluster mode is off") {
		t.Fatalf("single node = %q", h.stdout.String())
	}
	for _, route := range []string{"GET /v1/cluster/leader", "GET /v1/cluster/members"} {
		f.fail[route] = 1
		if code := h.run("cluster-info"); code != exitError {
			t.Fatalf("%s failure = %d", route, code)
		}
	}
	if code := h.run("cluster-info", "extra"); code != exitUsage {
		t.Fatal("extra arg")
	}
	if code := h.run("cluster-info", "--nope"); code != exitUsage {
		t.Fatal("bad flag")
	}
	h.env["SB_API_URL"] = "http://127.0.0.1:1"
	if code := h.run("cluster-info"); code != exitError {
		t.Fatal("unreachable")
	}
	delete(h.env, "SB_PAT_TOKEN")
	delete(h.env, "SB_API_URL")
	h.env["XDG_CONFIG_HOME"] = t.TempDir()
	if code := h.run("cluster-info"); code != exitError || !strings.Contains(h.stderr.String(), "not logged in") {
		t.Fatalf("no login = %d %q", code, h.stderr.String())
	}
}

func TestVersionServerIsOptIn(t *testing.T) {
	h, f := standardFleet(t)
	// Plain version never asks the server (TestVersionOutputUnchanged pins
	// its exact output).
	if code := h.run("version"); code != exitOK || h.stdout.String() != versionString()+"\n" || len(f.queries) != 0 {
		t.Fatalf("plain version = %d %q (queries %v)", code, h.stdout.String(), f.queries)
	}
	if code := h.run("version", "--server"); code != exitOK || h.stdout.String() != "Client Version: "+versionString()+"\nServer Version: v9.9.9\n" {
		t.Fatalf("--server = %d %q %q", code, h.stdout.String(), h.stderr.String())
	}
	for _, args := range [][]string{{"version", "-o", "json"}, {"version", "--server", "--json"}, {"version", "--output", "json"}} {
		if code := h.run(args...); code != exitOK {
			t.Fatalf("%v = %d %q", args, code, h.stderr.String())
		}
		var v map[string]string
		h.jsonOut(&v)
		if len(v) != 2 || v["client"] != versionString() || v["server"] != "v9.9.9" {
			t.Fatalf("%v = %+v", args, v)
		}
	}
	if code := h.run("version", "-o", "yaml"); code != exitUsage || !strings.Contains(h.stderr.String(), "-o must be json") {
		t.Fatalf("-o yaml = %d %q", code, h.stderr.String())
	}
	if code := h.run("version", "--nope"); code != exitUsage {
		t.Fatal("bad flag")
	}
	// Asked for and unreachable: the client's half, the error, exit 1.
	h.env["SB_API_URL"] = "http://127.0.0.1:1"
	if code := h.run("version", "--server"); code != exitError || h.stdout.String() != "Client Version: "+versionString()+"\n" || h.stderr.String() == "" {
		t.Fatalf("unreachable --server = %d %q %q", code, h.stdout.String(), h.stderr.String())
	}
	if code := h.run("version", "-o", "json"); code != exitError {
		t.Fatalf("unreachable -o json = %d", code)
	}
	var v map[string]string
	h.jsonOut(&v)
	if len(v) != 1 || v["client"] != versionString() {
		t.Fatalf("unreachable -o json = %+v", v)
	}
	// No login: the same, and plain version still works.
	delete(h.env, "SB_PAT_TOKEN")
	delete(h.env, "SB_API_URL")
	h.env["XDG_CONFIG_HOME"] = t.TempDir()
	if code := h.run("version", "--server"); code != exitError || !strings.Contains(h.stderr.String(), "not logged in") {
		t.Fatalf("no login --server = %d %q", code, h.stderr.String())
	}
	if code := h.run("version"); code != exitOK || h.stderr.String() != "" {
		t.Fatalf("no login plain = %d %q", code, h.stderr.String())
	}
}

func TestNodeHelpers(t *testing.T) {
	if got := percent(1, 0, true); got != "-" {
		t.Fatalf("percent with no budget = %q", got)
	}
	if got := nodeNotFound(fmt.Errorf("plain"), "x"); got.Error() != "plain" {
		t.Fatalf("non-404 changed: %v", got)
	}
	if _, ok := outputFormat(&commonFlags{}, "", "json"); !ok {
		t.Fatal("no -o is fine")
	}
	if idsIf(false) != 0 || idsIf(true) != nodeSandboxIDPage {
		t.Fatal("idsIf")
	}
	if kind, ok := lookupKind("NODES"); !ok || kind != kindNode {
		t.Fatal("kinds are case-insensitive")
	}
}

func TestDrainEdges(t *testing.T) {
	h, f := standardFleet(t)
	// The default poll interval: a node already empty never waits on it.
	h.app.pollEvery = 0
	if code := h.run("drain", "old-1"); code != exitOK || !strings.HasSuffix(h.stdout.String(), "node/old-1 drained\n") {
		t.Fatalf("empty node = %d %q %q", code, h.stdout.String(), h.stderr.String())
	}
	h.app.pollEvery = time.Millisecond
	// The deadline passes while a node read is in flight.
	f.running["srv-a"] = 1
	f.slowNodeGet = 200 * time.Millisecond
	if code := h.run("drain", "srv-a", "--timeout", "50ms", "--json"); code != exitError || h.errorEnvelope().Code != agenttools.CodeTimeout {
		t.Fatalf("deadline mid-read = %d %q", code, h.stderr.String())
	}
	f.mu.Lock()
	f.slowNodeGet = 0
	f.mu.Unlock()
	// --migrate re-reads the node for its sandbox list; that read can fail.
	f.calls["GET /v1/cluster/nodes/wkr-2"] = 0
	f.failOnCall["GET /v1/cluster/nodes/wkr-2"] = 2
	if code := h.run("drain", "wkr-2", "--migrate"); code != exitError || !strings.Contains(h.stderr.String(), "boom") {
		t.Fatalf("migrate read failure = %d %q", code, h.stderr.String())
	}
	// No login: the cluster call says so.
	delete(h.env, "SB_PAT_TOKEN")
	delete(h.env, "SB_API_URL")
	h.env["XDG_CONFIG_HOME"] = t.TempDir()
	if code := h.run("get", "nodes"); code != exitError || !strings.Contains(h.stderr.String(), "not logged in") {
		t.Fatalf("no login = %d %q", code, h.stderr.String())
	}
}

// A read survives one dropped connection or a 503: GETs are safe to repeat,
// and one reset from a load balancer failed a live describe (UC-612). A
// write is never retried by the CLI, and a 500 is final.
func TestClusterReadsRetryTransientFailures(t *testing.T) {
	old := clusterReadRetryDelays
	clusterReadRetryDelays = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	t.Cleanup(func() { clusterReadRetryDelays = old })

	h, f := standardFleet(t)
	f.dropOnCall["GET /v1/cluster/nodes/wkr-1"] = 1
	if code := h.run("describe", "node", "wkr-1"); code != exitOK {
		t.Fatalf("describe after one reset = %d: %s", code, h.stderr.String())
	}
	f.status503["GET /v1/cluster/members"] = 2
	if code := h.run("get", "nodes"); code != exitOK {
		t.Fatalf("get nodes after two 503s = %d: %s", code, h.stderr.String())
	}
	f.status503["GET /v1/cluster/members"] = 4
	if code := h.run("get", "nodes"); code == exitOK {
		t.Fatal("get nodes after four 503s succeeded, want the retries to give up")
	}
	f.fail["GET /v1/cluster/members"] = 1
	before := f.calls["GET /v1/cluster/members"]
	if code := h.run("get", "nodes"); code == exitOK || f.calls["GET /v1/cluster/members"] != before+1 {
		t.Fatalf("a 500 was retried: code %d, calls %d -> %d", code, before, f.calls["GET /v1/cluster/members"])
	}
	// A delete is idempotent, so a dropped connection is retried (live
	// UC-614: a Caddy reload dropped one in flight).
	f.dropOnCall["DELETE /v1/cluster/nodes/wkr-2"] = 1
	if code := h.run("delete", "node", "wkr-2"); code != exitOK || f.calls["DELETE /v1/cluster/nodes/wkr-2"] != 2 {
		t.Fatalf("delete after one reset = %d (calls %d): %s", code, f.calls["DELETE /v1/cluster/nodes/wkr-2"], h.stderr.String())
	}
	f.status503["POST /v1/cluster/nodes/wkr-1/cordon"] = 1
	before = f.calls["POST /v1/cluster/nodes/wkr-1/cordon"]
	if code := h.run("cordon", "wkr-1"); code == exitOK || f.calls["POST /v1/cluster/nodes/wkr-1/cordon"] != before+1 {
		t.Fatalf("a write was retried: code %d, calls %d -> %d", code, before, f.calls["POST /v1/cluster/nodes/wkr-1/cordon"])
	}
}

// A drain that times out says how many sandboxes are left when it knows,
// and only that some are when its last read failed.
func TestDrainTimeoutMessage(t *testing.T) {
	if got := drainTimeout("wkr-1", time.Minute, 3).Error(); !strings.Contains(got, "node wkr-1 still has 3 sandbox(es) after 1m0s") {
		t.Fatalf("known count = %q", got)
	}
	if got := drainTimeout("wkr-1", time.Minute, -1).Error(); !strings.Contains(got, "node wkr-1 still has sandboxes after 1m0s") {
		t.Fatalf("unknown count = %q", got)
	}
}
