package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/agenttools/agenttoolstest"
	"github.com/aerol-ai/microvm/pkg/release"
	"github.com/aerol-ai/microvm/pkg/upgradewire"
)

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// fakeReleases serves <base>/<version>/<asset> like GitHub's release
// download URLs.
type fakeReleases struct {
	srv *httptest.Server
	mu  sync.Mutex
	// files: version -> asset -> body.
	files map[string]map[string][]byte
	// lie serves other bytes for "version/asset" than checksums.txt says.
	lie map[string]bool
	// fail answers "version/asset" 500, a broken mirror rather than a
	// missing file.
	fail map[string]bool
	gets []string
}

func newFakeReleases(t *testing.T) *fakeReleases {
	f := &fakeReleases{files: map[string]map[string][]byte{}, lie: map[string]bool{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.gets = append(f.gets, r.URL.Path)
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/releases/"), "/")
		if len(parts) != 2 {
			http.NotFound(w, r)
			return
		}
		if f.fail[parts[0]+"/"+parts[1]] {
			http.Error(w, "mirror broken", http.StatusInternalServerError)
			return
		}
		body, ok := f.files[parts[0]][parts[1]]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if f.lie[parts[0]+"/"+parts[1]] {
			body = append([]byte("tampered "), body...)
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeReleases) base() string { return f.srv.URL + "/releases" }

// releaseMeta is a valid release.json for version.
func releaseMeta(version, from string, hostSetup string, gateway []int, oneWay ...int) *release.Metadata {
	if oneWay == nil {
		oneWay = []int{}
	}
	return &release.Metadata{Version: version, UpgradeFromMin: from, OneWayMigrations: oneWay,
		HostSetupSHA256: sha([]byte(hostSetup)), EgressGatewayProtocol: gateway, FSMOpsVersion: 13}
}

// releaseFiles is a release's assets for arches, with release.json when
// meta is given: the files an upgrade carries, plus ones it must ignore.
func releaseFiles(version string, meta *release.Metadata, arches ...string) map[string][]byte {
	files := map[string][]byte{
		"install.sh":             []byte("#!/bin/sh\n# install " + version + "\n"),
		"toolboxd_freebsd_amd64": []byte("toolboxd freebsd " + version),
		"toolboxd_darwin_arm64":  []byte("toolboxd darwin " + version),
		"aerolvm_linux_amd64":    []byte("aerolvm " + version),
	}
	for _, a := range arches {
		for _, role := range []string{"sandboxd", "toolboxd", "caddy"} {
			files[role+"_linux_"+a] = []byte(role + " " + version + " " + a + "\n")
		}
	}
	if meta != nil {
		raw, err := release.Marshal(*meta)
		if err != nil {
			panic(err)
		}
		files[release.FileName] = raw
	}
	// release.yml also ships each asset under a tagged name.
	for name, body := range files {
		files[version+"_"+name] = body
	}
	return files
}

func checksumsFor(files map[string][]byte) []byte {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		fmt.Fprintf(&b, "%s  %s\n", sha(files[n]), n)
	}
	return []byte(b.String())
}

// publish adds a release: its files, checksums.txt over them, and the
// provenance file (which checksums.txt can't name).
func (f *fakeReleases) publish(version string, files map[string][]byte, provenance bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string][]byte{}
	for n, b := range files {
		out[n] = b
	}
	out[checksumsName] = checksumsFor(files)
	if provenance {
		out[version+".intoto.jsonl"] = []byte(`{"payloadType":"application/vnd.in-toto+json"}` + "\n")
	}
	f.files[version] = out
}

// fakeUpgrade plays sandboxd's upgrade routes: the single-node ones or the
// cluster ones, following pkg/upgradewire and the §6.6 command table.
type fakeUpgrade struct {
	t   *testing.T
	srv *httptest.Server

	mu       sync.Mutex
	cluster  bool
	running  string
	members  []map[string]any
	files    map[string][]byte
	calls    []string
	noRoutes bool
	now      time.Time

	// Single node.
	remoteOff  bool
	ops        []upgradewire.NodeUpgradeResponse
	opSteps    []string
	opStep     int
	failWith   string
	dropOnStep string // answer one GET 502 at this step (sandboxd restarting)
	dropped    bool
	nodeReqs   []upgradewire.NodeUpgradeRequest

	// sandboxPages answers GET /v1/sandboxes, one page per call, with
	// X-Cluster-List-Next-Page-Token pointing at the next; nil answers 404.
	sandboxPages [][]map[string]any

	// Cluster.
	rollout *upgradewire.Rollout
	advance bool
	// onGet changes the rollout before a GET answers it.
	onGet func(*upgradewire.Rollout)
	// failRolloutGets answers this many reads of a rollout 503, as the
	// API does while a server restarts.
	failRolloutGets int
	// membershipRolloutGets answers this many reads of a rollout with the
	// leader's plain-text 403 "cluster peer not in membership", as a
	// leader that just restarted does until gossip catches up.
	membershipRolloutGets int
	applyReqs             []upgradewire.ApplyRequest
	manual                map[string]bool
	nextID                int
}

func newFakeUpgrade(t *testing.T, cluster bool, running string) *fakeUpgrade {
	f := &fakeUpgrade{t: t, cluster: cluster, running: running, files: map[string][]byte{}, manual: map[string]bool{},
		now: time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC), opSteps: []string{"staging", "swapping", "starting"}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeUpgrade) tick() time.Time {
	f.now = f.now.Add(time.Second)
	return f.now
}

func (f *fakeUpgrade) refuse(w http.ResponseWriter, status int, code, reason, hint string, nodes ...string) {
	writeFakeJSON(w, status, upgradewire.ErrorResponse{Error: code, Reason: reason, Hint: hint, Nodes: nodes})
}

func (f *fakeUpgrade) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	if r.URL.Path == "/health" {
		h := map[string]any{"status": "ok", "version": f.running}
		if f.cluster {
			h["cluster_topology"] = "ok"
			h["cluster_nodes"] = len(f.members)
		}
		writeFakeJSON(w, http.StatusOK, h)
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+agenttoolstest.Token {
		writeFakeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	path := r.URL.Path
	if f.noRoutes && strings.Contains(path, "upgrade") {
		http.NotFound(w, r)
		return
	}
	switch {
	case path == "/v1/cluster/members":
		writeFakeJSON(w, http.StatusOK, map[string]any{"members": f.members})
	case path == "/v1/sandboxes" && f.sandboxPages != nil:
		page, _ := strconv.Atoi(r.URL.Query().Get("page_token"))
		if page >= len(f.sandboxPages) {
			writeFakeJSON(w, http.StatusOK, []any{})
			return
		}
		if page+1 < len(f.sandboxPages) {
			w.Header().Set("X-Cluster-List-Next-Page-Token", strconv.Itoa(page+1))
		}
		writeFakeJSON(w, http.StatusOK, f.sandboxPages[page])
	case strings.HasPrefix(path, upgradewire.NodeUpgradeFilesPath+"/"):
		if f.cluster {
			f.refuse(w, http.StatusConflict, upgradewire.ErrCodeClusterMode, "this node runs in a cluster", "aerolvm upgrade apply <version>")
			return
		}
		f.serveFile(w, r, strings.TrimPrefix(path, upgradewire.NodeUpgradeFilesPath+"/"))
	case strings.HasPrefix(path, upgradewire.ClusterUpgradeFilesPath+"/"):
		f.serveFile(w, r, strings.TrimPrefix(path, upgradewire.ClusterUpgradeFilesPath+"/"))
	case path == upgradewire.NodeUpgradePath:
		if f.cluster {
			f.refuse(w, http.StatusConflict, upgradewire.ErrCodeClusterMode, "this node runs in a cluster", "aerolvm upgrade apply <version>")
			return
		}
		if r.Method == http.MethodPost {
			f.nodeStart(w, r)
			return
		}
		f.nodeStatus(w, r)
	case strings.HasPrefix(path, upgradewire.ClusterUpgradePath):
		if !f.cluster {
			f.refuse(w, http.StatusConflict, upgradewire.ErrCodeNotClusterMode, "this sandboxd is a single node", "")
			return
		}
		f.serveRollout(w, r, path)
	default:
		writeFakeJSON(w, http.StatusNotFound, map[string]string{"error": "no route"})
	}
}

func (f *fakeUpgrade) serveFile(w http.ResponseWriter, r *http.Request, sum string) {
	switch r.Method {
	case http.MethodHead:
		if _, ok := f.files[sum]; ok {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	case http.MethodPut:
		body, _ := io.ReadAll(r.Body)
		if r.ContentLength != int64(len(body)) {
			f.refuse(w, http.StatusBadRequest, "invalid_request", "length mismatch", "")
			return
		}
		if sha(body) != sum {
			f.refuse(w, http.StatusBadRequest, upgradewire.ErrCodeHashMismatch, "file does not match its SHA-256", "")
			return
		}
		if _, ok := f.files[sum]; ok {
			writeFakeJSON(w, http.StatusOK, map[string]any{"sha256": sum, "size": len(body)})
			return
		}
		f.files[sum] = body
		writeFakeJSON(w, http.StatusCreated, map[string]any{"sha256": sum, "size": len(body)})
	}
}

// --- single node ---------------------------------------------------------

func (f *fakeUpgrade) latest() *upgradewire.NodeUpgradeResponse {
	if len(f.ops) == 0 {
		return nil
	}
	return &f.ops[len(f.ops)-1]
}

func (f *fakeUpgrade) nodeStart(w http.ResponseWriter, r *http.Request) {
	if f.remoteOff {
		f.refuse(w, http.StatusForbidden, upgradewire.ErrCodeRemoteUpgradeDisabled, "SB_REMOTE_UPGRADE is off on this node", "on the node: sudo sandboxd upgrade node <version> --sha256 <file>=<hash>...")
		return
	}
	var req upgradewire.NodeUpgradeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		f.refuse(w, http.StatusBadRequest, "invalid_request", err.Error(), "")
		return
	}
	f.nodeReqs = append(f.nodeReqs, req)
	if req.Source == upgradewire.SourceUpload {
		var missing []string
		for name, sum := range req.Files {
			if _, ok := f.files[sum]; !ok {
				missing = append(missing, name)
			}
		}
		if len(missing) > 0 {
			sort.Strings(missing)
			f.refuse(w, http.StatusConflict, upgradewire.ErrCodeFilesMissing, "these files were not uploaded: "+strings.Join(missing, ", "), "")
			return
		}
	}
	if l := f.latest(); l != nil && l.State != upgradewire.NodeOpDone && l.State != upgradewire.NodeOpFailed {
		if l.Version == req.Version {
			writeFakeJSON(w, http.StatusAccepted, l)
			return
		}
		f.refuse(w, http.StatusConflict, upgradewire.ErrCodeUpgradeRunning, "upgrade "+l.Op+" is running", "aerolvm upgrade status")
		return
	}
	if req.Version == f.running {
		writeFakeJSON(w, http.StatusOK, upgradewire.NodeUpgradeResponse{State: upgradewire.NodeOpDone, Version: f.running, From: f.running, StartedAt: f.now, UpdatedAt: f.now})
		return
	}
	now := f.tick()
	op := upgradewire.NodeUpgradeResponse{Op: fmt.Sprintf("op-%d", len(f.ops)+1), State: upgradewire.NodeOpPending, Version: req.Version,
		From: f.running, Rollback: req.Rollback, StartedAt: now, UpdatedAt: now}
	f.ops = append(f.ops, op)
	f.opStep = 0
	f.dropped = false
	writeFakeJSON(w, http.StatusAccepted, op)
}

// nodeStatus answers the latest op; each read moves it one phase on.
func (f *fakeUpgrade) nodeStatus(w http.ResponseWriter, r *http.Request) {
	l := f.latest()
	if l == nil {
		f.refuse(w, http.StatusNotFound, "not_found", "no upgrade has run on this node", "")
		return
	}
	if l.State != upgradewire.NodeOpDone && l.State != upgradewire.NodeOpFailed {
		if f.dropOnStep != "" && l.State == f.dropOnStep && !f.dropped {
			// sandboxd is down: Caddy in front of it answers 502.
			f.dropped = true
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		l.UpdatedAt = f.tick()
		switch {
		case f.opStep < len(f.opSteps):
			l.State = f.opSteps[f.opStep]
			f.opStep++
		case f.failWith != "":
			l.State, l.Error = upgradewire.NodeOpFailed, f.failWith
		default:
			l.State = upgradewire.NodeOpDone
			f.running = l.Version
		}
	}
	writeFakeJSON(w, http.StatusOK, l)
}

// --- cluster -------------------------------------------------------------

func (f *fakeUpgrade) newRollout(req upgradewire.ApplyRequest, caller string) *upgradewire.Rollout {
	f.nextID++
	now := f.tick()
	batch := req.Batch
	if batch == "" {
		batch = "10%"
	}
	ro := &upgradewire.Rollout{ID: fmt.Sprintf("r-%d", f.nextID), State: upgradewire.StateStaging, Direction: upgradewire.DirectionUpgrade,
		TargetVersion: req.Version, PreviousVersion: f.running, Source: req.Source, Caller: caller, Hold: req.Hold, Batch: batch,
		PauseAfter: req.PauseAfter, NodeTimeout: req.NodeTimeout, AllowDowntime: req.AllowDowntime, CreatedAt: now, UpdatedAt: now,
		ActiveVersion: f.running}
	order := 0
	for _, m := range f.members {
		id, _ := m["node_id"].(string)
		role, _ := m["role"].(string)
		version, _ := m["version"].(string)
		alive, _ := m["alive"].(bool)
		order++
		n := upgradewire.RolloutNode{NodeID: id, Role: role, Arch: "amd64", State: upgradewire.NodePending, Version: version, Order: order, UpdatedAt: now}
		if role == "worker" {
			n.Batch = 1
		}
		switch {
		case !alive:
			n.State, n.Error = upgradewire.NodeSkipped, "down when its turn came"
		case f.manual[id]:
			n.State, n.Error = upgradewire.NodeManual, "remote upgrade is off"
			n.ManualCommand = "sudo sandboxd upgrade node " + req.Version + " --sha256 sandboxd_linux_amd64=" + req.Files["sandboxd_linux_amd64"]
		}
		ro.Nodes = append(ro.Nodes, n)
	}
	return ro
}

func (f *fakeUpgrade) step() {
	ro := f.rollout
	if ro == nil || !f.advance {
		return
	}
	ro.UpdatedAt = f.tick()
	switch ro.State {
	case upgradewire.StateStaging:
		for i := range ro.Nodes {
			if ro.Nodes[i].State == upgradewire.NodePending {
				ro.Nodes[i].State = upgradewire.NodeStaged
			}
		}
		ro.State = upgradewire.StateRunning
	case upgradewire.StateRunning:
		doneWorkers := 0
		for i := range ro.Nodes {
			n := &ro.Nodes[i]
			switch n.State {
			case upgradewire.NodeUpgrading:
				n.State, n.Version = upgradewire.NodeDone, ro.TargetVersion
				if n.Role == "worker" {
					doneWorkers++
				}
				if ro.PauseAfter > 0 && n.Role == "worker" && countDone(ro, "worker") == ro.PauseAfter {
					ro.State = upgradewire.StatePaused
					ro.PauseAfter = -ro.PauseAfter // once per rollout
				}
				return
			case upgradewire.NodeStaged:
				n.State = upgradewire.NodeUpgrading
				return
			}
		}
		ro.State = upgradewire.StateDone
	case upgradewire.StateDone:
		if !ro.Hold {
			ro.State = upgradewire.StateFinalizing
		}
	case upgradewire.StateFinalizing:
		ro.State, ro.ActiveVersion = upgradewire.StateFinalized, ro.TargetVersion
	case upgradewire.StateRollingBack:
		for i := len(ro.Nodes) - 1; i >= 0; i-- {
			n := &ro.Nodes[i]
			if n.Version != ro.TargetVersion && n.State != upgradewire.NodeSkipped {
				n.Version, n.State = ro.TargetVersion, upgradewire.NodeDone
				return
			}
		}
		ro.State = upgradewire.StateRolledBack
	}
}

func countDone(ro *upgradewire.Rollout, role string) int {
	n := 0
	for _, x := range ro.Nodes {
		if x.Role == role && x.State == upgradewire.NodeDone {
			n++
		}
	}
	return n
}

func (f *fakeUpgrade) conflict(w http.ResponseWriter, why, hint string) {
	f.refuse(w, http.StatusConflict, upgradewire.ErrCodeRolloutConflict, why, hint)
}

func (f *fakeUpgrade) serveRollout(w http.ResponseWriter, r *http.Request, path string) {
	ro := f.rollout
	if path == upgradewire.ClusterUpgradePath && r.Method == http.MethodGet {
		if ro == nil {
			f.refuse(w, http.StatusNotFound, "not_found", "no rollout has run on this cluster", "")
			return
		}
		if f.failRolloutGets > 0 {
			f.failRolloutGets--
			writeFakeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "restarting"})
			return
		}
		if f.membershipRolloutGets > 0 {
			f.membershipRolloutGets--
			http.Error(w, "cluster peer not in membership", http.StatusForbidden)
			return
		}
		f.step()
		if f.onGet != nil {
			f.onGet(ro)
		}
		writeFakeJSON(w, http.StatusOK, ro)
		return
	}
	if r.Method != http.MethodPost {
		writeFakeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method"})
		return
	}
	state := ""
	if ro != nil {
		state = ro.State
	}
	switch path {
	case upgradewire.ClusterUpgradePath:
		var req upgradewire.ApplyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			f.refuse(w, http.StatusBadRequest, "invalid_request", err.Error(), "")
			return
		}
		f.applyReqs = append(f.applyReqs, req)
		if req.Source == upgradewire.SourceUpload {
			for name, sum := range req.Files {
				if _, ok := f.files[sum]; !ok {
					f.refuse(w, http.StatusConflict, upgradewire.ErrCodeFilesMissing, "the leader lacks "+name, "")
					return
				}
			}
		}
		same := ro != nil && ro.TargetVersion == req.Version && ro.Direction == upgradewire.DirectionUpgrade
		switch {
		case same && (state == upgradewire.StateStaging || state == upgradewire.StateRunning || state == upgradewire.StatePaused ||
			state == upgradewire.StateDone || state == upgradewire.StateFinalizing || state == upgradewire.StateFinalized):
			writeFakeJSON(w, http.StatusOK, ro)
		case same && (state == upgradewire.StateFailed || state == upgradewire.StateStopped):
			ro.State = upgradewire.StateStaging
			writeFakeJSON(w, http.StatusOK, ro)
		case state == upgradewire.StateRollingBack:
			f.conflict(w, "a rollback is running; wait for it to end", "aerolvm upgrade status")
		case ro == nil || state == upgradewire.StateFinalized || state == upgradewire.StateRolledBack:
			f.rollout = f.newRollout(req, "operator")
			writeFakeJSON(w, http.StatusCreated, f.rollout)
		default:
			f.conflict(w, fmt.Sprintf("rollout %s to %s is %s", ro.ID, ro.TargetVersion, state), "finalize or roll back first: aerolvm upgrade finalize")
		}
		return
	}
	if ro == nil {
		f.refuse(w, http.StatusNotFound, "not_found", "no rollout has run on this cluster", "")
		return
	}
	switch path {
	case upgradewire.ClusterUpgradeStopPath:
		switch state {
		case upgradewire.StateStaging, upgradewire.StateRunning, upgradewire.StatePaused:
			ro.State = upgradewire.StateStopped
		case upgradewire.StateStopped:
		default:
			f.conflict(w, "rollout "+ro.ID+" is "+state+"; there is nothing to stop", "")
			return
		}
	case upgradewire.ClusterUpgradeResumePath:
		switch state {
		case upgradewire.StatePaused:
			ro.State = upgradewire.StateRunning
		case upgradewire.StateRunning:
		default:
			f.conflict(w, "rollout "+ro.ID+" is "+state, "run the same apply again: aerolvm upgrade apply "+ro.TargetVersion)
			return
		}
	case upgradewire.ClusterUpgradeFinalizePath:
		switch state {
		case upgradewire.StateDone:
			var skipped []string
			for _, n := range ro.Nodes {
				if n.State == upgradewire.NodeSkipped {
					skipped = append(skipped, n.NodeID)
				}
			}
			if len(skipped) > 0 {
				f.refuse(w, http.StatusConflict, upgradewire.ErrCodeSkippedNodes, "skipped nodes must be upgraded or deleted first",
					"aerolvm delete node <name>", skipped...)
				return
			}
			ro.State = upgradewire.StateFinalizing
		case upgradewire.StateFinalizing, upgradewire.StateFinalized:
		default:
			f.conflict(w, "rollout "+ro.ID+" is "+state+"; finalize needs it done", "")
			return
		}
	case upgradewire.ClusterUpgradeRollbackPath:
		switch {
		case state == upgradewire.StateDone || state == upgradewire.StateFailed || state == upgradewire.StateStopped || state == upgradewire.StatePaused:
			if ro.Direction == upgradewire.DirectionUpgrade {
				ro.Direction = upgradewire.DirectionRollback
				ro.TargetVersion, ro.PreviousVersion = ro.PreviousVersion, ro.TargetVersion
			}
			ro.State = upgradewire.StateRollingBack
		case state == upgradewire.StateRollingBack || state == upgradewire.StateRolledBack:
		default:
			f.conflict(w, "rollout "+ro.ID+" is "+state+"; after finalize there is no rollback", "")
			return
		}
	default:
		writeFakeJSON(w, http.StatusNotFound, map[string]string{"error": "no route"})
		return
	}
	ro.UpdatedAt = f.tick()
	writeFakeJSON(w, http.StatusOK, ro)
}

func (f *fakeUpgrade) sawCall(call string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if c == call {
			n++
		}
	}
	return n
}

// upgradeHarness is a CLI harness pointed at f.
func upgradeHarness(t *testing.T, f *fakeUpgrade) *harness {
	h := newHarness(t)
	h.env["SB_API_URL"] = f.srv.URL
	// make test stays offline: a test that forgets a release server
	// fails here instead of reaching GitHub.
	h.env["AEROLVM_RELEASE_URL"] = "http://127.0.0.1:1/releases"
	h.app.pollEvery = time.Millisecond
	return h
}

// stdFleet is a leader, a second server, an ingress node and three
// workers, all on from.
func stdFleet(f *fakeUpgrade, from string) {
	f.members = []map[string]any{
		{"node_id": "srv-a", "role": "server", "alive": true, "version": from, "voter": true, "leader": true},
		{"node_id": "srv-b", "role": "server", "alive": true, "version": from, "voter": true},
		{"node_id": "srv-c", "role": "server", "alive": true, "version": from, "voter": true},
		{"node_id": "ing-1", "role": "ingress", "alive": true, "version": from},
		{"node_id": "wkr-1", "role": "worker", "alive": true, "version": from},
		{"node_id": "wkr-2", "role": "worker", "alive": true, "version": from},
		{"node_id": "wkr-3", "role": "worker", "alive": true, "version": from},
	}
}
