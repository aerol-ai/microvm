//go:build integration

package suite

// Helpers for the cluster-correctness fault cases (z_cluster_chaos_test.go,
// UC-470..UC-479, plans/cluster-correctness-and-create-latency.md §3.2).
//
// Three rules shape them:
//
//   - Observe from the side that is not under test. During a partition the
//     API domain may sit on the cut-off side (UC-470 puts the ingress there
//     on purpose), so the authoritative view is read on a server's own
//     loopback through an SSH tunnel (chaosAPI).
//   - The runtime is the truth. "Two copies" and "came back" are answered by
//     asking every worker's container engine over SSH (harness
//     RuntimeCensusScript), not the API, which only knows what sandboxd
//     believes. A census that failed is unknown, never "none".
//   - Every fault is undone by a cleanup, armed before the fault, plus a
//     dead-man on the node for the ones the harness could lose control of
//     (partitions, netem).

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

// --- knobs --------------------------------------------------------------

func chaosSeconds(name string, def int) time.Duration {
	return time.Duration(envInt(name, def)) * time.Second
}

func chaosFloat(name string, def float64) float64 {
	if v, err := strconv.ParseFloat(strings.TrimSpace(os.Getenv(name)), 64); err == nil && v > 0 {
		return v
	}
	return def
}

func chaosString(name, def string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return def
}

// chaosSmallSize is what the bulk cases' sandboxes ask for: small enough that
// a t3.medium worker (18 CPU of budget: 2 cores x 0.9 x 10 overprovision)
// holds about 70, so 200 creates fit on three workers.
func chaosSmallSize() (float64, int) {
	return chaosFloat("AEROL_CHAOS_SANDBOX_CPU", 0.25), envInt("AEROL_CHAOS_SANDBOX_MEMORY_MB", 128)
}

// chaosReservationTTL is how long the leader lets an unpromoted reservation
// hold capacity before its GC sweep cancels it (internal/cluster opReserve
// ExpiresUnix).
const chaosReservationTTL = 120 * time.Second

// --- topology -------------------------------------------------------------

type chaosTopo struct {
	targets   *harness.IntegrationTargets
	servers   []harness.IntegrationNode
	workers   []harness.IntegrationNode
	ingresses []harness.IntegrationNode
}

// chaosTopology splits the fleet by role and skips unless it is the
// role-separated shape the cases need, with SSH to every node.
func chaosTopology(t *testing.T) chaosTopo {
	t.Helper()
	targets := harness.LoadIntegrationTargets()
	if targets == nil || len(targets.Nodes) == 0 {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	tp := chaosTopo{targets: targets}
	for _, n := range targets.Nodes {
		switch strings.ToLower(strings.TrimSpace(n.Role)) {
		case "server":
			tp.servers = append(tp.servers, n)
		case "worker":
			tp.workers = append(tp.workers, n)
		case "ingress":
			tp.ingresses = append(tp.ingresses, n)
		}
	}
	if len(tp.servers) < 3 || len(tp.workers) < 2 || len(tp.ingresses) < 1 {
		t.Skipf("needs the role-separated cluster-chaos topology (>=3 servers, >=2 workers, >=1 ingress), have %d/%d/%d",
			len(tp.servers), len(tp.workers), len(tp.ingresses))
	}
	for _, n := range targets.Nodes {
		harness.RequireNodeSSH(t, n)
	}
	return tp
}

func (tp chaosTopo) all() []harness.IntegrationNode { return tp.targets.Nodes }

// chaosExcept is nodes without drop (matched by name).
func chaosExcept(nodes []harness.IntegrationNode, drop ...harness.IntegrationNode) []harness.IntegrationNode {
	var out []harness.IntegrationNode
	for _, n := range nodes {
		keep := true
		for _, d := range drop {
			if n.Name == d.Name {
				keep = false
				break
			}
		}
		if keep {
			out = append(out, n)
		}
	}
	return out
}

func chaosNames(nodes []harness.IntegrationNode) []string {
	out := make([]string, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, n.Name)
	}
	return out
}

// chaosAddrs is every address the nodes have, private and public: a
// partition that blocked only private addresses would leave any path that
// goes through a public one (the API domain, an advertised URL) open.
func chaosAddrs(nodes []harness.IntegrationNode) []string {
	var out []string
	for _, n := range nodes {
		for _, ip := range []string{n.PrivateIP, n.PublicIP} {
			if ip = strings.TrimSpace(ip); ip != "" {
				out = append(out, ip)
			}
		}
	}
	return out
}

// chaosAPI is an operator client on node's own loopback listener, through
// an SSH tunnel: it reaches that node whatever the partition does to the
// API domain.
func chaosAPI(t *testing.T, node harness.IntegrationNode) *harness.APIClient {
	t.Helper()
	return harness.NewAPIClient(nodeBase(t, node), sc.OperatorPAT)
}

// chaosNodeIDs maps every node's Terraform name to its cluster node id. Read
// once, before any fault, through api.
func chaosNodeIDs(t *testing.T, api *harness.APIClient, tp chaosTopo) map[string]string {
	t.Helper()
	resp := statusAs(t, api, http.MethodGet, "/v1/cluster/members", nil)
	var cv capacityView
	if resp.Status != http.StatusOK || resp.JSON(&cv) != nil {
		t.Fatalf("read members: %s", resp)
	}
	out := map[string]string{}
	for _, n := range tp.all() {
		for _, m := range cv.Members {
			if m.NodeID == n.Name || strings.HasSuffix(m.NodeID, "-"+n.Name) ||
				m.NodeName == n.Name || strings.HasSuffix(m.NodeName, "-"+n.Name) {
				out[n.Name] = m.NodeID
			}
		}
		if out[n.Name] == "" {
			t.Fatalf("%s is not in the member list; the fleet is not whole, so no fault can be read against it", n.Name)
		}
	}
	return out
}

// chaosNodeByID maps a cluster node id back to the node.
func chaosNodeByID(tp chaosTopo, ids map[string]string, id string) (harness.IntegrationNode, bool) {
	for _, n := range tp.all() {
		if ids[n.Name] == id {
			return n, true
		}
	}
	return harness.IntegrationNode{}, false
}

// --- the API ----------------------------------------------------------------

type chaosPlacementView struct {
	Owner struct {
		NodeID string `json:"node_id"`
	} `json:"owner"`
	Orphaned   bool   `json:"orphaned"`
	OwnerState string `json:"owner_state"`
	Version    uint64 `json:"placement_version"`
}

// chaosPlacement reads one placement. found is false on a 404 ("no
// placement record"); an error is anything else (a 503 "not caught up" is
// not an answer about the sandbox).
func chaosPlacement(ctx context.Context, api *harness.APIClient, id string) (chaosPlacementView, bool, error) {
	var pv chaosPlacementView
	resp, err := api.Do(ctx, http.MethodGet, "/v1/cluster/placements/"+id, nil)
	switch {
	case err != nil:
		return pv, false, err
	case resp.Status == http.StatusNotFound:
		return pv, false, nil
	case resp.Status != http.StatusOK:
		return pv, false, fmt.Errorf("placement %s: %s", id, resp)
	}
	return pv, true, resp.JSON(&pv)
}

// chaosIndexRow is one placement as GET /v1/cluster/sandbox-index pages it.
// State is "" (placed), "reserved" or "deleting".
type chaosIndexRow struct {
	SandboxID     string `json:"sandbox_id"`
	OwnerNodeID   string `json:"owner_node_id"`
	OwnerState    string `json:"owner_state"`
	State         string `json:"state"`
	Name          string `json:"name"`
	IncarnationID string `json:"incarnation_id"`
	Version       uint64 `json:"version"`
}

// chaosIndex pages every placement through api.
func chaosIndex(ctx context.Context, api *harness.APIClient) ([]chaosIndexRow, error) {
	var all []chaosIndexRow
	token := ""
	for page := 0; page < 400; page++ {
		path := "/v1/cluster/sandbox-index?limit=500"
		if token != "" {
			path += "&page_token=" + token
		}
		resp, err := api.Do(ctx, http.MethodGet, path, nil)
		if err != nil {
			return nil, err
		}
		if resp.Status != http.StatusOK {
			return nil, fmt.Errorf("sandbox-index: %s", resp)
		}
		var pg struct {
			Placements    []chaosIndexRow `json:"placements"`
			NextPageToken string          `json:"next_page_token"`
		}
		if err := resp.JSON(&pg); err != nil {
			return nil, err
		}
		all = append(all, pg.Placements...)
		if pg.NextPageToken == "" {
			return all, nil
		}
		token = pg.NextPageToken
	}
	return nil, fmt.Errorf("sandbox-index: more than 400 pages")
}

// chaosIndexEventually retries chaosIndex through a leader election or a
// node that has not caught up.
func chaosIndexEventually(t *testing.T, api *harness.APIClient) []chaosIndexRow {
	t.Helper()
	deadline := time.Now().Add(3 * time.Minute)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		rows, err := chaosIndex(ctx, api)
		cancel()
		if err == nil {
			return rows
		}
		if time.Now().After(deadline) {
			t.Fatalf("read the placement index: %v", err)
		}
		time.Sleep(5 * time.Second)
	}
}

func chaosGetStatus(ctx context.Context, api *harness.APIClient, id string) (int, models.Sandbox, error) {
	var sb models.Sandbox
	resp, err := api.Do(ctx, http.MethodGet, "/v1/sandboxes/"+id, nil)
	if err != nil {
		return 0, sb, err
	}
	if resp.Status == http.StatusOK {
		_ = resp.JSON(&sb)
	}
	return resp.Status, sb, nil
}

func chaosDelete(ctx context.Context, api *harness.APIClient, id string) (int, error) {
	resp, err := api.Do(ctx, http.MethodDelete, "/v1/sandboxes/"+id, nil)
	if err != nil {
		return 0, err
	}
	return resp.Status, nil
}

// chaosLeaderID reads the Raft leader's node id, waiting out an election.
func chaosLeaderID(t *testing.T, api *harness.APIClient) string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		resp, err := api.Do(ctx, http.MethodGet, "/v1/cluster/leader", nil)
		cancel()
		if err == nil && resp.Status == http.StatusOK {
			if id := harness.ParseLeaderJSON(string(resp.Body)); id != "" {
				return id
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no Raft leader: %v %s", err, resp)
		}
		time.Sleep(3 * time.Second)
	}
}

// chaosCreateResult is one create's answer.
type chaosCreateResult struct {
	Name   string
	ID     string
	Status int
	Err    error
	Body   string
	At     time.Time
}

func (r chaosCreateResult) ok() bool { return r.Err == nil && r.Status/100 == 2 && r.ID != "" }

// describe is a short form for logs and tallies: the status, or the
// transport error's kind.
func (r chaosCreateResult) describe() string {
	if r.Err != nil {
		return "transport error"
	}
	return strconv.Itoa(r.Status)
}

func chaosCreate(ctx context.Context, api *harness.APIClient, req models.CreateSandboxRequest) chaosCreateResult {
	r := chaosCreateResult{Name: req.Name, At: time.Now()}
	resp, err := api.Do(ctx, http.MethodPost, "/v1/sandboxes", req)
	if err != nil {
		r.Err = err
		return r
	}
	r.Status = resp.Status
	r.Body = strings.TrimSpace(string(resp.Body))
	if len(r.Body) > 300 {
		r.Body = r.Body[:300]
	}
	if resp.Status/100 == 2 {
		var sb models.Sandbox
		if resp.JSON(&sb) == nil {
			r.ID = sb.ID
		}
	}
	return r
}

// chaosTag is a tag value unique to this case's run; every sandbox it
// creates carries {chaos-run: tag}, and the cleanup deletes by it.
func chaosTag(t *testing.T) string {
	t.Helper()
	tag := strings.ToLower(fmt.Sprintf("%s-%d", strings.TrimPrefix(t.Name(), "TestClusterChaos"), time.Now().Unix()))
	tag = regexp.MustCompile(`[^a-z0-9-]`).ReplaceAllString(tag, "-")
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		gone, err := client(t).SDK().DestroyAll(ctx, map[string]string{"chaos-run": tag})
		if err != nil {
			t.Logf("cleanup: destroy sandboxes tagged chaos-run=%s: %v (%d deleted)", tag, err, len(gone))
		}
	})
	return tag
}

// chaosRequest is the create body for one chaos sandbox. Public, so a
// preview URL works without a separate opt-in; alpine sleeping unless cmd
// says otherwise.
func chaosRequest(name, tag string, recreate bool, cpu float64, memMB int, image string, cmd []string) models.CreateSandboxRequest {
	public := true
	if image == "" {
		image = harness.DefaultImage
	}
	if len(cmd) == 0 {
		cmd = []string{"sleep", "infinity"}
	}
	req := models.CreateSandboxRequest{
		Name:               name,
		Image:              image,
		CPU:                cpu,
		MemoryMB:           memMB,
		ContainerCommand:   cmd,
		AllowPublicTraffic: &public,
		Tags:               map[string]string{"chaos-run": tag},
	}
	if recreate {
		req.Failover = &models.Failover{Policy: models.FailoverPolicyRecreate}
	}
	return req
}

// chaosNewSandbox creates one sandbox through api and waits for it to start.
func chaosNewSandbox(t *testing.T, api *harness.APIClient, req models.CreateSandboxRequest) string {
	t.Helper()
	if req.Name == "" {
		req.Name = harness.UniqueName(sc, t)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	r := chaosCreate(ctx, api, req)
	if !r.ok() {
		t.Fatalf("create %s: %s %v %s", req.Name, r.describe(), r.Err, r.Body)
	}
	chaosAwaitStarted(t, api, r.ID, 3*time.Minute)
	return r.ID
}

// chaosAwaitStarted polls until the sandbox reports started.
func chaosAwaitStarted(t *testing.T, api *harness.APIClient, id string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	last := ""
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		st, sb, err := chaosGetStatus(ctx, api, id)
		cancel()
		switch {
		case err != nil:
			last = err.Error()
		case st == http.StatusOK && sb.Status == models.SandboxStatusStarted:
			return
		case st == http.StatusOK && sb.Status == models.SandboxStatusError:
			t.Fatalf("sandbox %s entered error: %s", id, sb.LastError)
		default:
			last = fmt.Sprintf("%d %s", st, sb.Status)
		}
		if time.Now().After(deadline) {
			t.Fatalf("sandbox %s never started within %s (last %s)", id, timeout, last)
		}
		time.Sleep(2 * time.Second)
	}
}

// chaosOwner waits for the placement to name an owner.
func chaosOwner(t *testing.T, api *harness.APIClient, id string) string {
	t.Helper()
	deadline := time.Now().Add(time.Minute)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		pv, found, err := chaosPlacement(ctx, api, id)
		cancel()
		if err == nil && found && pv.Owner.NodeID != "" {
			return pv.Owner.NodeID
		}
		if time.Now().After(deadline) {
			t.Fatalf("no owner recorded for %s: found=%v err=%v", id, found, err)
		}
		time.Sleep(2 * time.Second)
	}
}

// chaosAwaitReassign polls (every poll) until the placement names an owner
// other than from. It returns "" when timeout passes first; the caller
// decides whether that is a precondition failure.
func chaosAwaitReassign(api *harness.APIClient, id, from string, timeout, poll time.Duration) (string, time.Time) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		pv, found, err := chaosPlacement(ctx, api, id)
		cancel()
		if err == nil && found && pv.Owner.NodeID != "" && pv.Owner.NodeID != from {
			return pv.Owner.NodeID, time.Now()
		}
		time.Sleep(poll)
	}
	return "", time.Time{}
}

// chaosReconcileInterval is the node's SB_RECONCILE_INTERVAL (the daemon's 5
// minute default when unset).
func chaosReconcileInterval(t *testing.T, node harness.IntegrationNode) time.Duration {
	t.Helper()
	target, _ := harness.SSHTarget(node)
	out, _ := harness.SSHRun(t, target, harness.ReconcileIntervalScript)
	return harness.ParseReconcileInterval(out, 5*time.Minute)
}

// chaosConvergeBound is T in I6: how long after the faults stop a case
// waits before it calls a state final. Two reconcile intervals (the plan's
// "stays absent after two reconcile intervals") plus a minute for the
// dead-owner grace and the owner watcher. AEROL_CHAOS_CONVERGE_SECONDS
// overrides it.
func chaosConvergeBound(t *testing.T, tp chaosTopo) time.Duration {
	t.Helper()
	r := chaosReconcileInterval(t, tp.workers[0])
	return chaosSeconds("AEROL_CHAOS_CONVERGE_SECONDS", int((2*r + time.Minute).Seconds()))
}

// chaosFailoverBound is how long a case waits for a dead or cut-off owner's
// sandbox to be reassigned (the dead-owner grace is 30 s by default).
func chaosFailoverBound() time.Duration {
	return chaosSeconds("AEROL_CHAOS_FAILOVER_BOUND_SECONDS", 300)
}

type chaosCapacity struct {
	ReservedCPU      float64 `json:"reserved_cpu"`
	ReservedMemoryMB int     `json:"reserved_memory_mb"`
	CPUBudget        float64 `json:"cpu_budget"`
	MemoryBudgetMB   int     `json:"memory_budget_mb"`
	SandboxesActive  int     `json:"sandboxes_active"`
}

// chaosCapacityOf reads a node's own admitter (GET /v1/capacity on its
// loopback).
func chaosCapacityOf(ctx context.Context, api *harness.APIClient) (chaosCapacity, error) {
	var c chaosCapacity
	resp, err := api.Do(ctx, http.MethodGet, "/v1/capacity", nil)
	if err != nil {
		return c, err
	}
	if resp.Status != http.StatusOK {
		return c, fmt.Errorf("capacity: %s", resp)
	}
	return c, resp.JSON(&c)
}

// chaosWorkerAPIs opens one tunnel per worker.
func chaosWorkerAPIs(t *testing.T, tp chaosTopo) map[string]*harness.APIClient {
	t.Helper()
	out := map[string]*harness.APIClient{}
	for _, w := range tp.workers {
		out[w.Name] = chaosAPI(t, w)
	}
	return out
}

// chaosBudgets reads every worker's CPU budget before a fault. Budgets are
// static per host (cores x reservation ratio x overprovision), so a value
// read now still holds while the worker is cut off or down.
func chaosBudgets(t *testing.T, apis map[string]*harness.APIClient) map[string]chaosCapacity {
	t.Helper()
	out := map[string]chaosCapacity{}
	for name, api := range apis {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		c, err := chaosCapacityOf(ctx, api)
		cancel()
		if err != nil || c.CPUBudget <= 0 {
			t.Fatalf("read %s's capacity budget: %+v %v", name, c, err)
		}
		out[name] = c
	}
	return out
}

// --- the runtime ----------------------------------------------------------

// chaosCensus asks node's container engine what runs. An SSH failure or a
// cut-short script is an error, never an empty census.
func chaosCensus(t *testing.T, node harness.IntegrationNode) (harness.RuntimeCensus, error) {
	t.Helper()
	target, ok := harness.SSHTarget(node)
	if !ok {
		return harness.RuntimeCensus{}, fmt.Errorf("%s has no SSH address", node.Name)
	}
	out, err := harness.SSHRun(t, target, harness.RuntimeCensusScript)
	if err != nil {
		return harness.RuntimeCensus{}, fmt.Errorf("census on %s: %v: %s", node.Name, err, strings.TrimSpace(out))
	}
	c, perr := harness.ParseRuntimeCensus(out)
	if perr != nil {
		return c, fmt.Errorf("%s: %w", node.Name, perr)
	}
	return c, nil
}

// chaosFleetCensus is one census of several nodes, taken in parallel.
type chaosFleetCensus struct {
	at     time.Time
	byNode map[string]harness.RuntimeCensus
	errs   map[string]error
}

func chaosCensusAll(t *testing.T, nodes []harness.IntegrationNode) chaosFleetCensus {
	t.Helper()
	fc := chaosFleetCensus{at: time.Now(), byNode: map[string]harness.RuntimeCensus{}, errs: map[string]error{}}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, n := range nodes {
		wg.Add(1)
		go func(n harness.IntegrationNode) {
			defer wg.Done()
			c, err := chaosCensus(t, n)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				fc.errs[n.Name] = err
				return
			}
			fc.byNode[n.Name] = c
		}(n)
	}
	wg.Wait()
	return fc
}

// runningOn is the nodes (of those that answered) running id, sorted.
func (fc chaosFleetCensus) runningOn(id string) []string {
	var out []string
	for name, c := range fc.byNode {
		if c.Running(id) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// running is every id running on any node that answered.
func (fc chaosFleetCensus) running() map[string][]string {
	out := map[string][]string{}
	for name, c := range fc.byNode {
		for _, id := range c.RunningIDs() {
			out[id] = append(out[id], name)
		}
	}
	for id := range out {
		sort.Strings(out[id])
	}
	return out
}

// complete reports whether every node answered.
func (fc chaosFleetCensus) complete() bool { return len(fc.errs) == 0 }

func (fc chaosFleetCensus) errSummary() string {
	var parts []string
	for name, err := range fc.errs {
		parts = append(parts, name+": "+err.Error())
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

// --- faults ------------------------------------------------------------------

// chaosPartition cuts every node in side off from every address of every
// node in from, in both directions, and returns the heal. The cleanup heals
// whatever the case did not; each node also carries a dead-man that heals it
// after deadman if this process dies.
func chaosPartition(t *testing.T, side, from []harness.IntegrationNode, deadman time.Duration) func() {
	t.Helper()
	ips := chaosAddrs(from)
	var once sync.Once
	heal := func() {
		once.Do(func() {
			for _, n := range side {
				target, _ := harness.SSHTarget(n)
				out, err := harness.SSHRun(t, target, harness.ChaosHealScript(ips))
				if err != nil || !strings.Contains(out, "HEALED") {
					t.Errorf("RESTORE FAILED: %s may still be partitioned (its dead-man heals it within %s): %v %s", n.Name, deadman, err, out)
				}
			}
		})
	}
	t.Cleanup(heal)
	for _, n := range side {
		target, _ := harness.SSHTarget(n)
		out, err := harness.SSHRun(t, target, harness.ChaosPartitionScript(ips, deadman))
		if err != nil || !strings.Contains(out, "PARTITIONED") {
			t.Fatalf("partition %s from %v: %v\n%s", n.Name, chaosNames(from), err, out)
		}
	}
	t.Logf("partitioned %v from %v", chaosNames(side), chaosNames(from))
	return heal
}

// chaosHardKill kills node the way a crashed machine dies: sandboxd stopped,
// every sandbox container SIGKILLed, the container engine stopped. Until now
// the live failover cases only stopped sandboxd, which leaves the old copy
// running, so none of them could check that it dies or stays dead. The
// restore starts the engine, then sandboxd, and waits for the node to rejoin
// (restoreNodeDaemon). Never the seed unless the case says so: losing the
// seed is UC-170's subject, not these cases'.
func chaosHardKill(t *testing.T, node harness.IntegrationNode, allowSeed bool) func() {
	t.Helper()
	if node.Seed && !allowSeed {
		t.Skipf("%s is the seed; this case kills workers only", node.Name)
	}
	target, _ := harness.SSHTarget(node)
	out, err := harness.SSHRun(t, target, "set -u\nsudo systemctl stop sandboxd\n"+harness.HardKillRuntimeScript)
	harness.MarkNodeDown(node.PublicIP)
	engine, remaining, perr := harness.ParseHardKill(out)
	var once sync.Once
	restore := func() {
		once.Do(func() {
			script := harness.HardKillRestoreEngineScript(engine)
			if engine == "" {
				script = "sudo systemctl start containerd 2>/dev/null; sudo systemctl start docker.socket docker 2>/dev/null; echo ENGINE-STARTED"
			}
			if o, e := harness.SSHRun(t, target, script); e != nil || !strings.Contains(o, "ENGINE-STARTED") {
				t.Errorf("RESTORE FAILED: the container engine did not start on %s: %v %s", node.Name, e, o)
			}
			restoreNodeDaemon(t, node, target)
		})
	}
	t.Cleanup(restore)
	if err != nil || perr != nil {
		t.Fatalf("hard kill %s: %v %v\n%s", node.Name, err, perr, out)
	}
	if remaining != 0 {
		t.Fatalf("hard kill %s left %d sandbox containers running; the case would read a live old copy as a bug", node.Name, remaining)
	}
	t.Logf("hard-killed %s (sandboxd and the %s engine stopped, every container killed)", node.Name, engine)
	return restore
}

// chaosKillLeader stops sandboxd on the current Raft leader (KillNodeDaemon,
// which restores and waits for the rejoin). The leader is whoever leads,
// the seed included: these cases are about the control plane, and UC-170
// proves a stopped seed rejoins.
func chaosKillLeader(t *testing.T, tp chaosTopo, ids map[string]string, leaderID string) (harness.IntegrationNode, func()) {
	t.Helper()
	victim, ok := chaosNodeByID(tp, ids, leaderID)
	if !ok {
		t.Fatalf("the leader %s is not a provisioned node", leaderID)
	}
	if victim.Seed {
		t.Logf("the leader is the seed %s; killing it anyway (UC-170 proves the seed rejoins)", victim.Name)
	}
	return victim, harness.KillNodeDaemon(t, victim)
}

// chaosStopVoters stops sandboxd on several servers at once and returns the
// restore, which starts them all BEFORE waiting for any to rejoin: with two
// of three voters down there is no leader, so waiting for the first to
// rejoin before starting the second would wait forever.
func chaosStopVoters(t *testing.T, nodes []harness.IntegrationNode) func() {
	t.Helper()
	return chaosDownVoters(t, nodes, "sudo systemctl stop sandboxd", "stop")
}

// chaosKillVoters SIGKILLs sandboxd on several servers at once
// (harness.KillSandboxdScript): a crash, not a shutdown. systemd restarts
// each by itself; the restore is chaosStopVoters', whose start is a no-op on
// a unit already back, and which waits for every node to rejoin.
func chaosKillVoters(t *testing.T, nodes []harness.IntegrationNode) func() {
	t.Helper()
	return chaosDownVoters(t, nodes, harness.KillSandboxdScript, "SIGKILL")
}

// chaosDownVoters runs down on every node in parallel, so they go down
// together, and returns the shared restore.
func chaosDownVoters(t *testing.T, nodes []harness.IntegrationNode, down, verb string) func() {
	t.Helper()
	for _, n := range nodes {
		if n.Seed {
			t.Logf("%s on the seed %s on purpose (UC-170 proves it rejoins)", verb, n.Name)
		}
	}
	var once sync.Once
	restore := func() {
		once.Do(func() {
			for _, n := range nodes {
				target, _ := harness.SSHTarget(n)
				if out, err := harness.SSHRun(t, target, "sudo systemctl reset-failed sandboxd; sudo systemctl start sandboxd"); err != nil {
					t.Errorf("RESTORE FAILED: sandboxd is left stopped on %s: %v %s", n.Name, err, out)
				}
			}
			for _, n := range nodes {
				if err := waitNodeRejoined(t, n); err != nil {
					t.Errorf("RESTORE INCOMPLETE: %s did not rejoin: %v", n.Name, err)
					continue
				}
				harness.MarkNodeUp(n.PublicIP)
			}
		})
	}
	t.Cleanup(restore)
	var wg sync.WaitGroup
	for _, n := range nodes {
		wg.Add(1)
		go func(n harness.IntegrationNode) {
			defer wg.Done()
			target, _ := harness.SSHTarget(n)
			if out, err := harness.SSHRun(t, target, down); err != nil {
				t.Errorf("%s sandboxd on %s: %v %s", verb, n.Name, err, out)
			}
			harness.MarkNodeDown(n.PublicIP)
		}(n)
	}
	wg.Wait()
	return restore
}

// chaosArmFailpoint arms failpoint name for sandbox names starting with
// prefix on every node, and disarms them all in the cleanup: a failpoint
// left armed would park the next matching create on that node.
func chaosArmFailpoint(t *testing.T, nodes []harness.IntegrationNode, name, prefix string) {
	t.Helper()
	t.Cleanup(func() {
		for _, n := range nodes {
			target, _ := harness.SSHTarget(n)
			if out, err := harness.SSHRun(t, target, harness.FailpointDisarmScript(name)); err != nil || !strings.Contains(out, "DISARMED") {
				t.Errorf("RESTORE FAILED: failpoint %s may still be armed on %s: %v %s", name, n.Name, err, out)
			}
		}
	})
	for _, n := range nodes {
		target, _ := harness.SSHTarget(n)
		if out, err := harness.SSHRun(t, target, harness.FailpointArmScript(name, prefix)); err != nil || !strings.Contains(out, "ARMED") {
			t.Fatalf("arm failpoint %s on %s: %v %s", name, n.Name, err, out)
		}
	}
}

// chaosFailpointHit reports whether failpoint name fired on node, and the key
// it fired for. An SSH failure is an error, not "no hit".
func chaosFailpointHit(t *testing.T, node harness.IntegrationNode, name string) (string, bool, error) {
	t.Helper()
	target, _ := harness.SSHTarget(node)
	out, err := harness.SSHRun(t, target, harness.FailpointHitScript(name))
	if err != nil {
		return "", false, fmt.Errorf("%s: %v %s", node.Name, err, strings.TrimSpace(out))
	}
	return harness.ParseFailpointHit(out)
}

// chaosNetnsInUse is how many of a worker's containerd netns pool slots are
// held, from its own /v1/capacity (the pool's total less its free and
// prewarmed slots). ok is false when the node reports no such pool (the
// docker engine), where there is nothing to count.
func chaosNetnsInUse(ctx context.Context, api *harness.APIClient) (int, bool, error) {
	resp, err := api.Do(ctx, http.MethodGet, "/v1/capacity", nil)
	if err != nil {
		return 0, false, err
	}
	if resp.Status != http.StatusOK {
		return 0, false, fmt.Errorf("capacity: %s", resp)
	}
	var c struct {
		SlotPools []struct {
			Name  string `json:"name"`
			Total int    `json:"total"`
			Free  int    `json:"free"`
		} `json:"slot_pools"`
	}
	if err := resp.JSON(&c); err != nil {
		return 0, false, err
	}
	for _, p := range c.SlotPools {
		if p.Name == capacity.SlotPoolContainerNetns {
			return p.Total - p.Free, true, nil
		}
	}
	return 0, false, nil
}

// chaosRestartDaemon restarts sandboxd on node and waits until it has
// rejoined (member, leader, fresh capacity). The seed is restarted on
// purpose when the case is about every server.
func chaosRestartDaemon(t *testing.T, node harness.IntegrationNode) {
	t.Helper()
	if node.Seed {
		t.Logf("restarting the seed %s on purpose (UC-170 proves it rejoins)", node.Name)
	}
	target, _ := harness.SSHTarget(node)
	harness.MarkNodeDown(node.PublicIP)
	if out, err := harness.SSHRun(t, target, "sudo systemctl restart sandboxd"); err != nil {
		t.Fatalf("restart sandboxd on %s: %v %s", node.Name, err, out)
	}
	if err := waitNodeRejoined(t, node); err != nil {
		t.Fatalf("%s did not rejoin after a restart: %v", node.Name, err)
	}
	harness.MarkNodeUp(node.PublicIP)
}

// chaosNetem delays and drops every node's packets to every other node and
// returns the clear. The operator's SSH and the internet are untouched.
func chaosNetem(t *testing.T, nodes []harness.IntegrationNode, delay, loss string, deadman time.Duration) func() {
	t.Helper()
	var once sync.Once
	clear := func() {
		once.Do(func() {
			for _, n := range nodes {
				target, _ := harness.SSHTarget(n)
				if out, err := harness.SSHRun(t, target, harness.NetemClearScript()); err != nil || !strings.Contains(out, "NETEM-OFF") {
					t.Errorf("RESTORE FAILED: %s may still delay and drop packets (its dead-man clears it within %s): %v %s", n.Name, deadman, err, out)
				}
			}
		})
	}
	t.Cleanup(clear)
	// In parallel: a fresh node may have to install linux-modules-extra for
	// sch_netem, which is most of a minute; seven of those in a row would
	// stagger the impairment across the fleet.
	failures := make([]string, len(nodes))
	var wg sync.WaitGroup
	for i, n := range nodes {
		wg.Add(1)
		go func(i int, n harness.IntegrationNode) {
			defer wg.Done()
			var peers []string
			for _, p := range chaosExcept(nodes, n) {
				if p.PrivateIP != "" {
					peers = append(peers, p.PrivateIP)
				}
			}
			target, _ := harness.SSHTarget(n)
			out, err := harness.SSHRun(t, target, harness.NetemScript(peers, delay, loss, deadman))
			if err != nil || !strings.Contains(out, "NETEM-ON") {
				failures[i] = fmt.Sprintf("%s: %v\n%s", n.Name, err, out)
			}
		}(i, n)
	}
	wg.Wait()
	for _, f := range failures {
		if f != "" {
			t.Fatalf("netem on %s", f)
		}
	}
	t.Logf("netem on %d nodes: delay %s, loss %s to every peer", len(nodes), delay, loss)
	return clear
}

// chaosPurgeImageScript removes an image from the node's engine so the next
// create has to pull it. Best effort.
func chaosPurgeImageScript(image string) string {
	ref := image
	if !strings.Contains(strings.SplitN(ref, "/", 2)[0], ".") {
		if !strings.Contains(ref, "/") {
			ref = "library/" + ref
		}
		ref = "docker.io/" + ref
	}
	return `ns=$(sudo bash -c '. /etc/sandboxd/sandboxd.env 2>/dev/null; . /etc/sandboxd/cluster.env 2>/dev/null; printf %s "${SB_CONTAINERD_NAMESPACE:-aerolvm}"'); ` +
		`sudo ctr -n "$ns" images rm ` + shellQuote(ref) + ` >/dev/null 2>&1; ` +
		`sudo docker rmi -f ` + shellQuote(image) + ` >/dev/null 2>&1; echo PURGED`
}

// --- the cut-off ingress probe -------------------------------------------

// chaosCopyServer serves "copy=<id>" on 8080, where id is made when the
// process starts. The original and a failover recreate are different
// processes, so the answer says which copy served it: a request the old
// copy answered after its placement moved is an I7 violation no status
// code can hide.
const chaosCopyServer = `import http.server, uuid
cid = uuid.uuid4().hex
open("/tmp/copy-id", "w").write(cid)
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        b = ("copy=" + cid + "\n").encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)
    def log_message(self, *a):
        pass
http.server.ThreadingHTTPServer(("0.0.0.0", 8080), H).serve_forever()
`

var chaosCopyRE = regexp.MustCompile(`copy=([0-9a-f]{32})`)

// chaosProbeClient opens a fresh connection per request (a routing change
// must not hide behind a kept-alive connection) and does not verify the
// certificate: routing is under test here, not the chain (staging
// certificates do not chain to public roots).
func chaosProbeClient() *http.Client {
	tr := harness.NewTransport(func(tr *http.Transport) {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // routing under test, not the chain
		tr.DisableKeepAlives = true
	})
	return &http.Client{Timeout: 10 * time.Second, Transport: tr}
}

type chaosProbe struct {
	at     time.Time
	status int
	copyID string
	err    error
}

func (p chaosProbe) String() string {
	switch {
	case p.err != nil:
		return "transport error (" + p.err.Error() + ")"
	case p.copyID != "":
		return fmt.Sprintf("%d from copy %s", p.status, p.copyID[:8])
	}
	return strconv.Itoa(p.status)
}

func chaosProbeCopy(hc *http.Client, url string) chaosProbe {
	p := chaosProbe{at: time.Now()}
	resp, err := hc.Get(url)
	if err != nil {
		p.err = err
		return p
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	p.status = resp.StatusCode
	if m := chaosCopyRE.FindSubmatch(body); m != nil {
		p.copyID = string(m[1])
	}
	return p
}

// chaosExpose exposes port 8080 and returns its public URL.
func chaosExpose(t *testing.T, api *harness.APIClient, id string) string {
	t.Helper()
	resp := statusAs(t, api, http.MethodPost, "/v1/sandboxes/"+id+"/ports/8080", nil)
	var er models.ExposePortResponse
	if resp.Status/100 != 2 || resp.JSON(&er) != nil || er.PublicURL == "" {
		t.Fatalf("expose 8080 on %s: %s", id, resp)
	}
	return er.PublicURL
}

// chaosAwaitServed waits until url is served by a copy and returns its id.
func chaosAwaitServed(t *testing.T, hc *http.Client, url string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last chaosProbe
	for time.Now().Before(deadline) {
		if last = chaosProbeCopy(hc, url); last.copyID != "" {
			return last.copyID
		}
		time.Sleep(3 * time.Second)
	}
	t.Fatalf("%s was never served by the sandbox within %s (last %s)", url, timeout, last)
	return ""
}

// --- shared invariant checks --------------------------------------------------

// chaosWatchDeleted watches deleted sandboxes for window and records:
//
//   - I3 the moment one is placed again, or the API answers it, or a copy
//     starts running again after the census had seen it gone;
//   - I6 when a copy that never stopped (the old owner's, say) is still
//     running when window ends.
//
// window should be at least chaosConvergeBound. It returns how many full
// samples it took; a node whose census never succeeded is an error, because
// "no copy" was then never actually observed there.
func chaosWatchDeleted(t *testing.T, inv *harness.Invariants, tp chaosTopo, api *harness.APIClient, ids []string, window time.Duration, phase string) int {
	t.Helper()
	start := time.Now()
	deadline := start.Add(window)
	seenGone := map[string]bool{}
	flagged := map[string]bool{}
	observed := map[string]int{}
	var lastRunning map[string][]string
	samples := 0
	once := func(key, invID, format string, args ...any) {
		if !flagged[key] {
			flagged[key] = true
			inv.Violate(invID, format, args...)
		}
	}
	for {
		for _, id := range ids {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			pv, found, perr := chaosPlacement(ctx, api, id)
			st, _, gerr := chaosGetStatus(ctx, api, id)
			cancel()
			if perr == nil && found {
				once("placed:"+id, "I3", "deleted sandbox %s has a placement again (owner %q) at +%s %s",
					id, pv.Owner.NodeID, time.Since(start).Round(time.Second), phase)
			}
			if gerr == nil && st == http.StatusOK {
				once("api:"+id, "I3", "deleted sandbox %s answers 200 on the API at +%s %s", id, time.Since(start).Round(time.Second), phase)
			}
		}
		fc := chaosCensusAll(t, tp.workers)
		for name := range fc.byNode {
			observed[name]++
		}
		lastRunning = map[string][]string{}
		for _, id := range ids {
			on := fc.runningOn(id)
			lastRunning[id] = on
			switch {
			case len(on) == 0 && fc.complete():
				seenGone[id] = true
			case len(on) > 0 && seenGone[id]:
				once("back:"+id, "I3", "deleted sandbox %s runs again on %v at +%s %s, after the census had seen it gone",
					id, on, time.Since(start).Round(time.Second), phase)
			}
		}
		if !fc.complete() {
			t.Logf("census incomplete at +%s: %s", time.Since(start).Round(time.Second), fc.errSummary())
		}
		samples++
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Second)
	}
	for _, id := range ids {
		if on := lastRunning[id]; len(on) > 0 {
			inv.Violate("I6", "deleted sandbox %s still runs on %v %s after %s (two reconcile intervals and the grace)", id, on, phase, window.Round(time.Second))
		}
	}
	for _, w := range tp.workers {
		if observed[w.Name] == 0 {
			t.Errorf("%s never answered a census %s, so the absence of a copy there was never observed", w.Name, phase)
		}
	}
	return samples
}

// chaosCreateCheck is what chaosCheckCreates found.
type chaosCreateCheck struct {
	created, failed, appliedAnyway, absent int
	orphanContainers                       int
}

// chaosCheckCreates holds the outcome of a batch of creates (all named with
// prefix) against the converged cluster:
//
//   - I8: a create answered 2xx is placed and runs exactly once, on its
//     owner; a create that failed is either fully created (it was applied
//     after all) or fully absent: never a reservation, a placement with no
//     container, or a container with no placement. No name has two
//     placements.
//   - I6: no reservation outlives its TTL, nothing is stuck deleting, and no
//     container runs on a node that does not own it.
//   - I4: no worker runs more sandboxes than its CPU budget holds (every
//     sandbox the batch made asks for cpu).
//
// baseline is the census taken before the batch; containers in it are not
// the batch's. Call it after waiting out chaosReservationTTL and
// chaosConvergeBound.
func chaosCheckCreates(t *testing.T, inv *harness.Invariants, tp chaosTopo, api *harness.APIClient, ids map[string]string,
	results []chaosCreateResult, prefix string, baseline chaosFleetCensus, cpu float64, budgets map[string]chaosCapacity) chaosCreateCheck {
	t.Helper()
	var out chaosCreateCheck
	rows := chaosIndexEventually(t, api)
	fc := chaosCensusAll(t, tp.workers)
	if !fc.complete() {
		t.Fatalf("census after convergence is incomplete, so copies cannot be counted: %s", fc.errSummary())
	}
	placed := map[string]chaosIndexRow{}
	byName := map[string][]chaosIndexRow{}
	for _, r := range rows {
		placed[r.SandboxID] = r
		if strings.HasPrefix(r.Name, prefix) {
			byName[r.Name] = append(byName[r.Name], r)
		}
	}
	nodeOfID := func(clusterID string) string {
		if n, ok := chaosNodeByID(tp, ids, clusterID); ok {
			return n.Name
		}
		return clusterID
	}
	// Every row the batch left, by name.
	for name, rs := range byName {
		if len(rs) > 1 {
			var sbs []string
			for _, r := range rs {
				sbs = append(sbs, r.SandboxID)
			}
			inv.Violate("I8", "one create of %s left %d sandboxes: %v", name, len(rs), sbs)
		}
		for _, r := range rs {
			switch r.State {
			case "reserved":
				inv.Violate("I6", "reservation for %s (%s) outlived its %s TTL", name, r.SandboxID, chaosReservationTTL)
			case "deleting":
				inv.Violate("I6", "%s (%s) is stuck deleting", name, r.SandboxID)
			default:
				on := fc.runningOn(r.SandboxID)
				owner := nodeOfID(r.OwnerNodeID)
				switch {
				case len(on) == 0:
					inv.Violate("I8", "%s (%s) is placed on %s but runs nowhere", name, r.SandboxID, owner)
				case len(on) > 1:
					inv.Violate("I6", "%s (%s) runs on %v at once", name, r.SandboxID, on)
				case on[0] != owner:
					inv.Violate("I6", "%s (%s) runs on %s but is placed on %s", name, r.SandboxID, on[0], owner)
				}
			}
		}
	}
	// Every answer the batch got.
	for _, r := range results {
		rs := byName[r.Name]
		switch {
		case r.ok():
			out.created++
			if _, ok := placed[r.ID]; !ok {
				inv.Violate("I8", "create %s answered %d with %s, which has no placement", r.Name, r.Status, r.ID)
			}
		case len(rs) == 0:
			out.failed++
			out.absent++
		default:
			out.failed++
			out.appliedAnyway++
			t.Logf("create %s answered %s (%v) but was applied after all as %s; allowed when it converged to fully created", r.Name, r.describe(), r.Err, rs[0].SandboxID)
		}
	}
	// Containers nobody owns: started by a create whose placement is gone.
	running := fc.running()
	before := baseline.running()
	load := map[string]int{}
	for id, on := range running {
		if _, ok := before[id]; ok {
			continue
		}
		for _, n := range on {
			load[n]++
		}
		if _, ok := placed[id]; !ok {
			out.orphanContainers++
			inv.Violate("I8", "container %s runs on %v with no placement (a failed create left it)", id, on)
		}
	}
	for name, c := range budgets {
		if used := float64(load[name]) * cpu; used > c.CPUBudget {
			inv.Violate("I4", "%s runs %d of the batch's sandboxes (%.2f CPU), over its %.2f CPU budget", name, load[name], used, c.CPUBudget)
		}
	}
	return out
}

// chaosBannerServer is chaosCopyServer plus a raw TCP listener on 9000 that
// sends "banner=<copy id>" and closes, so a probe can tell a live TCP answer
// from a closed connection and from a hang (UC-484).
const chaosBannerServer = `import http.server, socket, threading, uuid
cid = uuid.uuid4().hex
open("/tmp/copy-id", "w").write(cid)
def tcp():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 9000))
    s.listen(64)
    while True:
        c, _ = s.accept()
        try:
            c.sendall(("banner=" + cid + "\n").encode())
        finally:
            c.close()
threading.Thread(target=tcp, daemon=True).start()
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        b = ("copy=" + cid + "\n").encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)
    def log_message(self, *a):
        pass
http.server.ThreadingHTTPServer(("0.0.0.0", 8080), H).serve_forever()
`

// chaosPausedProbeScript asks a node's own Caddy, over loopback, for the
// toolbox URL and the HTTP port URL (curl gives up after 8 s) and reads the
// raw TCP host port (timeout 6 s), printing one line each with the time
// taken. A hang shows as code 000 or rc=124; a refused TCP connect is rc=1, a
// connection closed with nothing read is rc=0 with no banner.
func chaosPausedProbeScript(toolboxHost, portHost string, hostPort int) string {
	return fmt.Sprintf(`probe() { curl -sk -o /dev/null -w '%%{http_code} %%{time_total}' --max-time 8 --resolve "$1:443:127.0.0.1" "https://$1/" 2>/dev/null || true; }
echo "TOOLBOX $(probe %[1]s)"
echo "PORT $(probe %[2]s)"
s=$(date +%%s.%%N)
out=$(timeout 6 bash -c 'exec 3<>/dev/tcp/127.0.0.1/%[3]d && cat <&3' 2>/dev/null)
rc=$?
e=$(date +%%s.%%N)
echo "TCP rc=$rc secs=$(awk -v s="$s" -v e="$e" 'BEGIN{printf "%%.2f", e-s}') out=$(printf %%s "$out" | head -c 48 | tr -d '\n ')"
`, toolboxHost, portHost, hostPort)
}

type chaosHTTPAnswer struct {
	code int
	secs float64
}

func (a chaosHTTPAnswer) String() string { return fmt.Sprintf("%d in %.2fs", a.code, a.secs) }

type chaosTCPAnswer struct {
	rc     int
	secs   float64
	banner bool
}

func (a chaosTCPAnswer) String() string {
	what := "closed"
	switch {
	case a.banner:
		what = "banner"
	case a.rc == 124:
		what = "hung"
	case a.rc == 1:
		what = "refused"
	}
	return fmt.Sprintf("%s (rc=%d) in %.2fs", what, a.rc, a.secs)
}

// chaosAddressProbe is one run of chaosPausedProbeScript.
type chaosAddressProbe struct {
	toolbox, port chaosHTTPAnswer
	tcp           chaosTCPAnswer
}

func (p chaosAddressProbe) String() string {
	return fmt.Sprintf("toolbox %s, port %s, tcp %s", p.toolbox, p.port, p.tcp)
}

// live: the toolbox URL answers with anything but 503 (toolboxd's own 401
// counts), the HTTP port serves 200, and the TCP port sends the banner.
func (p chaosAddressProbe) live() bool {
	return p.toolbox.code != 0 && p.toolbox.code != 503 && p.port.code == 200 && p.tcp.banner
}

// chaosPausedAnswerBound: an answer slower than this is a hang, not a quick
// refusal (curl gives up at 8 s, the TCP read at 6 s).
const chaosPausedAnswerBound = 5.0

// pausedProblems lists what is wrong with p for a paused sandbox: each HTTP
// address must answer 503 within the bound, and the TCP port must close or
// refuse within it, with no banner (a banner means it still reaches the
// sandbox).
func (p chaosAddressProbe) pausedProblems() []string {
	var bad []string
	for _, a := range []struct {
		name string
		ans  chaosHTTPAnswer
	}{{"toolbox URL", p.toolbox}, {"HTTP port", p.port}} {
		if a.ans.code != 503 || a.ans.secs >= chaosPausedAnswerBound {
			bad = append(bad, fmt.Sprintf("%s answered %s, want 503 within %.0fs", a.name, a.ans, chaosPausedAnswerBound))
		}
	}
	switch {
	case p.tcp.banner:
		bad = append(bad, "TCP port still reached the sandbox: "+p.tcp.String())
	case p.tcp.rc == 124 || p.tcp.secs >= chaosPausedAnswerBound:
		bad = append(bad, "TCP port hung: "+p.tcp.String())
	}
	return bad
}

func parseChaosAddressProbe(out string) chaosAddressProbe {
	var p chaosAddressProbe
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case "TOOLBOX", "PORT":
			var a chaosHTTPAnswer
			if len(f) >= 3 {
				a.code, _ = strconv.Atoi(f[1])
				a.secs, _ = strconv.ParseFloat(f[2], 64)
			}
			if f[0] == "TOOLBOX" {
				p.toolbox = a
			} else {
				p.port = a
			}
		case "TCP":
			for _, kv := range f[1:] {
				k, v, _ := strings.Cut(kv, "=")
				switch k {
				case "rc":
					p.tcp.rc, _ = strconv.Atoi(v)
				case "secs":
					p.tcp.secs, _ = strconv.ParseFloat(v, 64)
				case "out":
					p.tcp.banner = strings.HasPrefix(v, "banner=")
				}
			}
		}
	}
	return p
}
