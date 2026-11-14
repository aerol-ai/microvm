package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/aerol-ai/microvm/internal/agenttools"
)

// Node verbs in kubectl grammar (plans/kubectl-style-cluster-ops.md §3.2,
// §5): get/describe/delete take a kind first; cordon, uncordon, drain and
// cluster-info are their own verbs. They call the fleet.admin /v1/cluster
// routes through callAPI, like token and whoami: no SDK exposes /v1/cluster.
//
// The kind dispatch (get, describe, delete) is kinds.go; nodes are one entry
// in its table.

// nodeSandboxIDPage is how many owned sandbox IDs one node read asks for.
const nodeSandboxIDPage = 500

// nodeRecord is the part of a /v1/cluster member or node the CLI reads. The
// CLI keeps no server types (deps_test.go), so it declares its own.
type nodeRecord struct {
	NodeID        string            `json:"node_id"`
	NodeName      string            `json:"node_name,omitempty"`
	APIURL        string            `json:"api_url"`
	InternalURL   string            `json:"internal_url,omitempty"`
	RaftAddr      string            `json:"raft_addr,omitempty"`
	DataPlaneHost string            `json:"data_plane_host,omitempty"`
	PublicHost    string            `json:"public_host,omitempty"`
	Role          string            `json:"role,omitempty"`
	FSMOpsVersion int               `json:"fsm_ops_version,omitempty"`
	Alive         bool              `json:"alive"`
	Version       string            `json:"version,omitempty"`
	Voter         bool              `json:"voter,omitempty"`
	Leader        bool              `json:"leader,omitempty"`
	Drained       bool              `json:"drained,omitempty"`
	Zone          string            `json:"zone,omitempty"`
	Labels        map[string]string `json:"labels,omitempty"`
	CapacityStale bool              `json:"capacity_stale,omitempty"`
	Capacity      struct {
		HostCPUCores      int     `json:"host_cpu_cores"`
		HostMemoryTotalMB int     `json:"host_memory_total_mb"`
		ReservedCPU       float64 `json:"reserved_cpu"`
		ReservedMemoryMB  int     `json:"reserved_memory_mb"`
		CPUBudget         float64 `json:"cpu_budget"`
		MemoryBudgetMB    int     `json:"memory_budget_mb"`
		SandboxesActive   int     `json:"sandboxes_active"`
		ParkedSlots       int     `json:"parked_slots,omitempty"`
	} `json:"capacity"`
	// GET /v1/cluster/nodes/{id} only.
	SandboxesOwned   int      `json:"sandboxes_owned"`
	SandboxesRunning int      `json:"sandboxes_running"`
	RunningKnown     bool     `json:"running_known"`
	SandboxIDs       []string `json:"sandbox_ids,omitempty"`
}

func (n nodeRecord) role() string {
	if n.Role == "" {
		return "mixed" // an older build gossips no role; sandboxd reads it as mixed
	}
	return n.Role
}

// status is kubectl's STATUS column.
func (n nodeRecord) status() string {
	parts := []string{"NotReady"}
	if n.Alive {
		parts[0] = "Ready"
	}
	if n.Drained {
		parts = append(parts, "SchedulingDisabled")
	}
	if n.Leader {
		parts = append(parts, "Leader")
	}
	return strings.Join(parts, ",")
}

func (n nodeRecord) hasHeartbeat() bool {
	return !n.CapacityStale && (n.Capacity.HostCPUCores > 0 || n.Capacity.HostMemoryTotalMB > 0)
}

func (n nodeRecord) sandboxes() string {
	if !n.hasHeartbeat() {
		return "-"
	}
	return strconv.Itoa(max(n.Capacity.SandboxesActive-n.Capacity.ParkedSlots, 0))
}

func percent(used, budget float64, ok bool) string {
	if !ok || budget <= 0 {
		return "-"
	}
	return fmt.Sprintf("%.0f%%", used*100/budget)
}

// nodeRaw is one node as the server sent it, and as the CLI read it. -o json
// and -o yaml print the server's object, so no field is lost on the way.
type nodeRaw struct {
	raw json.RawMessage
	rec nodeRecord
}

// clusterCall is one /v1/cluster call with the verb's connection. A GET is
// retried on a dropped connection or a 502/503/504: reads are safe to repeat
// (the CLI contract), and a drain or describe from a laptop otherwise fails
// on one reset from a load balancer (live UC-612, 2026-11-07). DELETEs are
// retried the same way: every delete here is idempotent (a node, join token,
// snapshot, token or sandbox that is already gone counts as deleted), and a
// Caddy reload on the ingress node can drop a delete in flight (live UC-614,
// 2026-11-08). cordon, drain and uncordon are retried too: they only set or
// clear a node's mark (setNodeDrainState), and the same Caddy reload reset a
// cordon in flight (live UC-613, 2026-11-08). Other writes are never retried
// here: a second join token would be a second credential, and their own
// idempotency is the server's job.
func (a *app) clusterCall(ctx context.Context, c *commonFlags, method, path string, in, out any) error {
	conn, err := a.resolve(ctx, c)
	if err != nil {
		return err
	}
	for attempt := 0; ; attempt++ {
		err = a.callAPI(ctx, c, conn, method, path, in, out)
		retryable := method == http.MethodGet || method == http.MethodDelete || nodeMarkPost(method, path)
		if err == nil || !retryable || attempt >= len(clusterReadRetryDelays) || !retryableRead(err) {
			return err
		}
		if c != nil && c.debug {
			a.note("aerolvm debug: %s %s failed (%v), retrying", method, path, err)
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(clusterReadRetryDelays[attempt]):
		}
	}
}

// nodeMarkPost is a POST that running twice leaves as running it once: it
// sets or clears a node's mark, or runs an evacuate pass (C9), which is
// safe to repeat: each move is a compare-and-swap on the old owner, a moved
// sandbox is no longer the node's, and stops and notices are idempotent. A
// leader change answers 503 with Retry-After, and `aerolvm drain
// --evacuate` retries it instead of failing the whole drain.
func nodeMarkPost(method, path string) bool {
	if method != http.MethodPost || !strings.HasPrefix(path, "/v1/cluster/nodes/") {
		return false
	}
	for _, suffix := range []string{"/cordon", "/uncordon", "/drain", "/evacuate"} {
		if strings.HasSuffix(path, suffix) {
			return true
		}
	}
	return false
}

// clusterReadRetryDelays bounds a read's retries: three more tries over about
// two seconds, short enough that a real outage still fails fast.
var clusterReadRetryDelays = []time.Duration{200 * time.Millisecond, 600 * time.Millisecond, 1200 * time.Millisecond}

// retryableRead is a transport failure (no HTTP answer at all) or a gateway
// or overload status; any other HTTP answer is final.
func retryableRead(err error) bool {
	var refusal *apiRefusal
	if errors.As(err, &refusal) {
		switch refusal.StatusCode {
		case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			return true
		}
		return false
	}
	return !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)
}

func (a *app) listNodes(ctx context.Context, c *commonFlags) ([]nodeRaw, error) {
	var resp struct {
		Members []json.RawMessage `json:"members"`
	}
	if err := a.clusterCall(ctx, c, http.MethodGet, "/v1/cluster/members", nil, &resp); err != nil {
		return nil, err
	}
	nodes := make([]nodeRaw, 0, len(resp.Members))
	for _, raw := range resp.Members {
		var rec nodeRecord
		if err := json.Unmarshal(raw, &rec); err != nil {
			return nil, fmt.Errorf("sandboxd sent an unreadable member: %w", err)
		}
		nodes = append(nodes, nodeRaw{raw: raw, rec: rec})
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].rec.NodeID < nodes[j].rec.NodeID })
	return nodes, nil
}

func (a *app) getNode(ctx context.Context, c *commonFlags, id string, sandboxIDs int) (nodeRaw, error) {
	path := "/v1/cluster/nodes/" + url.PathEscape(id)
	if sandboxIDs > 0 {
		path += "?sandboxes=" + strconv.Itoa(sandboxIDs)
	}
	var raw json.RawMessage
	if err := a.clusterCall(ctx, c, http.MethodGet, path, nil, &raw); err != nil {
		return nodeRaw{}, nodeNotFound(err, id)
	}
	var rec nodeRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nodeRaw{}, fmt.Errorf("sandboxd sent an unreadable node: %w", err)
	}
	return nodeRaw{raw: raw, rec: rec}, nil
}

// nodeNotFound words a 404 the way kubectl does.
func nodeNotFound(err error, id string) error {
	if agenttools.IsCode(err, agenttools.CodeNotFound) {
		return &agenttools.Error{Code: agenttools.CodeNotFound, HTTPStatus: http.StatusNotFound,
			Message: fmt.Sprintf("node %q not found", id), Hint: "run `aerolvm get nodes` to list them"}
	}
	return err
}

// outputFormat validates -o.
func outputFormat(c *commonFlags, output string, allowed ...string) (string, bool) {
	if output == "" && c.json {
		return "json", true
	}
	if output == "" {
		return "", true
	}
	for _, f := range allowed {
		if output == f {
			return output, true
		}
	}
	return output, false
}

// getNodes is `aerolvm get nodes […]`.
func getNodes(ctx context.Context, a *app, c *commonFlags, call kindCall) int {
	format, code := a.getFormat(c, call.output)
	if code >= 0 {
		return code
	}
	names := call.names
	nodes, err := a.listNodes(ctx, c)
	if err != nil {
		return a.fail(c, err, exitError)
	}
	if len(names) > 0 {
		byID := make(map[string]nodeRaw, len(nodes))
		for _, n := range nodes {
			byID[n.rec.NodeID] = n
		}
		picked := make([]nodeRaw, 0, len(names))
		for _, name := range names {
			n, ok := byID[name]
			if !ok {
				return a.fail(c, nodeNotFound(&agenttools.Error{Code: agenttools.CodeNotFound}, name), exitError)
			}
			picked = append(picked, n)
		}
		nodes = picked
	}
	switch format {
	case "json", "yaml":
		raws := make([]any, len(nodes))
		for i, n := range nodes {
			raws[i] = n.raw
		}
		a.printObjects(format, "nodes", raws, len(names) == 1)
		return exitOK
	case "name":
		for _, n := range nodes {
			fmt.Fprintf(a.stdout, "node/%s\n", n.rec.NodeID)
		}
		return exitOK
	}
	if len(nodes) == 0 {
		a.note("aerolvm: no nodes")
		return exitOK
	}
	tw := tabwriter.NewWriter(a.stdout, 0, 4, 3, ' ', 0)
	if format == "wide" {
		fmt.Fprintln(tw, "NAME\tROLE\tSTATUS\tVERSION\tSANDBOXES\tCPU\tMEMORY\tZONE\tAPI-URL")
	} else {
		fmt.Fprintln(tw, "NAME\tROLE\tSTATUS\tVERSION\tSANDBOXES")
	}
	for _, n := range nodes {
		r := n.rec
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s", r.NodeID, r.role(), r.status(), dash(r.Version), r.sandboxes())
		if format == "wide" {
			fmt.Fprintf(tw, "\t%s\t%s\t%s\t%s",
				percent(r.Capacity.ReservedCPU, r.Capacity.CPUBudget, r.hasHeartbeat()),
				percent(float64(r.Capacity.ReservedMemoryMB), float64(r.Capacity.MemoryBudgetMB), r.hasHeartbeat()),
				dash(r.Zone), dash(r.APIURL))
		}
		fmt.Fprintln(tw)
	}
	_ = tw.Flush()
	return exitOK
}

// describeNode is `aerolvm describe node <name>`.
func describeNode(ctx context.Context, a *app, c *commonFlags, call kindCall) int {
	if !a.oneName(c, call) {
		return exitUsage
	}
	format, code := a.describeFormat(c, call.output)
	if code >= 0 {
		return code
	}
	names := call.names
	n, err := a.getNode(ctx, c, names[0], 0)
	if err != nil {
		return a.fail(c, err, exitError)
	}
	if format != "" {
		a.printObjects(format, "nodes", []any{n.raw}, true)
		return exitOK
	}
	r := n.rec
	running := strconv.Itoa(r.SandboxesRunning)
	if !r.RunningKnown {
		running = fmt.Sprintf("unknown (no fresh capacity heartbeat; at most %d)", r.SandboxesOwned)
	}
	labels := make([]string, 0, len(r.Labels))
	for k, v := range r.Labels {
		labels = append(labels, k+"="+v)
	}
	sort.Strings(labels)
	tw := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
	rows := [][2]string{
		{"Name:", r.NodeID},
		{"Node name:", dash(r.NodeName)},
		{"Role:", r.role()},
		{"Status:", r.status()},
		{"Version:", dash(r.Version)},
		{"Voter:", strconv.FormatBool(r.Voter)},
		{"Leader:", strconv.FormatBool(r.Leader)},
		{"Cordoned:", strconv.FormatBool(r.Drained)},
		{"API URL:", dash(r.APIURL)},
		{"Internal URL:", dash(r.InternalURL)},
		{"Raft address:", dash(r.RaftAddr)},
		{"Data plane host:", dash(r.DataPlaneHost)},
		{"Public host:", dash(r.PublicHost)},
		{"FSM ops version:", strconv.Itoa(r.FSMOpsVersion)},
		{"Zone:", dash(r.Zone)},
		{"Labels:", dash(strings.Join(labels, ","))},
		{"Sandboxes owned:", strconv.Itoa(r.SandboxesOwned)},
		{"Sandboxes running:", running},
	}
	if r.hasHeartbeat() {
		rows = append(rows,
			[2]string{"CPU reserved:", fmt.Sprintf("%.1f of %.1f (%s)", r.Capacity.ReservedCPU, r.Capacity.CPUBudget, percent(r.Capacity.ReservedCPU, r.Capacity.CPUBudget, true))},
			[2]string{"Memory reserved:", fmt.Sprintf("%d MiB of %d MiB (%s)", r.Capacity.ReservedMemoryMB, r.Capacity.MemoryBudgetMB,
				percent(float64(r.Capacity.ReservedMemoryMB), float64(r.Capacity.MemoryBudgetMB), true))},
		)
	}
	for _, row := range rows {
		fmt.Fprintf(tw, "%s\t%s\n", row[0], row[1])
	}
	_ = tw.Flush()
	return exitOK
}

// deleteNodes is `aerolvm delete node <name>... [--force]`.
func deleteNodes(ctx context.Context, a *app, c *commonFlags, call kindCall) int {
	names, force := call.names, call.force
	if len(names) == 0 {
		return a.usageError(c, "delete", "name at least one node")
	}
	code := exitOK
	var results []any
	for _, name := range names {
		path := "/v1/cluster/nodes/" + url.PathEscape(name)
		if force {
			path += "?force=true"
		}
		var res map[string]any
		err := a.clusterCall(ctx, c, http.MethodDelete, path, nil, &res)
		switch {
		case agenttools.IsCode(err, agenttools.CodeNotFound):
			// Already gone counts as deleted: a retry never fails on its
			// own success (§5.2 rule 7).
			res = map[string]any{"node_id": name, "already_gone": true}
		case err != nil:
			code = a.fail(c, err, exitError)
			continue
		}
		results = append(results, res)
		if !c.json {
			fmt.Fprintf(a.stdout, "node %q deleted\n", name)
		}
	}
	if c.json && len(results) > 0 {
		a.printJSON(jsonResults(results))
	}
	return code
}

func runCordon(ctx context.Context, a *app, args []string) int {
	return a.setCordon(ctx, "cordon", args, true)
}

func runUncordon(ctx context.Context, a *app, args []string) int {
	return a.setCordon(ctx, "uncordon", args, false)
}

func (a *app) setCordon(ctx context.Context, verbName string, args []string, on bool) int {
	fs, c := a.newFlagSet(verbName)
	pos, _, err := parseArgs(fs, args)
	if err != nil {
		return a.flagError(c, verbName, err)
	}
	if len(pos) == 0 {
		return a.usageError(c, verbName, "name at least one node")
	}
	code := exitOK
	var results []any
	for _, name := range pos {
		if err := a.cordon(ctx, c, name, on); err != nil {
			code = a.fail(c, err, exitError)
			continue
		}
		results = append(results, map[string]any{"node_id": name, "cordoned": on})
		if !c.json {
			fmt.Fprintf(a.stdout, "node/%s %sed\n", name, verbName)
		}
	}
	if c.json && len(results) > 0 {
		a.printJSON(jsonResults(results))
	}
	return code
}

// cordon sets or clears the drain mark. A server older than the cordon route
// answers 404 there, so cordon falls back to the drain route it has always
// had (the same mark).
func (a *app) cordon(ctx context.Context, c *commonFlags, name string, on bool) error {
	base := "/v1/cluster/nodes/" + url.PathEscape(name)
	if !on {
		return a.clusterCall(ctx, c, http.MethodPost, base+"/uncordon", nil, nil)
	}
	err := a.clusterCall(ctx, c, http.MethodPost, base+"/cordon", nil, nil)
	if agenttools.IsCode(err, agenttools.CodeNotFound) {
		err = a.clusterCall(ctx, c, http.MethodPost, base+"/drain", nil, nil)
	}
	return err
}

func runDrain(ctx context.Context, a *app, args []string) int {
	fs, c := a.newFlagSet("drain")
	var deleteSandboxes, migrate, evacuate bool
	timeout := 10 * time.Minute
	fs.BoolVar(&deleteSandboxes, "delete-sandboxes", false, "")
	fs.BoolVar(&migrate, "migrate", false, "")
	fs.BoolVar(&evacuate, "evacuate", false, "")
	fs.DurationVar(&timeout, "timeout", timeout, "")
	pos, _, err := parseArgs(fs, args)
	if err != nil {
		return a.flagError(c, "drain", err)
	}
	if len(pos) != 1 {
		return a.usageError(c, "drain", "expected one node name")
	}
	if timeout < 0 {
		return a.usageError(c, "drain", "--timeout must not be negative")
	}
	name := pos[0]
	if _, err := a.getNode(ctx, c, name, 0); err != nil {
		return a.fail(c, err, exitError)
	}
	if err := a.cordon(ctx, c, name, true); err != nil {
		return a.fail(c, err, exitError)
	}
	if !c.json {
		fmt.Fprintf(a.stdout, "node/%s cordoned\n", name)
	}
	result := map[string]any{"node_id": name, "cordoned": true}
	if migrate {
		moved, err := a.migrateWasm(ctx, c, name)
		if err != nil {
			return a.fail(c, err, exitError)
		}
		result["migrated"] = moved
	}
	var deleted, evacuated []string
	movable := evacuate
	waitCtx := ctx
	if timeout > 0 {
		var cancel context.CancelFunc
		waitCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	every := a.pollEvery
	if every <= 0 {
		every = 2 * time.Second
	}
	for {
		if movable {
			// One decommission pass (C9): the leader moves up to a batch of
			// the node's failover.policy=recreate sandboxes to other
			// workers, stop then start, and tells the owners of the rest.
			var res evacuateResult
			if err := a.clusterCall(waitCtx, c, http.MethodPost, "/v1/cluster/nodes/"+url.PathEscape(name)+"/evacuate", nil, &res); err != nil {
				if waitCtx.Err() != nil {
					return a.fail(c, drainTimeout(name, timeout, -1), exitError)
				}
				return a.fail(c, err, exitError)
			}
			for _, id := range res.Moved {
				evacuated = append(evacuated, id)
				a.progress(c, "aerolvm: moved sandbox %s off %s", id, name)
			}
			for id, why := range res.Failed {
				a.progress(c, "aerolvm: moving sandbox %s failed (retrying): %s", id, why)
			}
			movable = res.RemainingMovable > 0
		}
		n, err := a.getNode(waitCtx, c, name, idsIf(deleteSandboxes))
		if err != nil {
			if waitCtx.Err() != nil {
				return a.fail(c, drainTimeout(name, timeout, -1), exitError)
			}
			return a.fail(c, err, exitError)
		}
		left := n.rec.SandboxesRunning
		if deleteSandboxes {
			left = n.rec.SandboxesOwned
			for _, id := range n.rec.SandboxIDs {
				if err := a.clusterCall(waitCtx, c, http.MethodDelete, "/v1/sandboxes/"+url.PathEscape(id), nil, nil); err != nil && !agenttools.IsCode(err, agenttools.CodeNotFound) {
					a.progress(c, "aerolvm: deleting sandbox %s failed (retrying): %v", id, agenttools.Classify(err).Message)
					continue
				}
				if !contains(deleted, id) {
					deleted = append(deleted, id)
					a.progress(c, "aerolvm: deleted sandbox %s", id)
				}
			}
		}
		if left == 0 {
			break
		}
		a.progress(c, "aerolvm: waiting for node %s: %d sandbox(es) left", name, left)
		select {
		case <-waitCtx.Done():
			return a.fail(c, drainTimeout(name, timeout, left), exitError)
		case <-time.After(every):
		}
	}
	result["drained"] = true
	if evacuate {
		result["evacuated"] = append([]string{}, evacuated...)
	}
	if deleteSandboxes {
		result["deleted"] = append([]string{}, deleted...)
	}
	if c.json {
		a.printJSON(result)
		return exitOK
	}
	fmt.Fprintf(a.stdout, "node/%s drained\n", name)
	return exitOK
}

// evacuateResult is the part of an evacuate pass drain reads.
type evacuateResult struct {
	Moved            []string          `json:"moved"`
	Failed           map[string]string `json:"failed"`
	RemainingMovable int               `json:"remaining_movable"`
}

// progress is a note that --json leaves out, so stderr then carries only
// the error envelope a script parses.
func (a *app) progress(c *commonFlags, format string, args ...any) {
	if !c.json {
		a.note(format, args...)
	}
}

func idsIf(want bool) int {
	if want {
		return nodeSandboxIDPage
	}
	return 0
}

func drainTimeout(name string, timeout time.Duration, left int) error {
	msg := fmt.Sprintf("node %s still has sandboxes after %s", name, timeout)
	if left >= 0 {
		msg = fmt.Sprintf("node %s still has %d sandbox(es) after %s", name, left, timeout)
	}
	return &agenttools.Error{Code: agenttools.CodeTimeout, Message: msg,
		Hint: "the node stays cordoned; stop or destroy what is left, or run drain again with --delete-sandboxes"}
}

// migrateWasm moves the node's WASM sandboxes with the existing live
// migration route, one at a time, to the first ready worker that is not
// cordoned. Other runtimes stay; Firecracker moves through snapshots later.
func (a *app) migrateWasm(ctx context.Context, c *commonFlags, name string) ([]string, error) {
	n, err := a.getNode(ctx, c, name, nodeSandboxIDPage)
	if err != nil {
		return nil, err
	}
	nodes, err := a.listNodes(ctx, c)
	if err != nil {
		return nil, err
	}
	target := ""
	for _, m := range nodes {
		r := m.rec
		if r.NodeID != name && r.Alive && !r.Drained && (r.Role == "worker" || r.Role == "mixed" || r.Role == "") {
			target = r.NodeID
			break
		}
	}
	moved := []string{}
	for _, id := range n.rec.SandboxIDs {
		var sb struct {
			Runtime string `json:"runtime"`
		}
		if err := a.clusterCall(ctx, c, http.MethodGet, "/v1/sandboxes/"+url.PathEscape(id), nil, &sb); err != nil || sb.Runtime != "wasm" {
			continue
		}
		if target == "" {
			return moved, &agenttools.Error{Code: agenttools.CodeUnavailable, Message: "no ready, uncordoned worker to migrate WASM sandboxes to"}
		}
		body := map[string]string{"sandbox_id": id, "target_node_id": target}
		if err := a.clusterCall(ctx, c, http.MethodPost, "/v1/cluster/wasm-migrate", body, nil); err != nil {
			a.progress(c, "aerolvm: migrating sandbox %s failed: %v", id, agenttools.Classify(err).Message)
			continue
		}
		moved = append(moved, id)
		a.progress(c, "aerolvm: migrated sandbox %s to %s", id, target)
	}
	return moved, nil
}

func runClusterInfo(ctx context.Context, a *app, args []string) int {
	fs, c := a.newFlagSet("cluster-info")
	pos, _, err := parseArgs(fs, args)
	if err != nil {
		return a.flagError(c, "cluster-info", err)
	}
	if len(pos) > 0 {
		return a.usageError(c, "cluster-info", "unexpected argument %q", pos[0])
	}
	conn, err := a.resolve(ctx, c)
	if err != nil {
		return a.fail(c, err, exitError)
	}
	var health struct {
		Version string `json:"version"`
	}
	if err := a.callAPI(ctx, c, conn, http.MethodGet, "/health", nil, &health); err != nil {
		return a.fail(c, err, exitError)
	}
	var leader struct {
		Leader string `json:"leader"`
	}
	if err := a.callAPI(ctx, c, conn, http.MethodGet, "/v1/cluster/leader", nil, &leader); err != nil {
		return a.fail(c, err, exitError)
	}
	nodes, err := a.listNodes(ctx, c)
	if err != nil {
		return a.fail(c, err, exitError)
	}
	roles := map[string]int{}
	alive, voters, minFV := 0, 0, -1
	leaderURL := ""
	for _, n := range nodes {
		r := n.rec
		roles[r.role()]++
		if r.Alive {
			alive++
			if minFV < 0 || r.FSMOpsVersion < minFV {
				minFV = r.FSMOpsVersion
			}
		}
		if r.Voter {
			voters++
		}
		if r.NodeID == leader.Leader {
			leaderURL = r.APIURL
		}
	}
	info := map[string]any{
		"api_url": conn.apiURL, "server_version": health.Version, "leader": leader.Leader,
		"members": len(nodes), "alive": alive, "voters": voters, "roles": roles, "fsm_ops_version": max(minFV, 0),
	}
	if c.json {
		a.printJSON(info)
		return exitOK
	}
	fmt.Fprintf(a.stdout, "sandboxd is running at %s (version %s)\n", conn.apiURL, dash(health.Version))
	if leader.Leader == "" {
		fmt.Fprintln(a.stdout, "Cluster mode is off: this is a single node.")
		return exitOK
	}
	fmt.Fprintf(a.stdout, "Leader: %s (%s)\n", leader.Leader, dash(leaderURL))
	parts := make([]string, 0, len(roles))
	for role, count := range roles {
		parts = append(parts, fmt.Sprintf("%s %d", role, count))
	}
	sort.Strings(parts)
	fmt.Fprintf(a.stdout, "Members: %d alive of %d (%s); %d Raft voter(s)\n", alive, len(nodes), strings.Join(parts, ", "), voters)
	fmt.Fprintf(a.stdout, "Cluster version: FSM ops %d (the lowest any live member runs)\n", max(minFV, 0))
	return exitOK
}

// serverVersion asks the configured sandboxd for its build. /health needs
// no token, but it needs the URL, so it follows the same connection rules.
func (a *app) serverVersion(ctx context.Context, c *commonFlags) (string, string, error) {
	conn, err := a.prepare(ctx, c)
	if err != nil {
		return "", "", err
	}
	var health struct {
		Version string `json:"version"`
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := a.callAPI(ctx, c, conn, http.MethodGet, "/health", nil, &health); err != nil {
		return "", conn.apiURL, err
	}
	return health.Version, conn.apiURL, nil
}
