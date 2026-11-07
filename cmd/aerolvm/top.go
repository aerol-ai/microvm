package main

import (
	"context"
	"net/http"
	"net/url"
	"strconv"

	"github.com/aerol-ai/microvm/internal/agenttools"
)

// runTop is `aerolvm top nodes` (plans/kubectl-style-cluster-ops.md §3.2):
// what each node has reserved for sandboxes, against its budget. kubectl top
// shows live usage; sandboxd schedules on reservations, so that is what
// decides whether the next sandbox fits.
//
// The numbers come from each member's capacity heartbeat in
// /v1/cluster/members. A single node has no members, so it reads
// /v1/capacity instead and the row is named after the API host.
func runTop(ctx context.Context, a *app, args []string) int {
	fs, c := a.newFlagSet("top")
	var output string
	fs.StringVar(&output, "o", "", "")
	fs.StringVar(&output, "output", "", "")
	pos, _, err := parseArgs(fs, args)
	if err != nil {
		return a.flagError(c, "top", err)
	}
	if len(pos) == 0 {
		return a.usageError(c, "top", "expected a kind: aerolvm top nodes")
	}
	if kind, ok := lookupKind(pos[0]); !ok || kind != kindNode {
		return a.usageError(c, "top", "top takes only nodes, got %q", pos[0])
	}
	format, ok := outputFormat(c, output, "json", "yaml")
	if !ok {
		return a.usageError(c, "top", "-o must be json or yaml, got %q", format)
	}
	nodes, err := a.listNodes(ctx, c)
	if err != nil {
		return a.fail(c, err, exitError)
	}
	if len(nodes) == 0 {
		local, err := a.localCapacity(ctx, c)
		if err != nil {
			return a.fail(c, err, exitError)
		}
		nodes = []nodeRaw{{rec: local}}
	}
	if names := pos[1:]; len(names) > 0 {
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
	type usage struct {
		Node           string  `json:"node_id"`
		Known          bool    `json:"known"`
		CPU            float64 `json:"cpu_reserved"`
		CPUBudget      float64 `json:"cpu_budget"`
		MemoryMB       int     `json:"memory_reserved_mb"`
		MemoryBudgetMB int     `json:"memory_budget_mb"`
		Sandboxes      int     `json:"sandboxes"`
	}
	items := make([]any, 0, len(nodes))
	rows := make([][]string, 0, len(nodes))
	for _, n := range nodes {
		r, known := n.rec, n.rec.hasHeartbeat()
		u := usage{Node: r.NodeID, Known: known}
		row := []string{r.NodeID, "-", "-", "-", "-", "-"}
		if known {
			u.CPU, u.CPUBudget = r.Capacity.ReservedCPU, r.Capacity.CPUBudget
			u.MemoryMB, u.MemoryBudgetMB = r.Capacity.ReservedMemoryMB, r.Capacity.MemoryBudgetMB
			u.Sandboxes = max(r.Capacity.SandboxesActive-r.Capacity.ParkedSlots, 0)
			row = []string{r.NodeID,
				strconv.FormatFloat(u.CPU, 'f', 1, 64), percent(u.CPU, u.CPUBudget, true),
				strconv.Itoa(u.MemoryMB), percent(float64(u.MemoryMB), float64(u.MemoryBudgetMB), true),
				strconv.Itoa(u.Sandboxes)}
		}
		items = append(items, u)
		rows = append(rows, row)
	}
	if format != "" {
		a.printObjects(format, "nodes", items, false)
		return exitOK
	}
	table(a.stdout, "NAME\tCPU(cores)\tCPU%\tMEMORY(MiB)\tMEMORY%\tSANDBOXES", rows)
	return exitOK
}

// localCapacity reads a single node's capacity as a node record.
func (a *app) localCapacity(ctx context.Context, c *commonFlags) (nodeRecord, error) {
	conn, err := a.resolve(ctx, c)
	if err != nil {
		return nodeRecord{}, err
	}
	var rec nodeRecord
	if err := a.clusterCall(ctx, c, http.MethodGet, "/v1/capacity", nil, &rec.Capacity); err != nil {
		return nodeRecord{}, err
	}
	rec.NodeID = conn.apiURL
	if u, err := url.Parse(conn.apiURL); err == nil && u.Hostname() != "" {
		rec.NodeID = u.Hostname()
	}
	return rec, nil
}
