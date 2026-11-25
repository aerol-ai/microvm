package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/aerol-ai/microvm/internal/agenttools"
	"github.com/aerol-ai/microvm/pkg/models"
)

// The runtime kind: `aerolvm get runtimes` lists GET /v1/runtimes, every
// runtime a create accepts, what each can do and whether this deployment
// offers it now (plans/security-gaps-m1-m4.md §11). It only reads, so it
// takes get and nothing else. The server decides what a caller sees: a
// node count reaches fleet admins only, and no node is ever named.

type runtimeRaw struct {
	raw json.RawMessage
	rec models.RuntimeListEntry
}

func (a *app) listRuntimes(ctx context.Context, c *commonFlags) ([]runtimeRaw, error) {
	var resp struct {
		Runtimes []json.RawMessage `json:"runtimes"`
	}
	if err := a.clusterCall(ctx, c, http.MethodGet, "/v1/runtimes", nil, &resp); err != nil {
		return nil, err
	}
	out := make([]runtimeRaw, 0, len(resp.Runtimes))
	for _, raw := range resp.Runtimes {
		var rec models.RuntimeListEntry
		if err := json.Unmarshal(raw, &rec); err != nil {
			return nil, fmt.Errorf("sandboxd sent an unreadable runtime: %w", err)
		}
		out = append(out, runtimeRaw{raw: raw, rec: rec})
	}
	return out, nil
}

// pickRuntimes keeps the named runtimes, in the order they were named.
func pickRuntimes(all []runtimeRaw, names []string) ([]runtimeRaw, error) {
	out := make([]runtimeRaw, 0, len(names))
	for _, name := range names {
		found := false
		for _, rt := range all {
			if rt.rec.Name == name {
				out = append(out, rt)
				found = true
				break
			}
		}
		if !found {
			return nil, &agenttools.Error{Code: agenttools.CodeNotFound, HTTPStatus: http.StatusNotFound,
				Message: fmt.Sprintf("runtime %q not found", name), Hint: "run `aerolvm get runtimes` to list them"}
		}
	}
	return out, nil
}

func getRuntimes(ctx context.Context, a *app, c *commonFlags, call kindCall) int {
	format, code := a.getFormat(c, call.output)
	if code >= 0 {
		return code
	}
	// The server's order is kept: it is the order the runtime names are
	// defined in, not one a sort would improve.
	runtimes, err := a.listRuntimes(ctx, c)
	if err == nil && len(call.names) > 0 {
		runtimes, err = pickRuntimes(runtimes, call.names)
	}
	if err != nil {
		return a.fail(c, err, exitError)
	}
	switch format {
	case "json", "yaml":
		items := make([]any, len(runtimes))
		for i, rt := range runtimes {
			items[i] = rt.raw
		}
		a.printObjects(format, "runtimes", items, len(call.names) == 1)
		return exitOK
	case "name":
		names := make([]string, len(runtimes))
		for i, rt := range runtimes {
			names[i] = rt.rec.Name
		}
		a.printNames("runtime", names)
		return exitOK
	}
	if len(runtimes) == 0 {
		a.note("aerolvm: no runtimes")
		return exitOK
	}
	header := "NAME\tISOLATION\tBACKEND\tAVAILABLE\tSNAPSHOTS\tPAUSE\tMOVES\tWARM POOL"
	if format == "wide" {
		header += "\tCONFIDENTIAL\tCHECKPOINT MEMORY\tNODES"
	}
	rows := make([][]string, 0, len(runtimes))
	for _, rt := range runtimes {
		r := rt.rec
		f := r.Features
		row := []string{r.Name, dash(r.Isolation), dash(r.Backend), yesNo(r.Available),
			yesNo(f.Snapshots), yesNo(f.Pause), dash(f.Moves), dash(f.WarmPool)}
		if format == "wide" {
			row = append(row, yesNo(f.Confidential), checkpointLimit(r.Limits), nodeCount(r.Nodes))
		}
		rows = append(rows, row)
	}
	table(a.stdout, header, rows)
	return exitOK
}

// checkpointLimit is the most memory a checkpoint restores, or "-" when the
// runtime has no such limit.
func checkpointLimit(l *models.RuntimeLimits) string {
	if l == nil || l.MaxCheckpointMemoryMB <= 0 {
		return "-"
	}
	return strconv.Itoa(l.MaxCheckpointMemoryMB) + "Mi"
}

// nodeCount is "-" for a caller the server sends no count to (anyone but a
// fleet admin).
func nodeCount(n *int) string {
	if n == nil {
		return "-"
	}
	return strconv.Itoa(*n)
}
