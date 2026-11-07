package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/aerol-ai/microvm/internal/agenttools"
	"github.com/aerol-ai/microvm/pkg/models"
)

// The snapshot kind: get, describe and delete over /v1/snapshots. They read
// the server's objects raw, as the node verbs do, so -o json and -o yaml
// keep every field the server sends.

// snapshotListPage is the page size get asks for (the server's cap).
const snapshotListPage = 500

type snapshotRaw struct {
	raw json.RawMessage
	rec models.SandboxSnapshot
}

func (a *app) listSnapshots(ctx context.Context, c *commonFlags) ([]snapshotRaw, error) {
	var out []snapshotRaw
	after := ""
	for {
		q := url.Values{"limit": {strconv.Itoa(snapshotListPage)}}
		if after != "" {
			q.Set("starting_after", after)
		}
		var page struct {
			Snapshots []json.RawMessage `json:"snapshots"`
			HasMore   bool              `json:"has_more"`
		}
		if err := a.clusterCall(ctx, c, http.MethodGet, "/v1/snapshots?"+q.Encode(), nil, &page); err != nil {
			return nil, err
		}
		last := after
		for _, raw := range page.Snapshots {
			s, err := decodeSnapshot(raw)
			if err != nil {
				return nil, err
			}
			out = append(out, s)
			last = s.rec.Name
		}
		// The cursor is the last name; one that does not move would loop.
		if !page.HasMore || last == after {
			return out, nil
		}
		after = last
	}
}

func decodeSnapshot(raw json.RawMessage) (snapshotRaw, error) {
	var rec models.SandboxSnapshot
	if err := json.Unmarshal(raw, &rec); err != nil {
		return snapshotRaw{}, fmt.Errorf("sandboxd sent an unreadable snapshot: %w", err)
	}
	return snapshotRaw{raw: raw, rec: rec}, nil
}

func (a *app) getSnapshot(ctx context.Context, c *commonFlags, name string) (snapshotRaw, error) {
	var raw json.RawMessage
	if err := a.clusterCall(ctx, c, http.MethodGet, "/v1/snapshots/"+url.PathEscape(name), nil, &raw); err != nil {
		return snapshotRaw{}, notFoundAs(err, "snapshot", name, "aerolvm get snapshots")
	}
	return decodeSnapshot(raw)
}

// notFoundAs words a 404 the way kubectl does: `snapshot "x" not found`.
func notFoundAs(err error, kind, name, list string) error {
	if agenttools.IsCode(err, agenttools.CodeNotFound) {
		return &agenttools.Error{Code: agenttools.CodeNotFound, HTTPStatus: http.StatusNotFound,
			Message: fmt.Sprintf("%s %q not found", kind, name), Hint: "run `" + list + "` to list them"}
	}
	return err
}

func getSnapshots(ctx context.Context, a *app, c *commonFlags, call kindCall) int {
	format, code := a.getFormat(c, call.output)
	if code >= 0 {
		return code
	}
	var snaps []snapshotRaw
	if len(call.names) > 0 {
		for _, name := range call.names {
			s, err := a.getSnapshot(ctx, c, name)
			if err != nil {
				return a.fail(c, err, exitError)
			}
			snaps = append(snaps, s)
		}
	} else {
		var err error
		if snaps, err = a.listSnapshots(ctx, c); err != nil {
			return a.fail(c, err, exitError)
		}
	}
	switch format {
	case "json", "yaml":
		items := make([]any, len(snaps))
		for i, s := range snaps {
			items[i] = s.raw
		}
		a.printObjects(format, "snapshots", items, len(call.names) == 1)
		return exitOK
	case "name":
		names := make([]string, len(snaps))
		for i, s := range snaps {
			names[i] = s.rec.Name
		}
		a.printNames("snapshot", names)
		return exitOK
	}
	if len(snaps) == 0 {
		a.note("aerolvm: no snapshots")
		return exitOK
	}
	now := a.clock()
	header := "NAME\tSOURCE\tAGE"
	if format == "wide" {
		header += "\tIMAGE\tDISTRIBUTION"
	}
	rows := make([][]string, 0, len(snaps))
	for _, s := range snaps {
		r := s.rec
		row := []string{r.Name, dash(r.SourceSandboxID), age(now, r.CreatedAt)}
		if format == "wide" {
			row = append(row, dash(r.Image), dash(r.ImageDistributionMode))
		}
		rows = append(rows, row)
	}
	table(a.stdout, header, rows)
	return exitOK
}

func describeSnapshot(ctx context.Context, a *app, c *commonFlags, call kindCall) int {
	if !a.oneName(c, call) {
		return exitUsage
	}
	format, code := a.describeFormat(c, call.output)
	if code >= 0 {
		return code
	}
	s, err := a.getSnapshot(ctx, c, call.names[0])
	if err != nil {
		return a.fail(c, err, exitError)
	}
	if format != "" {
		a.printObjects(format, "snapshots", []any{s.raw}, true)
		return exitOK
	}
	r, now := s.rec, a.clock()
	verified := "-"
	if r.ImageVerifiedAt != nil {
		verified = whenAgo(now, *r.ImageVerifiedAt)
	}
	fields(a.stdout, [][2]string{
		{"Name:", r.Name},
		{"Source sandbox:", dash(r.SourceSandboxID)},
		{"Created:", whenAgo(now, r.CreatedAt)},
		{"Image:", dash(r.Image)},
		{"Image ID:", dash(r.ImageID)},
		{"Distribution:", dash(r.ImageDistributionMode)},
		{"Digest:", dash(r.ImageDigest)},
		{"Registry ref:", dash(r.ImageRegistryRef)},
		{"Verified:", verified},
		{"Entrypoint:", dash(strings.Join(r.Entrypoint, " "))},
	})
	return exitOK
}

// deleteSnapshots deletes each named snapshot. One already gone counts as
// deleted, so a retry never fails on its own success (§5.2 rule 7).
func deleteSnapshots(ctx context.Context, a *app, c *commonFlags, call kindCall) int {
	if len(call.names) == 0 {
		return a.usageError(c, "delete", "name at least one snapshot")
	}
	code := exitOK
	var results []any
	for _, name := range call.names {
		res := map[string]any{"name": name, "deleted": true}
		err := a.clusterCall(ctx, c, http.MethodDelete, "/v1/snapshots/"+url.PathEscape(name), nil, nil)
		switch {
		case agenttools.IsCode(err, agenttools.CodeNotFound):
			res["already_gone"] = true
		case err != nil:
			code = a.fail(c, err, exitError)
			continue
		}
		results = append(results, res)
		if !c.json {
			fmt.Fprintf(a.stdout, "snapshot %q deleted\n", name)
		}
	}
	if c.json && len(results) > 0 {
		a.printJSON(jsonResults(results))
	}
	return code
}
