package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/aerol-ai/microvm/internal/agenttools"
	"github.com/aerol-ai/microvm/pkg/identitywire"
	"github.com/aerol-ai/microvm/pkg/models"
)

// The token kind: scoped API tokens (aerolvm token) in kubectl grammar.
// There is no GET /v1/tokens/{id}, so get and describe read the list and
// pick from it; delete is revoke.

type tokenRaw struct {
	raw json.RawMessage
	rec models.APIToken
}

func (a *app) listTokens(ctx context.Context, c *commonFlags) ([]tokenRaw, error) {
	var resp struct {
		Tokens []json.RawMessage `json:"tokens"`
	}
	if err := a.clusterCall(ctx, c, http.MethodGet, "/v1/tokens", nil, &resp); err != nil {
		return nil, err
	}
	out := make([]tokenRaw, 0, len(resp.Tokens))
	for _, raw := range resp.Tokens {
		var rec models.APIToken
		if err := json.Unmarshal(raw, &rec); err != nil {
			return nil, fmt.Errorf("sandboxd sent an unreadable token: %w", err)
		}
		out = append(out, tokenRaw{raw: raw, rec: rec})
	}
	return out, nil
}

// pickTokens keeps the tokens each ref names: a token ID (or a pasted
// token, whose ID is its first part), or else a name. Names are unique only
// within a team, so a name can pick several.
func pickTokens(all []tokenRaw, refs []string) ([]tokenRaw, error) {
	var out []tokenRaw
	for _, ref := range refs {
		id, isID := identitywire.APITokenIDFrom(ref)
		found := false
		for _, t := range all {
			if (isID && t.rec.ID == id) || (!isID && t.rec.Name == ref) {
				out = append(out, t)
				found = true
			}
		}
		if !found {
			return nil, &agenttools.Error{Code: agenttools.CodeNotFound, HTTPStatus: http.StatusNotFound,
				Message: fmt.Sprintf("token %q not found", ref), Hint: "run `aerolvm get tokens` to list them"}
		}
	}
	return out, nil
}

func getTokens(ctx context.Context, a *app, c *commonFlags, call kindCall) int {
	format, code := a.getFormat(c, call.output)
	if code >= 0 {
		return code
	}
	tokens, err := a.listTokens(ctx, c)
	if err == nil && len(call.names) > 0 {
		tokens, err = pickTokens(tokens, call.names)
	}
	if err != nil {
		return a.fail(c, err, exitError)
	}
	switch format {
	case "json", "yaml":
		items := make([]any, len(tokens))
		for i, t := range tokens {
			items[i] = t.raw
		}
		a.printObjects(format, "tokens", items, len(call.names) == 1 && len(tokens) == 1)
		return exitOK
	case "name":
		ids := make([]string, len(tokens))
		for i, t := range tokens {
			ids[i] = t.rec.ID
		}
		a.printNames("token", ids)
		return exitOK
	}
	if len(tokens) == 0 {
		a.note("aerolvm: no API tokens")
		return exitOK
	}
	recs := make([]models.APIToken, len(tokens))
	for i, t := range tokens {
		recs[i] = t.rec
	}
	a.printTokenTable(recs, format == "wide")
	return exitOK
}

func describeToken(ctx context.Context, a *app, c *commonFlags, call kindCall) int {
	if !a.oneName(c, call) {
		return exitUsage
	}
	format, code := a.describeFormat(c, call.output)
	if code >= 0 {
		return code
	}
	tokens, err := a.listTokens(ctx, c)
	if err == nil {
		tokens, err = pickTokens(tokens, call.names)
	}
	if err != nil {
		return a.fail(c, err, exitError)
	}
	if format != "" {
		items := make([]any, len(tokens))
		for i, t := range tokens {
			items[i] = t.raw
		}
		a.printObjects(format, "tokens", items, true)
		return exitOK
	}
	now := a.clock()
	for i, t := range tokens {
		if i > 0 {
			fmt.Fprintln(a.stdout)
		}
		r := t.rec
		expires := r.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z")
		if r.Expired {
			expires += " (expired)"
		} else if left := r.ExpiresAt.Sub(now); left > 0 {
			expires += " (" + inDays(left) + ")"
		}
		fields(a.stdout, [][2]string{
			{"ID:", r.ID},
			{"Name:", r.Name},
			{"Role:", r.Role},
			{"Team:", teamWords(r.Team)},
			{"Created:", whenAgo(now, r.CreatedAt)},
			{"Created by:", dash(r.CreatedBy)},
			{"Expires:", expires},
		})
	}
	return exitOK
}

// deleteTokens revokes each token by ID. Only IDs: a name is unique only
// within a team, and a delete must never pick more than it was told to.
func deleteTokens(ctx context.Context, a *app, c *commonFlags, call kindCall) int {
	if len(call.names) == 0 {
		return a.usageError(c, "delete", "name at least one token id (tok_…)")
	}
	ids := make([]string, len(call.names))
	for i, ref := range call.names {
		id, ok := identitywire.APITokenIDFrom(ref)
		if !ok {
			return a.usageError(c, "delete", "%q is not a token id: an id looks like tok_ followed by 12 letters or digits", ref)
		}
		ids[i] = id
	}
	code := exitOK
	var results []any
	for _, id := range ids {
		res := map[string]any{"revoked": id}
		err := a.clusterCall(ctx, c, http.MethodDelete, "/v1/tokens/"+url.PathEscape(id), nil, nil)
		switch {
		case agenttools.IsCode(err, agenttools.CodeNotFound):
			res["already_gone"] = true
		case err != nil:
			code = a.fail(c, err, exitError)
			continue
		}
		results = append(results, res)
		if !c.json {
			fmt.Fprintf(a.stdout, "token %q deleted\n", id)
		}
	}
	if c.json && len(results) > 0 {
		a.printJSON(jsonResults(results))
	}
	return code
}
