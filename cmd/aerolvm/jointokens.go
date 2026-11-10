package main

import (
	"context"
	"encoding/json"
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

// Join tokens from the laptop (plans/kubectl-style-cluster-ops.md §3.2):
// `aerolvm join-command` makes one and prints the line a new machine runs;
// `get jointokens` and `delete jointoken` list and revoke them. They call
// the fleet.admin /v1/cluster/join-tokens routes; the CLI keeps no server
// types (deps_test.go), so the wire shapes are declared here.

const kindJoinToken = "jointoken"

// getJoinTokensKind and deleteJoinTokensKind plug join tokens into the
// kind table (resourceKinds).
func getJoinTokensKind(ctx context.Context, a *app, c *commonFlags, call kindCall) int {
	return getJoinTokens(ctx, a, c, call.names, call.output)
}

func deleteJoinTokensKind(ctx context.Context, a *app, c *commonFlags, call kindCall) int {
	return deleteJoinTokens(ctx, a, c, call.names)
}

// joinInstallerURL is the installer the printed command fetches.
const joinInstallerURL = "https://aerolvm.aerol.ai"

// joinTokenCreated is POST /v1/cluster/join-tokens' answer.
type joinTokenCreated struct {
	Token      string     `json:"token"`
	ID         string     `json:"id"`
	Role       string     `json:"role"`
	Reusable   bool       `json:"reusable"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	CACertHash string     `json:"ca_cert_hash"`
	JoinURLs   []string   `json:"join_urls"`
	Warning    string     `json:"warning,omitempty"`
	// The answering node's public setup, which the printed line repeats.
	Domain               string `json:"domain,omitempty"`
	IngressAdvertiseHost string `json:"ingress_advertise_host,omitempty"`
	TLSIssuer            string `json:"tls_issuer,omitempty"`
}

// joinTokenInfo is one token in GET /v1/cluster/join-tokens.
type joinTokenInfo struct {
	ID        string     `json:"id"`
	Role      string     `json:"role"`
	CreatedBy string     `json:"created_by,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	Reusable  bool       `json:"reusable"`
	Expired   bool       `json:"expired"`
	UsedBy    []struct {
		NodeID string `json:"node_id"`
	} `json:"used_by"`
}

func (t joinTokenInfo) status() string {
	switch {
	case t.Expired:
		return "Expired"
	case !t.Reusable && len(t.UsedBy) > 0:
		return "Used"
	}
	return "Valid"
}

func (t joinTokenInfo) expires() string {
	if t.ExpiresAt == nil {
		return "never"
	}
	return t.ExpiresAt.UTC().Format(time.RFC3339)
}

const joinCommandHelp = `Make a join token and print the command that adds a machine to the cluster.

Usage: aerolvm join-command [--role worker|ingress|server|mixed] [--ttl 2h] [--reusable]

Run the printed line on the new machine, as is: it installs AerolVM (the
version the cluster runs) and joins it with the token. When the cluster has
a domain, the line also carries its --domain and DNS options, so the node
serves the same addresses; it reads your Cloudflare API token from
$CLOUDFLARE_API_TOKEN on that machine, so set that first. The token decides
the role. It works for one machine unless --reusable, and lasts 2h unless --ttl says
otherwise; server tokens last at most 24h. --ttl 0 never expires and is only
for worker and ingress tokens (for autoscaling); in enterprise mode the
cluster also needs wrapped key custody for it. Each call makes a new token.

Stdout is only the command (with --json: the token object and "command").
Needs an admin.

  --role ROLE       worker (default), ingress or server; or mixed (a server
                    that also runs sandboxes and takes traffic), or a list
                    such as worker,ingress: the token of its strongest job,
                    and the line adds --role
  --ttl DURATION    like 30m, 2h or 24h; 0 for never (worker and ingress)
  --reusable        let many machines join with the same token

Examples:
  aerolvm join-command
  aerolvm join-command --role server
  aerolvm join-command --role mixed
  aerolvm join-command --role worker --ttl 0 --reusable
`

func runJoinCommand(ctx context.Context, a *app, args []string) int {
	fs, c := a.newFlagSet("join-command")
	role := "worker"
	var ttl string
	var reusable bool
	fs.StringVar(&role, "role", role, "")
	fs.StringVar(&ttl, "ttl", "", "")
	fs.BoolVar(&reusable, "reusable", false, "")
	pos, _, err := parseArgs(fs, args)
	if err != nil {
		return a.flagError(c, "join-command", err)
	}
	if len(pos) > 0 {
		return a.usageError(c, "join-command", "unexpected argument %q", pos[0])
	}
	role, nodeRole, ok := joinRoles(role)
	if !ok {
		return a.usageError(c, "join-command", "--role must be worker, ingress, server, mixed or a list such as server,worker; got %q", nodeRole)
	}
	if ttl = strings.TrimSpace(ttl); ttl != "" && ttl != "0" {
		d, err := time.ParseDuration(ttl)
		if err != nil || d <= 0 {
			return a.usageError(c, "join-command", "--ttl must be a duration like 2h, or 0 for never; got %q", ttl)
		}
		if role == "server" && d > 24*time.Hour {
			return a.usageError(c, "join-command", "server tokens last at most 24h")
		}
	}
	if ttl == "0" && role == "server" {
		return a.usageError(c, "join-command", "--ttl 0 is only for worker and ingress tokens; server tokens last at most 24h")
	}
	var created joinTokenCreated
	body := map[string]any{"role": role, "ttl": ttl, "reusable": reusable}
	if err := a.clusterCall(ctx, c, http.MethodPost, "/v1/cluster/join-tokens", body, &created); err != nil {
		return a.fail(c, joinTokenRefusal(err), exitError)
	}
	if len(created.JoinURLs) == 0 {
		return a.fail(c, &agenttools.Error{Code: agenttools.CodeUnavailable, Message: "the cluster reported no join URL",
			Hint: "no server has its join port (7003) open; check SB_CLUSTER_JOIN_LISTEN_ADDR on the servers"}, exitError)
	}
	line := joinLine{
		Installer: joinInstallerURL, JoinURL: created.JoinURLs[0], Token: created.Token, CACertHash: created.CACertHash,
		Domain: created.Domain, IngressHost: created.IngressAdvertiseHost, TLSIssuer: created.TLSIssuer, NodeRole: nodeRole,
	}
	command := line.String()
	if c.json {
		a.printJSON(struct {
			joinTokenCreated
			Command string `json:"command"`
		}{created, command})
		return exitOK
	}
	fmt.Fprintln(a.stdout, command)
	life := "never expires"
	if created.ExpiresAt != nil {
		life = "expires at " + created.ExpiresAt.UTC().Format(time.RFC3339)
	}
	use := "works for one machine"
	if created.Reusable {
		use = "works for any number of machines"
	}
	a.note("aerolvm: %s token %s %s and %s. To cancel it: aerolvm delete jointoken %s", created.Role, created.ID, life, use, created.ID)
	if line.needsDNSToken() {
		a.note("aerolvm: on the new machine, first set your Cloudflare API token: export %s=<token>", joinDNSTokenVar)
	}
	if created.Warning != "" {
		a.note("warning: %s", created.Warning)
	}
	return exitOK
}

// joinDNSTokenVar is the variable the printed line reads the DNS API token
// from on the new machine (internal/nodejoin DNSTokenVar): the token is a
// secret, so the line names it instead of holding it.
const joinDNSTokenVar = "CLOUDFLARE_API_TOKEN"

// joinLine is the line sandboxd init and sandboxd join-command print too
// (internal/nodejoin JoinLine): the installer options that give the new
// machine the cluster's public setup, then join and its flags. The CLI
// can't import nodejoin, so it is written out here; the golden files pin
// both to the same words.
type joinLine struct {
	Installer, JoinURL, Token, CACertHash string
	Domain, IngressHost, TLSIssuer        string
	NodeRole                              string
}

func (l joinLine) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "curl -fsSL %s | sudo bash -s --", l.Installer)
	if l.Domain != "" {
		fmt.Fprintf(&b, " --domain %s", l.Domain)
		if strings.EqualFold(l.TLSIssuer, "internal") {
			b.WriteString(" --tls-issuer internal")
		} else {
			fmt.Fprintf(&b, ` --dns-provider cloudflare --dns-api-token "$%s"`, joinDNSTokenVar)
		}
	}
	fmt.Fprintf(&b, " join %s --token %s", l.JoinURL, l.Token)
	if l.CACertHash != "" {
		fmt.Fprintf(&b, " --ca-cert-hash %s", l.CACertHash)
	}
	if l.NodeRole != "" {
		fmt.Fprintf(&b, " --role %s", l.NodeRole)
	}
	if l.IngressHost != "" && !strings.EqualFold(l.IngressHost, l.Domain) {
		fmt.Fprintf(&b, " --ingress-advertise-host %s", l.IngressHost)
	}
	return b.String()
}

func (l joinLine) needsDNSToken() bool {
	return l.Domain != "" && !strings.EqualFold(l.TLSIssuer, "internal")
}

// joinRoles splits --role into the token's role and the --role the line
// adds (internal/nodejoin NodeRoleForJoin): worker, ingress and server are
// tokens of their own; mixed and lists such as server,worker take the token
// of their strongest job (any server is a server, else worker beats
// ingress) and run as typed. On a bad value it returns the cleaned input.
func joinRoles(raw string) (tokenRole, nodeRole string, ok bool) {
	raw = strings.ToLower(strings.Join(strings.Fields(raw), ""))
	switch raw {
	case "", "worker":
		return "worker", "", true
	case "server", "ingress":
		return raw, "", true
	case "mixed":
		return "server", "mixed", true
	}
	jobs := map[string]bool{}
	for part := range strings.SplitSeq(raw, ",") {
		switch part {
		case "server", "worker", "ingress":
			jobs[part] = true
		default:
			return "", raw, false
		}
	}
	switch {
	case jobs["server"]:
		tokenRole = "server"
	case jobs["worker"]:
		tokenRole = "worker"
	default:
		tokenRole = "ingress"
	}
	if len(jobs) == 1 {
		return tokenRole, "", true
	}
	return tokenRole, raw, true
}

// joinTokenRefusal adds the fix for the refusals people meet.
func joinTokenRefusal(err error) error {
	e := agenttools.Classify(err)
	if strings.Contains(e.Message, "wrapped") && strings.Contains(e.Message, "never-expiring") {
		e.Hint = "give the token a TTL (--ttl 24h), or move the cluster to wrapped key custody (sandboxd key wrap)"
	}
	return e
}

func getJoinTokens(ctx context.Context, a *app, c *commonFlags, names []string, output string) int {
	format, ok := outputFormat(c, output, "wide", "json", "yaml", "name")
	if !ok {
		return a.usageError(c, "get", "-o must be wide, json, yaml or name, got %q", format)
	}
	var resp struct {
		Tokens []json.RawMessage `json:"tokens"`
	}
	if err := a.clusterCall(ctx, c, http.MethodGet, "/v1/cluster/join-tokens", nil, &resp); err != nil {
		return a.fail(c, err, exitError)
	}
	type tokenRaw struct {
		raw  json.RawMessage
		info joinTokenInfo
	}
	tokens := make([]tokenRaw, 0, len(resp.Tokens))
	for _, raw := range resp.Tokens {
		var info joinTokenInfo
		if err := json.Unmarshal(raw, &info); err != nil {
			return a.fail(c, fmt.Errorf("sandboxd sent an unreadable join token: %w", err), exitError)
		}
		tokens = append(tokens, tokenRaw{raw: raw, info: info})
	}
	sort.Slice(tokens, func(i, j int) bool { return tokens[i].info.ID < tokens[j].info.ID })
	if len(names) > 0 {
		byID := map[string]tokenRaw{}
		for _, t := range tokens {
			byID[t.info.ID] = t
		}
		picked := tokens[:0:0]
		for _, name := range names {
			t, ok := byID[name]
			if !ok {
				return a.fail(c, &agenttools.Error{Code: agenttools.CodeNotFound, HTTPStatus: http.StatusNotFound,
					Message: fmt.Sprintf("join token %q not found", name), Hint: "run `aerolvm get jointokens` to list them"}, exitError)
			}
			picked = append(picked, t)
		}
		tokens = picked
	}
	switch format {
	case "json", "yaml":
		raws := make([]json.RawMessage, len(tokens))
		for i, t := range tokens {
			raws[i] = t.raw
		}
		a.printObjects(format, "tokens", rawItems(raws), len(names) == 1)
		return exitOK
	case "name":
		for _, t := range tokens {
			fmt.Fprintf(a.stdout, "jointoken/%s\n", t.info.ID)
		}
		return exitOK
	}
	if len(tokens) == 0 {
		a.note("aerolvm: no join tokens")
		return exitOK
	}
	tw := tabwriter.NewWriter(a.stdout, 0, 4, 3, ' ', 0)
	header := "ID\tROLE\tSTATUS\tEXPIRES\tREUSABLE\tUSES"
	if format == "wide" {
		header += "\tCREATED\tCREATED-BY\tUSED-BY"
	}
	fmt.Fprintln(tw, header)
	for _, t := range tokens {
		i := t.info
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%t\t%s", i.ID, i.Role, i.status(), i.expires(), i.Reusable, strconv.Itoa(len(i.UsedBy)))
		if format == "wide" {
			var used []string
			for _, u := range i.UsedBy {
				used = append(used, u.NodeID)
			}
			fmt.Fprintf(tw, "\t%s\t%s\t%s", i.CreatedAt.UTC().Format(time.RFC3339), dash(i.CreatedBy), dash(strings.Join(used, ",")))
		}
		fmt.Fprintln(tw)
	}
	_ = tw.Flush()
	return exitOK
}

func deleteJoinTokens(ctx context.Context, a *app, c *commonFlags, names []string) int {
	if len(names) == 0 {
		return a.usageError(c, "delete", "name at least one join token, as in `aerolvm delete jointoken abc123`")
	}
	code := exitOK
	var results []any
	for _, id := range names {
		err := a.clusterCall(ctx, c, http.MethodDelete, "/v1/cluster/join-tokens/"+url.PathEscape(id), nil, nil)
		if err != nil {
			code = a.fail(c, err, exitError)
			continue
		}
		results = append(results, map[string]any{"id": id, "revoked": true})
		if !c.json {
			fmt.Fprintf(a.stdout, "jointoken %q deleted\n", id)
		}
	}
	if c.json && len(results) > 0 {
		a.printJSON(jsonResults(results))
	}
	return code
}
