package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"gopkg.in/yaml.v3"
)

// kubectl grammar for get, describe and delete (plans/kubectl-style-cluster-ops.md
// §3.3): the word after the verb is a kind when it names one, and each kind
// brings its own get, describe and delete. Adding a kind is one entry in
// resourceKinds.
//
// The old forms keep working: after get or describe, a word that is not a
// kind is a sandbox name, so `aerolvm get my-box` prints what it always did.
// delete has no such fallback: a mistyped kind ("delete nod wrk-1") would
// otherwise try to destroy sandboxes named "nod" and "wrk-1", and an
// already-gone sandbox counts as deleted, so the typo would even exit 0.

// kindFunc runs one verb on one kind, after the shared flag parse.
type kindFunc func(ctx context.Context, a *app, c *commonFlags, call kindCall) int

// kindCall is what the shared parse hands a kind.
type kindCall struct {
	kind     resourceKind
	names    []string
	output   string // -o
	selector string // -l
	force    bool   // delete --force
}

// resourceKind is one kind. A nil verb means the kind does not take it.
type resourceKind struct {
	plural   string   // the canonical name: api-resources, and -o json lists
	singular string   // -o name prints <singular>/<name>
	short    []string // short names, as in `get sb`
	title    string   // api-resources KIND column
	get      kindFunc
	describe kindFunc
	del      kindFunc
	selector bool // get takes -l (only kinds with tags)
	force    bool // delete takes --force
}

// resourceKinds is a function, not a package variable: the kinds' verbs
// reach code that looks kinds up, which a variable's initializer may not.
func resourceKinds() []resourceKind {
	return []resourceKind{
		{plural: "nodes", singular: kindNode, short: []string{"no"}, title: "Node", get: getNodes, describe: describeNode, del: deleteNodes, force: true},
		{plural: "sandboxes", singular: "sandbox", short: []string{"sb"}, title: "Sandbox", get: getSandboxes, describe: describeSandbox, del: deleteSandboxes, selector: true},
		{plural: "snapshots", singular: "snapshot", short: []string{"snap"}, title: "Snapshot", get: getSnapshots, describe: describeSnapshot, del: deleteSnapshots},
		{plural: "tokens", singular: "token", short: []string{"tok"}, title: "Token", get: getTokens, describe: describeToken, del: deleteTokens},
		{plural: "jointokens", singular: kindJoinToken, short: []string{"jt", "join-token", "join-tokens"}, title: "JoinToken", get: getJoinTokensKind, del: deleteJoinTokensKind},
	}
}

const kindNode = "node"

// findKind matches a plural, singular or short name, in any case.
func findKind(word string) (resourceKind, bool) {
	word = strings.ToLower(word)
	for _, k := range resourceKinds() {
		if word == k.plural || word == k.singular {
			return k, true
		}
		for _, s := range k.short {
			if word == s {
				return k, true
			}
		}
	}
	return resourceKind{}, false
}

// lookupKind is findKind for callers that need only the kind's name.
func lookupKind(word string) (string, bool) {
	k, ok := findKind(word)
	return k.singular, ok
}

// kindList names every kind for an error message: "nodes, sandboxes or tokens".
func kindList() string {
	names := make([]string, 0, len(resourceKinds()))
	for _, k := range resourceKinds() {
		names = append(names, k.plural)
	}
	// The table always has more than one kind.
	return strings.Join(names[:len(names)-1], ", ") + " or " + names[len(names)-1]
}

// parseKindArgs is the flag parse get, describe and delete share. -l and
// --force are parsed for every kind and refused by the ones without them, so
// the message names the kind instead of "flag provided but not defined".
func (a *app) parseKindArgs(verbName string, args []string) (*commonFlags, kindCall, []string, int) {
	fs, c := a.newFlagSet(verbName)
	var call kindCall
	fs.StringVar(&call.output, "o", "", "")
	fs.StringVar(&call.output, "output", "", "")
	fs.StringVar(&call.selector, "l", "", "")
	fs.StringVar(&call.selector, "selector", "", "")
	if verbName == "delete" {
		fs.BoolVar(&call.force, "force", false, "")
	}
	pos, _, err := parseArgs(fs, args)
	if err != nil {
		return c, call, nil, a.flagError(c, verbName, err)
	}
	return c, call, pos, -1
}

// runKind runs verbName on the kind named by pos[0], or reports false when
// pos[0] is not a kind.
func (a *app) runKind(ctx context.Context, c *commonFlags, verbName string, call kindCall, pos []string) (int, bool) {
	if len(pos) == 0 {
		return 0, false
	}
	kind, ok := findKind(pos[0])
	if !ok {
		return 0, false
	}
	call.kind, call.names = kind, pos[1:]
	return a.dispatchKind(ctx, c, verbName, call), true
}

// dispatchKind runs verbName on call.kind, refusing a verb or flag the kind
// does not take.
func (a *app) dispatchKind(ctx context.Context, c *commonFlags, verbName string, call kindCall) int {
	kind := call.kind
	run := map[string]kindFunc{"get": kind.get, "describe": kind.describe, "delete": kind.del}[verbName]
	switch {
	case run == nil:
		return a.usageError(c, verbName, "%s does not take %s", verbName, kind.plural)
	case call.selector != "" && (verbName != "get" || !kind.selector):
		return a.usageError(c, verbName, "-l selects by tag and works only with `aerolvm get sandboxes`")
	case call.force && !kind.force:
		return a.usageError(c, verbName, "--force works only with `aerolvm delete node`")
	}
	return run(ctx, a, c, call)
}

func runDescribe(ctx context.Context, a *app, args []string) int {
	c, call, pos, code := a.parseKindArgs("describe", args)
	if code >= 0 {
		return code
	}
	if len(pos) == 0 {
		return a.usageError(c, "describe", "expected a kind and a name, such as `aerolvm describe node <name>`")
	}
	if code, ok := a.runKind(ctx, c, "describe", call, pos); ok {
		return code
	}
	// Not a kind: a sandbox, as with get.
	sandboxes, _ := findKind("sandbox")
	call.kind, call.names = sandboxes, pos
	if call.selector != "" {
		return a.usageError(c, "describe", "-l selects by tag and works only with `aerolvm get sandboxes`")
	}
	return describeSandbox(ctx, a, c, call)
}

func runDelete(ctx context.Context, a *app, args []string) int {
	c, call, pos, code := a.parseKindArgs("delete", args)
	if code >= 0 {
		return code
	}
	if len(pos) == 0 {
		return a.usageError(c, "delete", "expected a kind and a name, such as `aerolvm delete node <name>`")
	}
	if code, ok := a.runKind(ctx, c, "delete", call, pos); ok {
		return code
	}
	return a.usageError(c, "delete", "unknown kind %q: delete takes %s (aerolvm api-resources lists them); to delete a sandbox: aerolvm delete sb <name>", pos[0], kindList())
}

// oneName is describe's check that it got exactly one name.
func (a *app) oneName(c *commonFlags, call kindCall) bool {
	if len(call.names) == 1 {
		return true
	}
	a.usageError(c, "describe", "expected one %s name", call.kind.singular)
	return false
}

// getFormat validates -o for get.
func (a *app) getFormat(c *commonFlags, output string) (string, int) {
	format, ok := outputFormat(c, output, "wide", "json", "yaml", "name")
	if !ok {
		return "", a.usageError(c, "get", "-o must be wide, json, yaml or name, got %q", format)
	}
	return format, -1
}

// describeFormat validates -o for describe.
func (a *app) describeFormat(c *commonFlags, output string) (string, int) {
	format, ok := outputFormat(c, output, "json", "yaml")
	if !ok {
		return "", a.usageError(c, "describe", "-o must be json or yaml, got %q", format)
	}
	return format, -1
}

// printObjects prints objects as JSON or YAML: one asked-for object bare,
// anything else as {"<key>": [...]}. JSON goes through printJSON, so a
// sandbox prints byte for byte as `aerolvm get <sandbox> --json` does.
func (a *app) printObjects(format, key string, items []any, single bool) {
	var v any = map[string]any{key: items}
	if single && len(items) == 1 {
		v = items[0]
	}
	if format == "json" {
		a.printJSON(v)
		return
	}
	b, _ := json.Marshal(v)
	var generic any
	_ = json.Unmarshal(b, &generic)
	out, _ := yaml.Marshal(generic)
	_, _ = a.stdout.Write(out)
}

// rawItems lets callers that hold the server's JSON as is (join tokens,
// upgrade status) print it through printObjects unchanged.
func rawItems(raws []json.RawMessage) []any {
	out := make([]any, len(raws))
	for i, r := range raws {
		out[i] = r
	}
	return out
}

// printNames is -o name: <singular>/<name>, one per line.
func (a *app) printNames(singular string, names []string) {
	for _, n := range names {
		fmt.Fprintf(a.stdout, "%s/%s\n", singular, n)
	}
}

// table writes rows under header, columns aligned like kubectl's.
func table(w io.Writer, header string, rows [][]string) {
	tw := tabwriter.NewWriter(w, 0, 4, 3, ' ', 0)
	fmt.Fprintln(tw, header)
	for _, r := range rows {
		fmt.Fprintln(tw, strings.Join(r, "\t"))
	}
	_ = tw.Flush()
}

// fields writes describe's "Key:  value" lines.
func fields(w io.Writer, rows [][2]string) {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	for _, row := range rows {
		fmt.Fprintf(tw, "%s\t%s\n", row[0], row[1])
	}
	_ = tw.Flush()
}

// age is kubectl's AGE column (k8s.io/apimachinery HumanDuration): coarse
// once it is old, precise while it is young. A zero time is unknown.
func age(now, then time.Time) string {
	if then.IsZero() {
		return "-"
	}
	d := now.Sub(then)
	if d < 0 {
		return "0s"
	}
	seconds := int(d.Round(time.Second) / time.Second)
	minutes, hours := seconds/60, seconds/3600
	days := hours / 24
	switch {
	case seconds < 120:
		return fmt.Sprintf("%ds", seconds)
	case minutes < 10:
		if s := seconds % 60; s != 0 {
			return fmt.Sprintf("%dm%ds", minutes, s)
		}
		return fmt.Sprintf("%dm", minutes)
	case minutes < 180:
		return fmt.Sprintf("%dm", minutes)
	case hours < 8:
		if m := minutes % 60; m != 0 {
			return fmt.Sprintf("%dh%dm", hours, m)
		}
		return fmt.Sprintf("%dh", hours)
	case hours < 48:
		return fmt.Sprintf("%dh", hours)
	case hours < 24*8:
		if h := hours % 24; h != 0 {
			return fmt.Sprintf("%dd%dh", days, h)
		}
		return fmt.Sprintf("%dd", days)
	case days < 365*2:
		return fmt.Sprintf("%dd", days)
	case days < 365*8:
		if dy := days % 365; dy != 0 {
			return fmt.Sprintf("%dy%dd", days/365, dy)
		}
		return fmt.Sprintf("%dy", days/365)
	}
	return fmt.Sprintf("%dy", days/365)
}

// whenAgo is describe's time: RFC 3339 and how long ago.
func whenAgo(now, t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return fmt.Sprintf("%s (%s ago)", t.UTC().Format(time.RFC3339), age(now, t))
}

// runAPIResources lists the kinds this client knows. It asks no server: the
// kinds are the CLI's, as `kubectl api-resources` lists what it can address.
func runAPIResources(_ context.Context, a *app, args []string) int {
	fs, c := a.newFlagSet("api-resources")
	var output string
	fs.StringVar(&output, "o", "", "")
	fs.StringVar(&output, "output", "", "")
	pos, _, err := parseArgs(fs, args)
	if err != nil {
		return a.flagError(c, "api-resources", err)
	}
	if len(pos) > 0 {
		return a.usageError(c, "api-resources", "unexpected argument %q", pos[0])
	}
	format, ok := outputFormat(c, output, "wide", "json", "yaml", "name")
	if !ok {
		return a.usageError(c, "api-resources", "-o must be wide, json, yaml or name, got %q", format)
	}
	kinds := resourceKinds()
	sort.Slice(kinds, func(i, j int) bool { return kinds[i].plural < kinds[j].plural })
	type resource struct {
		Name         string   `json:"name"`
		SingularName string   `json:"singular_name"`
		ShortNames   []string `json:"short_names"`
		Kind         string   `json:"kind"`
		Verbs        []string `json:"verbs"`
	}
	items := make([]any, 0, len(kinds))
	rows := make([][]string, 0, len(kinds))
	for _, k := range kinds {
		var verbs []string
		for _, v := range []struct {
			name string
			fn   kindFunc
		}{{"get", k.get}, {"describe", k.describe}, {"delete", k.del}} {
			if v.fn != nil {
				verbs = append(verbs, v.name)
			}
		}
		items = append(items, resource{Name: k.plural, SingularName: k.singular, ShortNames: k.short, Kind: k.title, Verbs: verbs})
		row := []string{k.plural, strings.Join(k.short, ","), k.title}
		if format == "wide" {
			row = append(row, strings.Join(verbs, ","))
		}
		rows = append(rows, row)
	}
	switch format {
	case "json", "yaml":
		a.printObjects(format, "resources", items, false)
	case "name":
		for _, k := range kinds {
			fmt.Fprintln(a.stdout, k.plural)
		}
	case "wide":
		table(a.stdout, "NAME\tSHORTNAMES\tKIND\tVERBS", rows)
	default:
		table(a.stdout, "NAME\tSHORTNAMES\tKIND", rows)
	}
	return exitOK
}
