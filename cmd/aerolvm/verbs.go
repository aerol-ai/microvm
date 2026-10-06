package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/aerol-ai/microvm/internal/agenttools"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

func runCreate(ctx context.Context, a *app, args []string) int {
	fs, c := a.newFlagSet("create")
	var (
		name, image, runtime string
		cpu                  float64
		memoryMB             int
		stopIdle, destroy    time.Duration
		blockNetwork         bool
	)
	env, tags := kvList{}, kvList{}
	var allowHosts agenttools.HostList
	fs.StringVar(&name, "name", "", "")
	fs.StringVar(&image, "image", "", "")
	fs.StringVar(&runtime, "runtime", "", "")
	fs.Float64Var(&cpu, "cpu", 0, "")
	fs.IntVar(&memoryMB, "memory-mb", 0, "")
	fs.Var(env, "env", "")
	fs.Var(tags, "tag", "")
	fs.DurationVar(&stopIdle, "stop-if-idle", 0, "")
	fs.DurationVar(&destroy, "destroy-if-idle", 0, "")
	fs.BoolVar(&blockNetwork, "block-network", false, "")
	fs.Var(&allowHosts, "allow-host", "")
	pos, _, err := parseArgs(fs, args)
	if err != nil {
		return a.flagError(c, "create", err)
	}
	if len(pos) > 0 {
		return a.usageError(c, "create", "unexpected argument %q (use --name)", pos[0])
	}
	if blockNetwork && len(allowHosts) > 0 {
		return a.usageError(c, "create", "--block-network and --allow-host can't be combined")
	}
	spec := agenttools.CreateSpec{
		Name: name, Image: image, Runtime: runtime, CPU: cpu, MemoryMB: memoryMB,
		Env: env.orNil(), Tags: tags.orNil(), BlockNetwork: blockNetwork, AllowOut: allowHosts,
	}
	if stopIdle > 0 || destroy > 0 {
		spec.Lifecycle = &models.Lifecycle{StopIfIdleFor: stopIdle, DestroyIfIdleFor: destroy}
	}
	tools, err := a.tools(c)
	if err != nil {
		return a.fail(c, err, exitError)
	}
	res, err := tools.GetOrCreate(ctx, spec)
	if err != nil {
		return a.fail(c, err, exitError)
	}
	if c.json {
		a.printJSON(withFields(res.Sandbox.Sandbox, map[string]any{"created": res.Created}))
		return exitOK
	}
	if res.Created {
		a.note("created sandbox %s (%s)", res.Sandbox.Name, res.Sandbox.ID)
	} else {
		a.note("using existing sandbox %s (%s)", res.Sandbox.Name, res.Sandbox.ID)
	}
	fmt.Fprintln(a.stdout, res.Sandbox.ID)
	return exitOK
}

// withFields renders v's JSON object with extra CLI fields added (§5.2
// rule 3: the wire type plus at most a few CLI fields).
func withFields(v any, extra map[string]any) map[string]any {
	raw, _ := json.Marshal(v)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	for k, val := range extra {
		out[k] = val
	}
	return out
}

func runList(ctx context.Context, a *app, args []string) int {
	fs, c := a.newFlagSet("list")
	tags := kvList{}
	var limit int
	var pageToken string
	fs.Var(tags, "tag", "")
	fs.IntVar(&limit, "limit", 0, "")
	fs.StringVar(&pageToken, "page-token", "", "")
	pos, _, err := parseArgs(fs, args)
	if err != nil {
		return a.flagError(c, "list", err)
	}
	if len(pos) > 0 {
		return a.usageError(c, "list", "unexpected argument %q", pos[0])
	}
	if limit < 0 {
		return a.usageError(c, "list", "--limit must be positive")
	}
	tools, err := a.tools(c)
	if err != nil {
		return a.fail(c, err, exitError)
	}
	opts := []microvm.ListOption{microvm.WithTags(tags.orNil())}
	if limit > 0 {
		opts = append(opts, microvm.WithLimit(limit))
	}
	items, next, err := tools.Client().ListPage(ctx, pageToken, opts...)
	if err != nil {
		return a.fail(c, err, exitError)
	}
	// A server without single-node paging returns every row; keep the page
	// the caller asked for.
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	if c.json {
		rows := make([]models.Sandbox, 0, len(items))
		for _, sb := range items {
			rows = append(rows, sb.Sandbox)
		}
		a.printJSON(map[string]any{"sandboxes": rows, "next_page_token": next})
		return exitOK
	}
	tw := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tNAME\tSTATUS\tRUNTIME\tCREATED")
	for _, sb := range items {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", sb.ID, dash(sb.Name), sb.Status, dash(sb.Runtime), sb.CreatedAt.UTC().Format(time.RFC3339))
	}
	_ = tw.Flush()
	if next != "" {
		a.note("more: aerolvm list --page-token %s", next)
	}
	return exitOK
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func runGet(ctx context.Context, a *app, args []string) int {
	fs, c := a.newFlagSet("get")
	pos, _, err := parseArgs(fs, args)
	if err != nil {
		return a.flagError(c, "get", err)
	}
	if len(pos) != 1 {
		return a.usageError(c, "get", "expected one sandbox")
	}
	tools, err := a.tools(c)
	if err != nil {
		return a.fail(c, err, exitError)
	}
	sb, err := tools.Resolve(ctx, pos[0])
	if err != nil {
		return a.fail(c, err, exitError)
	}
	if c.json {
		a.printJSON(sb.Sandbox)
		return exitOK
	}
	tw := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "id\t%s\nname\t%s\nstatus\t%s\nruntime\t%s\nimage\t%s\ncreated\t%s\n",
		sb.ID, dash(sb.Name), sb.Status, dash(sb.Runtime), dash(sb.Image), sb.CreatedAt.UTC().Format(time.RFC3339))
	if sb.PublicURL != "" {
		fmt.Fprintf(tw, "url\t%s\n", sb.PublicURL)
	}
	_ = tw.Flush()
	return exitOK
}

func runStart(ctx context.Context, a *app, args []string) int {
	return a.eachSandbox(ctx, "start", args, func(ctx context.Context, tools *agenttools.Tools, sb *microvm.Sandbox) (any, error) {
		return tools.Client().Start(ctx, sb.ID)
	})
}

func runStop(ctx context.Context, a *app, args []string) int {
	return a.eachSandbox(ctx, "stop", args, func(ctx context.Context, tools *agenttools.Tools, sb *microvm.Sandbox) (any, error) {
		return tools.Client().Stop(ctx, sb.ID)
	})
}

// runDestroy treats a sandbox that is already gone as destroyed, so retries
// and cleanup scripts never fail on their own success (§5.2 rule 7).
func runDestroy(ctx context.Context, a *app, args []string) int {
	return a.eachSandbox(ctx, "destroy", args, func(ctx context.Context, tools *agenttools.Tools, sb *microvm.Sandbox) (any, error) {
		if err := tools.Client().Destroy(ctx, sb.ID); err != nil && !agenttools.IsCode(err, agenttools.CodeNotFound) {
			return nil, err
		}
		return map[string]any{"id": sb.ID, "name": sb.Name, "destroyed": true}, nil
	})
}

// eachSandbox runs op on every named sandbox, reporting each failure and
// carrying on, and exits 1 if any failed.
func (a *app) eachSandbox(ctx context.Context, verbName string, args []string, op func(context.Context, *agenttools.Tools, *microvm.Sandbox) (any, error)) int {
	fs, c := a.newFlagSet(verbName)
	pos, _, err := parseArgs(fs, args)
	if err != nil {
		return a.flagError(c, verbName, err)
	}
	if len(pos) == 0 {
		return a.usageError(c, verbName, "name at least one sandbox")
	}
	tools, err := a.tools(c)
	if err != nil {
		return a.fail(c, err, exitError)
	}
	code := exitOK
	results := make([]any, 0, len(pos))
	for _, ref := range pos {
		sb, err := tools.Resolve(ctx, ref)
		if err != nil {
			if verbName == "destroy" && agenttools.IsCode(err, agenttools.CodeNotFound) {
				a.note("%s: already gone", ref)
				results = append(results, map[string]any{"ref": ref, "destroyed": true, "already_gone": true})
				continue
			}
			code = a.fail(c, err, exitError)
			continue
		}
		out, err := op(ctx, tools, sb)
		if err != nil {
			code = a.fail(c, err, exitError)
			continue
		}
		results = append(results, out)
		if !c.json {
			fmt.Fprintln(a.stdout, sb.ID)
		}
	}
	if c.json {
		a.printJSON(jsonResults(results))
	}
	return code
}

// jsonResults prints one object for one sandbox and an array for several.
func jsonResults(results []any) any {
	for i, r := range results {
		if sb, ok := r.(*microvm.Sandbox); ok {
			results[i] = sb.Sandbox
		}
	}
	if len(results) == 1 {
		return results[0]
	}
	return results
}

func runExpose(ctx context.Context, a *app, args []string) int {
	fs, c := a.newFlagSet("expose")
	var tcp bool
	fs.BoolVar(&tcp, "tcp", false, "")
	pos, _, err := parseArgs(fs, args)
	if err != nil {
		return a.flagError(c, "expose", err)
	}
	if len(pos) != 2 {
		return a.usageError(c, "expose", "expected <sandbox> <port>")
	}
	port, err := strconv.Atoi(pos[1])
	if err != nil || port <= 0 || port > 65535 {
		return a.usageError(c, "expose", "port must be 1-65535, got %q", pos[1])
	}
	tools, err := a.tools(c)
	if err != nil {
		return a.fail(c, err, exitError)
	}
	sb, err := tools.Resolve(ctx, pos[0])
	if err != nil {
		return a.fail(c, err, exitError)
	}
	var opts []microvm.ExposeOption
	if tcp {
		opts = append(opts, microvm.WithProtocol(sdktypes.ExposeProtocolTCP))
	}
	res, err := sb.ExposePort(ctx, port, opts...)
	if err != nil {
		return a.fail(c, err, exitError)
	}
	if c.json {
		a.printJSON(res)
		return exitOK
	}
	if tcp && res.Host != "" {
		fmt.Fprintf(a.stdout, "%s:%d\n", res.Host, res.HostPort)
		return exitOK
	}
	fmt.Fprintln(a.stdout, res.PublicURL)
	return exitOK
}

func runSnapshot(ctx context.Context, a *app, args []string) int {
	fs, c := a.newFlagSet("snapshot")
	pos, _, err := parseArgs(fs, args)
	if err != nil {
		return a.flagError(c, "snapshot", err)
	}
	if len(pos) != 2 || strings.TrimSpace(pos[1]) == "" {
		return a.usageError(c, "snapshot", "expected <sandbox> <name>")
	}
	tools, err := a.tools(c)
	if err != nil {
		return a.fail(c, err, exitError)
	}
	sb, err := tools.Resolve(ctx, pos[0])
	if err != nil {
		return a.fail(c, err, exitError)
	}
	snap, err := tools.Client().CreateSnapshot(ctx, sb.ID, pos[1])
	if err != nil {
		return a.fail(c, err, exitError)
	}
	if c.json {
		a.printJSON(snap)
		return exitOK
	}
	fmt.Fprintln(a.stdout, snap.Name)
	return exitOK
}

func runHealth(ctx context.Context, a *app, args []string) int {
	fs, c := a.newFlagSet("health")
	pos, _, err := parseArgs(fs, args)
	if err != nil {
		return a.flagError(c, "health", err)
	}
	if len(pos) > 0 {
		return a.usageError(c, "health", "unexpected argument %q", pos[0])
	}
	tools, err := a.tools(c)
	if err != nil {
		return a.fail(c, err, exitError)
	}
	health, err := tools.Client().Health(ctx)
	if err != nil {
		return a.fail(c, err, exitError)
	}
	if c.json {
		a.printJSON(health)
		return exitOK
	}
	fmt.Fprintf(a.stdout, "%s (sandboxd %s)\n", health.Status, health.Version)
	return exitOK
}

func runVersion(_ context.Context, a *app, args []string) int {
	fs, c := a.newFlagSet("version")
	if _, _, err := parseArgs(fs, args); err != nil {
		return a.flagError(c, "version", err)
	}
	if c.json {
		a.printJSON(map[string]string{"version": versionString()})
		return exitOK
	}
	fmt.Fprintln(a.stdout, versionString())
	return exitOK
}
