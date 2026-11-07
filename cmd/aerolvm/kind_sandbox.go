package main

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/agenttools"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
)

// The sandbox kind: get sb, describe sb, delete sb. Reads go through the SDK
// like the old verbs, so `get sb <name> --json` prints exactly what
// `get <name> --json` does.

// sandboxListPage is the page size get asks for. 500 is the server's cap;
// the biggest page means the fewest round trips over a fleet.
const sandboxListPage = 500

func getSandboxes(ctx context.Context, a *app, c *commonFlags, call kindCall) int {
	format, code := a.getFormat(c, call.output)
	if code >= 0 {
		return code
	}
	sel, err := parseSelector(call.selector)
	if err != nil {
		return a.usageError(c, "get", "-l %v", err)
	}
	if len(sel) > 0 && len(call.names) > 0 {
		return a.usageError(c, "get", "name sandboxes or select them with -l, not both")
	}
	tools, err := a.tools(ctx, c)
	if err != nil {
		return a.fail(c, err, exitError)
	}
	var rows []models.Sandbox
	if len(call.names) > 0 {
		for _, ref := range call.names {
			sb, err := tools.Resolve(ctx, ref)
			if err != nil {
				return a.fail(c, err, exitError)
			}
			rows = append(rows, sb.Sandbox)
		}
	} else if rows, err = listAllSandboxes(ctx, tools, sel); err != nil {
		return a.fail(c, err, exitError)
	}

	switch format {
	case "json", "yaml":
		items := make([]any, len(rows))
		for i := range rows {
			items[i] = rows[i]
		}
		a.printObjects(format, "sandboxes", items, len(call.names) == 1)
		return exitOK
	case "name":
		names := make([]string, len(rows))
		for i, sb := range rows {
			names[i] = sandboxName(sb)
		}
		a.printNames("sandbox", names)
		return exitOK
	}
	if len(rows) == 0 {
		a.note("aerolvm: no sandboxes")
		return exitOK
	}
	now := a.clock()
	header := "NAME\tID\tSTATUS\tRUNTIME\tAGE"
	if format == "wide" {
		header += "\tIMAGE\tCPU\tMEMORY\tURL"
	}
	lines := make([][]string, 0, len(rows))
	for _, sb := range rows {
		line := []string{dash(sb.Name), sb.ID, string(sb.Status), dash(sb.Runtime), age(now, sb.CreatedAt)}
		if format == "wide" {
			line = append(line, dash(sb.Image), cpuText(sb.CPU), memText(sb.MemoryMB), dash(sb.PublicURL))
		}
		lines = append(lines, line)
	}
	table(a.stdout, header, lines)
	return exitOK
}

// listAllSandboxes reads every page. The selector's equality terms go to the
// server (?tag.k=v, which it filters on); the rest (!=, exists) it cannot
// express, so they are checked here.
func listAllSandboxes(ctx context.Context, tools *agenttools.Tools, sel selector) ([]models.Sandbox, error) {
	opts := []microvm.ListOption{microvm.WithTags(sel.equal()), microvm.WithLimit(sandboxListPage)}
	var out []models.Sandbox
	token := ""
	seen := map[string]bool{}
	for {
		items, next, err := tools.Client().ListPage(ctx, token, opts...)
		if err != nil {
			return nil, err
		}
		for _, sb := range items {
			if sel.matches(sb.Tags) {
				out = append(out, sb.Sandbox)
			}
		}
		// A repeated token would loop forever; stop on it.
		if next == "" || seen[next] {
			return out, nil
		}
		seen[next] = true
		token = next
	}
}

// sandboxName is how -o name and the delete line name a sandbox: its name,
// or its ID when it has none. Both are accepted wherever a sandbox is.
func sandboxName(sb models.Sandbox) string {
	if sb.Name != "" {
		return sb.Name
	}
	return sb.ID
}

func cpuText(cpu float64) string {
	if cpu <= 0 {
		return "-"
	}
	return strconv.FormatFloat(cpu, 'f', -1, 64)
}

func memText(mb int) string {
	if mb <= 0 {
		return "-"
	}
	return strconv.Itoa(mb) + "Mi"
}

func describeSandbox(ctx context.Context, a *app, c *commonFlags, call kindCall) int {
	if !a.oneName(c, call) {
		return exitUsage
	}
	format, code := a.describeFormat(c, call.output)
	if code >= 0 {
		return code
	}
	tools, err := a.tools(ctx, c)
	if err != nil {
		return a.fail(c, err, exitError)
	}
	sb, err := tools.Resolve(ctx, call.names[0])
	if err != nil {
		return a.fail(c, err, exitError)
	}
	if format != "" {
		a.printObjects(format, "sandboxes", []any{sb.Sandbox}, true)
		return exitOK
	}
	s, now := sb.Sandbox, a.clock()
	status := string(s.Status)
	if s.StatusReason != "" {
		status += " (" + s.StatusReason + ")"
	}
	rows := [][2]string{
		{"Name:", dash(s.Name)},
		{"ID:", s.ID},
		{"Status:", status},
		{"Runtime:", dash(s.Runtime)},
		{"Image:", dash(s.Image)},
		{"CPU:", cpuText(s.CPU)},
		{"Memory:", memText(s.MemoryMB)},
		{"Created:", whenAgo(now, s.CreatedAt)},
		{"Last active:", whenAgo(now, s.LastActiveAt)},
		{"URL:", dash(s.PublicURL)},
		{"Tags:", dash(joinTags(s.Tags))},
		{"Ports:", dash(portsText(s.ExposedPorts))},
		{"Network:", networkText(s)},
		{"Lifecycle:", dash(lifecycleText(s.Lifecycle))},
	}
	if s.Engine != "" {
		rows = append(rows, [2]string{"Engine:", s.Engine})
	}
	if s.ExitCode != nil {
		rows = append(rows, [2]string{"Exit code:", strconv.Itoa(*s.ExitCode)})
	}
	if s.LastError != "" {
		rows = append(rows, [2]string{"Last error:", s.LastError})
	}
	fields(a.stdout, rows)
	return exitOK
}

func joinTags(tags map[string]string) string {
	parts := make([]string, 0, len(tags))
	for k, v := range tags {
		parts = append(parts, k+"="+v)
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

func portsText(ports []models.ExposedPort) string {
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		where := p.PublicURL
		if p.HostPort > 0 {
			where = "host port " + strconv.Itoa(p.HostPort)
		}
		parts = append(parts, fmt.Sprintf("%d/%s %s", p.Port, dash(p.Protocol), dash(where)))
	}
	return strings.Join(parts, ", ")
}

func networkText(s models.Sandbox) string {
	switch {
	case s.NetworkBlockAll:
		return "all outbound blocked"
	case len(s.NetworkAllowOut) > 0:
		return "outbound only to " + strings.Join(s.NetworkAllowOut, ", ")
	case len(s.NetworkDenyOut) > 0:
		return "outbound except " + strings.Join(s.NetworkDenyOut, ", ")
	}
	return "open"
}

func lifecycleText(l models.Lifecycle) string {
	var parts []string
	for _, p := range []struct {
		what string
		d    time.Duration
	}{
		{"stop if idle", l.StopIfIdleFor}, {"destroy if idle", l.DestroyIfIdleFor},
		{"stop at age", l.StopAtAge}, {"destroy at age", l.DestroyAtAge},
	} {
		if p.d > 0 {
			parts = append(parts, p.what+" "+shortDuration(p.d))
		}
	}
	return strings.Join(parts, ", ")
}

// deleteSandboxes is destroy in kubectl's words: the same step, the same
// --json results, and an already-gone sandbox counts as deleted.
func deleteSandboxes(ctx context.Context, a *app, c *commonFlags, call kindCall) int {
	if len(call.names) == 0 {
		return a.usageError(c, "delete", "name at least one sandbox")
	}
	return a.sandboxEach(ctx, c, true, call.names, destroySandbox, func(ref string, _ *microvm.Sandbox) {
		fmt.Fprintf(a.stdout, "sandbox %q deleted\n", ref)
	})
}

// selector is a kubectl equality-based label selector over sandbox tags:
// k=v, k==v, k!=v, k (has the tag) and !k (lacks it), comma-separated, all
// of which must hold. Set-based terms (in, notin) are not supported.
type selector []selectorTerm

type selectorTerm struct {
	key, value string
	op         string // "=", "!=", "exists", "!exists"
}

func parseSelector(s string) (selector, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	if strings.ContainsAny(s, "()") {
		// "app in (a,b)": set-based, which tags have no use for yet.
		return nil, fmt.Errorf("supports only k=v, k!=v, k and !k, not set-based terms like %q", s)
	}
	var sel selector
	for _, raw := range strings.Split(s, ",") {
		term := strings.TrimSpace(raw)
		var t selectorTerm
		switch {
		case term == "":
			return nil, fmt.Errorf("has an empty term in %q", s)
		case strings.Contains(term, " "):
			return nil, fmt.Errorf("supports only k=v, k!=v, k and !k, not %q", term)
		case strings.Contains(term, "!="):
			k, v, _ := strings.Cut(term, "!=")
			t = selectorTerm{key: k, value: v, op: "!="}
		case strings.Contains(term, "=="):
			k, v, _ := strings.Cut(term, "==")
			t = selectorTerm{key: k, value: v, op: "="}
		case strings.Contains(term, "="):
			k, v, _ := strings.Cut(term, "=")
			t = selectorTerm{key: k, value: v, op: "="}
		case strings.HasPrefix(term, "!"):
			t = selectorTerm{key: term[1:], op: "!exists"}
		default:
			t = selectorTerm{key: term, op: "exists"}
		}
		if t.key == "" || strings.ContainsAny(t.key, "=!") || strings.ContainsAny(t.value, "=!") {
			return nil, fmt.Errorf("term %q has no key or a stray = or !", term)
		}
		sel = append(sel, t)
	}
	return sel, nil
}

// equal is the k=v terms, which the list route filters on itself. nil when
// there are none, so the request carries no tag filter at all.
func (s selector) equal() map[string]string {
	var out map[string]string
	for _, t := range s {
		if t.op == "=" {
			if out == nil {
				out = map[string]string{}
			}
			out[t.key] = t.value
		}
	}
	return out
}

// matches checks every term against tags.
func (s selector) matches(tags map[string]string) bool {
	for _, t := range s {
		v, has := tags[t.key]
		switch t.op {
		case "=":
			if !has || v != t.value {
				return false
			}
		case "!=":
			if has && v == t.value {
				return false
			}
		case "exists":
			if !has {
				return false
			}
		case "!exists":
			if has {
				return false
			}
		}
	}
	return true
}
