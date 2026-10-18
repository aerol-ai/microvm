package harness

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/auditlog"
)

// Reading a node's own audit log, for records no API route returns: an
// auth_denied record has no sandbox, an identity_config or api_flood_mode
// record belongs to the node, and "the edge wrote no record" (UC-273) can
// only be checked where the edge keeps its log.

// nodeAuditGrepScript prints every line of the node's audit log and spill
// file that contains the needle read from stdin, then a terminator so an
// empty result is told apart from a failed command. The log is
// <dir of SB_DB_PATH>/audit/secrets.jsonl (internal/service/secret_audit.go).
const nodeAuditGrepScript = `sudo bash -c 'set -a; . /etc/sandboxd/sandboxd.env 2>/dev/null || true; . /etc/sandboxd/cluster.env 2>/dev/null || true; set +a; ` +
	`db="${SB_DB_PATH:-/var/lib/sandboxd/state.db}"; dir="$(dirname "$db")/audit"; ` +
	`IFS= read -r needle; [ -n "$needle" ] || { echo NONEEDLE; exit 2; }; ` +
	`for f in "$dir/secrets.jsonl" "$dir/secrets.spill.jsonl"; do [ -f "$f" ] && grep -F -- "$needle" "$f"; done; echo __AUDIT_END__'`

// NodeAuditEvents returns node's audit records whose JSON line contains
// needle, oldest first. The needle travels on stdin; it is an id (a token
// id, a sandbox id, a record kind), never a secret.
func NodeAuditEvents(t *testing.T, node IntegrationNode, needle string) ([]auditlog.Event, error) {
	t.Helper()
	target, ok := SSHTarget(node)
	if !ok {
		return nil, fmt.Errorf("node %s has no SSH address", node.Name)
	}
	out, err := SSHRunStdin(t, target, nodeAuditGrepScript, needle+"\n")
	if !strings.Contains(out, "__AUDIT_END__") {
		return nil, fmt.Errorf("read the audit log on %s: %v: %s", node.Name, err, snippet([]byte(out)))
	}
	return ParseAuditLines(out), nil
}

// ParseAuditLines decodes one audit record per line, skipping anything that
// is not one (the terminator, a torn tail line).
func ParseAuditLines(out string) []auditlog.Event {
	var events []auditlog.Event
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var ev auditlog.Event
		if json.Unmarshal([]byte(line), &ev) == nil {
			events = append(events, ev)
		}
	}
	return events
}

// FilterAudit returns the events keep accepts.
func FilterAudit(events []auditlog.Event, keep func(auditlog.Event) bool) []auditlog.Event {
	var out []auditlog.Event
	for _, ev := range events {
		if keep(ev) {
			out = append(out, ev)
		}
	}
	return out
}

// CallerID is the event's caller id, "" when it names none.
func CallerID(ev auditlog.Event) string {
	if ev.Caller == nil {
		return ""
	}
	return ev.Caller.ID
}

// RouteOf is the event's request route, "" when it carries no request.
func RouteOf(ev auditlog.Event) string {
	if ev.Request == nil {
		return ""
	}
	return ev.Request.Method + " " + ev.Request.Route
}
