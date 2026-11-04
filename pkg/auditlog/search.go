package auditlog

import (
	"context"
	"strings"
	"time"
)

// Searching the evidence offline (plans/identity-and-access.md §5.10):
// "what did Ana do this week" is answered from the export, not by a live
// fan-out to every node. SearchNode walks one node's records exactly as
// VerifyNode does, so every record it hands back has been proven to link
// into the chain, and the verdict that comes back with them says whether
// the node's history as a whole held up. `aerolvm audit search` prints the
// matches; `aerolvm access review` (T5b) walks with an empty filter and
// joins the caller and request fields itself.

// SearchFilter selects records. A zero field matches everything.
type SearchFilter struct {
	// Caller matches the record's caller id exactly ("tok_7Hq2…",
	// "operator", "system:lifecycle") or its display name ignoring case
	// ("ana@acme.com").
	Caller string
	// Kind matches the record kind ("api", "secret_open", "auth_denied").
	Kind string
	// SandboxID matches the sandbox the record is about.
	SandboxID string
	// Result matches the result ("ok", "denied", "error", "success", ...).
	Result string
	// Since and Until bound the record time: Since inclusive, Until
	// exclusive.
	Since, Until time.Time
}

// Match reports whether ev passes the filter. Records retention left behind
// (checkpoints and stubs) are chain structure, not evidence of anything,
// and match only a filter that asks for their kind.
func (f SearchFilter) Match(ev Event) bool {
	if f.Kind != "" {
		if ev.Kind != f.Kind {
			return false
		}
	} else if ev.Kind == KindRetentionCheckpoint || ev.Kind == KindRetentionRedacted {
		return false
	}
	if f.SandboxID != "" && ev.SandboxID != f.SandboxID {
		return false
	}
	if f.Result != "" && ev.Result != f.Result {
		return false
	}
	if !f.Since.IsZero() && ev.Time.Before(f.Since) {
		return false
	}
	if !f.Until.IsZero() && !ev.Time.Before(f.Until) {
		return false
	}
	if f.Caller != "" && !callerMatches(ev.Caller, f.Caller) {
		return false
	}
	return true
}

func callerMatches(c *Caller, want string) bool {
	if c == nil {
		return false
	}
	return c.ID == want || (c.Name != "" && strings.EqualFold(c.Name, want))
}

// SearchNode walks one node's evidence like VerifyNode and calls fn with
// every record that links into the chain and passes f, in chain order. The
// report is VerifyNode's: a FAIL means the history the matches came from
// does not hold up, and a caller must not present them as evidence.
func SearchNode(ctx context.Context, in NodeInput, f SearchFilter, fn func(Event)) (NodeReport, error) {
	return walkNode(ctx, in, func(ev Event) {
		if fn != nil && f.Match(ev) {
			fn(ev)
		}
	})
}
