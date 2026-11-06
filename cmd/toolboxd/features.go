package main

import "sort"

// toolboxFeatures lists the request options this toolboxd understands that an
// older toolboxd would silently ignore, keyed by the feature name it shows on
// /version. A sandbox can run an older toolboxd than the SDK expects: a
// Firecracker template keeps the toolboxd it was built with, and a running
// container keeps its bind-mounted binary. toolboxd decodes requests
// permissively, so an option it does not know is dropped, and an overwrite
// guard or an output cap would quietly not apply. The SDKs read the feature
// list from /version before sending such an option and fail closed instead
// (plans/agent-sandbox-feature-parity.md, section 10, ER4).
//
// The values are the option names (query parameters or JSON fields) the
// feature adds. TestEveryRequestOptionIsListed parses this package and fails
// when a handler reads an option that is neither here nor in
// baselineRequestOptions, so the list cannot drift from the handlers.
var toolboxFeatures = map[string][]string{
	// Buffered exec output caps (plan E1). An older agent drops them and
	// returns all output, which is what a caller that set a cap must never
	// get by surprise (ER4).
	"exec.max_output_bytes": {"max_stdout_bytes", "max_stderr_bytes"},
	// A command as a list, with no shell parsing, on buffered exec and the
	// exec stream (plan E2). An older agent answers "command is required".
	"exec.argv": {"argv"},
	// Files (plans/agent-sandbox-feature-parity.md, section 5.1).
	// F1: list with a depth and an entry cap (and the extended file info),
	// the move and copy overwrite guard, mkdir without parents, and the
	// POST /files/copy route.
	"files.verbs": {"depth", "extended", "limit", "overwrite", "parents"},
	// F2: upload write options. mode is also a baseline option of the
	// folder and permissions routes, but upload honours it only from here.
	"files.write_options": {"append", "atomic", "create_only", "mode"},
}

// baselineRequestOptions are the options toolboxd understood before /version
// listed features. Any agent honours them, so an SDK sends them unchecked.
// Never add to this list: a new option belongs to a feature above.
var baselineRequestOptions = []string{
	// Query parameters.
	"destination", "follow", "group", "mode", "owner", "path", "pattern", "recursive", "source", "username",
	// Buffered exec (models.ExecRequest) and the exec stream's start message.
	"command", "cols", "env", "rows", "timeout_seconds", "tty", "workdir",
}

// featureList is the sorted feature names, for /version.
func featureList() []string {
	// Never nil: an empty list must still serialize as [], not null.
	out := make([]string, 0, len(toolboxFeatures))
	for name := range toolboxFeatures {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
