package rootpolicy

import (
	"strconv"

	"github.com/containerd/containerd/v2/pkg/filters"
)

// ScopeEventFilters narrows an event subscription to the policy's
// namespace. containerd's Events.Subscribe does not read the caller's
// namespace (plugins/services/events: it hands the request's filters to the
// node-wide exchange), so a subscriber sees every namespace's events, the
// Kubernetes namespace's included, unless its filters say otherwise.
//
// In containerd's filter language a list of filters matches when any one
// matches, and the comma-separated selectors inside one filter must all
// match. So each filter gets the namespace selector in front of it, joined
// by a comma, and an empty filter (which matches everything) becomes the
// namespace selector alone, as does an empty list. Every filter in the
// result then requires the namespace; one of the agent's own, such as
// topic~="/tasks/", keeps matching the agent's events. A list that does not
// parse is refused here, as containerd would refuse it.
func ScopeEventFilters(p Policy, fs []string) ([]string, error) {
	selector := "namespace==" + strconv.Quote(p.Namespace)
	if len(fs) == 0 {
		return []string{selector}, nil
	}
	out := make([]string, len(fs))
	for i, f := range fs {
		if f == "" {
			out[i] = selector
			continue
		}
		out[i] = selector + "," + f
	}
	if _, err := filters.ParseAll(out...); err != nil {
		return nil, violate(RuleNamespace, "event filters %q do not parse: %v", fs, err)
	}
	return out, nil
}
