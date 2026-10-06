package isolate

import "fmt"

// UpdateEgressPolicy replaces a sandbox's egress policy live
// (plans/egress-domain-filtering.md §5.8). The record keeps it for the next
// reload; a loaded sandbox's host gets it now, so the next outbound request
// is judged by it. The push happens under d.mu, the same as reloadSandbox's,
// so an update racing a reload can't be overwritten by the older policy.
//
// Moving between block-all and a list changes the sandbox's egress slot. The
// controller keys its loader cache by id and slot, so the next request
// compiles a fresh isolate bound to the new slot instead of reusing one
// still bound to the old one.
func (d *Driver) UpdateEgressPolicy(sandboxID string, blockAll bool, allow, deny []string) error {
	p := policyFromCreate(blockAll, allow, deny)
	d.mu.Lock()
	defer d.mu.Unlock()
	rec := d.byID[sandboxID]
	if rec == nil {
		return fmt.Errorf("isolate: unknown sandbox %q", sandboxID)
	}
	rec.egress = p
	if rec.groupKey == "" || rec.needsReload {
		return nil
	}
	d.groupsMu.Lock()
	g := d.groups[rec.groupKey]
	d.groupsMu.Unlock()
	if g == nil {
		return nil
	}
	if setter, ok := g.host.(EgressPolicySetter); ok {
		setter.SetEgressPolicy(sandboxID, p)
	}
	return nil
}
