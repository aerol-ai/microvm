package isolate

import (
	"fmt"

	"github.com/aerol-ai/microvm/pkg/egresspolicy"
)

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
func (d *Driver) UpdateEgressPolicy(sandboxID string, blockAll bool, allow, deny []string, learn bool, rules []egresspolicy.RuleSpec, secrets map[string]string) error {
	p := policyFromCreate(blockAll, allow, deny, learn, rules, secrets)
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

// observeLearn records a destination a learn-mode sandbox reached. The
// recordings live here, not in the group host, so an idle reap that stops
// the host keeps them.
func (d *Driver) observeLearn(sandboxID, host string, port uint16) {
	d.mu.Lock()
	rec := d.byID[sandboxID]
	if rec == nil {
		d.mu.Unlock()
		return
	}
	if rec.learn == nil {
		rec.learn = egresspolicy.NewRecorder(egresspolicy.DefaultLearnMax)
	}
	r := rec.learn
	d.mu.Unlock()
	r.ObserveHost(host, port)
}

// EgressLearned returns a sandbox's learn-mode recording; it stays readable
// after a switch to enforce, until the sandbox is destroyed.
func (d *Driver) EgressLearned(sandboxID string) (egresspolicy.Learned, error) {
	d.mu.Lock()
	rec := d.byID[sandboxID]
	var r *egresspolicy.Recorder
	if rec != nil {
		r = rec.learn
	}
	d.mu.Unlock()
	if rec == nil {
		return egresspolicy.Learned{}, fmt.Errorf("isolate: unknown sandbox %q", sandboxID)
	}
	if r == nil {
		return egresspolicy.NewRecorder(0).Snapshot(), nil
	}
	return r.Snapshot(), nil
}
