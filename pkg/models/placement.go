package models

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Placement rules (plans/placement-rules.md). A node declares labels at boot
// (SB_NODE_ZONE, SB_NODE_LABELS); a create may require some of them. The
// rules here are shared by the daemon's config loader and the create path so
// a label a node can declare is exactly a label a create can ask for.
const (
	// PlacementZoneLabel is the reserved label key SB_NODE_ZONE and a
	// rule's zone field both set. A zone is a label so one matcher serves
	// both; the separate field exists because "run this in zone X" is the
	// common ask and should not need a map.
	PlacementZoneLabel = "zone"
	// MaxNodeLabels caps the labels a node may declare and a rule may
	// require (zone included). Labels ride every capacity heartbeat and a
	// rule rides every replicated spec, so both stay small and bounded.
	MaxNodeLabels = 16
	// MaxLabelLength caps one label key and one label value (owner decision
	// P1.1: 63 characters each, the Kubernetes name length).
	MaxLabelLength = 63
)

// ErrorCodePlacementUnsatisfiable is the API code of a create whose placement
// rule no node satisfies (HTTP 409).
const ErrorCodePlacementUnsatisfiable = "placement_unsatisfiable"

var (
	// ErrInvalidPlacement is a malformed placement rule or node label. It
	// maps to HTTP 400 (the default branch of the API's error classifier).
	ErrInvalidPlacement = errors.New("invalid placement")
	// ErrPlacementUnsatisfiable is a create whose rule no node satisfies. It
	// is a refusal, never a fallback: a rule that is quietly ignored is worse
	// than no rule for regulated work (owner decision P1.4).
	ErrPlacementUnsatisfiable = errors.New("placement_unsatisfiable")
)

// labelNamePattern is the Kubernetes "name" segment: alphanumeric at both
// ends, with '-', '_' and '.' allowed inside.
var labelNamePattern = regexp.MustCompile(`^[A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?$`)

// labelPrefixPattern is a lower-case DNS subdomain, the Kubernetes key prefix
// ("example.com" in "example.com/tier").
var labelPrefixPattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)

// PlacementRule says where a sandbox may run. Every given key must match a
// node's label exactly (AND); there are no operators in this version (owner
// decision P1.3). Zone is shorthand for the label "zone".
type PlacementRule struct {
	Zone   string            `json:"zone,omitempty"`
	Labels map[string]string `json:"labels,omitempty"`
}

// ValidateLabelKey checks a label key against the Kubernetes syntax: an
// optional DNS-subdomain prefix and '/', then a name. The whole key is at
// most MaxLabelLength characters.
func ValidateLabelKey(key string) error {
	if key == "" {
		return fmt.Errorf("%w: label key is empty", ErrInvalidPlacement)
	}
	if len(key) > MaxLabelLength {
		return fmt.Errorf("%w: label key %q is longer than %d characters", ErrInvalidPlacement, key, MaxLabelLength)
	}
	name := key
	if prefix, rest, ok := strings.Cut(key, "/"); ok {
		if !labelPrefixPattern.MatchString(prefix) {
			return fmt.Errorf("%w: label key %q has an invalid prefix (want a lower-case DNS name)", ErrInvalidPlacement, key)
		}
		name = rest
	}
	if !labelNamePattern.MatchString(name) {
		return fmt.Errorf("%w: label key %q must start and end with a letter or digit and use only letters, digits, '-', '_' and '.'", ErrInvalidPlacement, key)
	}
	return nil
}

// ValidateLabelValue checks a label value against the Kubernetes syntax. An
// empty value is allowed, as in Kubernetes.
func ValidateLabelValue(key, value string) error {
	if len(value) > MaxLabelLength {
		return fmt.Errorf("%w: label %q value is longer than %d characters", ErrInvalidPlacement, key, MaxLabelLength)
	}
	if value != "" && !labelNamePattern.MatchString(value) {
		return fmt.Errorf("%w: label %q value %q must start and end with a letter or digit and use only letters, digits, '-', '_' and '.'", ErrInvalidPlacement, key, value)
	}
	return nil
}

// ValidateLabels checks a whole label set: every key and value, and the
// MaxNodeLabels cap.
func ValidateLabels(labels map[string]string) error {
	if len(labels) > MaxNodeLabels {
		return fmt.Errorf("%w: %d labels given, at most %d allowed", ErrInvalidPlacement, len(labels), MaxNodeLabels)
	}
	for _, k := range sortedLabelKeys(labels) {
		if err := ValidateLabelKey(k); err != nil {
			return err
		}
		if err := ValidateLabelValue(k, labels[k]); err != nil {
			return err
		}
	}
	return nil
}

// ParseNodeLabels parses SB_NODE_LABELS ("k=v,k=v") and folds zone (from
// SB_NODE_ZONE) in under PlacementZoneLabel. A key given twice, a zone given
// both ways with different values, or a malformed entry is an error, so a
// typo fails the boot instead of making a node silently unmatchable.
func ParseNodeLabels(raw, zone string) (map[string]string, error) {
	out := map[string]string{}
	raw = strings.TrimSpace(raw)
	if raw != "" {
		for entry := range strings.SplitSeq(raw, ",") {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				return nil, fmt.Errorf("%w: SB_NODE_LABELS=%q has an empty entry (check for stray commas)", ErrInvalidPlacement, raw)
			}
			k, v, ok := strings.Cut(entry, "=")
			if !ok {
				return nil, fmt.Errorf("%w: SB_NODE_LABELS entry %q is not key=value", ErrInvalidPlacement, entry)
			}
			k, v = strings.TrimSpace(k), strings.TrimSpace(v)
			if prev, dup := out[k]; dup && prev != v {
				return nil, fmt.Errorf("%w: SB_NODE_LABELS sets %q twice (%q and %q)", ErrInvalidPlacement, k, prev, v)
			}
			out[k] = v
		}
	}
	if zone = strings.TrimSpace(zone); zone != "" {
		if prev, ok := out[PlacementZoneLabel]; ok && prev != zone {
			return nil, fmt.Errorf("%w: SB_NODE_ZONE=%q disagrees with zone=%q in SB_NODE_LABELS", ErrInvalidPlacement, zone, prev)
		}
		out[PlacementZoneLabel] = zone
	}
	if err := ValidateLabels(out); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// NormalizePlacementRule validates a create's rule and returns its canonical
// form: the zone in Zone (moved there from labels["zone"] if given that way)
// and every other label in Labels. An empty rule normalizes to nil, so a
// create that sends "placement": {} places exactly like one that sends
// nothing and carries no rule in its replicated spec.
func NormalizePlacementRule(r *PlacementRule) (*PlacementRule, error) {
	if r == nil {
		return nil, nil
	}
	zone := strings.TrimSpace(r.Zone)
	labels := make(map[string]string, len(r.Labels))
	for k, v := range r.Labels {
		labels[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	if lz, ok := labels[PlacementZoneLabel]; ok {
		if zone != "" && lz != zone {
			return nil, fmt.Errorf("%w: zone %q disagrees with labels.zone %q", ErrInvalidPlacement, zone, lz)
		}
		zone = lz
		delete(labels, PlacementZoneLabel)
	}
	required := make(map[string]string, len(labels)+1)
	for k, v := range labels {
		required[k] = v
	}
	if zone != "" {
		required[PlacementZoneLabel] = zone
	}
	if err := ValidateLabels(required); err != nil {
		return nil, err
	}
	if len(required) == 0 {
		return nil, nil
	}
	out := &PlacementRule{Zone: zone}
	if len(labels) > 0 {
		out.Labels = labels
	}
	return out, nil
}

// RequiredLabels is the label set a node must carry to run the sandbox: the
// rule's labels plus its zone under PlacementZoneLabel. nil for no rule.
func (r *PlacementRule) RequiredLabels() map[string]string {
	if r == nil {
		return nil
	}
	zone := strings.TrimSpace(r.Zone)
	if zone == "" && len(r.Labels) == 0 {
		return nil
	}
	out := make(map[string]string, len(r.Labels)+1)
	for k, v := range r.Labels {
		out[k] = v
	}
	if zone != "" {
		out[PlacementZoneLabel] = zone
	}
	return out
}

// LabelsSatisfy reports whether a node with labels have may run a sandbox
// that requires want: every wanted key present with exactly the wanted value.
// An empty want is satisfied by any node, labelled or not.
func LabelsSatisfy(have, want map[string]string) bool {
	for k, v := range want {
		got, ok := have[k]
		if !ok || got != v {
			return false
		}
	}
	return true
}

// FormatLabels renders a label set as "k=v, k2=v2" in key order, for error
// messages and logs that must name the rule.
func FormatLabels(labels map[string]string) string {
	keys := sortedLabelKeys(labels)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+labels[k])
	}
	return strings.Join(parts, ", ")
}

// PlacementUnsatisfiableError is the refusal for a rule no node satisfies.
// The message names the rule, never the nodes, so it reads the same from any
// node that refuses.
func PlacementUnsatisfiableError(want map[string]string) error {
	return fmt.Errorf("%w: no node has the labels %s", ErrPlacementUnsatisfiable, FormatLabels(want))
}

// CloneLabels returns an independent copy, nil for an empty set.
func CloneLabels(labels map[string]string) map[string]string {
	if len(labels) == 0 {
		return nil
	}
	out := make(map[string]string, len(labels))
	for k, v := range labels {
		out[k] = v
	}
	return out
}

func sortedLabelKeys(labels map[string]string) []string {
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
