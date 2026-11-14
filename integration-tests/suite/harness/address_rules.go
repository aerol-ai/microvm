package harness

import (
	"regexp"
	"sort"
	"strings"
)

var (
	ruleCounters = regexp.MustCompile(`counter packets \d+ bytes \d+ ?`)
	setExpires   = regexp.MustCompile(` expires \S+`)
)

// AddressRuleLines returns what a host firewall dump (iptables-save and
// `nft list ruleset` output, concatenated) holds for ip, normalised so two
// dumps of an unchanged rule set compare equal.
//
// Rule lines that name ip are kept, without their packet counters. An nft
// set is read element by element ("set element <e>"), not line by line:
// nft wraps a set's elements two or more to a line, so the line that holds
// ip shifts whenever any other address joins or leaves the set. On a node
// with the containerd warm pool every parked container's address sits in
// the block set, and a pool refill re-wrapped it under UC-345 (2026-11-08),
// which read as ip's rule being removed. An element's " expires <t>" is
// dropped for the same reason: it counts down between two dumps.
func AddressRuleLines(dump, ip string) []string {
	re := regexp.MustCompile(`(^|[^0-9.])` + regexp.QuoteMeta(ip) + `([^0-9.]|$)`)
	var (
		rules []string
		set   strings.Builder
		inSet bool
	)
	for _, line := range strings.Split(dump, "\n") {
		line = strings.TrimSpace(line)
		if !inSet {
			i := strings.Index(line, "elements = {")
			if i < 0 {
				if re.MatchString(line) {
					rules = append(rules, ruleCounters.ReplaceAllString(line, ""))
				}
				continue
			}
			inSet = true
			set.Reset()
			line = line[i+len("elements = {"):]
		}
		j := strings.Index(line, "}")
		if j < 0 {
			set.WriteString(line)
			set.WriteString(" ")
			continue
		}
		set.WriteString(line[:j])
		inSet = false
		for _, e := range strings.Split(set.String(), ",") {
			e = strings.Join(strings.Fields(setExpires.ReplaceAllString(e, "")), " ")
			if e != "" && re.MatchString(e) {
				rules = append(rules, "set element "+e)
			}
		}
	}
	sort.Strings(rules)
	return rules
}
