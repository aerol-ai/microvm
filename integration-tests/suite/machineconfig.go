// This file is deliberately NOT behind the `integration` build tag: the tfvars
// parser is pure and gets an offline `make test` regression test
// (machineconfig_test.go), while the rest of package suite needs a live cluster.

package suite

import (
	"regexp"
	"strings"
)

// machineConfig is the hardware the numbers were measured on, copied from the
// scenario's tfvars so a result is self-describing — a create latency is
// meaningless without knowing whether the worker is a t3.medium or a c5.metal.
// It records the intended (terraform-declared) topology, not live-probed specs;
// that's the deliberate trade in keeping the bench tfvars-sourced and offline.
type machineConfig struct {
	Source          string     `json:"source"`           // tfvars path it was read from
	DefaultInstance string     `json:"default_instance"` // default_instance_type
	Nodes           []nodeSpec `json:"nodes"`            // one row per declared node
}

// nodeSpec is one node's declared shape from the tfvars nodes map.
type nodeSpec struct {
	Name         string `json:"name"`
	Role         string `json:"role"`
	InstanceType string `json:"instance_type"` // empty => inherits DefaultInstance
	Extras       string `json:"extras,omitempty"`
}

var (
	// nodeStartRe matches the opening of a node entry: `name = {` (with or
	// without body following on the same line).
	nodeStartRe = regexp.MustCompile(`^([A-Za-z0-9_-]+)\s*=\s*\{`)
	// heredocStartRe captures a heredoc terminator (`<<-EOT`, `<<EOT`, `<<"EOT"`).
	heredocStartRe = regexp.MustCompile(`<<-?\s*"?([A-Za-z_][A-Za-z0-9_]*)"?`)
)

// tfvarsAttr pulls a quoted `key = "value"` attribute out of a node body.
func tfvarsAttr(body, key string) string {
	re := regexp.MustCompile(key + `\s*=\s*"([^"]*)"`)
	if m := re.FindStringSubmatch(body); m != nil {
		return m[1]
	}
	return ""
}

// parseMachineConfig parses a scenario tfvars into a machineConfig. It handles
// BOTH single-line (`ingress-1 = { role = "ingress" }`) and multi-line node
// bodies, and skips heredoc (`<<-EOT … EOT`) content so an `extra_user_data`
// script's braces or a stray `instance_type =` line inside it cannot corrupt the
// node map. The original single-line-only parser silently produced an empty
// Nodes list for the benchmark scenarios (whose worker bodies span a heredoc),
// which meant the flagship report stamped `m6i.large` instead of the actual
// `c5.metal` workers — the whole CM-4 hardware-disclosure point. This is that
// regression's fix.
func parseMachineConfig(raw []byte, source string) *machineConfig {
	mc := &machineConfig{Source: source}
	inNodes := false
	heredocTerm := ""
	var curName string
	var curBody strings.Builder
	depth := 0 // brace depth of the node body currently being accumulated (0 = none)

	flush := func() {
		if curName == "" {
			return
		}
		body := curBody.String()
		ns := nodeSpec{Name: curName, Role: tfvarsAttr(body, "role"), InstanceType: tfvarsAttr(body, "instance_type")}
		// Capture with_* feature flags so the reader knows which runtime a worker
		// was provisioned for.
		var extras []string
		for _, flag := range []string{"with_firecracker", "with_gvisor"} {
			if regexp.MustCompile(flag + `\s*=\s*true`).MatchString(body) {
				extras = append(extras, flag)
			}
		}
		ns.Extras = strings.Join(extras, ",")
		mc.Nodes = append(mc.Nodes, ns)
		curName = ""
		curBody.Reset()
	}

	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)

		// Inside a heredoc: skip content (do NOT count braces or feed it to attr
		// extraction) until the terminator line.
		if heredocTerm != "" {
			if trimmed == heredocTerm {
				heredocTerm = ""
			}
			continue
		}
		if strings.HasPrefix(trimmed, "#") {
			continue
		}

		if !inNodes {
			if v := tfvarsAttr(trimmed, "default_instance_type"); v != "" {
				mc.DefaultInstance = v
			}
			if strings.HasPrefix(trimmed, "nodes") && strings.Contains(trimmed, "{") {
				inNodes = true
			}
			continue
		}

		// inNodes == true.
		if depth == 0 {
			// Between node entries: the nodes map closes, or a node begins.
			if trimmed == "}" || trimmed == "}," {
				inNodes = false
				continue
			}
			m := nodeStartRe.FindStringSubmatch(trimmed)
			if m == nil {
				continue
			}
			curName = m[1]
			curBody.Reset()
			// Process from the `{` onward so a single-line node closes immediately.
			idx := strings.Index(line, "{")
			depth = processBodyLine(line[idx:], &curBody, &heredocTerm)
			if depth <= 0 && heredocTerm == "" {
				depth = 0
				flush()
			}
			continue
		}

		// depth > 0: accumulating a multi-line node body.
		depth += processBodyLine(line, &curBody, &heredocTerm)
		if depth <= 0 && heredocTerm == "" {
			depth = 0
			flush()
		}
	}
	return mc
}

// processBodyLine appends s to the node body, arms heredocTerm if a heredoc
// starts on this line, and returns the net brace delta — counting braces only in
// the portion before a `<<` so the skipped heredoc script cannot skew depth.
func processBodyLine(s string, body *strings.Builder, heredocTerm *string) int {
	countPart := s
	if loc := strings.Index(s, "<<"); loc >= 0 {
		if m := heredocStartRe.FindStringSubmatch(s[loc:]); m != nil {
			*heredocTerm = m[1]
			countPart = s[:loc]
		}
	}
	body.WriteString(s)
	body.WriteByte('\n')
	return strings.Count(countPart, "{") - strings.Count(countPart, "}")
}
