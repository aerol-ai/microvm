package netrules

import (
	"fmt"
	"slices"
	"strings"
)

// ClearCommented implements commentClearer: each chain listed once
// (`iptables -S`), and every rule keyed by ip with the comment deleted.
func (e *execBackend) ClearCommented(chains []string, ip, comment string) error {
	for _, chain := range chains {
		rules, err := e.commentedRules(chain, ip, comment)
		if err != nil {
			return err
		}
		for _, spec := range rules {
			if err := e.ipt.Delete("filter", chain, spec...); err != nil && !ruleNotExist(err) {
				return fmt.Errorf("delete %s rule: %w", chain, err)
			}
		}
	}
	return nil
}

// PolicyState implements policyReader.
func (e *execBackend) PolicyState(chain, ip, comment string, specs [][]string) (int, bool, error) {
	got, err := e.commentedRules(chain, ip, comment)
	if err != nil || len(got) != len(specs) {
		return len(got), false, err
	}
	for i, spec := range specs {
		if !slices.Equal(listedForm(got[i]), listedForm(spec)) {
			return len(got), false, nil
		}
	}
	return len(got), true, nil
}

// commentedRules are chain's rules keyed by ip that carry comment, in
// chain order, as `iptables -S` prints them; a chain that does not exist
// has none.
func (e *execBackend) commentedRules(chain, ip, comment string) ([][]string, error) {
	lines, err := e.ipt.List("filter", chain)
	if err != nil {
		if ruleNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list %s: %w", chain, err)
	}
	var out [][]string
	for _, line := range lines {
		f := strings.Fields(line)
		if len(f) < 3 || f[0] != "-A" || f[1] != chain {
			continue
		}
		spec := f[2:]
		for i := range spec {
			spec[i] = strings.Trim(spec[i], `"`)
		}
		if addressRuleKeyed(spec, ip) && hasComment(spec, comment) {
			out = append(out, spec)
		}
	}
	return out, nil
}

// listedForm is a rulespec as `iptables -S` prints it: a host address
// with its /32.
func listedForm(spec []string) []string {
	out := slices.Clone(spec)
	for i := 0; i+1 < len(out); i++ {
		if (out[i] == "-s" || out[i] == "-d") && !strings.Contains(out[i+1], "/") {
			out[i+1] += "/32"
		}
	}
	return out
}

// hasComment reports whether an iptables-shaped rule carries comment.
func hasComment(tokens []string, comment string) bool {
	i := slices.Index(tokens, "--comment")
	return i >= 0 && i+1 < len(tokens) && tokens[i+1] == comment
}

// HasJump implements jumpBackend.
func (e *execBackend) HasJump(parent, child string) (bool, error) {
	return e.ipt.Exists("filter", parent, "-j", child)
}

// DeleteJump implements jumpBackend: every "-j child" rule of parent.
func (e *execBackend) DeleteJump(parent, child string) error {
	for {
		err := e.ipt.Delete("filter", parent, "-j", child)
		if err == nil {
			continue
		}
		if ruleNotExist(err) {
			return nil
		}
		return fmt.Errorf("delete %s jump to %s: %w", parent, child, err)
	}
}
