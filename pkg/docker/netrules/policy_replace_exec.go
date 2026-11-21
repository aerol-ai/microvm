package netrules

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
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

// commentedRules are chain's rules keyed by ip that carry comment, in
// chain order, as `iptables -S` prints them; a chain that does not exist
// has none.
func (e *execBackend) commentedRules(chain, ip, comment string) ([][]string, error) {
	all, err := e.chainRules(chain)
	var out [][]string
	for _, spec := range all {
		if addressRuleKeyed(spec, ip) && hasComment(spec, comment) {
			out = append(out, spec)
		}
	}
	return out, err
}

// chainRules are chain's rules in order, as `iptables -S` prints them
// (unquoted); a chain that does not exist has none.
func (e *execBackend) chainRules(chain string) ([][]string, error) {
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
		out = append(out, spec)
	}
	return out, nil
}

// ReplaceBlock implements policyWriter in one iptables-restore
// transaction, from one listing: the address's rules with comment out and
// specs in at pos, together. The kernel applies a restore whole (an nft
// commit, or a legacy table swap), so the address has its old policy or
// its new one, never neither; a caller that gives up (ctx) stops the
// restore before it commits, and nothing changes. Exactly specs, in order,
// already in place writes nothing.
func (e *execBackend) ReplaceBlock(ctx context.Context, chain string, pos int, ip, comment string, specs [][]string) error {
	all, err := e.chainRules(chain)
	if err != nil {
		return err
	}
	var old [][]string
	for _, spec := range all {
		if addressRuleKeyed(spec, ip) && hasComment(spec, comment) {
			old = append(old, spec)
		}
	}
	if len(old) == len(specs) && slices.EqualFunc(old, specs, func(a, b []string) bool {
		return slices.Equal(listedForm(a), listedForm(b))
	}) {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return runRestore(ctx, policyRestore(chain, min(max(pos, 1), len(all)-len(old)+1), old, specs))
}

// policyRestore is the iptables-restore input that takes old out of chain
// and puts specs in at pos, in their order: the deletions first (so each
// names an old rule, never a new copy of it), then the insertions bottom
// first.
func policyRestore(chain string, pos int, old, specs [][]string) string {
	var b strings.Builder
	b.WriteString("*filter\n")
	for _, spec := range old {
		fmt.Fprintf(&b, "-D %s %s\n", chain, strings.Join(spec, " "))
	}
	for _, spec := range slices.Backward(specs) {
		fmt.Fprintf(&b, "-I %s %d %s\n", chain, pos, strings.Join(spec, " "))
	}
	b.WriteString("COMMIT\n")
	return b.String()
}

// runRestore applies an iptables-restore input to the live ruleset
// (--noflush), waiting for the xtables lock; tests replace it.
var runRestore = func(ctx context.Context, input string) error {
	path, err := exec.LookPath("iptables-restore")
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, path, "--noflush", "--wait")
	cmd.Stdin = strings.NewReader(input)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("iptables-restore: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// FloorDrops implements floorReader: chain's DROP rules from src, by
// destination.
func (e *execBackend) FloorDrops(chain string, src netip.Prefix) ([]netip.Prefix, error) {
	all, err := e.chainRules(chain)
	var out []netip.Prefix
	for _, spec := range all {
		if spec[len(spec)-1] != "DROP" {
			continue
		}
		s, d := specValue(spec, "-s"), specValue(spec, "-d")
		sp, err1 := parseAddrOrPrefix(s)
		dp, err2 := parseAddrOrPrefix(d)
		if err1 == nil && err2 == nil && sp.Masked() == src.Masked() {
			out = append(out, dp.Masked())
		}
	}
	return out, err
}

// specValue is the token after flag in spec, or "".
func specValue(spec []string, flag string) string {
	if i := slices.Index(spec, flag); i >= 0 && i+1 < len(spec) {
		return spec[i+1]
	}
	return ""
}

// parseAddrOrPrefix reads "a.b.c.d/n" or a bare address (a /32).
func parseAddrOrPrefix(v string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(v); err == nil {
		return p, nil
	}
	a, err := netip.ParseAddr(v)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
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

// HasJump implements jumpBackend. A child chain that does not exist has
// no jump to it (iptables -C fails on the chain itself, not "no such
// rule", on a kernel no floor was ever written to).
func (e *execBackend) HasJump(parent, child string) (bool, error) {
	if ok, err := e.ipt.ChainExists("filter", child); err != nil || !ok {
		return false, err
	}
	return e.ipt.Exists("filter", parent, "-j", child)
}

// DeleteJump implements jumpBackend: every "-j child" rule of parent.
func (e *execBackend) DeleteJump(parent, child string) error {
	if ok, err := e.ipt.ChainExists("filter", child); err != nil || !ok {
		return err
	}
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
