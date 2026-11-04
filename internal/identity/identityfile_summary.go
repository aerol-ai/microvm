package identity

import (
	"fmt"
	"sort"
	"strings"
	"unicode"

	"github.com/aerol-ai/microvm/pkg/auditlog"
)

// Binding changes are evidence (CEO review D20). Every node writes one
// identity_config record when the file it enforces changes: the old and new
// hash, and what changed in canonical one-line form. A Summary is those
// lines for one file; Diff turns two into the record body. The node keeps
// the last recorded Summary next to its audit log, so a boot with a changed
// file can say what changed too.

// Summary is the part of a Config an identity_config record diffs. Lines
// are canonical and never carry a secret (the file holds none).
type Summary struct {
	Hash     string   `json:"hash"`
	Issuers  []string `json:"issuers"`
	Bindings []string `json:"bindings"`
	Deny     []string `json:"deny"`
}

// Diff caps keep a record far below the audit line cap (1 MiB) even for a
// 10k-binding file rewritten wholesale: the hashes still name both files.
const (
	maxDiffLines     = 1000
	maxDiffLineBytes = 512
)

// Summary returns c's canonical lines: issuers and bindings in file order,
// deny subjects sorted.
func (c *Config) Summary() Summary {
	s := Summary{Hash: c.hash}
	for _, iss := range c.Issuers {
		s.Issuers = append(s.Issuers, iss.String())
	}
	if c.MCPResource != "" {
		line := fmt.Sprintf("mcp.resource=%q", c.MCPResource)
		if len(c.MCPScopes) > 0 {
			// The scopes decide which token a connector asks for, so a
			// change to them is evidence like the resource itself.
			line += fmt.Sprintf(" mcp.scopes=%q", c.MCPScopes)
		}
		s.Issuers = append(s.Issuers, line)
	}
	for _, b := range c.Bindings {
		s.Bindings = append(s.Bindings, b.String())
	}
	for subject := range c.deny {
		s.Deny = append(s.Deny, subject)
	}
	sort.Strings(s.Deny)
	return s
}

// String is the binding's canonical line: "<issuer> <match> -> <role>/<team>",
// for example `okta group="platform-admins" -> admin/*`.
func (b *Binding) String() string {
	var match string
	switch {
	case b.Group != "":
		match = fmt.Sprintf("group=%q", b.Group)
	case b.AppRole != "":
		match = fmt.Sprintf("app_role=%q", b.AppRole)
	default:
		parts := make([]string, 0, len(b.claimKeys))
		for _, k := range b.claimKeys {
			parts = append(parts, fmt.Sprintf("%s=%q", k, b.Claim[k]))
		}
		match = "claim:" + strings.Join(parts, ",")
	}
	return fmt.Sprintf("%s %s -> %s/%s", b.Issuer, match, b.Role, b.Team)
}

// String is the issuer's canonical line: everything that decides which
// tokens it accepts. The display name and client ids are left out: they
// change labels, not trust (the client ids must already be audiences).
func (iss *Issuer) String() string {
	line := fmt.Sprintf("%s url=%q audiences=%q", iss.Name, iss.URL, iss.Audiences)
	if len(iss.MCPAudiences) > 0 {
		line += fmt.Sprintf(" mcp_audiences=%q", iss.MCPAudiences)
	}
	if iss.JWKSFile != "" {
		line += fmt.Sprintf(" jwks_file=%q", iss.JWKSFile)
	}
	line += fmt.Sprintf(" kind=%s claims=username:%s,groups:%s,roles:%s max_token_lifetime=%s",
		iss.Kind, iss.UsernameClaim, iss.GroupsClaim, iss.RolesClaim, iss.MaxTokenLifetime)
	if iss.MCP {
		line += " mcp=true"
	}
	return line
}

// Diff is the identity_config record body for a change from old to new.
// old is the zero Summary for the first file a node records.
func Diff(old, new Summary) *auditlog.IdentityConfig {
	rec := &auditlog.IdentityConfig{OldHash: old.Hash, NewHash: new.Hash}
	budget := maxDiffLines
	take := func(lines []string) []string {
		var out []string
		for _, l := range lines {
			if budget == 0 {
				rec.Omitted++
				continue
			}
			budget--
			out = append(out, clipLine(l))
		}
		return out
	}
	added, removed, reordered := diffLines(old.Bindings, new.Bindings)
	rec.Reordered = reordered
	// Bindings first: who holds which role is what an auditor reads this
	// record for, so issuer and deny lines yield the budget to them.
	rec.BindingsAdded = take(added)
	rec.BindingsRemoved = take(removed)
	added, removed, _ = diffLines(old.Deny, new.Deny)
	rec.DenyAdded = take(added)
	rec.DenyRemoved = take(removed)
	added, removed, _ = diffLines(old.Issuers, new.Issuers)
	rec.IssuersAdded = take(added)
	rec.IssuersRemoved = take(removed)
	return rec
}

// diffLines compares two ordered line lists as multisets: added lines are
// in new only, removed in old only (counting repeats), and reordered is
// whether the lines both keep appear in a different order.
func diffLines(old, new []string) (added, removed []string, reordered bool) {
	count := make(map[string]int, len(old))
	for _, l := range old {
		count[l]++
	}
	kept := make(map[string]int, len(new))
	var keptNew []string
	for _, l := range new {
		if count[l] > kept[l] {
			kept[l]++
			keptNew = append(keptNew, l)
			continue
		}
		added = append(added, l)
	}
	used := make(map[string]int, len(kept))
	var keptOld []string
	for _, l := range old {
		if used[l] < kept[l] {
			used[l]++
			keptOld = append(keptOld, l)
			continue
		}
		removed = append(removed, l)
	}
	for i := range keptOld {
		if keptOld[i] != keptNew[i] {
			reordered = true
			break
		}
	}
	return added, removed, reordered
}

// clipLine strips control characters and caps a line at maxDiffLineBytes
// on a rune boundary.
func clipLine(l string) string {
	l = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, l)
	if len(l) <= maxDiffLineBytes {
		return l
	}
	cut := maxDiffLineBytes
	for cut > 0 && !isRuneStart(l[cut]) {
		cut--
	}
	return l[:cut] + "…"
}

func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }
