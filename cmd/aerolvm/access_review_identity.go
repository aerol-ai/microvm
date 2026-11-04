package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
	"unicode"

	"gopkg.in/yaml.v3"

	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// The identity file in the access review (plans/identity-and-access.md
// §5.10, CEO review D20). Two parts:
//
//   - every identity_config record in the window: what each node's identity
//     file change did to who can sign in and with which role;
//   - with --identity-file, the bindings of the file the reviewer holds,
//     with the admin and every-team grants flagged, and which nodes the
//     records show enforcing that exact file (by its SHA-256).
//
// The file's schema and its enforcing parser live in internal/identity,
// which the CLI does not import (it drags in the OIDC verifier). pkg/
// identitywire, the identity package the CLI may import, stays standard
// library only. So the review decodes the few keys it reads here, leniently
// about the rest: sandboxd is the strict parser, and the hash ties the file
// the reviewer holds to the file a node recorded. The canonical binding line
// matches internal/identity's Binding.String(), which
// TestIdentityFileMatchesTheServerParser pins.

// maxIdentityFileBytes is internal/identity.MaxFileBytes: sandboxd refuses a
// larger file, so no node can be enforcing one.
const maxIdentityFileBytes = 1 << 20

// identityFileVersion is the only format sandboxd reads.
const identityFileVersion = 1

// reviewIdentityFile is the identity file as the review reports it.
type reviewIdentityFile struct {
	// Hash is the SHA-256 of the file's bytes, hex: what identity_config
	// records and the aerolvm_identity_file_info metric name.
	Hash         string          `json:"hash"`
	Issuers      []reviewIssuer  `json:"issuers"`
	Bindings     []reviewBinding `json:"bindings"`
	DenySubjects int             `json:"deny_subjects"`
}

type reviewIssuer struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name,omitempty"`
}

// reviewBinding is one binding, in file order: bindings are tried top to
// bottom and a person's first match is their default role.
type reviewBinding struct {
	Index  int    `json:"index"`
	Issuer string `json:"issuer"`
	Match  string `json:"match"`
	Role   string `json:"role"`
	Team   string `json:"team"`
	// Line is the canonical form identity_config records carry.
	Line  string       `json:"line"`
	Flags []reviewFlag `json:"flags"`
}

// reviewIdentityChange is one identity_config record: a node's identity
// file changed, at reload or at boot.
type reviewIdentityChange struct {
	At   time.Time `json:"at"`
	Node string    `json:"node"`
	auditlog.IdentityConfig
	// Flags is identity_change, plus admin_grant when the change added a
	// binding that grants the admin role.
	Flags []reviewFlag `json:"flags"`
}

// identityFileDoc is the part of the identity file the review decodes.
type identityFileDoc struct {
	Version int `yaml:"version"`
	Issuers []struct {
		Name        string `yaml:"name"`
		DisplayName string `yaml:"display_name"`
	} `yaml:"issuers"`
	Bindings []struct {
		Issuer  string            `yaml:"issuer"`
		Group   string            `yaml:"group"`
		AppRole string            `yaml:"app_role"`
		Claim   map[string]string `yaml:"claim"`
		Role    string            `yaml:"role"`
		Team    string            `yaml:"team"`
	} `yaml:"bindings"`
	DenySubjects []string `yaml:"deny_subjects"`
}

// readIdentityFile reads and decodes path.
func readIdentityFile(path string) (*reviewIdentityFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("--identity-file: %w", err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxIdentityFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("--identity-file: %w", err)
	}
	file, err := parseIdentityFile(raw)
	if err != nil {
		return nil, fmt.Errorf("--identity-file %s: %w", path, err)
	}
	return file, nil
}

// parseIdentityFile decodes the bindings and issuer names, refusing what
// sandboxd would refuse about them, so a binding line here is the line a
// node records for the same file.
func parseIdentityFile(raw []byte) (*reviewIdentityFile, error) {
	if len(raw) > maxIdentityFileBytes {
		return nil, fmt.Errorf("larger than %d bytes; sandboxd refuses it", maxIdentityFileBytes)
	}
	var doc identityFileDoc
	if err := yaml.NewDecoder(bytes.NewReader(raw)).Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("empty; sandboxd refuses an empty identity file")
		}
		return nil, err
	}
	if doc.Version != identityFileVersion {
		return nil, fmt.Errorf("version %d, want %d", doc.Version, identityFileVersion)
	}
	sum := sha256.Sum256(raw)
	file := &reviewIdentityFile{Hash: hex.EncodeToString(sum[:]), Issuers: []reviewIssuer{}, Bindings: []reviewBinding{}, DenySubjects: len(doc.DenySubjects)}
	for _, iss := range doc.Issuers {
		file.Issuers = append(file.Issuers, reviewIssuer{Name: clean(iss.Name), DisplayName: clean(iss.DisplayName)})
	}
	for i, fb := range doc.Bindings {
		b := reviewBinding{
			Index: i + 1, Issuer: strings.TrimSpace(fb.Issuer),
			Role: strings.TrimSpace(fb.Role), Team: strings.TrimSpace(fb.Team), Flags: []reviewFlag{},
		}
		group, appRole := strings.TrimSpace(fb.Group), strings.TrimSpace(fb.AppRole)
		matchers := 0
		for _, set := range []bool{group != "", appRole != "", len(fb.Claim) > 0} {
			if set {
				matchers++
			}
		}
		role := controlplane.Role(b.Role)
		switch {
		case matchers != 1:
			return nil, fmt.Errorf("bindings[%d]: set exactly one of group, app_role or claim", i)
		case !role.Valid():
			return nil, fmt.Errorf("bindings[%d]: role %q: want viewer, runner, auditor or admin", i, fb.Role)
		case b.Team == "" && role.RequiresFleet():
			// auditor and admin are bound to every team when the file
			// names none, exactly as sandboxd reads it.
			b.Team = controlplane.FleetTeam
		case b.Team == "":
			return nil, fmt.Errorf("bindings[%d]: team: role %s needs a team, or * for every team", i, b.Role)
		}
		b.Match = bindingMatch(group, appRole, fb.Claim)
		b.Line = cleanLine(fmt.Sprintf("%s %s -> %s/%s", b.Issuer, b.Match, b.Role, b.Team))
		b.Issuer, b.Match, b.Team = clean(b.Issuer), cleanLine(b.Match), clean(b.Team)
		if role == controlplane.RoleAdmin {
			b.Flags = append(b.Flags, flagAdmin)
		}
		if b.Team == controlplane.FleetTeam {
			b.Flags = append(b.Flags, flagEveryTeam)
		}
		file.Bindings = append(file.Bindings, b)
	}
	return file, nil
}

// bindingMatch is a binding's matcher as its canonical line writes it:
// group="…", app_role="…" or claim:k="v",k2="v2" with the keys sorted.
func bindingMatch(group, appRole string, claim map[string]string) string {
	switch {
	case group != "":
		return fmt.Sprintf("group=%q", group)
	case appRole != "":
		return fmt.Sprintf("app_role=%q", appRole)
	}
	keys := make([]string, 0, len(claim))
	trimmed := make(map[string]string, len(claim))
	for k, v := range claim {
		k = strings.TrimSpace(k)
		keys = append(keys, k)
		trimmed[k] = strings.TrimSpace(v)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s=%q", k, trimmed[k])
	}
	return "claim:" + strings.Join(parts, ",")
}

// bindingGrant reads the role and team out of a canonical binding line
// ("<issuer> <match> -> <role>/<team>"). The match is quoted, so the last
// " -> " is the one before the grant.
func bindingGrant(line string) (role, team string, ok bool) {
	i := strings.LastIndex(line, " -> ")
	if i < 0 {
		return "", "", false
	}
	return strings.Cut(line[i+len(" -> "):], "/")
}

// grantFlags are the flags a binding line earns: admin for the admin role,
// every_team for a grant on every team.
func grantFlags(line string) []reviewFlag {
	flags := []reviewFlag{}
	role, team, ok := bindingGrant(line)
	if !ok {
		return flags
	}
	if role == string(controlplane.RoleAdmin) {
		flags = append(flags, flagAdmin)
	}
	if team == controlplane.FleetTeam {
		flags = append(flags, flagEveryTeam)
	}
	return flags
}

// cleanLine strips control characters from a canonical line. Unlike clean
// it does not cut at 256 characters: a claim binding can be longer, and the
// writer already caps each line at 512 bytes.
func cleanLine(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if r := []rune(s); len(r) > maxReviewLineRunes {
		return string(r[:maxReviewLineRunes]) + "…"
	}
	return s
}

// maxReviewLineRunes bounds a line from a record: twice the writer's cap,
// so it only ever cuts a record a node did not write that way.
const maxReviewLineRunes = 1024

// identityChange turns one identity_config record into the report's row.
func (s *reviewShare) identityChange(ev auditlog.Event) {
	rec := ev.IdentityConfig
	if rec == nil {
		return
	}
	lines := func(in []string) []string {
		var out []string
		for _, l := range in {
			out = append(out, cleanLine(l))
		}
		return out
	}
	ch := reviewIdentityChange{At: ev.Time.UTC(), Node: s.node, Flags: []reviewFlag{flagIdentityChange}}
	ch.OldHash, ch.NewHash = clean(rec.OldHash), clean(rec.NewHash)
	ch.BindingsAdded, ch.BindingsRemoved, ch.Reordered = lines(rec.BindingsAdded), lines(rec.BindingsRemoved), rec.Reordered
	ch.DenyAdded, ch.DenyRemoved = lines(rec.DenyAdded), lines(rec.DenyRemoved)
	ch.IssuersAdded, ch.IssuersRemoved = lines(rec.IssuersAdded), lines(rec.IssuersRemoved)
	ch.Omitted = rec.Omitted
	for _, l := range ch.BindingsAdded {
		if role, _, ok := bindingGrant(l); ok && role == string(controlplane.RoleAdmin) {
			ch.Flags = append(ch.Flags, flagAdminGrant)
			break
		}
	}
	s.identityChanges = append(s.identityChanges, ch)
	if !ev.Time.Before(s.identityAt) {
		s.identityHash, s.identityAt = ch.NewHash, ev.Time
	}
}

// identityChangeWords sums up one change for its finding.
func identityChangeWords(ch reviewIdentityChange) string {
	var parts []string
	count := func(n int, one, many string) {
		if n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, plural(int64(n), one, many)))
		}
	}
	count(len(ch.BindingsAdded), "binding added", "bindings added")
	count(len(ch.BindingsRemoved), "binding removed", "bindings removed")
	if ch.Reordered {
		parts = append(parts, "bindings reordered")
	}
	count(len(ch.DenyAdded), "deny subject added", "deny subjects added")
	count(len(ch.DenyRemoved), "deny subject removed", "deny subjects removed")
	count(len(ch.IssuersAdded), "issuer added", "issuers added")
	count(len(ch.IssuersRemoved), "issuer removed", "issuers removed")
	count(ch.Omitted, "line left out of the record", "lines left out of the record")
	what := strings.Join(parts, ", ")
	if what == "" {
		what = "no line changed"
	}
	from := "no file recorded before"
	if ch.OldHash != "" {
		from = shortHash(ch.OldHash)
	}
	return fmt.Sprintf("identity file changed from %s to %s at %s: %s", from, shortHash(ch.NewHash), ch.At.Format(time.RFC3339), what)
}

// shortHash is a file hash as the Markdown shows it; the CSV and JSON carry
// it whole.
func shortHash(h string) string {
	if len(h) > 16 {
		return h[:16]
	}
	return h
}

// identityChangeLine is one line of a change as the report lists it.
type identityChangeLine struct {
	change string // file, binding_added, ..., omitted
	line   string
	flags  []reviewFlag
}

// changeLines lists a change line by line: the file row first, then
// bindings (what an auditor reads it for), deny subjects and issuers. hash
// formats the file hashes: shortened for Markdown, whole for CSV.
func changeLines(ch reviewIdentityChange, hash func(string) string) []identityChangeLine {
	old := "(none)"
	if ch.OldHash != "" {
		old = hash(ch.OldHash)
	}
	out := []identityChangeLine{{change: "file", line: "old_hash=" + old + " new_hash=" + hash(ch.NewHash), flags: []reviewFlag{flagIdentityChange}}}
	add := func(change string, lines []string, flagged bool) {
		for _, l := range lines {
			flags := []reviewFlag{}
			if flagged {
				flags = grantFlags(l)
			}
			out = append(out, identityChangeLine{change: change, line: l, flags: flags})
		}
	}
	add("binding_added", ch.BindingsAdded, true)
	add("binding_removed", ch.BindingsRemoved, false)
	if ch.Reordered {
		out = append(out, identityChangeLine{change: "bindings_reordered", line: "the first-match order changed: a person can get another default role with no line added or removed", flags: []reviewFlag{}})
	}
	add("deny_added", ch.DenyAdded, false)
	add("deny_removed", ch.DenyRemoved, false)
	add("issuer_added", ch.IssuersAdded, false)
	add("issuer_removed", ch.IssuersRemoved, false)
	if ch.Omitted > 0 {
		out = append(out, identityChangeLine{change: "lines_omitted", line: fmt.Sprintf("%d %s left out of the record; the hashes name both files", ch.Omitted, plural(int64(ch.Omitted), "line", "lines")), flags: []reviewFlag{}})
	}
	return out
}

// nodeFile is a node and the file its newest identity_config record names.
type nodeFile struct{ node, hash string }

// enforcement sorts the nodes by whether their newest identity_config record
// in the window names the file the reviewer gave, another file, or none.
func enforcement(file *reviewIdentityFile, nodes []reviewNode) (same []string, other []nodeFile, unknown []string) {
	for _, n := range nodes {
		switch n.IdentityHash {
		case "":
			unknown = append(unknown, n.NodeID)
		case file.Hash:
			same = append(same, n.NodeID)
		default:
			other = append(other, nodeFile{n.NodeID, n.IdentityHash})
		}
	}
	return same, other, unknown
}
