package egresspolicy

import (
	"regexp"
	"strings"
)

// FieldEgressProfiles names the profile-reference list in errors.
const FieldEgressProfiles = "egress_profiles"

// Profile references (plans/egress-domain-filtering.md D21). A plain name is
// one of the owner's own profiles; the prefixes are reserved for profiles
// nobody owns.
const (
	// OrgProfilePrefix marks the operator file's org profiles (§5.10).
	OrgProfilePrefix = "org:"
	// BuiltinProfilePrefix marks the built-in catalogue, pinned at create to
	// builtin:<name>@<YYYYMMDD> (CEO D11).
	BuiltinProfilePrefix = "builtin:"
	// MaxProfileRefs bounds how many profiles one sandbox references. The
	// union cap bounds the entries; this keeps the reference list, which
	// rides in the replicated spec, small.
	MaxProfileRefs = 16
)

var profileNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// ValidProfileName reports whether name can name an owner's profile.
func ValidProfileName(name string) bool { return profileNameRe.MatchString(name) }

// ValidateProfileName returns a 400-mapped error for a bad profile name.
func ValidateProfileName(name string) error {
	if !ValidProfileName(name) {
		return invalidf("egress profile name %q: names match %s", name, profileNameRe)
	}
	return nil
}

// ValidateProfileRefs checks a sandbox's profile references: at most
// MaxProfileRefs, no duplicates, each a valid name or a reserved-prefix
// reference with a valid name after the prefix.
func ValidateProfileRefs(refs []string) error {
	if len(refs) > MaxProfileRefs {
		return invalidf("%s has %d entries; the limit is %d", FieldEgressProfiles, len(refs), MaxProfileRefs)
	}
	seen := make(map[string]struct{}, len(refs))
	for _, ref := range refs {
		name, key := ref, ref
		switch {
		case strings.HasPrefix(ref, OrgProfilePrefix):
			name = strings.TrimPrefix(ref, OrgProfilePrefix)
		case strings.HasPrefix(ref, BuiltinProfilePrefix):
			// One version of a built-in per sandbox: a bare name and its
			// pinned form are the same profile.
			name, _, _ = strings.Cut(strings.TrimPrefix(ref, BuiltinProfilePrefix), "@")
			key = BuiltinProfilePrefix + name
		}
		if !ValidProfileName(name) {
			return &EntryError{Field: FieldEgressProfiles, Entry: ref, Reason: "not a profile name (" + profileNameRe.String() + ", optionally after org: or builtin:)"}
		}
		if _, dup := seen[key]; dup {
			return &EntryError{Field: FieldEgressProfiles, Entry: ref, Reason: "listed twice"}
		}
		seen[key] = struct{}{}
	}
	return nil
}

// Union returns a sandbox's effective allow list: its inline entries, then
// each referenced profile's in order, deduped in canonical form and held to
// MaxUnionHostnames (plans/egress-domain-filtering.md D21). Inline entries
// keep their own MaxInlineHostnames cap at the API; this only bounds what an
// enforcement point has to hold.
func Union(inline []string, profiles ...[]string) ([]string, error) {
	all := append([]string(nil), inline...)
	for _, p := range profiles {
		all = append(all, p...)
	}
	entries, err := ParseAllowList(FieldEgressProfiles, all, MaxUnionHostnames)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(entries))
	for i, e := range entries {
		out[i] = e.String()
	}
	return out, nil
}
