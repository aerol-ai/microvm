package release

import (
	"cmp"
	"fmt"
	"strconv"
	"strings"
)

// Version is a release tag, vMAJOR.MINOR.PATCH with an optional -PRERELEASE,
// ordered by semantic versioning (semver.org §11). Build metadata (+...) is
// not accepted: release tags never carry it.
type Version struct {
	Major, Minor, Patch uint64
	// Prerelease holds the dot-separated identifiers after '-'; empty for a
	// release.
	Prerelease []string
}

// ParseVersion parses a release tag such as v0.6.12 or v0.7.0-rc.1. The
// leading 'v' is required, as release.yml requires it of every tag.
func ParseVersion(s string) (Version, error) {
	rest, ok := strings.CutPrefix(s, "v")
	if !ok {
		return Version{}, fmt.Errorf("version %q does not start with v", s)
	}
	core, pre, hasPre := strings.Cut(rest, "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return Version{}, fmt.Errorf("version %q is not vMAJOR.MINOR.PATCH", s)
	}
	var nums [3]uint64
	for i, p := range parts {
		n, err := parseNumericIdentifier(p)
		if err != nil {
			return Version{}, fmt.Errorf("version %q: %w", s, err)
		}
		nums[i] = n
	}
	v := Version{Major: nums[0], Minor: nums[1], Patch: nums[2]}
	if hasPre {
		ids := strings.Split(pre, ".")
		for _, id := range ids {
			if err := checkPrereleaseIdentifier(id); err != nil {
				return Version{}, fmt.Errorf("version %q: %w", s, err)
			}
		}
		v.Prerelease = ids
	}
	return v, nil
}

func parseNumericIdentifier(p string) (uint64, error) {
	if p == "" {
		return 0, fmt.Errorf("empty number")
	}
	if len(p) > 1 && p[0] == '0' {
		return 0, fmt.Errorf("number %q has a leading zero", p)
	}
	n, err := strconv.ParseUint(p, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("number %q: %w", p, err)
	}
	return n, nil
}

func checkPrereleaseIdentifier(id string) error {
	if id == "" {
		return fmt.Errorf("empty prerelease identifier")
	}
	for _, r := range id {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r == '-') {
			return fmt.Errorf("prerelease identifier %q has %q", id, r)
		}
	}
	if isNumeric(id) && len(id) > 1 && id[0] == '0' {
		return fmt.Errorf("prerelease identifier %q has a leading zero", id)
	}
	return nil
}

func isNumeric(id string) bool {
	for _, r := range id {
		if r < '0' || r > '9' {
			return false
		}
	}
	return id != ""
}

// String formats v as a tag.
func (v Version) String() string {
	s := fmt.Sprintf("v%d.%d.%d", v.Major, v.Minor, v.Patch)
	if len(v.Prerelease) > 0 {
		s += "-" + strings.Join(v.Prerelease, ".")
	}
	return s
}

// Compare returns -1, 0 or +1 as v is older than, the same as, or newer than
// o. A prerelease is older than its release: v0.7.0-rc.1 < v0.7.0.
func (v Version) Compare(o Version) int {
	if c := cmp.Compare(v.Major, o.Major); c != 0 {
		return c
	}
	if c := cmp.Compare(v.Minor, o.Minor); c != 0 {
		return c
	}
	if c := cmp.Compare(v.Patch, o.Patch); c != 0 {
		return c
	}
	switch {
	case len(v.Prerelease) == 0 && len(o.Prerelease) == 0:
		return 0
	case len(v.Prerelease) == 0:
		return 1
	case len(o.Prerelease) == 0:
		return -1
	}
	for i := 0; i < len(v.Prerelease) && i < len(o.Prerelease); i++ {
		if c := comparePrereleaseIdentifier(v.Prerelease[i], o.Prerelease[i]); c != 0 {
			return c
		}
	}
	return cmp.Compare(len(v.Prerelease), len(o.Prerelease))
}

// comparePrereleaseIdentifier orders numeric identifiers numerically and
// below alphanumeric ones, which compare in ASCII order.
func comparePrereleaseIdentifier(a, b string) int {
	an, bn := isNumeric(a), isNumeric(b)
	switch {
	case an && bn:
		// Leading zeros are refused at parse, so the longer one is larger.
		if c := cmp.Compare(len(a), len(b)); c != 0 {
			return c
		}
		return strings.Compare(a, b)
	case an:
		return -1
	case bn:
		return 1
	}
	return strings.Compare(a, b)
}

// CompareVersions parses two tags and compares them like Version.Compare.
func CompareVersions(a, b string) (int, error) {
	va, err := ParseVersion(a)
	if err != nil {
		return 0, err
	}
	vb, err := ParseVersion(b)
	if err != nil {
		return 0, err
	}
	return va.Compare(vb), nil
}
