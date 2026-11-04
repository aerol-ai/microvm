package egresspolicy

import (
	"fmt"
	"net/netip"
)

// Ceiling is the operator's ceiling.allow_out (§5.10 PC-2): when set, every
// effective allow entry of every policy must fit inside it. It is compiled
// once at operator-file load, and a check is an in-memory walk, so it costs
// microseconds even at MaxUnionHostnames.
type Ceiling struct {
	hosts map[string][]Entry // exact ceiling hosts, by name
	wild  map[string]struct{}
	cidrs []netip.Prefix
}

// CeilingError names the first entry outside the ceiling, or explains why the
// policy's shape cannot fit one. It matches ErrInvalid (callers return 400).
type CeilingError struct {
	Entry  string // canonical form; "" when the policy shape is the problem
	Reason string
}

func (e *CeilingError) Error() string {
	if e.Entry == "" {
		return "outside the operator egress ceiling: " + e.Reason
	}
	return fmt.Sprintf("%s entry %q is outside the operator egress ceiling: %s", FieldAllowOut, e.Entry, e.Reason)
}

// Is makes every CeilingError match ErrInvalid.
func (e *CeilingError) Is(target error) bool { return target == ErrInvalid }

// NewCeiling compiles a ceiling allow list (same grammar as any allow list,
// capped at MaxUnionHostnames). An empty list means "no ceiling" and returns
// nil, whose Fits accepts everything.
func NewCeiling(allow []string) (*Ceiling, error) {
	entries, err := ParseAllowList("ceiling.allow_out", allow, MaxUnionHostnames)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, nil
	}
	c := &Ceiling{hosts: make(map[string][]Entry), wild: make(map[string]struct{})}
	for _, e := range entries {
		switch e.Kind {
		case KindCIDR:
			c.cidrs = append(c.cidrs, e.Prefix)
		case KindHost:
			c.hosts[e.Host] = append(c.hosts[e.Host], e)
		case KindWildcard:
			c.wild[e.Host] = struct{}{}
		}
	}
	return c, nil
}

// Fits returns nil when p stays inside the ceiling, or a *CeilingError naming
// the first effective allow entry (in input order) that does not.
//
//   - Block-all fits: it allows nothing.
//   - Learn mode fits: the caller runs it with the ceiling as its allowlist.
//   - A default-accept policy (deny list only, or no lists) never fits.
//   - A hostname fits under a ceiling host with the same name (a bare ceiling
//     host covers every port of it; a ceiling host:port covers only that
//     port) or under a ceiling wildcard it sits strictly below.
//   - A wildcard fits under a ceiling wildcard with the same or a parent
//     suffix.
//   - A CIDR fits when it is a subset of a ceiling CIDR.
func (c *Ceiling) Fits(p *Policy) error {
	if c == nil || p.BlockAll() || p.Mode() == ModeLearn {
		return nil
	}
	if p.DefaultVerdict() == VerdictAllow {
		return &CeilingError{Reason: "a policy that allows by default (deny list only, or no restriction) cannot fit a ceiling; list the allowed destinations instead"}
	}
	for _, e := range p.allow {
		if !c.covers(e) {
			return &CeilingError{Entry: e.String(), Reason: "no ceiling entry covers it"}
		}
	}
	return nil
}

func (c *Ceiling) covers(e Entry) bool {
	switch e.Kind {
	case KindCIDR:
		for _, cp := range c.cidrs {
			if cp.Addr().BitLen() == e.Prefix.Addr().BitLen() && cp.Bits() <= e.Prefix.Bits() && cp.Contains(e.Prefix.Addr()) {
				return true
			}
		}
		return false
	case KindHost:
		for _, ch := range c.hosts[e.Host] {
			if ch.Port == 0 || ch.Port == e.Port {
				return true
			}
		}
		return c.underWildcard(e.Host, false)
	case KindWildcard:
		return c.underWildcard(e.Host, true)
	}
	return false
}

// underWildcard reports whether a ceiling wildcard covers name. For a host,
// the ceiling suffix must be a strict parent (wildcards never cover their
// apex); for a user wildcard "*.name", the ceiling suffix may equal name.
func (c *Ceiling) underWildcard(name string, orEqual bool) bool {
	if orEqual {
		if _, ok := c.wild[name]; ok {
			return true
		}
	}
	for i := 0; i < len(name); i++ {
		if name[i] != '.' {
			continue
		}
		if _, ok := c.wild[name[i+1:]]; ok {
			return true
		}
	}
	return false
}
