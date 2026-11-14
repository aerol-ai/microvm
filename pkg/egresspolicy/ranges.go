package egresspolicy

import (
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync/atomic"
)

// Two lists of addresses a node adds to the guard's own, set once at start
// (plans/kubernetes-v2-architecture.md C24). On Kubernetes a sandbox's
// traffic leaves with the worker pod's address, so the bank's own rules
// cannot tell it from AerolVM's; these keep a sandbox off the cluster:
//
//   - The deny floor (DenyFloorEnv): addresses no sandbox may reach, ever,
//     whatever its policy allows. They join the cloud metadata endpoints.
//     The Kubernetes API server's addresses go here.
//   - The private ranges (PrivateRangesEnv): treated like RFC 1918. A
//     sandbox with no policy cannot reach them, and a policy opens one only
//     with an allow entry for that range (an egress profile, on purpose).
//     The cluster's pod, Service and node ranges go here: some clusters use
//     ranges outside RFC 1918, and a bank may want to open one of them.
//
// Every process that guards sandbox traffic holds the same lists: sandboxd
// (the host firewall and isolate), the WASM workers it starts, and the
// egress gateway. Each reads them with LoadRangesFromEnv (sandboxd from its
// config), so a setting that one runtime ignores cannot happen quietly.

const (
	// DenyFloorEnv lists the extra deny-floor addresses, comma separated.
	DenyFloorEnv = "SB_EGRESS_DENY_FLOOR_CIDRS"
	// PrivateRangesEnv lists the extra private ranges, comma separated.
	PrivateRangesEnv = "SB_EGRESS_PRIVATE_DEFAULT_CIDRS"
	// BlockPrivateEnv is the private-range default for sandboxes with no
	// policy. sandboxd writes it back in the form it read it, so the WASM
	// workers it starts keep their no-policy sandboxes off the same ranges.
	BlockPrivateEnv = "SB_EGRESS_BLOCK_PRIVATE_BY_DEFAULT"
)

var (
	extraFloor   atomic.Pointer[[]netip.Prefix]
	extraPrivate atomic.Pointer[[]netip.Prefix]
)

// ParseRanges reads one of the lists: CIDRs or bare addresses (a single
// host), comma separated, IPv4 or IPv6. It refuses an entry that does not
// parse, one with host bits set (10.0.0.5/16 is a typo for either a host or
// a range, and guessing could block the wrong one), and a /0 (it would cut
// every sandbox off from everything, or open nothing on purpose). name is
// the setting, for the error.
func ParseRanges(name, raw string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, f := range strings.Split(raw, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		p, err := netip.ParsePrefix(f)
		if err != nil {
			ip, ierr := netip.ParseAddr(f)
			if ierr != nil || ip.Zone() != "" {
				return nil, fmt.Errorf("invalid %s entry %q: want a CIDR such as 10.96.0.0/12 or an address such as 10.96.0.1", name, f)
			}
			ip = ip.Unmap()
			p = netip.PrefixFrom(ip, ip.BitLen())
		}
		if p.Addr().Is4In6() {
			// The guard unmaps every address before it compares, so a
			// v4-mapped range would never match anything.
			return nil, fmt.Errorf("invalid %s entry %q: write an IPv4 range as IPv4", name, f)
		}
		if p != p.Masked() {
			return nil, fmt.Errorf("invalid %s entry %q: not a network address; did you mean %s?", name, f, p.Masked())
		}
		if p.Bits() == 0 {
			return nil, fmt.Errorf("invalid %s entry %q: a range that covers every address is not allowed", name, f)
		}
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out, nil
}

// FormatRanges renders a list for DenyFloorEnv or PrivateRangesEnv.
func FormatRanges(ps []netip.Prefix) string {
	parts := make([]string, 0, len(ps))
	for _, p := range ps {
		parts = append(parts, p.String())
	}
	return strings.Join(parts, ",")
}

// SetRanges installs this process's extra deny floor and private ranges.
func SetRanges(floor, private []netip.Prefix) {
	f, p := slices.Clone(floor), slices.Clone(private)
	extraFloor.Store(&f)
	extraPrivate.Store(&p)
}

// LoadRangesFromEnv reads both lists from the environment, and the floor
// file when FloorFileEnv names one, and installs them. A process that
// cannot read a list it was given must not run: it would guard sandboxes
// without a floor entry the operator asked for.
func LoadRangesFromEnv() error {
	floor, err := ParseRanges(DenyFloorEnv, os.Getenv(DenyFloorEnv))
	if err != nil {
		return err
	}
	private, err := ParseRanges(PrivateRangesEnv, os.Getenv(PrivateRangesEnv))
	if err != nil {
		return err
	}
	var file []netip.Prefix
	if path := os.Getenv(FloorFileEnv); path != "" {
		if file, err = ReadFloorFile(path); err != nil {
			return err
		}
	}
	SetRanges(floor, private)
	SetFileFloor(file)
	return nil
}

// ExtraDenyFloor returns the deny floor SetRanges installed, with the
// floor file's (SetFileFloor).
func ExtraDenyFloor() []netip.Prefix {
	return withEach(loadPrefixes(&extraFloor), loadPrefixes(&fileFloor))
}

// ExtraPrivateRanges returns the private ranges SetRanges installed.
func ExtraPrivateRanges() []netip.Prefix { return loadPrefixes(&extraPrivate) }

func loadPrefixes(a *atomic.Pointer[[]netip.Prefix]) []netip.Prefix {
	if p := a.Load(); p != nil {
		return slices.Clone(*p)
	}
	return nil
}

// inExtra reports whether ip is in the list a holds, without copying it:
// the dial guard asks on every connection.
func inExtra(a *atomic.Pointer[[]netip.Prefix], ip netip.Addr) (netip.Prefix, bool) {
	if p := a.Load(); p != nil {
		return firstContaining(*p, ip)
	}
	return netip.Prefix{}, false
}
