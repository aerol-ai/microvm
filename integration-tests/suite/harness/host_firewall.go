package harness

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
)

// IsUnenforcedPolicyRefusal reports whether err is the documented refusal of
// network policy a node cannot enforce (#846): HTTP 501 with the code
// network_policy_unenforced, at create, start, a policy change or a byte cap.
//
// It reads the fields of the SDK's *microvm.APIError. The error's text is the
// server's message alone ("network_allow_out refused: runtime "docker"
// enforces it with the host firewall, which is off on this node ..."), which
// names neither the status nor the code. Matching on that text is why the
// first local-mode run (main f34b607e) failed every no-host-firewall case
// while the server answered exactly what the docs promise.
func IsUnenforcedPolicyRefusal(err error) bool {
	var apiErr *microvm.APIError
	return errors.As(err, &apiErr) &&
		apiErr.StatusCode == http.StatusNotImplemented &&
		apiErr.Code == models.ErrorCodeNetworkPolicyUnenforced
}

// IsEgressFloorNotReady reports whether err is the refusal of a create on a
// runtime whose egress deny floor (the cloud metadata endpoints and the
// operator's deny_cidrs, dropped on the host firewall) is not installed:
// HTTP 503 with the code egress_floor_not_ready.
func IsEgressFloorNotReady(err error) bool {
	var apiErr *microvm.APIError
	return errors.As(err, &apiErr) &&
		apiErr.StatusCode == http.StatusServiceUnavailable &&
		apiErr.Code == models.ErrorCodeEgressFloorNotReady
}

// FloorChain is one sandbox subnet's egress deny floor as a node's host
// firewall holds it (pkg/docker/netrules floor.go): the AEROLVM-FLOOR-<8 hex>
// chain, the subnet whose traffic it drops, the destinations it drops, and
// the user chains (DOCKER-USER, AEROLVM-USER, AEROLVM-FC) whose first rule
// jumps to it.
type FloorChain struct {
	Name  string
	Src   netip.Prefix
	Dsts  []netip.Prefix
	TopOf []string
}

// Drops reports whether the chain drops its subnet's traffic to dst.
func (f *FloorChain) Drops(dst netip.Addr) bool {
	for _, p := range f.Dsts {
		if p.Contains(dst) {
			return true
		}
	}
	return false
}

var (
	floorChainName = `AEROLVM-FLOOR-[0-9a-f]{8}`
	// iptables-save, nft-backed or legacy.
	iptFloorDropRe = regexp.MustCompile(`^-A (` + floorChainName + `) -s (\S+) -d (\S+) -j DROP$`)
	iptRuleRe      = regexp.MustCompile(`^-A (\S+) (.*)$`)
	iptFloorJumpRe = regexp.MustCompile(`^-j (` + floorChainName + `)$`)
	// nft list ruleset: the netlink backend's rules, and iptables-nft's.
	nftChainRe     = regexp.MustCompile(`^chain (\S+) \{$`)
	nftFloorDropRe = regexp.MustCompile(`^ip saddr (\S+) ip daddr (\S+)(?: counter packets \d+ bytes \d+)? drop$`)
	nftFloorJumpRe = regexp.MustCompile(`^(?:counter packets \d+ bytes \d+ )?jump (` + floorChainName + `)$`)
	floorChainRe   = regexp.MustCompile(`^` + floorChainName + `$`)
)

// ParseFloorChains reads every floor chain out of a node's rule dump: the
// output of iptables-save, iptables-legacy-save and nft list ruleset, in any
// mix (an exec-backend node on iptables-nft shows the same chain in two of
// them). The chain shared by an older daemon (plain AEROLVM-FLOOR) is not one.
func ParseFloorChains(dump string) map[string]*FloorChain {
	chains := map[string]*FloorChain{}
	get := func(name string) *FloorChain {
		if c, ok := chains[name]; ok {
			return c
		}
		c := &FloorChain{Name: name}
		chains[name] = c
		return c
	}
	addDrop := func(chain, src, dst string) {
		s, ok1 := parsePrefixOrAddr(src)
		d, ok2 := parsePrefixOrAddr(dst)
		if !ok1 || !ok2 {
			return
		}
		c := get(chain)
		c.Src = s
		if !slices.Contains(c.Dsts, d) {
			c.Dsts = append(c.Dsts, d)
		}
	}
	addTop := func(floor, parent string) {
		c := get(floor)
		if !slices.Contains(c.TopOf, parent) {
			c.TopOf = append(c.TopOf, parent)
		}
	}
	// The first rule of each chain, per iptables-save table section and per
	// nft chain block: the floor's jump must be first, above any
	// per-sandbox ACCEPT.
	section := 0
	seenFirst := map[string]bool{}
	nftChain, nftFirst := "", false
	for _, raw := range strings.Split(dump, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "*"):
			section++
		case strings.HasPrefix(line, "-A "):
			if m := iptFloorDropRe.FindStringSubmatch(line); m != nil {
				addDrop(m[1], m[2], m[3])
			}
			m := iptRuleRe.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			key := fmt.Sprintf("%d|%s", section, m[1])
			if seenFirst[key] {
				continue
			}
			seenFirst[key] = true
			if j := iptFloorJumpRe.FindStringSubmatch(m[2]); j != nil {
				addTop(j[1], m[1])
			}
		case nftChainRe.MatchString(line):
			nftChain, nftFirst = nftChainRe.FindStringSubmatch(line)[1], true
		case line == "}":
			nftChain = ""
		case nftChain != "" && line != "" && !strings.HasPrefix(line, "type ") && !strings.HasPrefix(line, "policy "):
			if m := nftFloorDropRe.FindStringSubmatch(line); m != nil && floorChainRe.MatchString(nftChain) {
				addDrop(nftChain, m[1], m[2])
			}
			if nftFirst {
				nftFirst = false
				if j := nftFloorJumpRe.FindStringSubmatch(line); j != nil {
					addTop(j[1], nftChain)
				}
			}
		}
	}
	return chains
}

// FloorFor returns the floor chain of the sandbox subnet that holds ip.
func FloorFor(chains map[string]*FloorChain, ip netip.Addr) (*FloorChain, bool) {
	names := make([]string, 0, len(chains))
	for n := range chains {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if c := chains[n]; c.Src.IsValid() && c.Src.Contains(ip) {
			return c, true
		}
	}
	return nil, false
}

// parsePrefixOrAddr reads "10.0.0.0/16" (both tools) or "169.254.169.254"
// (nft prints a /32 as the bare address).
func parsePrefixOrAddr(s string) (netip.Prefix, bool) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), true
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(a, a.BitLen()), true
}

// DescribeAPIError is err with the HTTP status and error code the server
// sent, for a failure message that has to say what the server answered.
func DescribeAPIError(err error) string {
	var apiErr *microvm.APIError
	if errors.As(err, &apiErr) {
		return fmt.Sprintf("status %d, code %q: %v", apiErr.StatusCode, apiErr.Code, err)
	}
	return fmt.Sprintf("not an API error: %v", err)
}
