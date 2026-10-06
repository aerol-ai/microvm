// Package egress is the per-node egress gateway core for hostname-filtered
// ("gateway-mode") sandboxes (plans/egress-domain-filtering.md §5.3).
//
// The gateway owns its own nftables table (inet aerolvm_egress) and never
// touches DOCKER-USER or AEROLVM-USER. Per-sandbox cost is set elements, not
// rules: the layout is static and attaching a sandbox is one netlink batch.
// The DNS filter (internal/egress/dnsfilter) and the SNI/Host proxy
// (internal/egress/proxy) read the same Gateway state.
package egress

import (
	"errors"
	"net/netip"
	"time"
)

// Mode is a gateway-mode sandbox's nft class, derived from its compiled
// policy: the default verdict picks the source set.
type Mode string

const (
	// ModeAllowlist: default deny; only allow entries pass.
	ModeAllowlist Mode = "allowlist"
	// ModeDenylist: default accept; deny CIDRs drop (D4/A8). Hostnames are
	// never deny entries, so DNS is forwarded unfiltered in this mode.
	ModeDenylist Mode = "denylist"
	// ModeLearn: allow-all while recording destinations (CEO X1).
	ModeLearn Mode = "learn"
)

// BlockReason is why a gateway-mode sandbox is egress-blocked. The sandbox is
// in @blocked_src while ANY reason is set, so one blocker lifting its reason
// never lifts another's (eng re-review D2).
type BlockReason uint8

const (
	BlockAll BlockReason = 1 << iota
	BlockQuota
	BlockHold
	// BlockRestart is the in-memory-only block a restarted gateway applies to
	// every snapshot sandbox until sandboxd's Sync confirms the real state.
	// It never reaches @blocked_src, so long-lived flows survive an upgrade.
	BlockRestart
)

// Spec is the desired gateway state for one sandbox, as sandboxd sends it.
type Spec struct {
	ID string     `json:"id"`
	IP netip.Addr `json:"ip"`
	// Learn selects learn mode (CEO X1): allow-all while recording.
	Learn bool `json:"learn,omitempty"`
	// AllowOut / DenyOut are the raw policy entries (§5.1 grammar), compiled
	// once by pkg/egresspolicy. The nft layer consumes the CIDRs; the DNS
	// filter and the proxy share the compiled matcher.
	AllowOut []string `json:"allow_out,omitempty"`
	DenyOut  []string `json:"deny_out,omitempty"`
	// Blocked carries sandboxd's view of the block reasons, so Attach and Sync
	// apply the latest block state themselves (Section 4: callers never read
	// the blocked state and act on it).
	Blocked BlockReason `json:"blocked,omitempty"`
}

// Elem is one nft set element. Which fields matter depends on the set's key:
// Src only (source sets), Src+Dst(+DstEnd for interval CIDRs), or
// Src+Dst+Port (learned and dynamic flow sets).
type Elem struct {
	Src netip.Addr `json:"src"`
	// SrcEnd is the inclusive end of a source range (a bridge subnet in the
	// node-wide deny_floor and node_control sets); zero means Src alone.
	SrcEnd  netip.Addr    `json:"src_end,omitempty"`
	Dst     netip.Addr    `json:"dst,omitempty"`
	DstEnd  netip.Addr    `json:"dst_end,omitempty"` // inclusive end of a CIDR range
	Port    uint16        `json:"port,omitempty"`
	Timeout time.Duration `json:"timeout,omitempty"`
}

// Set names in the inet aerolvm_egress table (§5.2).
const (
	SetFQDNSrc        = "fqdn_src"
	SetSrcDenyDefault = "fqdn_src_deny_default"
	SetSrcAccept      = "fqdn_src_accept_default"
	SetLearnSrc       = "learn_src"
	SetBlockedSrc     = "blocked_src"
	SetAllowCIDR      = "allow_cidr"
	SetDenyCIDR       = "deny_cidr"
	SetAllowLearned   = "allow_learned"
	SetLearnFlows     = "learn_flows"
	SetRejectedFlows  = "rejected_flows"
	SetDenyFloor      = "deny_floor"
	SetNodeControl    = "node_control"
)

// managedSets are the sets whose contents Sync replaces from sandboxd's state.
// allow_learned is excluded: its elements are preserved for unchanged
// sandboxes and rebuilt from the shadow map (D13).
var managedSets = []string{
	SetFQDNSrc, SetSrcDenyDefault, SetSrcAccept, SetLearnSrc, SetBlockedSrc,
	SetAllowCIDR, SetDenyCIDR,
}

// Op adds or deletes elements of one set. A slice of Ops is applied in one
// nft transaction.
type Op struct {
	Set   string
	Del   bool
	Elems []Elem
}

// LayoutConfig parameterizes the static table layout.
type LayoutConfig struct {
	DNSPort   uint16
	ProxyPort uint16
	// FlowSetSize sizes the dynamic flow sets (learn_flows, rejected_flows,
	// reject_meter). Zero means the production default; tests shrink it to
	// prove a full set never turns a reject into an accept (S10, EF-77).
	FlowSetSize uint32
}

// Backend is the kernel seam. The nftables implementation applies each call
// as one netlink transaction; tests use MemBackend.
type Backend interface {
	// EnsureLayout creates the table, sets and chains if absent, or replaces
	// a layout of another version, in one transaction. A matching layout is
	// left untouched (set contents survive both processes' restarts).
	EnsureLayout(LayoutConfig) error
	// CheckLayout reports ErrLayoutMissing if the table, a chain or a set is
	// gone (table-loss detection, CEO D17).
	CheckLayout() error
	// Apply adds and deletes elements across sets in one transaction.
	Apply(ops []Op) error
	// Replace atomically sets the full contents of the given sets: flush and
	// re-add in the same transaction, so membership never passes through
	// empty (D13).
	Replace(contents map[string][]Elem) error
	// List returns a set's current elements (dynamic flow sets, verification).
	List(set string) ([]Elem, error)
}

// ErrLayoutMissing means the gateway's nft table, a chain or a set is gone.
var ErrLayoutMissing = errors.New("egress: nft layout missing")

// ErrUnavailable is returned when the gateway can't apply a change; callers
// keep (or set) the fail-closed hold (CEO D16).
var ErrUnavailable = errors.New("egress: gateway unavailable")
