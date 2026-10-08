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
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/aerol-ai/microvm/pkg/egresspolicy"
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
	// BlockCleanup is the gateway's own: a sandbox kept by a Sync whose
	// source still has revoked learned elements or conntrack entries the
	// kernel wouldn't delete is shut until they are gone (RetryDirty), so
	// a Sync never leaves a narrowed sandbox running on what it revoked.
	BlockCleanup
)

// SyncToken names a point in one gateway process's block writes: the
// process's epoch, and the newest write number then (Gateway.SyncToken).
type SyncToken struct {
	Epoch uint64 `json:"epoch"`
	Gen   uint64 `json:"gen"`
}

// newEpoch picks a gateway process's epoch: random, so a restarted process
// never reuses one, and never 0, which stands for a missing token.
func newEpoch() uint64 {
	var b [8]byte
	for {
		if _, err := rand.Read(b[:]); err != nil {
			panic("egress: no randomness for the gateway epoch: " + err.Error())
		}
		if e := binary.LittleEndian.Uint64(b[:]); e != 0 {
			return e
		}
	}
}

// serviceBlocks are the reasons sandboxd sets with SetBlocked; the restart
// and cleanup blocks are the gateway's own.
const serviceBlocks = ^(BlockRestart | BlockCleanup)

// blockWrites is a sandbox's newest block write per reason: whether it set
// or cleared the reason, and its number.
type blockWrites struct {
	on  BlockReason
	gen [8]uint64
}

func (w *blockWrites) set(reasons BlockReason, on bool, gen uint64) {
	for i := range w.gen {
		bit := BlockReason(1) << i
		if reasons&bit == 0 {
			continue
		}
		w.gen[i] = gen
		if on {
			w.on |= bit
		} else {
			w.on &^= bit
		}
	}
}

// newerThan returns blocked with every reason written after since taken
// from the write.
func (w *blockWrites) newerThan(since uint64, blocked BlockReason) BlockReason {
	for i, gen := range w.gen {
		if gen <= since {
			continue
		}
		bit := BlockReason(1) << i
		blocked = blocked&^bit | w.on&bit
	}
	return blocked
}

func (w *blockWrites) newest() uint64 {
	var n uint64
	for _, gen := range w.gen {
		n = max(n, gen)
	}
	return n
}

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
	// Rules are the method and path rules for hosts the lists allow
	// (plans/egress-domain-filtering.md §5.9, P3-1); the proxy holds each
	// request to a ruled host to them.
	Rules []egresspolicy.RuleSpec `json:"rules,omitempty"`
	// Pid is the sandbox's init process on the host, for tracing a
	// connection to its executable when rules name binaries (P3-3); 0 when
	// none do.
	Pid int `json:"pid,omitempty"`
	// Secrets are the values inject rules send, by env key (P3-2). They
	// cross the UDS and live in memory only: SaveSnapshot drops them, and
	// sandboxd's Sync after a restart brings them back.
	Secrets map[string]string `json:"secrets,omitempty"`
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
	// SetBinLearned holds (src, dst, port) for host:port rules that trace
	// connections to executables (P3-3): prerouting redirects them to the
	// proxy instead of accepting them in forward.
	SetBinLearned    = "bin_learned"
	SetLearnFlows    = "learn_flows"
	SetRejectedFlows = "rejected_flows"
	SetDenyFloor     = "deny_floor"
	SetNodeControl   = "node_control"
)

// managedSets are the sets whose contents Sync replaces from sandboxd's state.
// allow_learned is excluded: its elements are preserved for unchanged
// sandboxes and rebuilt from the shadow map (D13).
var managedSets = []string{
	SetFQDNSrc, SetSrcDenyDefault, SetSrcAccept, SetLearnSrc, SetBlockedSrc,
	SetAllowCIDR, SetDenyCIDR,
}

// carriedSets are copied into the replacement table when the layout of
// another version is replaced (EnsureLayout): the per-source sets and the
// node-wide floor and guard. Learned and flow sets, whose elements carry
// timeouts, start empty: a lost learned element only denies until the next
// DNS answer.
var carriedSets = append(append([]string(nil), managedSets...), SetDenyFloor, SetNodeControl)

// migrateContents is what the replacement table starts with: the carried
// sets as they were, and every carried gateway-mode source also in
// @blocked_src. Replacing a layout used to install empty sets, which is the
// same as no filtering for every sandbox until sandboxd's next Sync; this
// keeps them shut instead (D13), and the Sync lifts it.
func migrateContents(old map[string][]Elem) map[string][]Elem {
	out := map[string][]Elem{}
	for _, name := range carriedSets {
		if elems := old[name]; len(elems) > 0 {
			out[name] = append([]Elem(nil), elems...)
		}
	}
	for _, e := range old[SetFQDNSrc] {
		b := Elem{Src: e.Src}
		if !slices.Contains(out[SetBlockedSrc], b) {
			out[SetBlockedSrc] = append(out[SetBlockedSrc], b)
		}
	}
	return out
}

// mustCarry are the carried sets a replacement can't start without: the
// sources (fqdn_src, so they can be blocked), their blocks, and the
// node-wide floor and guard, which bind sandboxes outside gateway mode too.
// The per-source class and CIDR sets aren't needed while every carried
// source is blocked until Sync.
var mustCarry = map[string]bool{SetFQDNSrc: true, SetBlockedSrc: true, SetDenyFloor: true, SetNodeControl: true}

// SetRead reads one set of the layout being replaced: present reports
// whether the old layout has it, compatible whether its key type is this
// version's (so its elements decode).
type SetRead func(name string) (elems []Elem, present, compatible bool, err error)

// carryContents reads what a layout replacement carries over and plans the
// replacement table's contents (migrateContents). A failed read, or a
// required set whose type changed, aborts: replacing the table without the
// sources would leave every gateway sandbox unfiltered until sandboxd's next
// Sync, so the old table (still enforcing) is kept and the error reported
// instead (review 2 finding 8). A set the old layout doesn't have starts
// empty.
func carryContents(read SetRead) (map[string][]Elem, error) {
	old := map[string][]Elem{}
	for _, name := range carriedSets {
		elems, present, compatible, err := read(name)
		switch {
		case err != nil:
			return nil, fmt.Errorf("read set %s of the layout being replaced: %w", name, err)
		case !present:
			continue
		case !compatible && mustCarry[name]:
			return nil, fmt.Errorf("set %s changed type; the layout migration must convert it before replacing the table", name)
		case !compatible:
			continue
		}
		old[name] = elems
	}
	return migrateContents(old), nil
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

// ErrNotPermitted is returned when a learned destination is no longer
// allowed by the sandbox's current policy (a DNS answer that outlived the
// policy it was admitted under).
var ErrNotPermitted = errors.New("egress: not permitted by the current policy")

// ErrUnavailable is returned when the gateway can't apply a change; callers
// keep (or set) the fail-closed hold (CEO D16).
var ErrUnavailable = errors.New("egress: gateway unavailable")
