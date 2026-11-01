//go:build linux

package ipv6fence

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/userdata"
	"golang.org/x/sys/unix"

	"github.com/aerol-ai/microvm/internal/network/hostnet"
)

// Chain priorities: the bridge family's filter priority, and the ip6
// family's raw priority, so the drops run before conntrack sees the packet
// and before any other filter chain on the hook. A drop is final whatever
// another base chain on the same hook says.
var (
	priorityBridge = nftables.ChainPriorityRef(-200)
	priorityIP6    = nftables.ChainPriorityRaw
)

// newConn opens one netlink connection per call. Tests replace it with a
// connection whose TestDial never touches the kernel.
var newConn = func() (*nftables.Conn, error) {
	c, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("ipv6 fence: nftables conn: %w", err)
	}
	return c, nil
}

// NFTBackend drives the two TableName tables over netlink.
type NFTBackend struct {
	// bridgeLayer is whether the last Apply installed the bridge-family
	// table. A kernel that refuses it (no nft_meta_bridge for `meta
	// ibrname`, as in some minimal kernels) gets the ip6 table alone, and
	// bridged frames reach that through br_netfilter, which Apply then
	// turns on and Check keeps verifying.
	bridgeLayer atomic.Bool
}

// NewBackend returns the netlink backend.
func NewBackend() Backend { return &NFTBackend{} }

var families = []string{FamilyBridge, FamilyIP6}

// Seams over br_netfilter: ensureBridgeNetfilter loads it and sets
// bridge-nf-call-ip6tables (hostnet.EnsureForwardingSysctls, which every
// sandbox node runs anyway); bridgeNFCallIP6Tables is where to read it.
var (
	ensureBridgeNetfilter = hostnet.EnsureForwardingSysctls
	bridgeNFCallIP6Tables = "/proc/sys/net/bridge/bridge-nf-call-ip6tables"
)

// Layers says which tables hold the fence, for the supervisor's log.
func (b *NFTBackend) Layers() string {
	if b.bridgeLayer.Load() {
		return "bridge+ip6"
	}
	return "ip6 via br_netfilter (this kernel refuses the bridge-family table)"
}

func table(family string) *nftables.Table {
	if family == FamilyBridge {
		return &nftables.Table{Family: nftables.TableFamilyBridge, Name: TableName}
	}
	return &nftables.Table{Family: nftables.TableFamilyIPv6, Name: TableName}
}

func chain(t *nftables.Table, name string) *nftables.Chain {
	hook := map[string]*nftables.ChainHook{
		ChainForward: nftables.ChainHookForward,
		ChainInput:   nftables.ChainHookInput,
		ChainOutput:  nftables.ChainHookOutput,
	}[name]
	prio := priorityIP6
	if t.Family == nftables.TableFamilyBridge {
		prio = priorityBridge
	}
	accept := nftables.ChainPolicyAccept
	return &nftables.Chain{
		Name:     name,
		Table:    t,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  hook,
		Priority: prio,
		Policy:   &accept,
	}
}

// nameData is the bytes a cmp matches on an interface or bridge name: the
// name and its NUL for an exact match, the prefix alone for "name*".
func nameData(n string) []byte {
	if p, ok := strings.CutSuffix(n, "*"); ok {
		return []byte(p)
	}
	return append([]byte(n), 0)
}

var metaKeys = map[string]expr.MetaKey{
	MatchInBridge:  expr.MetaKeyBRIIIFNAME,
	MatchOutBridge: expr.MetaKeyBRIOIFNAME,
	MatchIn:        expr.MetaKeyIIFNAME,
	MatchOut:       expr.MetaKeyOIFNAME,
}

// ruleExprs is `meta <match> "<name>" [meta protocol ip6] counter drop`.
// The bridge family sees every ethertype, so its rules also match IPv6;
// the counter shows the operator what the fence dropped.
func ruleExprs(r Rule) ([]expr.Any, error) {
	key, ok := metaKeys[r.Match]
	if !ok {
		return nil, fmt.Errorf("ipv6 fence: unknown match %q", r.Match)
	}
	exprs := []expr.Any{
		&expr.Meta{Key: key, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: nameData(r.Name)},
	}
	if r.Family == FamilyBridge {
		exprs = append(exprs,
			&expr.Meta{Key: expr.MetaKeyPROTOCOL, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(unix.ETH_P_IPV6)},
		)
	}
	return append(exprs, &expr.Counter{}, &expr.Verdict{Kind: expr.VerdictDrop}), nil
}

// Apply implements Backend: both tables if the kernel takes them, else the
// ip6 table with br_netfilter on (see bridgeLayer).
func (b *NFTBackend) Apply(rules []Rule) error {
	full := apply(rules, families)
	if full == nil {
		b.bridgeLayer.Store(true)
		return nil
	}
	if err := apply(onlyFamily(rules, FamilyIP6), []string{FamilyIP6}); err != nil {
		return errors.Join(full, err)
	}
	if err := ensureBridgeNetfilter(); err != nil {
		return fmt.Errorf("ipv6 fence: the kernel refused the bridge-family table (%v) and br_netfilter is off, so bridged IPv6 would pass the ip6 table: %w", full, err)
	}
	if !bridgeNFOn() {
		return fmt.Errorf("ipv6 fence: the kernel refused the bridge-family table (%v) and %s is not 1, so bridged IPv6 would pass the ip6 table", full, bridgeNFCallIP6Tables)
	}
	b.bridgeLayer.Store(false)
	return nil
}

// bridgeNFOn reports whether bridged IPv6 frames go through the ip6 hooks.
func bridgeNFOn() bool {
	v, err := os.ReadFile(bridgeNFCallIP6Tables)
	return err == nil && strings.TrimSpace(string(v)) == "1"
}

func onlyFamily(rules []Rule, family string) []Rule {
	var out []Rule
	for _, r := range rules {
		if r.Family == family {
			out = append(out, r)
		}
	}
	return out
}

// apply replaces the tables of fams with rules in one batch: add, delete
// and re-add each table, the nft idiom for an atomic replace (the first add
// makes the delete safe when the table is not there yet).
func apply(rules []Rule, fams []string) error {
	c, err := newConn()
	if err != nil {
		return err
	}
	chains := map[string]*nftables.Chain{}
	for _, fam := range fams {
		t := table(fam)
		c.AddTable(t)
		c.DelTable(t)
		c.AddTable(t)
		for _, name := range chainOrder {
			chains[fam+"/"+name] = c.AddChain(chain(t, name))
		}
	}
	for _, r := range rules {
		ch, ok := chains[r.Family+"/"+r.Chain]
		if !ok {
			return fmt.Errorf("ipv6 fence: rule for unknown chain %s/%s", r.Family, r.Chain)
		}
		exprs, err := ruleExprs(r)
		if err != nil {
			return err
		}
		c.AddRule(&nftables.Rule{
			Table:    ch.Table,
			Chain:    ch,
			Exprs:    exprs,
			UserData: userdata.AppendString(nil, userdata.TypeComment, r.Comment()),
		})
	}
	if err := c.Flush(); err != nil {
		return fmt.Errorf("ipv6 fence: install: %w", err)
	}
	return nil
}

// Check implements Backend, for the tables the last Apply installed.
func (b *NFTBackend) Check(rules []Rule) (bool, error) {
	c, err := newConn()
	if err != nil {
		return false, err
	}
	if b.bridgeLayer.Load() {
		return check(c, rules, families)
	}
	// Something turned br_netfilter's IPv6 hook off: bridged frames now
	// skip the ip6 table. Apply turns it back on.
	if !bridgeNFOn() {
		return false, nil
	}
	return check(c, onlyFamily(rules, FamilyIP6), []string{FamilyIP6})
}

// kernelReader is the slice of *nftables.Conn Check reads with; tests hand
// check a fake kernel.
type kernelReader interface {
	ListChainsOfTableFamily(family nftables.TableFamily) ([]*nftables.Chain, error)
	GetRules(t *nftables.Table, c *nftables.Chain) ([]*nftables.Rule, error)
}

func check(c kernelReader, rules []Rule, fams []string) (bool, error) {
	want := ChainRules(rules)
	for _, fam := range fams {
		t := table(fam)
		listed, err := c.ListChainsOfTableFamily(t.Family)
		if err != nil {
			return false, fmt.Errorf("ipv6 fence: list %s chains: %w", fam, err)
		}
		have := map[string]*nftables.Chain{}
		for _, ch := range listed {
			if ch.Table != nil && ch.Table.Name == TableName {
				have[ch.Name] = ch
			}
		}
		for _, name := range chainOrder {
			got, ok := have[name]
			if !ok || !sameBaseChain(got, chain(t, name)) {
				return false, nil
			}
			kernel, err := c.GetRules(t, got)
			if err != nil {
				return false, fmt.Errorf("ipv6 fence: list %s/%s rules: %w", fam, name, err)
			}
			if !sameComments(kernel, want[fam+"/"+name]) {
				return false, nil
			}
		}
	}
	return true, nil
}

func sameBaseChain(got, want *nftables.Chain) bool {
	if got.Hooknum == nil || got.Priority == nil || *got.Hooknum != *want.Hooknum || *got.Priority != *want.Priority {
		return false
	}
	if got.Type != "" && got.Type != want.Type {
		return false
	}
	return got.Policy == nil || *got.Policy == *want.Policy
}

func sameComments(kernel []*nftables.Rule, want []Rule) bool {
	if len(kernel) != len(want) {
		return false
	}
	for i, r := range kernel {
		got, _ := userdata.GetString(r.UserData, userdata.TypeComment)
		if got != want[i].Comment() {
			return false
		}
	}
	return true
}
