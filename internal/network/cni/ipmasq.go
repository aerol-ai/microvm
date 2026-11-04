package cni

import (
	"context"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/coreos/go-iptables/iptables"
)

// IPMasqTeardown removes the outbound-NAT (ipMasq) state the bridge plugin's
// ADD installed for one container id, independent of the plugin's own DEL.
//
// Why the plugin's DEL is not enough: it derives which masquerade rules to
// delete from the addresses it finds on the container interface at DEL time
// (plugins/main/bridge cmdDel → ip.DelLinkByNameAddr → TeardownIPMasq per
// address). gVisor's runsc, in its default network=sandbox mode, moves the
// interface address into its own netstack and deletes it from the interface
// when the sandbox starts, so DEL sees no address and leaves the NAT chain
// and its POSTROUTING jump behind: four iptables lines per gVisor sandbox.
type IPMasqTeardown interface {
	TeardownIPMasq(ctx context.Context, containerID, containerIP string) error
}

// IPMasqChain is the nat chain the bridge plugin creates for (network,
// containerID): containernetworking/plugins pkg/utils FormatChainName, i.e.
// "CNI-" + hex(sha512(network+containerID)), cut to 28 characters.
func IPMasqChain(network, containerID string) string {
	sum := sha512.Sum512([]byte(network + containerID))
	return fmt.Sprintf("CNI-%x", sum)[:28]
}

// IPMasqComment is the rule comment the bridge plugin tags those rules with
// (pkg/utils FormatComment).
func IPMasqComment(network, containerID string) string {
	return fmt.Sprintf("name: %q id: %q", network, containerID)
}

// natTable is the subset of go-iptables the teardown drives; tests swap in an
// in-memory table.
type natTable interface {
	ChainExists(table, chain string) (bool, error)
	List(table, chain string) ([]string, error)
	Delete(table, chain string, rulespec ...string) error
	ClearAndDeleteChain(table, chain string) error
}

var newNATTable = func() (natTable, error) { return iptables.New() }

// TeardownIPMasq deletes the bridge plugin's masquerade chain for containerID
// and every POSTROUTING rule that jumps to it. It only touches the chain
// whose name is derived from this network + containerID, so it can never
// remove another container's rules. Idempotent: an absent chain is success.
// containerIP is accepted for symmetry with the ADD; the POSTROUTING jumps
// are found by their target chain, which also catches any jump left from an
// earlier ADD of the same id under a different address.
func (r *ExecRunner) TeardownIPMasq(ctx context.Context, containerID, containerIP string) error {
	_ = ctx
	_ = containerIP
	containerID = strings.TrimSpace(containerID)
	if containerID == "" {
		return nil
	}
	network, masq, err := r.masqConfig()
	if err != nil {
		return err
	}
	if !masq {
		return nil
	}
	ipt, err := r.natTable()
	if err != nil {
		return fmt.Errorf("cni ipmasq teardown %s: %w", containerID, err)
	}
	return teardownIPMasq(ipt, network, containerID)
}

// natTable returns the cached iptables handle. go-iptables execs
// `iptables --version` on construction, so build it once per runner; a
// failed construction is retried on the next call rather than cached.
func (r *ExecRunner) natTable() (natTable, error) {
	r.natMu.Lock()
	defer r.natMu.Unlock()
	if r.nat != nil {
		return r.nat, nil
	}
	ipt, err := newNATTable()
	if err != nil {
		return nil, err
	}
	r.nat = ipt
	return ipt, nil
}

func teardownIPMasq(ipt natTable, network, containerID string) error {
	chain := IPMasqChain(network, containerID)
	exists, err := ipt.ChainExists("nat", chain)
	if err != nil {
		return fmt.Errorf("cni ipmasq teardown %s: %w", containerID, err)
	}
	if !exists {
		// iptables refuses a jump to a missing chain, so no POSTROUTING rule
		// can reference it either: nothing to do (the runc fast path, where the
		// plugin's own DEL already cleaned up).
		return nil
	}
	rules, err := ipt.List("nat", "POSTROUTING")
	if err != nil {
		return fmt.Errorf("cni ipmasq teardown %s: list POSTROUTING: %w", containerID, err)
	}
	comment := IPMasqComment(network, containerID)
	var errs []error
	for _, rule := range rules {
		src, ok := masqJumpSource(rule, chain)
		if !ok {
			continue
		}
		// Same rulespec SetupIPMasq appended, so iptables matches it exactly.
		if err := ipt.Delete("nat", "POSTROUTING", "-s", src, "-j", chain, "-m", "comment", "--comment", comment); err != nil && !natNotExist(err) {
			errs = append(errs, fmt.Errorf("delete POSTROUTING jump %s -> %s: %w", src, chain, err))
		}
	}
	if err := ipt.ClearAndDeleteChain("nat", chain); err != nil && !natNotExist(err) {
		errs = append(errs, fmt.Errorf("delete chain %s: %w", chain, err))
	}
	if len(errs) > 0 {
		return fmt.Errorf("cni ipmasq teardown %s: %w", containerID, errors.Join(errs...))
	}
	return nil
}

// masqJumpSource returns the -s address of an `iptables -S POSTROUTING` line
// whose target is chain. The comment is quoted and may contain spaces, but
// "-s <addr>" and the trailing "-j <chain>" are always plain fields.
func masqJumpSource(rule, chain string) (string, bool) {
	fields := strings.Fields(rule)
	n := len(fields)
	if n < 4 || fields[n-2] != "-j" || fields[n-1] != chain {
		return "", false
	}
	for i := 0; i+1 < n; i++ {
		if fields[i] == "-s" {
			return fields[i+1], true
		}
	}
	return "", false
}

// natNotExist reports whether an iptables error only says the rule or chain
// is already gone. Message differs by flavor (legacy vs nft); go-iptables'
// typed error knows both, the string match covers plain errors from fakes.
func natNotExist(err error) bool {
	var iptErr *iptables.Error
	if errors.As(err, &iptErr) {
		return iptErr.IsNotExist()
	}
	msg := err.Error()
	return strings.Contains(msg, "No chain/target/match") ||
		strings.Contains(msg, "does a matching rule exist") ||
		strings.Contains(msg, "does not exist")
}

// masqConfig reads the network name and the plugin's ipMasq flag from the
// configured netconf (a .conflist is reduced to plugins[0], like ADD/DEL).
func (r *ExecRunner) masqConfig() (network string, masq bool, err error) {
	raw, err := os.ReadFile(r.cfg.ConfPath)
	if err != nil {
		return "", false, fmt.Errorf("read cni conf %q: %w", r.cfg.ConfPath, err)
	}
	conf, err := singlePluginNetconf(raw)
	if err != nil {
		return "", false, err
	}
	var m struct {
		Name   string `json:"name"`
		IPMasq bool   `json:"ipMasq"`
	}
	if err := json.Unmarshal(conf, &m); err != nil {
		return "", false, fmt.Errorf("parse cni plugin config: %w", err)
	}
	return m.Name, m.IPMasq, nil
}
