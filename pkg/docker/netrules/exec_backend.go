package netrules

import (
	"fmt"
	"strings"

	"github.com/coreos/go-iptables/iptables"
)

// bootstrapBackend is the chain-create + FORWARD-jump subset of iptables
// bootstrap. Implemented by execBackend (production) and memBackend (tests).
type bootstrapBackend interface {
	EnsureUserChain(chain string) error
	EnsureForwardJump(userChain string) error
}

// inputBootstrapBackend creates the AEROLVM-INPUT chain: a regular filter
// chain jumped from the top of INPUT whose first rule returns established and
// related traffic, so per-IP drops below it only stop NEW connections from a
// sandbox to host services. Replies to sandboxd→toolboxd connections are
// established and keep flowing (plans/egress-domain-filtering.md P0-5).
type inputBootstrapBackend interface {
	EnsureInputChain(chain string) error
}

// inputEstablishedReturn is the static first rule of the input chain.
var inputEstablishedReturn = []string{"-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "RETURN"}

// execBackend wraps go-iptables for RuleBackend + chain bootstrap.
type execBackend struct {
	ipt *iptables.IPTables
}

func newExecBackend(ipt *iptables.IPTables) *execBackend {
	return &execBackend{ipt: ipt}
}

func (e *execBackend) Exists(table, chain string, spec ...string) (bool, error) {
	return e.ipt.Exists(table, chain, spec...)
}

func (e *execBackend) Insert(table, chain string, pos int, spec ...string) error {
	return e.ipt.Insert(table, chain, pos, spec...)
}

func (e *execBackend) Delete(table, chain string, spec ...string) error {
	return e.ipt.Delete(table, chain, spec...)
}

func (e *execBackend) EnsureUserChain(chain string) error {
	chain = strings.TrimSpace(chain)
	if chain == "" {
		return fmt.Errorf("ensure user chain: empty chain name")
	}
	exists, err := e.ipt.ChainExists("filter", chain)
	if err != nil {
		return fmt.Errorf("check user chain %s: %w", chain, err)
	}
	if exists {
		return nil
	}
	if err := e.ipt.NewChain("filter", chain); err != nil {
		return fmt.Errorf("create user chain %s: %w", chain, err)
	}
	return nil
}

func (e *execBackend) EnsureForwardJump(userChain string) error {
	userChain = strings.TrimSpace(userChain)
	if userChain == "" {
		return fmt.Errorf("ensure forward jump: empty chain name")
	}
	spec := []string{"-j", userChain}
	exists, err := e.ipt.Exists("filter", "FORWARD", spec...)
	if err != nil {
		return fmt.Errorf("check forward jump to %s: %w", userChain, err)
	}
	if exists {
		return nil
	}
	if err := e.ipt.Insert("filter", "FORWARD", 1, spec...); err != nil {
		return fmt.Errorf("insert forward jump to %s: %w", userChain, err)
	}
	return nil
}

func (e *execBackend) EnsureInputChain(chain string) error {
	if err := e.EnsureUserChain(chain); err != nil {
		return err
	}
	exists, err := e.ipt.Exists("filter", chain, inputEstablishedReturn...)
	if err != nil {
		return fmt.Errorf("check %s established return: %w", chain, err)
	}
	if !exists {
		if err := e.ipt.Insert("filter", chain, 1, inputEstablishedReturn...); err != nil {
			return fmt.Errorf("insert %s established return: %w", chain, err)
		}
	}
	jump := []string{"-j", chain}
	exists, err = e.ipt.Exists("filter", "INPUT", jump...)
	if err != nil {
		return fmt.Errorf("check input jump to %s: %w", chain, err)
	}
	if exists {
		return nil
	}
	if err := e.ipt.Insert("filter", "INPUT", 1, jump...); err != nil {
		return fmt.Errorf("insert input jump to %s: %w", chain, err)
	}
	return nil
}

// EnsureJumpChain implements floorBackend.
func (e *execBackend) EnsureJumpChain(parent, child string) error {
	if err := e.EnsureUserChain(child); err != nil {
		return err
	}
	jump := []string{"-j", child}
	exists, err := e.ipt.Exists("filter", parent, jump...)
	if err != nil {
		return fmt.Errorf("check %s jump to %s: %w", parent, child, err)
	}
	if exists {
		return nil
	}
	if err := e.ipt.Insert("filter", parent, 1, jump...); err != nil {
		return fmt.Errorf("insert %s jump to %s: %w", parent, child, err)
	}
	return nil
}

// FlushChain implements floorBackend.
func (e *execBackend) FlushChain(chain string) error {
	return e.ipt.ClearChain("filter", chain)
}
