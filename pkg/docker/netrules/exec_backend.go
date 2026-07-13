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
