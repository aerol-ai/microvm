package hostport

import "github.com/coreos/go-iptables/iptables"

// iptablesBackend adapts go-iptables (the same library pkg/docker/netrules
// uses) to Backend.
type iptablesBackend struct{ ipt *iptables.IPTables }

// NewIPTablesBackend returns the production backend (IPv4).
func NewIPTablesBackend() (Backend, error) {
	ipt, err := iptables.New()
	if err != nil {
		return nil, err
	}
	return &iptablesBackend{ipt: ipt}, nil
}

func (b *iptablesBackend) ChainExists(table, chain string) (bool, error) {
	return b.ipt.ChainExists(table, chain)
}
func (b *iptablesBackend) NewChain(table, chain string) error { return b.ipt.NewChain(table, chain) }
func (b *iptablesBackend) Exists(table, chain string, spec ...string) (bool, error) {
	return b.ipt.Exists(table, chain, spec...)
}
func (b *iptablesBackend) Insert(table, chain string, pos int, spec ...string) error {
	return b.ipt.Insert(table, chain, pos, spec...)
}
func (b *iptablesBackend) Append(table, chain string, spec ...string) error {
	return b.ipt.Append(table, chain, spec...)
}
func (b *iptablesBackend) Delete(table, chain string, spec ...string) error {
	return b.ipt.Delete(table, chain, spec...)
}
func (b *iptablesBackend) List(table, chain string) ([]string, error) {
	return b.ipt.List(table, chain)
}
