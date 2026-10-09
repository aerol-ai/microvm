package daemon

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/network/tap"
	fcruntime "github.com/aerol-ai/microvm/internal/runtime/firecracker"
	"github.com/aerol-ai/microvm/pkg/docker/netrules"
)

// fcRuleBackend is an in-memory iptables for the FC firewall manager.
type fcRuleBackend struct {
	mu     sync.Mutex
	rules  map[string]bool
	chains []string
}

func (b *fcRuleBackend) key(table, chain string, spec []string) string {
	return table + "/" + chain + " " + strings.Join(spec, " ")
}
func (b *fcRuleBackend) Exists(table, chain string, spec ...string) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.rules[b.key(table, chain, spec)], nil
}
func (b *fcRuleBackend) Insert(table, chain string, _ int, spec ...string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.rules[b.key(table, chain, spec)] = true
	return nil
}
func (b *fcRuleBackend) Delete(table, chain string, spec ...string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.rules, b.key(table, chain, spec))
	return nil
}
func (b *fcRuleBackend) EnsureUserChain(chain string) error {
	b.chains = append(b.chains, chain)
	return nil
}
func (b *fcRuleBackend) EnsureForwardJump(string) error { return nil }

type fcNAT struct {
	rules []string
	err   error
}

func (n *fcNAT) Exists(string, string, ...string) (bool, error) { return false, n.err }
func (n *fcNAT) Append(_, _ string, spec ...string) error {
	n.rules = append(n.rules, strings.Join(spec, " "))
	return nil
}

func TestWireFirecrackerEgress(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	oldRules, oldNAT, oldSysctl := newFirecrackerRules, newFirecrackerNAT, ensureForwardingSysctls
	t.Cleanup(func() { newFirecrackerRules, newFirecrackerNAT, ensureForwardingSysctls = oldRules, oldNAT, oldSysctl })
	ensureForwardingSysctls = func() error { return nil }
	nat := &fcNAT{}
	newFirecrackerNAT = func() (tap.NATBackend, error) { return nat, nil }
	be := &fcRuleBackend{rules: map[string]bool{}}
	newFirecrackerRules = func(config.Config) (*netrules.Manager, error) { return netrules.NewWithBackend(be), nil }
	cfg := config.Config{FirecrackerTapBaseCIDR: "172.16.0.0/16"}

	d := fcruntime.New(fcruntime.Config{}, log)
	stop, err := wireFirecrackerEgress(context.Background(), cfg, log, d)
	if err != nil {
		t.Fatal(err)
	}
	stop()
	if !d.NetRulesEnabled() || len(nat.rules) != 1 || !strings.Contains(nat.rules[0], "172.16.0.0/16") {
		t.Fatalf("wired: rules=%v nat=%v", d.NetRulesEnabled(), nat.rules)
	}
	// The fake manager keeps the default chain; production's is AEROLVM-FC.
	if len(be.chains) != 1 || !be.rules["filter/"+be.chains[0]+" -s 172.16.0.0/16 -j ACCEPT"] || !be.rules["filter/"+be.chains[0]+" -d 172.16.0.0/16 -j ACCEPT"] {
		t.Fatalf("chain = %v rules = %v", be.chains, be.rules)
	}
	if m, err := oldRules(config.Config{}); err != nil || m.Enabled() {
		t.Fatalf("production constructor with rules off = %v %v", m, err)
	}

	// Rules disabled: NAT only, no firewall for the driver.
	newFirecrackerRules = func(config.Config) (*netrules.Manager, error) {
		return netrules.NewWithOptions(false, "", netrules.ChainAerolvmFC)
	}
	d2 := fcruntime.New(fcruntime.Config{}, log)
	if _, err := wireFirecrackerEgress(context.Background(), cfg, log, d2); err != nil || d2.NetRulesEnabled() {
		t.Fatalf("disabled: %v %v", err, d2.NetRulesEnabled())
	}

	for name, setup := range map[string]func(){
		"bad cidr": func() { cfg.FirecrackerTapBaseCIDR = "nope" },
		"sysctl":   func() { ensureForwardingSysctls = func() error { return errors.New("ro /proc") } },
		"iptables": func() { newFirecrackerNAT = func() (tap.NATBackend, error) { return nil, errors.New("no iptables") } },
		"nat": func() {
			newFirecrackerNAT = func() (tap.NATBackend, error) { return &fcNAT{err: errors.New("x")}, nil }
		},
		"netrules": func() {
			newFirecrackerRules = func(config.Config) (*netrules.Manager, error) { return nil, errors.New("x") }
		},
		"bootstrap": func() {
			newFirecrackerRules = func(config.Config) (*netrules.Manager, error) { return netrules.NewWithBackend(&fcNoBootstrap{}), nil }
		},
	} {
		cfg = config.Config{FirecrackerTapBaseCIDR: "172.16.0.0/16"}
		ensureForwardingSysctls = func() error { return nil }
		newFirecrackerNAT = func() (tap.NATBackend, error) { return &fcNAT{}, nil }
		newFirecrackerRules = func(config.Config) (*netrules.Manager, error) {
			return netrules.NewWithBackend(&fcRuleBackend{rules: map[string]bool{}}), nil
		}
		setup()
		if _, err := wireFirecrackerEgress(context.Background(), cfg, log, fcruntime.New(fcruntime.Config{}, log)); err == nil {
			t.Fatalf("%s: want an error", name)
		}
	}
}

// fcNoBootstrap can't create chains, which EnsureChain refuses loudly.
type fcNoBootstrap struct{}

func (fcNoBootstrap) Exists(string, string, ...string) (bool, error) { return false, nil }
func (fcNoBootstrap) Insert(string, string, int, ...string) error    { return nil }
func (fcNoBootstrap) Delete(string, string, ...string) error         { return nil }
