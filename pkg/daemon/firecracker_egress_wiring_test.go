package daemon

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

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

// fcNAT is the in-memory iptables for the masquerade and the guest
// isolation: it records every rule by table/chain.
type fcNAT struct {
	mu        sync.Mutex
	rules     []string
	err       error
	insertErr error
	chains    map[string]bool
}

func (n *fcNAT) has(rule string) bool {
	for _, r := range n.rules {
		if r == rule {
			return true
		}
	}
	return false
}
func (n *fcNAT) Exists(table, chain string, spec ...string) (bool, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.has(table + "/" + chain + " " + strings.Join(spec, " ")), n.err
}
func (n *fcNAT) Append(table, chain string, spec ...string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.rules = append(n.rules, table+"/"+chain+" "+strings.Join(spec, " "))
	return nil
}
func (n *fcNAT) Insert(table, chain string, _ int, spec ...string) error {
	if n.insertErr != nil {
		return n.insertErr
	}
	return n.Append(table, chain, spec...)
}
func (n *fcNAT) ChainExists(table, chain string) (bool, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.chains[table+"/"+chain], nil
}
func (n *fcNAT) NewChain(table, chain string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.chains == nil {
		n.chains = map[string]bool{}
	}
	n.chains[table+"/"+chain] = true
	return nil
}

// flush drops every rule, as an operator's iptables -F would.
func (n *fcNAT) flush() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.rules = nil
}

func (n *fcNAT) isolated() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.has("mangle/FORWARD -j "+tap.IsolationChain) &&
		n.has("mangle/"+tap.IsolationChain+" -s 172.16.0.0/16 -d 172.16.0.0/16 -m comment --comment aerolvm-fc-isolate -j DROP")
}

func TestWireFirecrackerEgress(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	oldRules, oldNAT, oldSysctl := newFirecrackerRules, newFirecrackerIPTables, ensureForwardingSysctls
	t.Cleanup(func() {
		newFirecrackerRules, newFirecrackerIPTables, ensureForwardingSysctls = oldRules, oldNAT, oldSysctl
	})
	ensureForwardingSysctls = func() error { return nil }
	nat := &fcNAT{}
	newFirecrackerIPTables = func() (tap.IsolationBackend, error) { return nat, nil }
	be := &fcRuleBackend{rules: map[string]bool{}}
	newFirecrackerRules = func(config.Config) (*netrules.Manager, error) { return netrules.NewWithBackend(be), nil }
	cfg := config.Config{FirecrackerTapBaseCIDR: "172.16.0.0/16"}

	d := fcruntime.New(fcruntime.Config{}, log)
	stop, err := wireFirecrackerEgress(context.Background(), cfg, log, d)
	if err != nil {
		t.Fatal(err)
	}
	stop()
	if !d.NetRulesEnabled() || !strings.Contains(nat.rules[0], "nat/POSTROUTING -s 172.16.0.0/16") || !nat.isolated() {
		t.Fatalf("wired: rules=%v nat=%v", d.NetRulesEnabled(), nat.rules)
	}
	// The fake manager keeps the default chain; production's is AEROLVM-FC.
	if len(be.chains) != 1 || !be.rules["filter/"+be.chains[0]+" -s 172.16.0.0/16 -j ACCEPT"] || !be.rules["filter/"+be.chains[0]+" -d 172.16.0.0/16 -j ACCEPT"] {
		t.Fatalf("chain = %v rules = %v", be.chains, be.rules)
	}
	if m, err := oldRules(config.Config{}); err != nil || m.Enabled() {
		t.Fatalf("production constructor with rules off = %v %v", m, err)
	}

	// Rules disabled: NAT and isolation, no firewall for the driver.
	newFirecrackerRules = func(config.Config) (*netrules.Manager, error) {
		return netrules.NewWithOptions(false, "", netrules.ChainAerolvmFC)
	}
	nat2 := &fcNAT{}
	newFirecrackerIPTables = func() (tap.IsolationBackend, error) { return nat2, nil }
	d2 := fcruntime.New(fcruntime.Config{}, log)
	stop2, err := wireFirecrackerEgress(context.Background(), cfg, log, d2)
	if err != nil || d2.NetRulesEnabled() || !nat2.isolated() {
		t.Fatalf("disabled: %v %v isolated=%v", err, d2.NetRulesEnabled(), nat2.isolated())
	}
	stop2()
	newFirecrackerIPTables = func() (tap.IsolationBackend, error) { return nat, nil }

	for name, setup := range map[string]func(){
		"bad cidr": func() { cfg.FirecrackerTapBaseCIDR = "nope" },
		"sysctl":   func() { ensureForwardingSysctls = func() error { return errors.New("ro /proc") } },
		"iptables": func() {
			newFirecrackerIPTables = func() (tap.IsolationBackend, error) { return nil, errors.New("no iptables") }
		},
		"nat": func() {
			newFirecrackerIPTables = func() (tap.IsolationBackend, error) { return &fcNAT{err: errors.New("x")}, nil }
		},
		"isolation": func() {
			newFirecrackerIPTables = func() (tap.IsolationBackend, error) { return &fcNAT{insertErr: errors.New("x")}, nil }
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
		newFirecrackerIPTables = func() (tap.IsolationBackend, error) { return &fcNAT{}, nil }
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

// The isolation comes back on the reassert tick after something flushes the
// tables, with or without per-guest network rules.
func TestFirecrackerIsolationIsReasserted(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	oldRules, oldNAT, oldSysctl, oldInterval := newFirecrackerRules, newFirecrackerIPTables, ensureForwardingSysctls, chainReassertInterval
	t.Cleanup(func() {
		newFirecrackerRules, newFirecrackerIPTables, ensureForwardingSysctls, chainReassertInterval = oldRules, oldNAT, oldSysctl, oldInterval
	})
	ensureForwardingSysctls = func() error { return nil }
	chainReassertInterval = 5 * time.Millisecond
	for _, enabled := range []bool{false, true} {
		nat := &fcNAT{}
		newFirecrackerIPTables = func() (tap.IsolationBackend, error) { return nat, nil }
		newFirecrackerRules = func(config.Config) (*netrules.Manager, error) {
			if !enabled {
				return netrules.NewWithOptions(false, "", netrules.ChainAerolvmFC)
			}
			return netrules.NewWithBackend(&fcRuleBackend{rules: map[string]bool{}}), nil
		}
		stop, err := wireFirecrackerEgress(context.Background(), config.Config{FirecrackerTapBaseCIDR: "172.16.0.0/16"}, log, fcruntime.New(fcruntime.Config{}, log))
		if err != nil {
			t.Fatal(err)
		}
		nat.flush()
		deadline := time.Now().Add(5 * time.Second)
		for !nat.isolated() {
			if time.Now().After(deadline) {
				t.Fatalf("rules enabled=%v: isolation not re-asserted after a flush", enabled)
			}
			time.Sleep(5 * time.Millisecond)
		}
		stop()
	}
}

// A reassert that fails is logged and retried on the next tick.
func TestFirecrackerIsolationReassertLogsAFailure(t *testing.T) {
	oldInterval := chainReassertInterval
	t.Cleanup(func() { chainReassertInterval = oldInterval })
	chainReassertInterval = 5 * time.Millisecond
	logs := &syncBuffer{}
	stop := startIsolationReassert(context.Background(), &fcNAT{err: errors.New("iptables: gone")}, "172.16.0.0/16",
		slog.New(slog.NewTextHandler(logs, nil)))
	defer stop()
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(logs.String(), "re-assert "+tap.IsolationChain+" failed") {
		if time.Now().After(deadline) {
			t.Fatalf("no reassert failure logged: %q", logs.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
}
