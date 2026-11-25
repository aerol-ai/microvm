package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/network/netns"
	cntr "github.com/aerol-ai/microvm/internal/runtime/containerd"
	"github.com/aerol-ai/microvm/pkg/docker/netrules"
)

// memRules is an in-memory netrules backend that can clear an address the
// way both real backends do (ClearAddressRules).
type memRules struct{ rules []string }

func memKey(table, chain string, spec []string) string {
	return strings.Join(append([]string{table, chain}, spec...), "|")
}

func (m *memRules) EnsureInputChain(string) error { return nil }
func (m *memRules) Exists(table, chain string, spec ...string) (bool, error) {
	return slices.Contains(m.rules, memKey(table, chain, spec)), nil
}
func (m *memRules) Insert(table, chain string, _ int, spec ...string) error {
	m.rules = append(m.rules, memKey(table, chain, spec))
	return nil
}
func (m *memRules) Delete(table, chain string, spec ...string) error {
	i := slices.Index(m.rules, memKey(table, chain, spec))
	if i < 0 {
		return errors.New("No chain/target/match by that name")
	}
	m.rules = slices.Delete(m.rules, i, i+1)
	return nil
}
func (m *memRules) ClearAddressRules(_ []string, ip string) error {
	m.rules = slices.DeleteFunc(m.rules, func(r string) bool { return strings.Contains(r, "|"+ip+"|") })
	return nil
}

// In single mode the netns pool's boot reconcile gives a dead holder's
// address back with its rules, as the driver's own releases do (containerd
// give_back.go): the wiring hands the pool the driver's whole-address
// clear. Without it a holder gone across a restart left its rules on an
// address the pool then handed to its next sandbox.
func TestWireNetnsPoolClearsADeadHoldersRulesInSingleMode(t *testing.T) {
	ctx := context.Background()
	st := openDaemonTestStore(t)
	work := t.TempDir()
	origSysctls := ensureForwardingSysctls
	ensureForwardingSysctls = func() error { return nil }
	t.Cleanup(func() { ensureForwardingSysctls = origSysctls })
	cfg := config.Config{
		ContainerEngine:                   "containerd",
		ContainerdNativeNetnsPoolEnabled:  true,
		ContainerdNetnsPoolDepth:          0,
		ContainerdNetnsPoolSize:           1,
		ContainerdNetnsPoolRefillInterval: 10,
		ContainerdCNIPluginDir:            filepath.Join(work, "cni-bin"),
		ContainerdCNIConfPath:             filepath.Join(work, "cni", "aerolvm.conflist"),
	}
	be := &memRules{}
	driver := cntr.New(cntr.FromDaemonConfig(cfg), netrules.NewWithBackend(be), testLogger())
	wired, err := wireContainerdNativeNetnsPool(ctx, cfg, testLogger(), st, driver)
	if err != nil {
		t.Fatalf("wire: %v", err)
	}
	t.Cleanup(wired.Stop)

	// A sandbox held a slot and had its rules on; it died while sandboxd
	// was down.
	now := time.Now()
	const ip = "10.88.0.50"
	if _, err := wired.pool.Reserve(ctx, "sb-dead", now); err != nil {
		t.Fatal(err)
	}
	if _, err := wired.pool.MarkRealized(ctx, "sb-dead", "/run/netns/aerol-netns-0", ip, now); err != nil {
		t.Fatal(err)
	}
	if _, err := wired.pool.Adopt(ctx, "sb-dead", now); err != nil {
		t.Fatal(err)
	}
	if err := driver.ApplyNetworkBlockAll(ip); err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(be.rules, func(r string) bool { return strings.Contains(r, "|"+ip+"|") }) {
		t.Fatalf("setup: no rule on %s: %v", ip, be.rules)
	}
	reaped, err := wired.pool.Reconcile(ctx, netns.NewFakeHost(), nil, func(string) bool { return true }, now)
	if err != nil || reaped != 1 {
		t.Fatalf("reconcile reaped %d, %v; want the dead holder's slot", reaped, err)
	}
	if slices.ContainsFunc(be.rules, func(r string) bool { return strings.Contains(r, "|"+ip+"|") }) {
		t.Fatalf("the dead holder's rules on %s stayed: %v", ip, be.rules)
	}
}
