package netns

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/network/cni"
	"github.com/aerol-ai/microvm/internal/network/hostnet"
	"github.com/aerol-ai/microvm/internal/store"
)

// HostManager realizes reserved slots: create netns, CNI ADD, and inverse on
// Remove. Idempotent Ensure/Remove mirrors tap.HostManager.
type HostManager interface {
	Realize(ctx context.Context, slot Slot) (netnsPath string, ip string, err error)
	Remove(ctx context.Context, slot Slot) error
}

// Host is the production HostManager. NetnsRoot is typically /run/netns.
type Host struct {
	Runner    cni.Runner
	NetnsRoot string
	// mkdir is a test seam for the netns root dir; production leaves nil.
	mkdir func(path string, perm os.FileMode) error
	// addNetns/delNetns create and remove a REAL named network namespace.
	// Production leaves them nil and execs `ip netns add/del`; tests stub them
	// so unit tests need neither `ip` nor CAP_NET_ADMIN.
	addNetns func(ctx context.Context, name string) error
	delNetns func(ctx context.Context, name string) error
	// loopbackUp flips `lo` up inside the named netns. Test seam like
	// addNetns/delNetns; production leaves it nil and execs `ip -n <name> link
	// set lo up`.
	loopbackUp func(ctx context.Context, name string) error
}

func (h *Host) Realize(ctx context.Context, slot Slot) (string, string, error) {
	if h == nil || h.Runner == nil {
		return "", "", errors.New("netns host: runner is required")
	}
	if strings.TrimSpace(slot.SandboxID) == "" {
		return "", "", errors.New("netns host: sandbox_id is required")
	}
	root := h.netnsRoot()
	if err := h.ensureDir(root); err != nil {
		return "", "", err
	}
	// One name for the netns AND the CNI container id; Remove derives the same
	// name back from the recorded path (Slot.netnsName).
	name := slot.netnsName()
	// Create a REAL network namespace, not just a directory: the CNI plugin and
	// the containerd shim both open this path as a netns. `ip netns add` bind-
	// mounts a fresh netns at /run/netns/<name>; a plain mkdir'd directory makes
	// CNI ADD fail with a bare "exit status 1" (the plugin cannot enter a dir).
	if err := h.createNetns(ctx, name); err != nil {
		return "", "", fmt.Errorf("netns host: create netns %s: %w", name, err)
	}
	// A fresh netns has loopback DOWN, and the CNI runner invokes only the bridge
	// plugin (cni.resolve reduces the conflist to plugins[0]), so nothing brings
	// lo up. Without this, 127.0.0.1 / localhost TCP inside the sandbox times out
	// even though a service binds 0.0.0.0 — breaking any app that dials localhost
	// (postgres, redis, dev servers, multi-process apps). Do it before CNI ADD so
	// the namespace is fully usable the instant the container attaches; roll back
	// the netns on failure, mirroring the CNI ADD path below.
	if err := h.bringLoopbackUp(ctx, name); err != nil {
		_ = h.deleteNetns(ctx, name)
		return "", "", fmt.Errorf("netns host: loopback up %s: %w", name, err)
	}
	path := filepath.Join(root, name)
	// IPv6 off before the sandbox's interface exists: "default" is what the
	// veth CNI ADD creates in here starts with, so it never gets a
	// link-local address a neighbour on the bridge could reach (every host
	// rule between sandboxes is IPv4). Prewarmed slots come through here
	// too.
	if err := disableIPv6InNetns(path); err != nil {
		_ = h.deleteNetns(ctx, name)
		return "", "", fmt.Errorf("netns host: disable ipv6 in %s: %w", name, err)
	}
	res, err := h.Runner.Add(ctx, path, name)
	if err != nil {
		_ = h.deleteNetns(ctx, name)
		return "", "", fmt.Errorf("netns host: cni add: %w", err)
	}
	// And again after: IPAM turns IPv6 back on for an interface it gives an
	// IPv6 address (an operator conflist with a v6 range). "all" switches
	// it off on every interface there. The ADD succeeded, so a failure
	// here undoes all of it, as Remove would.
	if err := disableIPv6InNetns(path); err != nil {
		rmErr := h.Remove(ctx, Slot{SlotID: slot.SlotID, SandboxID: slot.SandboxID, NetnsPath: path, ContainerIP: res.IP4})
		return "", "", errors.Join(fmt.Errorf("netns host: disable ipv6 in %s after cni add: %w", name, err), rmErr)
	}
	return path, res.IP4, nil
}

// disableIPv6InNetns turns IPv6 off inside a sandbox netns. A var because
// unit tests have no real netns to enter (TestMain stands in a no-op; the
// IPv6 tests record calls).
var disableIPv6InNetns = hostnet.DisableIPv6InNetns

// DisableIPv6 turns IPv6 off in an already-realized slot's netns.
// Reconcile runs it on every slot that survives a restart, so a warm slot
// an older daemon realized is not handed out with IPv6 on, and a running
// sandbox loses the link-local address it booted with. Idempotent.
func (h *Host) DisableIPv6(_ context.Context, slot Slot) error {
	path := strings.TrimSpace(slot.NetnsPath)
	if path == "" {
		return errors.New("netns host: slot has no netns path")
	}
	return disableIPv6InNetns(path)
}

// createNetns creates a persistent named netns (bind-mounted at
// /run/netns/<name>). Idempotent: an already-present netns is not an error.
func (h *Host) createNetns(ctx context.Context, name string) error {
	if h.addNetns != nil {
		return h.addNetns(ctx, name)
	}
	out, err := exec.CommandContext(ctx, "ip", "netns", "add", name).CombinedOutput()
	if err != nil && !strings.Contains(strings.ToLower(string(out)), "file exists") {
		return fmt.Errorf("ip netns add: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// bringLoopbackUp flips `lo` up inside the named netns. Idempotent: bringing an
// already-up loopback up again is a no-op in iproute2. Uses `ip -n <name>`
// (runs in the netns at /run/netns/<name> created by createNetns).
func (h *Host) bringLoopbackUp(ctx context.Context, name string) error {
	if h.loopbackUp != nil {
		return h.loopbackUp(ctx, name)
	}
	out, err := exec.CommandContext(ctx, "ip", "-n", name, "link", "set", "lo", "up").CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip -n %s link set lo up: %v: %s", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// deleteNetns removes a named netns. Idempotent: a missing netns is not an error.
func (h *Host) deleteNetns(ctx context.Context, name string) error {
	if h.delNetns != nil {
		return h.delNetns(ctx, name)
	}
	out, err := exec.CommandContext(ctx, "ip", "netns", "del", name).CombinedOutput()
	if err != nil {
		low := strings.ToLower(string(out))
		if strings.Contains(low, "no such file") || strings.Contains(low, "cannot remove") {
			return nil
		}
		return fmt.Errorf("ip netns del: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Remove deletes everything Realize created for slot: the CNI attachment
// (veth, host-local lease, masquerade chain), conntrack entries and the named
// netns. It uses the same identity Realize used (Slot.netnsName), whoever owns
// the slot now. Errors are joined, never swallowed: the pool keeps a slot out
// of circulation until Remove succeeds.
func (h *Host) Remove(ctx context.Context, slot Slot) error {
	if h == nil || h.Runner == nil {
		return nil
	}
	name := slot.netnsName()
	if name == "" {
		return nil
	}
	path := strings.TrimSpace(slot.NetnsPath)
	if path == "" {
		path = filepath.Join(h.netnsRoot(), name)
	}
	delErr := h.Runner.Del(ctx, path, name)
	// The bridge plugin's DEL removes the masquerade chain only for addresses
	// it still finds on the container interface. gVisor (runsc, network=sandbox)
	// moves the address into its own netstack and deletes it from that
	// interface at start, so for every gVisor sandbox DEL finds nothing and the
	// chain plus its POSTROUTING jump stay behind. Tear them down by identity.
	var masqErr error
	if t, ok := h.Runner.(cni.IPMasqTeardown); ok {
		masqErr = t.TeardownIPMasq(ctx, name, slot.ContainerIP)
	}
	_ = hostnet.FlushConntrackForIP(slot.ContainerIP)
	rmErr := h.deleteNetns(ctx, name)
	return errors.Join(delErr, masqErr, rmErr)
}

func (h *Host) netnsPathFor(name string) string {
	return filepath.Join(h.netnsRoot(), name)
}

func (h *Host) netnsRoot() string {
	if strings.TrimSpace(h.NetnsRoot) != "" {
		return h.NetnsRoot
	}
	return "/run/netns"
}

func (h *Host) ensureDir(path string) error {
	if h.mkdir != nil {
		return h.mkdir(path, 0o755)
	}
	return os.MkdirAll(path, 0o755)
}

// Builder sequences reserve → realize → adopt with LIFO teardown on failure.
type Builder struct {
	pool *Pool
	host HostManager
	now  func() time.Time
}

func NewBuilder(pool *Pool, host HostManager) *Builder {
	return &Builder{pool: pool, host: host, now: func() time.Time { return timeNow() }}
}

// Build runs the FSM for sandboxID. On failure, teardown runs in reverse order.
func (b *Builder) Build(ctx context.Context, sandboxID string) (*Slot, error) {
	if b == nil || b.pool == nil || b.host == nil {
		return nil, errors.New("netns builder: pool and host are required")
	}
	now := b.now()
	slot, err := b.pool.Reserve(ctx, sandboxID, now)
	if err != nil {
		return nil, err
	}
	// Keep the id: slot is reassigned from MarkRealized/Adopt below, which
	// return nil on error, and the deferred teardown must still name the slot
	// (it used to dereference that nil and panic on exactly this path).
	slotID := slot.SlotID
	unlock := b.pool.lockSlot(slotID)
	defer unlock()
	// Reserve is idempotent per sandbox, so a concurrent duplicate create gets
	// the same row and waits on the lock above. Re-read: if the first Build
	// already adopted it, hand that back instead of realizing a second time —
	// the second `ip netns add` would reuse the live netns, its CNI ADD would
	// fail as a duplicate, and the rollback would delete the live netns and
	// free the slot under the running sandbox.
	cur, err := b.pool.Get(ctx, sandboxID)
	if err != nil {
		return nil, err
	}
	if cur == nil || cur.SlotID != slotID {
		return nil, fmt.Errorf("netns builder: reservation of %s for %s was released concurrently", slotID, sandboxID)
	}
	if cur.State == store.NetnsSlotStateAdopted {
		return cur, nil
	}
	var (
		netnsPath string
		ip        string
		realized  bool
		adopted   bool
	)
	defer func() {
		if adopted {
			return
		}
		release := func() error { return b.pool.Release(ctx, sandboxID, b.now()) }
		if !realized {
			_ = release()
			return
		}
		teardown := Slot{
			SlotID:      slotID,
			SandboxID:   sandboxID,
			NetnsPath:   netnsPath,
			ContainerIP: ip,
		}
		_ = b.pool.teardown(ctx, b.host, teardown, sandboxID, release, b.now())
	}()

	netnsPath, ip, err = b.host.Realize(ctx, *slot)
	if err != nil {
		return nil, err
	}
	realized = true
	slot, err = b.pool.MarkRealized(ctx, sandboxID, netnsPath, ip, b.now())
	if err != nil {
		return nil, err
	}
	slot, err = b.pool.Adopt(ctx, sandboxID, b.now())
	if err != nil {
		return nil, err
	}
	adopted = true
	return slot, nil
}

// FakeHost records realize/remove calls for tests. Like Host, it keys host
// state by Slot.netnsName, so a test that releases under the wrong identity
// leaves the realized entry behind exactly as a real node would.
type FakeHost struct {
	mu         sync.Mutex
	realized   map[string]string // netns name -> ip
	removed    []string
	realizeErr error
	removeErr  error
}

func NewFakeHost() *FakeHost {
	return &FakeHost{realized: make(map[string]string)}
}

func (f *FakeHost) SetRealizeError(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.realizeErr = err
}

func (f *FakeHost) SetRemoveError(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removeErr = err
}

func (f *FakeHost) Realize(ctx context.Context, slot Slot) (string, string, error) {
	_ = ctx
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.realizeErr != nil {
		return "", "", f.realizeErr
	}
	name := slot.netnsName()
	ip := fmt.Sprintf("10.88.0.%d", len(f.realized)+2)
	f.realized[name] = ip
	return f.netnsPathFor(name), ip, nil
}

func (f *FakeHost) Remove(ctx context.Context, slot Slot) error {
	_ = ctx
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.removeErr != nil {
		return f.removeErr
	}
	name := slot.netnsName()
	f.removed = append(f.removed, name)
	delete(f.realized, name)
	return nil
}

func (f *FakeHost) netnsPathFor(name string) string { return "/run/netns/" + name }

func (f *FakeHost) RealizedCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.realized)
}

func (f *FakeHost) RemovedCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.removed)
}

// Removed returns the netns names Remove was called with, in order.
func (f *FakeHost) Removed() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.removed...)
}

// timeNow is overridden in tests.
var timeNow = func() time.Time {
	return time.Unix(0, 0).UTC()
}
