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
	// Create a REAL network namespace, not just a directory: the CNI plugin and
	// the containerd shim both open this path as a netns. `ip netns add` bind-
	// mounts a fresh netns at /run/netns/<name>; a plain mkdir'd directory makes
	// CNI ADD fail with a bare "exit status 1" (the plugin cannot enter a dir).
	if err := h.createNetns(ctx, slot.SandboxID); err != nil {
		return "", "", fmt.Errorf("netns host: create netns %s: %w", slot.SandboxID, err)
	}
	path := filepath.Join(root, slot.SandboxID)
	res, err := h.Runner.Add(ctx, path, slot.SandboxID)
	if err != nil {
		_ = h.deleteNetns(ctx, slot.SandboxID)
		return "", "", fmt.Errorf("netns host: cni add: %w", err)
	}
	return path, res.IP4, nil
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

func (h *Host) Remove(ctx context.Context, slot Slot) error {
	if h == nil || h.Runner == nil {
		return nil
	}
	name := strings.TrimSpace(slot.SandboxID)
	path := strings.TrimSpace(slot.NetnsPath)
	if name == "" && path != "" {
		name = filepath.Base(path)
	}
	if name == "" {
		return nil
	}
	if path == "" {
		path = filepath.Join(h.netnsRoot(), name)
	}
	// Surface the CNI DEL error rather than swallowing it: a dropped DEL leaks
	// the veth pair and the host-local IPAM lease with no process death to free
	// them. Conntrack flush and netns teardown are still attempted regardless.
	delErr := h.Runner.Del(ctx, path, name)
	_ = hostnet.FlushConntrackForIP(slot.ContainerIP)
	rmErr := h.deleteNetns(ctx, name)
	return errors.Join(delErr, rmErr)
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
		teardown := Slot{
			SlotID:      slot.SlotID,
			SandboxID:   sandboxID,
			NetnsPath:   netnsPath,
			ContainerIP: ip,
		}
		if realized {
			_ = b.host.Remove(ctx, teardown)
		}
		_ = b.pool.Release(ctx, sandboxID, b.now())
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

// FakeHost records realize/remove calls for tests.
type FakeHost struct {
	mu         sync.Mutex
	realized   map[string]string // sandboxID -> ip
	removed    []string
	realizeErr error
	removeErr  error
}

func NewFakeHost() *FakeHost {
	return &FakeHost{realized: make(map[string]string)}
}

func (f *FakeHost) SetRealizeError(err error) { f.realizeErr = err }
func (f *FakeHost) SetRemoveError(err error)  { f.removeErr = err }

func (f *FakeHost) Realize(ctx context.Context, slot Slot) (string, string, error) {
	_ = ctx
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.realizeErr != nil {
		return "", "", f.realizeErr
	}
	ip := fmt.Sprintf("10.88.0.%d", len(f.realized)+2)
	path := "/run/netns/" + slot.SandboxID
	f.realized[slot.SandboxID] = ip
	return path, ip, nil
}

func (f *FakeHost) Remove(ctx context.Context, slot Slot) error {
	_ = ctx
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.removeErr != nil {
		return f.removeErr
	}
	f.removed = append(f.removed, slot.SandboxID)
	delete(f.realized, slot.SandboxID)
	return nil
}

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

// timeNow is overridden in tests.
var timeNow = func() time.Time {
	return time.Unix(0, 0).UTC()
}
