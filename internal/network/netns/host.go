package netns

import (
	"context"
	"errors"
	"fmt"
	"os"
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
	// mkdir is a test seam; production leaves nil (os.MkdirAll).
	mkdir func(path string, perm os.FileMode) error
	// unlink removes a netns path; production uses os.Remove.
	unlink func(path string) error
}

func (h *Host) Realize(ctx context.Context, slot Slot) (string, string, error) {
	if h == nil || h.Runner == nil {
		return "", "", errors.New("netns host: runner is required")
	}
	if strings.TrimSpace(slot.SandboxID) == "" {
		return "", "", errors.New("netns host: sandbox_id is required")
	}
	root := h.netnsRoot()
	path := filepath.Join(root, slot.SandboxID)
	if err := h.ensureDir(root); err != nil {
		return "", "", err
	}
	// Touch path — production linux uses `ip netns add`; tests stub via mkdir.
	if err := h.ensureDir(path); err != nil {
		return "", "", fmt.Errorf("netns host: create %s: %w", path, err)
	}
	res, err := h.Runner.Add(ctx, path, slot.SandboxID)
	if err != nil {
		_ = h.removePath(path)
		return "", "", fmt.Errorf("netns host: cni add: %w", err)
	}
	return path, res.IP4, nil
}

func (h *Host) Remove(ctx context.Context, slot Slot) error {
	if h == nil || h.Runner == nil {
		return nil
	}
	path := strings.TrimSpace(slot.NetnsPath)
	if path == "" && strings.TrimSpace(slot.SandboxID) != "" {
		path = filepath.Join(h.netnsRoot(), slot.SandboxID)
	}
	if path == "" {
		return nil
	}
	_ = h.Runner.Del(ctx, path, slot.SandboxID)
	_ = hostnet.FlushConntrackForIP(slot.ContainerIP)
	return h.removePath(path)
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

func (h *Host) removePath(path string) error {
	if h.unlink != nil {
		return h.unlink(path)
	}
	err := os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
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
