package mounts

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// Remote mounts (privilege mode split, M1 PR 8): sandboxd has no rights,
// and the root helper (internal/rootd) runs the mount work in a Manager of
// its own (Config.Tools). sandboxd's Manager then keeps no state and starts
// nothing: each call is one helper call, which the helper checks and runs.
// The service holds the same *Manager in both modes, so nothing above this
// package knows which one runs.

// RemoteMode is what a remote mount call does with mounts already serving:
// MountAll's, Reestablish's or KeepLive's rule.
type RemoteMode int

const (
	RemoteCreate RemoteMode = iota + 1
	RemoteReestablish
	RemoteKeepLive
)

// RemoteResult is a remote mount call's answer.
type RemoteResult struct {
	Binds  []ContainerBind
	Report KeepReport
}

// Remote is the root helper's mount calls (internal/rootclient Mounts).
type Remote interface {
	Mount(ctx context.Context, sandboxID string, mode RemoteMode, specs []models.MountSpec) (RemoteResult, error)
	Unmount(ctx context.Context, sandboxID string, discard bool) (had bool, err error)
	Sweep(ctx context.Context, keep []string) error
	// Ready says why the helper cannot mount, or nil when it can (or when
	// it has not been asked yet, and the call will say).
	Ready() error
}

// remoteCallTimeout bounds an unmount or a sweep the service runs with no
// context of its own (UnmountAll, Discard, Sweep take none).
var remoteCallTimeout = 2 * time.Minute

// NewRemote is the Manager of privilege mode split: every call goes to the
// helper. unavailable, when set, refuses every mount set as Config's does.
func NewRemote(logger *slog.Logger, remote Remote, unavailable string) (*Manager, error) {
	if logger == nil {
		return nil, errors.New("logger is required")
	}
	if remote == nil {
		return nil, errors.New("a remote is required")
	}
	return &Manager{
		logger:      logger,
		state:       make(map[string][]*mountState),
		mounting:    make(map[string]int),
		sweeping:    make(map[string]chan struct{}),
		closeCh:     make(chan struct{}),
		unavailable: unavailable,
		remote:      remote,
		remoteBinds: make(map[string][]ContainerBind),
	}, nil
}

func (m *Manager) remoteMount(ctx context.Context, sandboxID string, mode RemoteMode, specs []models.MountSpec) (RemoteResult, error) {
	if err := models.ValidateSandboxID(sandboxID); err != nil {
		return RemoteResult{}, fmt.Errorf("mount: %w", err)
	}
	if _, ok := consumerFrom(ctx); ok {
		// Split mode runs no WASM sandbox (the helper does not start host
		// processes yet), so no consumer can reach here.
		return RemoteResult{}, errors.New("mount: the root helper serves no WASM consumer")
	}
	res, err := m.remote.Mount(ctx, sandboxID, mode, specs)
	if err != nil {
		return RemoteResult{}, err
	}
	m.mu.Lock()
	m.remoteBinds[sandboxID] = slices.Clone(res.Binds)
	m.mu.Unlock()
	return res, nil
}

func (m *Manager) remoteUnmount(sandboxID string, discard bool) (bool, error) {
	m.mu.Lock()
	delete(m.remoteBinds, sandboxID)
	m.mu.Unlock()
	if models.ValidateSandboxID(sandboxID) != nil {
		return false, nil // nothing was ever mounted under such an ID
	}
	ctx, cancel := context.WithTimeout(context.Background(), remoteCallTimeout)
	defer cancel()
	return m.remote.Unmount(ctx, sandboxID, discard)
}

func (m *Manager) remoteSweep(keep map[string]struct{}) {
	ids := make([]string, 0, len(keep))
	for id := range keep {
		if models.ValidateSandboxID(id) == nil {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	ctx, cancel := context.WithTimeout(context.Background(), remoteCallTimeout)
	defer cancel()
	if err := m.remote.Sweep(ctx, ids); err != nil {
		m.logger.Warn("mounts sweep: the root helper's sweep failed", "error", err)
	}
}
