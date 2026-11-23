package rootd

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"google.golang.org/grpc/codes"

	"github.com/aerol-ai/microvm/internal/network/hostnet"
	"github.com/aerol-ai/microvm/internal/network/tap/taphost"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// The Firecracker TAP calls (M1 PR 9b): EnsureTap and RemoveTap. In
// privilege mode single sandboxd makes each guest's TAP (taphost.Host)
// and, at its start, the guests' NAT and isolation; in split the helper
// does, from its own settings. The agent names one of the pool's TAPs;
// the helper works its slot out from the name and its own TAP base
// (rootpolicy.CheckTap), so it never touches another link or address.

// tapFeatures are the calls the helper lists when it serves Firecracker.
var tapFeatures = []string{rootdpb.FeatureEnsureTap, rootdpb.FeatureRemoveTap, rootdpb.FeatureMakeFilesystem}

// TapDevices make and remove one TAP (taphost.Host). Tests stand in a fake.
type TapDevices interface {
	Ensure(ctx context.Context, slot taphost.Slot) error
	Remove(ctx context.Context, name string) error
}

// tapCalls serves the TAP calls; nil when the helper serves no Firecracker.
type tapCalls struct {
	cfg   *FirecrackerHostsConfig
	dev   TapDevices
	ipt   func() (taphost.IsolationBackend, error)
	locks *keyedLocks
	log   *slog.Logger
	// sysctls turns forwarding on (hostnet.EnsureForwardingSysctls).
	sysctls func() error

	// The guests' NAT and isolation go in once, before the first TAP; a
	// failed attempt is tried again by the next call (no TAP comes up
	// without them).
	netMu  sync.Mutex
	netUp  bool
	stop   context.CancelFunc
	reTick time.Duration
}

func newTapCalls(c *FirecrackerHostsConfig, opts Options, locks *keyedLocks, log *slog.Logger) *tapCalls {
	t := &tapCalls{cfg: c, dev: opts.TapDevices, ipt: opts.TapTables, locks: locks, log: log,
		sysctls: hostnet.EnsureForwardingSysctls, reTick: tapIsolationTick}
	if t.dev == nil {
		h := taphost.NewHost(c.IPBinary)
		h.Owner = &taphost.Owner{UID: c.UID, GID: c.GID}
		t.dev = h
	}
	if t.ipt == nil {
		t.ipt = newIPTables
	}
	if opts.TapSysctls != nil {
		t.sysctls = opts.TapSysctls
	}
	return t
}

// tapIsolationTick is how often the helper puts the guests' isolation back
// (a firewall reload flushes it), as sandboxd does on its chain tick.
var tapIsolationTick = 30 * time.Second

func (t *tapCalls) close() {
	if t != nil {
		t.netMu.Lock()
		if t.stop != nil {
			t.stop()
		}
		t.netMu.Unlock()
	}
}

// ensureNetwork puts in forwarding, the guests' NAT and their isolation
// for the helper's TAP base, as sandboxd's wireFirecrackerEgress does at
// its start, and keeps the isolation in place.
func (t *tapCalls) ensureNetwork() error {
	t.netMu.Lock()
	defer t.netMu.Unlock()
	if t.netUp {
		return nil
	}
	if err := t.sysctls(); err != nil {
		return fmt.Errorf("forwarding sysctls: %w", err)
	}
	ipt, err := t.ipt()
	if err != nil {
		return fmt.Errorf("iptables: %w", err)
	}
	if err := taphost.EnsureNAT(ipt, t.cfg.TapBase); err != nil {
		return err
	}
	if err := taphost.EnsureIsolation(ipt, t.cfg.TapBase); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.stop = cancel
	go func() {
		tick := time.NewTicker(t.reTick)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				if err := taphost.EnsureIsolation(ipt, t.cfg.TapBase); err != nil {
					t.log.Warn("root helper: put the Firecracker guests' isolation back", "error", err)
				}
			}
		}
	}()
	t.netUp = true
	return nil
}

func (t *tapCalls) slot(name string) (taphost.Slot, error) {
	slot, err := rootpolicy.CheckTap(name, t.cfg.TapBase, t.cfg.TapPoolSize)
	if err != nil {
		return slot, refusedRule(codes.InvalidArgument, err)
	}
	return slot, nil
}

func (t *tapCalls) ensureTap(ctx context.Context, req *rootdpb.EnsureTapRequest) (*rootdpb.EnsureTapResponse, error) {
	slot, err := t.slot(req.GetName())
	if err != nil {
		return nil, err
	}
	// A VM restored from a snapshot keeps the MAC the snapshot froze (M1
	// PR 14b): the helper works it out from the snapshot's CID itself, so
	// the agent names a number, never an address.
	if cid := req.GetGuestCid(); cid != 0 {
		if err := rootpolicy.CheckSnapshotCID(cid); err != nil {
			return nil, refusedRule(codes.InvalidArgument, err)
		}
		slot.GuestMAC = taphost.MACFromCID(cid)
	}
	if err := t.ensureNetwork(); err != nil {
		return nil, &fileError{code: codes.Unavailable, msg: "root helper: the Firecracker guests' NAT and isolation are not in place, so no TAP comes up: " + err.Error()}
	}
	unlock, err := t.locks.lock(ctx, "tap/"+slot.TapName)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := t.dev.Ensure(ctx, slot); err != nil {
		return nil, fmt.Errorf("root helper: %w", err)
	}
	return &rootdpb.EnsureTapResponse{Cidr: slot.CIDR, HostIp: slot.HostIP, GuestIp: slot.GuestIP, VsockCid: slot.VsockCID}, nil
}

func (t *tapCalls) removeTap(ctx context.Context, req *rootdpb.RemoveTapRequest) (*rootdpb.RemoveTapResponse, error) {
	slot, err := t.slot(req.GetName())
	if err != nil {
		return nil, err
	}
	unlock, err := t.locks.lock(ctx, "tap/"+slot.TapName)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := t.dev.Remove(ctx, slot.TapName); err != nil {
		return nil, fmt.Errorf("root helper: %w", err)
	}
	return &rootdpb.RemoveTapResponse{}, nil
}

// newIPTables is the kernel's iptables, as sandboxd drives it for the
// guests (pkg/daemon newFirecrackerIPTables).
func newIPTables() (taphost.IsolationBackend, error) { return iptables.New() }
