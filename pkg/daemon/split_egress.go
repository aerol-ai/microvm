package daemon

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/internal/egress/procid"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
)

// The hostname egress gateway's host side in privilege mode split (M1 PR
// 5b): the self-test's probe network and the executable lookups are root
// work, which the helper does (internal/rootd egress.go). The gateway and
// everything sandboxd asks of it are unchanged.

// egressHelper is the helper's calls for it (*rootclient.Client).
type egressHelper interface {
	BridgeProbe(ctx context.Context, op rootdpb.BridgeProbeOp, slot uint32) (*rootdpb.BridgeProbeResponse, error)
	MatchProcess(ctx context.Context, pid uint32, local, remote string, paths []string) ([]string, bool, error)
}

// helperProbeNet is egress.ProbeNet through the helper: each step of the
// self-test is one call, in the order sandboxd runs them in single mode.
// The helper probes its own bridge; the slot is the bridge's index.
type helperProbeNet struct{ h egressHelper }

var _ egress.ProbeNet = helperProbeNet{}

func (p helperProbeNet) Setup(ctx context.Context, b egress.Bridge, _ netip.Addr, index int) (egress.ProbeEnv, error) {
	if index < 0 {
		return nil, fmt.Errorf("probe slot %d", index)
	}
	resp, err := p.h.BridgeProbe(ctx, rootdpb.BridgeProbeOp_BRIDGE_PROBE_OP_SETUP, uint32(index))
	switch {
	case err != nil:
		return nil, err
	case resp.GetBridgeAbsent():
		return nil, egress.ErrBridgeAbsent
	case resp.GetNotReady() != "":
		return nil, fmt.Errorf("%w: bridge %s: %s", egress.ErrSelfTest, b.Name, resp.GetNotReady())
	}
	return helperProbeEnv{h: p.h, slot: uint32(index)}, nil
}

type helperProbeEnv struct {
	h    egressHelper
	slot uint32
}

func (e helperProbeEnv) Send(ctx context.Context) error {
	resp, err := e.h.BridgeProbe(ctx, rootdpb.BridgeProbeOp_BRIDGE_PROBE_OP_SEND, e.slot)
	if err != nil {
		return err
	}
	if s := resp.GetSendError(); s != "" {
		return errors.New(s)
	}
	return nil
}

func (e helperProbeEnv) Close() error {
	_, err := e.h.BridgeProbe(context.Background(), rootdpb.BridgeProbeOp_BRIDGE_PROBE_OP_CLOSE, e.slot)
	return err
}

// helperMatch is procid.Server.Match through the helper.
func helperMatch(h egressHelper) func(pid int, local, remote netip.AddrPort, paths []string) ([]string, error) {
	return func(pid int, local, remote netip.AddrPort, paths []string) ([]string, error) {
		if pid <= 0 || pid > 1<<22 {
			return nil, fmt.Errorf("process id %d", pid)
		}
		matched, notFound, err := h.MatchProcess(context.Background(), uint32(pid), local.String(), remote.String(), paths)
		if err != nil {
			return nil, err
		}
		if notFound {
			return nil, procid.ErrNotFound
		}
		return matched, nil
	}
}
