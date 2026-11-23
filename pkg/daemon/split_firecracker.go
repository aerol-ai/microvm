package daemon

import (
	"context"
	"errors"

	"github.com/aerol-ai/microvm/internal/rootclient"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	fcruntime "github.com/aerol-ai/microvm/internal/runtime/firecracker"
)

// Firecracker in privilege mode split (M1 PR 9b): the driver's split seam
// (fcruntime.SplitHelper) over the root helper's calls.

// firecrackerHelper is the helper's calls the Firecracker driver uses
// (*rootclient.Client).
type firecrackerHelper interface {
	hostHelper
	PrepareFirecracker(ctx context.Context, id string, stage ...string) (root, stageDir string, err error)
	EnsureTap(ctx context.Context, name string) (*rootdpb.EnsureTapResponse, error)
	RemoveTap(ctx context.Context, name string) error
	MakeFilesystem(ctx context.Context, id, name, source string, sizeMiB uint64) error
}

const firecrackerKind = rootdpb.HostKind_HOST_KIND_FIRECRACKER

// splitFirecracker adapts the helper's calls to fcruntime.SplitHelper.
type splitFirecracker struct{ h firecrackerHelper }

var _ fcruntime.SplitHelper = splitFirecracker{}

func (s splitFirecracker) PrepareFirecracker(ctx context.Context, id string, stage ...string) (string, string, error) {
	return s.h.PrepareFirecracker(ctx, id, stage...)
}

func (s splitFirecracker) SpawnFirecracker(ctx context.Context, id string) (fcruntime.SplitProcess, error) {
	resp, err := s.h.SpawnHost(ctx, &rootdpb.SpawnHostRequest{Kind: firecrackerKind, Id: id})
	if err != nil {
		return nil, err
	}
	if resp.GetPid() == 0 {
		return nil, errors.New("root helper answered a Firecracker VM with no process")
	}
	return s.h.HoldHost(firecrackerKind, id, int(resp.GetPid()), resp.GetStartTicks()), nil
}

func (s splitFirecracker) OpenFirecracker(ctx context.Context, id string, pid int, ticks uint64) (fcruntime.SplitProcess, error) {
	p, err := s.h.OpenHost(ctx, firecrackerKind, id, pid, ticks)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (s splitFirecracker) StopFirecracker(ctx context.Context, id string) error {
	_, err := s.h.StopHost(ctx, firecrackerKind, id)
	return err
}

func (s splitFirecracker) EnsureTap(ctx context.Context, name string) (fcruntime.TapSlot, error) {
	resp, err := s.h.EnsureTap(ctx, name)
	if err != nil {
		return fcruntime.TapSlot{}, err
	}
	return fcruntime.TapSlot{TapName: name, CIDR: resp.GetCidr(), HostIP: resp.GetHostIp(), GuestIP: resp.GetGuestIp(),
		VsockCID: resp.GetVsockCid()}, nil
}

func (s splitFirecracker) RemoveTap(ctx context.Context, name string) error {
	return s.h.RemoveTap(ctx, name)
}

func (s splitFirecracker) MakeFilesystem(ctx context.Context, id, name, source string, sizeMiB uint64) error {
	return s.h.MakeFilesystem(ctx, id, name, source, sizeMiB)
}

// the client is the helper.
var _ firecrackerHelper = (*rootclient.Client)(nil)
