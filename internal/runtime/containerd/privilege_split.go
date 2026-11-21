package containerd

import (
	"context"
	"errors"
	"fmt"
	"path"

	cntr "github.com/containerd/containerd/v2/client"

	"github.com/aerol-ai/microvm/internal/privmode"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Privilege mode split (internal/privmode, plans/security-gaps-m1-m4.md
// §3.3): sandboxd runs with no rights, and the root helper does the root
// work. In single mode, today's, none of this is reached: d.helper is nil,
// and each place below is one nil check on the way.
//
// What the driver does through the helper so far (M1 PR 4):
//   - it reaches containerd through the helper's socket, where the gate
//     answers containerd's API (rootclient.ContainerdOptions): sandboxd can
//     no longer open containerd's own socket;
//   - it reads a running sandbox's address from its pool namespace through
//     the helper (taskAddress): entering a namespace takes root. A create
//     skips the read: its address is the one the helper gave the slot
//     (sandboxAddress). A start, an inspect or an adoption reads it.
//
// The netns pool's build and teardown go through the helper too, in
// pkg/daemon's wiring. The rest of a create and a start is root work the
// helper does not do yet; those fail at once with a privmode.Gap naming
// each step, before any of it is tried, and never fall back to root.

// RootHelper is the root helper as the driver uses it
// (*rootclient.Client).
type RootHelper interface {
	// Socket and ContainerdOptions reach containerd through the helper.
	Socket() string
	ContainerdOptions() []cntr.Opt
	// NetnsAddrs reads a pool namespace's addresses.
	NetnsAddrs(ctx context.Context, name string) (exists bool, ipv4 []string, err error)
}

// SetRootHelper puts the driver in privilege mode split. Call it before
// the first call that reaches containerd.
func (d *Driver) SetRootHelper(h RootHelper) {
	d.clientMu.Lock()
	defer d.clientMu.Unlock()
	d.helper = h
}

// connectHelperFn connects to containerd through the helper's gate; tests
// replace it.
var connectHelperFn = func(h RootHelper, namespace string) (*Client, error) {
	return connectVia(h.Socket(), namespace, func(socket, ns string) (rawAPI, error) {
		raw, err := cntr.New(socket, append(h.ContainerdOptions(), cntr.WithDefaultNamespace(ns))...)
		if err != nil {
			return nil, err
		}
		return cntrClientRaw{raw}, nil
	})
}

// errNoPoolNamespace: split mode reads an address only from a sandbox's
// pool namespace; every split create has one (pkg/daemon refuses split
// without the netns pool).
var errNoPoolNamespace = errors.New("containerd: the task's spec names no pool network namespace, and split mode reads addresses only there")

// taskAddress is a running task's IPv4 from the netns probe: today's in
// process (containerIPv4FromTaskFn), or in split mode the helper's read of
// the namespace the task's spec pins. Either fails when the namespace
// holds no address (gVisor's case), and the caller falls back to the
// address the slot was given, as before.
func (d *Driver) taskAddress(ctx context.Context, task cntr.Task) (string, error) {
	if d.helper == nil {
		return containerIPv4FromTaskFn(ctx, task)
	}
	if task == nil {
		return "", errors.New("task is nil")
	}
	spec, err := task.Spec(ctx)
	if err != nil {
		return "", fmt.Errorf("task spec: %w", err)
	}
	p := specNetworkNamespacePath(spec)
	if p == "" {
		return "", errNoPoolNamespace
	}
	_, addrs, err := d.helper.NetnsAddrs(ctx, path.Base(p))
	if err != nil {
		return "", err
	}
	if len(addrs) == 0 {
		return "", errors.New("no container IPv4 found")
	}
	return addrs[0], nil
}

// splitCreateGaps is the root work a create needs that split mode does not
// do yet. A create in split mode fails with it before it starts.
func (d *Driver) splitCreateGaps(req models.CreateSandboxRequest) error {
	steps := []privmode.Step{privmode.StepContainerFile, privmode.StepImageUser}
	if d.cfg.CgroupParent != "" {
		steps = append(steps, privmode.StepCgroups)
	}
	if d.cfg.DiskQuota && req.DiskGB > 0 {
		steps = append(steps, privmode.StepDiskQuota)
	}
	return privmode.NotYet("create a sandbox", steps...)
}

// splitStartGaps is the same for a start of a stopped sandbox: new host
// files, task output and the out-of-memory setting.
func (d *Driver) splitStartGaps() error {
	steps := []privmode.Step{privmode.StepContainerFile}
	if d.cfg.CgroupParent != "" {
		steps = append(steps, privmode.StepCgroups)
	}
	return privmode.NotYet("start a sandbox", steps...)
}
