package containerd

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	cntr "github.com/containerd/containerd/v2/client"
	"github.com/opencontainers/runtime-spec/specs-go"

	"github.com/aerol-ai/microvm/internal/pool/containerdpool"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
	dockerpkg "github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// The containerd warm pool in privilege mode split (M1 PR 13). A park is a
// create (split_create.go) with one difference: its ready socket is the
// slot's park socket, which the agent binds in its own ready folder as in
// single mode (<ready>/<slot>.sock) and keeps open for the slot's whole
// life, through the adopt frame and the env it carries. The helper gives
// that socket a second name in its own folder, <helper ready>/<slot>/
// ready.sock (EnsureReadySocket with no nonce), which the slot's spec binds
// read-only, as the gate requires of every file there. So the root work of
// a park is the root work of a create, in the same one call, plus that
// name; nothing else of the pool needs root:
//
//   - a claim (warm_adopt.go) reads and relabels the container through the
//     gate, sends the adopt frame and the env on the agent's own socket,
//     and puts the request's rules on the slot's address through the
//     helper's firewall, as single mode does in process; the relabel and
//     the rules go at once (splitClaimFinish). A disk limit goes through
//     the helper's disk_quota part, alone, as a resize's.
//   - a start of an adopted container binds the park socket again and has
//     the helper make the container's files and name the socket again
//     (splitParkFiles), as any split start does with its ready socket.
//   - a slot's teardown (an evict, a reap, the drain, the boot purge)
//     deletes the container through the gate and releases the helper's
//     files with the agent's own (destroyParked).

// parkSocketName has the helper name a warm-pool slot's park socket, which
// the agent bound already, in its own folder, and checks the answer is the
// name for that slot.
func (d *Driver) parkSocketName(ctx context.Context, slotID string) (string, error) {
	if d.parkSockets == nil {
		return "", errors.New("containerd: privilege mode split needs the root helper's EnsureReadySocket for a warm-pool slot's park socket")
	}
	p, err := d.parkSockets.EnsureReadySocket(ctx, slotID, "")
	if err != nil {
		return "", fmt.Errorf("root helper: park socket: %w", err)
	}
	if filepath.Base(p) != rootpolicy.ParkSocketFile || filepath.Base(filepath.Dir(p)) != slotID || !filepath.IsAbs(p) {
		return "", fmt.Errorf("root helper: park socket: the answer %q is not slot %s's park socket", p, slotID)
	}
	return p, nil
}

// specReadySource is where a spec binds the guest's ready socket from, ""
// for none.
func specReadySource(spec *specs.Spec) string {
	if spec == nil {
		return ""
	}
	for _, m := range spec.Mounts {
		if m.Destination == dockerpkg.GuestReadySocketPath {
			return filepath.Clean(m.Source)
		}
	}
	return ""
}

// splitParkSlot is the warm-pool slot whose park socket a split spec binds
// from source, <helper ready>/<slot>/ready.sock; "" when source is no park
// socket's name in that shape.
func splitParkSlot(source string) string {
	if filepath.Base(source) != rootpolicy.ParkSocketFile {
		return ""
	}
	slot := filepath.Base(filepath.Dir(source))
	if !IsParkedSandboxID(slot) || validateSandboxID(slot) != nil {
		return ""
	}
	return slot
}

// splitParkFiles is a split start's files for an adopted warm-pool
// container: the container's files part, as any split start makes it, and
// then the park socket's name again, which the agent has bound again by
// then. The name must be the one the spec binds (source): a start cannot
// change the spec.
func (d *Driver) splitParkFiles(ctx context.Context, containerID, source string) (*rootdpb.SandboxFilePaths, error) {
	files, err := d.helperFiles(ctx, containerID, "", rootdpb.RunscConfig_RUNSC_CONFIG_UNSPECIFIED)
	if err != nil {
		return nil, err
	}
	got, err := d.parkSocketName(ctx, containerID)
	if err != nil {
		return nil, err
	}
	if got != source {
		return nil, fmt.Errorf("root helper: park socket %q, but container %s's spec binds %q", got, containerID, source)
	}
	return files, nil
}

// splitClaimFinish is a split claim's last two trips, made at once. Single
// mode relabels the container and then puts the request's rules on the
// slot's address, both in process. In split each is a trip to the root
// helper: the relabel through its containerd gate, the rules through its
// firewall. Neither reads what the other writes (containerd's record of
// the container; the helper's rules for one address), so the claim waits
// for the slower trip, not for both. The calls are single mode's, so the
// gate still checks the relabel and the helper still checks that the
// address is its slot's lease. The netns slot's new owner (the agent's own
// store) is written once the relabel is in, as in single mode.
//
// Both trips start only after the toolbox acked the sandbox's identity, as
// in single mode: a parked slot has no identity and no network.
//
// The rollback rule: when either trip fails, the slot's egress block goes
// back on before the claim returns, and only after the rules trip has
// ended, so no lift can land after it. tryWarmAdopt then destroys the
// slot. A claim that fails part way leaves its slot blocked until it is
// removed, never open.
func (d *Driver) splitClaimFinish(ctx context.Context, container cntr.Container, labels map[string]string, slot *containerdpool.ParkedSlot, sandboxID string, req models.CreateSandboxRequest) error {
	rules := make(chan error, 1)
	go func() { rules <- d.applyAdoptNetworkPolicy(slot.ContainerIP, req) }()
	_, labelErr := container.SetLabels(ctx, labels)
	if labelErr == nil && d.netns != nil && slot.ID != "" && slot.ID != sandboxID {
		_ = d.netns.ReassignOwner(ctx, slot.ID, sandboxID)
	}
	err := errors.Join(labelErr, <-rules)
	if err == nil {
		return nil
	}
	if d.networkRules != nil && slot.ContainerIP != "" {
		if berr := d.networkRules.BlockAllEgress(slot.ContainerIP); berr != nil {
			err = errors.Join(err, fmt.Errorf("put the slot's egress block back: %w", berr))
		}
	}
	return err
}
