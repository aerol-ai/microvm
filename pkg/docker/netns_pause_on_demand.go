package docker

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// A create with network rules (block-all, a CIDR allow or deny list, or a
// hostname allowlist, which reaches the driver as block-all) must have them
// on its address before its workload runs. Docker gives a container its
// address only when it starts it, so on its own path the rules could go on
// only once the workload was already running: a few milliseconds of
// unfiltered traffic. A pause slot from the pool closes that, since its
// address exists before the workload does. A restricted create that gets no
// slot (pool off, or empty) starts a pause container of its own instead,
// through the pool's code, and goes on exactly as with a slot: rules on the
// pause's address, the workload created into its network namespace and
// started only then, and, on failure or destroy, the workload first, its
// rules next and the pause with the address last. A create without rules
// keeps Docker's own path and its latency.
//
// The pause is named as an adopted slot (netnsAdoptedName), so everything
// that finds a slot by its sandbox finds this one too: Destroy, the pool's
// reconcile, and PrepareNetnsPause on a node without the pool.

// errLoopbackRestricted refuses a restricted create under
// SB_DOCKER_TOOLBOX_LOOPBACK: a workload in a pause's network namespace
// cannot publish the toolbox port, and starting it on Docker's own path
// would run it before its rules.
var errLoopbackRestricted = errors.New("docker: a create with network rules needs the toolbox on the sandbox network; SB_DOCKER_TOOLBOX_LOOPBACK cannot serve it")

// SetNetnsPauseImage sets the image of the pause containers restricted
// creates start for themselves: SB_DOCKER_NETNS_POOL_PAUSE_IMAGE, the same
// image the pool's slots run.
func (c *Client) SetNetnsPauseImage(image string) {
	c.pauseImage = strings.TrimSpace(image)
}

// needsOwnPause reports whether a create without a pool slot must start a
// pause container: it is on runc and its rules would be enforced (with
// network rules off there is nothing to install before the start). gVisor
// keeps Docker's own path: runsc builds its own network stack, and joining
// another container's namespace is not a shape the pool supports there
// either.
func (c *Client) needsOwnPause(req models.CreateSandboxRequest, effectiveRuntime string) bool {
	return effectiveRuntime == models.RuntimeDocker && hasCreateNetRules(req) && c.networkRules.Enabled()
}

// ownPause is a create's own pause container: created before the
// workload, which joins its namespace (Docker allows that while the pause
// is not running yet), and started alongside the workload's create, so its
// start costs the create only what the workload's create doesn't cover.
type ownPause struct {
	id   string
	done chan struct{}
	slot netnsSlot
	err  error
}

// wait returns the pause's slot once its start is over; nil waits for
// nothing.
func (p *ownPause) wait() (netnsSlot, error) {
	if p == nil {
		return netnsSlot{}, nil
	}
	<-p.done
	return p.slot, p.err
}

// startSandboxPause creates sandboxID's own pause container and starts it
// in the background. An image that is missing (never pulled on this node,
// or image GC removed it after the last restricted create went) is pulled
// once and the create retried; pulled reports that. A name conflict means
// another create of this sandbox holds the pause: it is that create's, and
// is left alone. A pause that fails to start is not removed here: the
// create removes its workload first, then the pause.
func (c *Client) startSandboxPause(ctx context.Context, sandboxID string) (p *ownPause, pulled bool, err error) {
	if c.toolboxLoopback {
		return nil, false, errLoopbackRestricted
	}
	if c.pauseImage == "" {
		return nil, false, errors.New("docker: a create with network rules needs a pause container and no pause image is configured (SB_DOCKER_NETNS_POOL_PAUSE_IMAGE)")
	}
	name := netnsAdoptedName(sandboxID)
	id, err := c.createNetnsPause(ctx, c.pauseImage, name)
	if err != nil && isNoSuchImageError(err) {
		if pullErr := c.pullImageDedup(ctx, c.pauseImage, nil); pullErr != nil {
			return nil, false, fmt.Errorf("pull pause image: %w", pullErr)
		}
		pulled = true
		id, err = c.createNetnsPause(ctx, c.pauseImage, name)
	}
	if err != nil {
		if isConflictStatus(err) {
			return nil, pulled, fmt.Errorf("%w: %s", ErrSandboxContainerExists, name)
		}
		return nil, pulled, err
	}
	p = &ownPause{id: id, done: make(chan struct{})}
	go func() {
		defer close(p.done)
		p.slot, p.err = c.bootNetnsPause(ctx, id)
	}()
	return p, pulled, nil
}

// releaseSandboxPause removes a create's pause container, a pool slot or
// its own, once nothing runs in its network namespace.
func (c *Client) releaseSandboxPause(ctx context.Context, slot netnsSlot) {
	if err := c.removeContainer(context.WithoutCancel(ctx), slot.containerID, true); err != nil {
		c.logger.Warn("remove pause container failed; the boot sweep removes it", "container_id", slot.containerID, "error", err)
	}
}

// pausesPossible reports whether a sandbox here may run in a pause's
// network namespace: the pool hands out slots, or restricted creates start
// their own.
func (c *Client) pausesPossible() bool {
	return c.netnsPool != nil || c.networkRules.Enabled()
}

// PrepareNetnsPause readies restricted creates on a node without the pause
// pool (whose own loop does both): it pulls the pause image if it is
// missing, so the first restricted create doesn't wait for the pull, and
// removes the pause containers an earlier run left for sandboxes whose
// workload container is gone (a crash between the two creates, or a destroy
// that died halfway). Only pauses created before `before` are judged, so a
// create in flight is never touched. Best effort, off the boot path: the
// create path pulls for itself and the next boot sweeps again.
func (c *Client) PrepareNetnsPause(ctx context.Context, before time.Time) {
	if c.pauseImage != "" {
		if _, err := c.inspectImage(ctx, c.pauseImage); err != nil {
			if pullErr := c.pullImageDedup(ctx, c.pauseImage, nil); pullErr != nil {
				c.logger.Warn("pause image pull failed; restricted creates pull it themselves", "image", c.pauseImage, "error", pullErr)
			}
		}
	}
	summaries, err := c.listNetnsPauseContainers(ctx)
	if err != nil {
		c.logger.Warn("pause container sweep: list failed", "error", err)
		return
	}
	for _, s := range summaries {
		sandboxID, ok := strings.CutPrefix(containerSummaryName(s), netnsAdoptedPrefix)
		if !ok || s.Created >= before.Unix() {
			continue
		}
		if _, err := c.inspectContainer(ctx, sandboxID); !isContainerNotFoundError(err) {
			continue // its workload exists (or the engine didn't say): keep it
		}
		netnsPoolOrphansReaped.Add(1)
		if err := c.removeContainer(ctx, s.ID, true); err != nil {
			c.logger.Warn("pause container sweep: remove failed", "container_id", s.ID, "error", err)
		}
	}
}

// isNoSuchImageError matches Docker's answer to a create of an image it
// does not have.
func isNoSuchImageError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "failed with status 404") && strings.Contains(strings.ToLower(err.Error()), "no such image")
}

// isConflictStatus matches Docker's 409, a name another container holds.
func isConflictStatus(err error) bool {
	return err != nil && strings.Contains(err.Error(), "failed with status 409")
}
