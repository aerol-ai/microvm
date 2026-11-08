package docker

import (
	"context"
	"net/http"
	"net/url"
	"strings"
)

// Freeze pauses every process of the container with the cgroup freezer
// (docker pause), memory intact, for the cluster ownership fence
// (runtime.Freezer). The sandbox row is not touched: a frozen sandbox is still
// "started", and the events consumer ignores pause/unpause.
//
// Idempotent. Docker answers 409 when the container is already paused or not
// running; either way nothing of it is executing, which is all the fence
// needs. A container that is gone (404) is not executing either. Any other
// 409 (e.g. "restarting") is returned, so the caller retries.
func (c *Client) Freeze(ctx context.Context, containerRef string) error {
	err := c.doJSON(ctx, http.MethodPost, "/containers/"+url.PathEscape(containerRef)+"/pause", nil, nil, nil, nil)
	if err == nil || isContainerNotFoundError(err) || isConflictSaying(err, "already paused", "is not running") {
		return nil
	}
	return err
}

// Thaw undoes Freeze (docker unpause). A container that is not paused, or is
// gone, is already in the state Thaw leaves it in.
func (c *Client) Thaw(ctx context.Context, containerRef string) error {
	err := c.doJSON(ctx, http.MethodPost, "/containers/"+url.PathEscape(containerRef)+"/unpause", nil, nil, nil, nil)
	if err == nil || isContainerNotFoundError(err) || isConflictSaying(err, "is not paused") {
		return nil
	}
	return err
}

// isConflictSaying matches a 409 from doRequest whose body names one of the
// given states.
func isConflictSaying(err error, states ...string) bool {
	if err == nil || !strings.Contains(err.Error(), "failed with status 409") {
		return false
	}
	msg := err.Error()
	for _, s := range states {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}
