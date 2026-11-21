// Package procgroup runs a child process, and everything it starts, as one
// unit that never outlives the call that ran it.
//
// The root helper runs CNI plugins and conntrack for the agent's calls
// (privilege mode split). A plugin starts its own children (the bridge
// plugin runs its IPAM plugin), and exec.CommandContext kills only the
// process it started: on a cancelled call, or a helper stopped for a swap,
// a grandchild would go on and finish the first try of a call after its
// retry, freeing an address the retry's namespace now holds (PR 4 review).
// Run puts the child in a process group of its own, kills the whole group
// when the call ends, whichever way it ends, and waits until no member is
// left.
package procgroup

import (
	"context"
	"os/exec"
	"time"
)

// GoneWait bounds the wait for a killed group's members to go: a member
// stuck in the kernel still runs no more of its own code once SIGKILL is
// pending, which is what matters. Tests shorten it.
var GoneWait = 2 * time.Second

// Run runs cmd in a process group of its own; when ctx ends the whole
// group is killed, and when cmd ends any member it left behind is too.
// Off Linux it is cmd.Run.
func Run(ctx context.Context, cmd *exec.Cmd) error {
	return run(ctx, cmd)
}
